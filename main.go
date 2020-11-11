/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"debug/pe"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/tunnel"
	"golang.zx2c4.com/wireguard/windows/ui"
	"golang.zx2c4.com/wireguard/windows/updater"
)

func fatal(v ...interface{}) {
	windows.MessageBox(0, windows.StringToUTF16Ptr(fmt.Sprint(v...)), windows.StringToUTF16Ptr(l18n.Sprintf("Error")), windows.MB_ICONERROR)
	os.Exit(1)
}

func fatalf(format string, v ...interface{}) {
	fatal(l18n.Sprintf(format, v...))
}

func info(title string, format string, v ...interface{}) {
	windows.MessageBox(0, windows.StringToUTF16Ptr(l18n.Sprintf(format, v...)), windows.StringToUTF16Ptr(title), windows.MB_ICONINFORMATION)
}

func usage() {
	var flags = [...]string{
		l18n.Sprintf("(no argument): elevate and install manager service"),
		"/installmanagerservice",
		"/installtunnelservice CONFIG_PATH",
		"/uninstallmanagerservice",
		"/uninstalltunnelservice TUNNEL_NAME",
		"/managerservice",
		"/tunnelservice CONFIG_PATH",
		"/ui CMD_READ_HANDLE CMD_WRITE_HANDLE CMD_EVENT_HANDLE LOG_MAPPING_HANDLE",
		"/dumplog OUTPUT_PATH",
		"/update [LOG_FILE]",
		"/removealladapters [LOG_FILE]",
	}
	builder := strings.Builder{}
	for _, flag := range flags {
		builder.WriteString(fmt.Sprintf("    %s\n", flag))
	}
	info(l18n.Sprintf("Command Line Options"), "Usage: %s [\n%s]", os.Args[0], builder.String())
	os.Exit(1)
}

//TODO: replace with https://go-review.googlesource.com/c/sys/+/269077 once merged
func isWow64Process2(handle windows.Handle, processMachine *uint16, nativeMachine *uint16) (err error) {
	p := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsWow64Process2")
	err = p.Find()
	if err != nil {
		return
	}
	ret, _, e := syscall.Syscall(p.Addr(), 3, uintptr(handle), uintptr(unsafe.Pointer(processMachine)), uintptr(unsafe.Pointer(nativeMachine)))
	if ret == 0 {
		err = e
		return err
	}
	return
}

func checkForWow64() {
	b, err := func() (bool, error) {
		var processMachine, nativeMachine uint16
		err := isWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine)
		if err == nil {
			if nativeMachine == pe.IMAGE_FILE_MACHINE_ARM64 && runtime.GOARCH == "arm" {
				//TODO: remove this exception when Go supports arm64
				return false, nil
			}
			return processMachine != pe.IMAGE_FILE_MACHINE_UNKNOWN, nil
		}
		if _, isDllErr := err.(*windows.DLLError); !isDllErr {
			return false, err
		}
		var b bool
		err = windows.IsWow64Process(windows.CurrentProcess(), &b)
		if err != nil {
			return false, err
		}
		return b, nil
	}()
	if err != nil {
		fatalf("Unable to determine whether the process is running under WOW64: %v", err)
	}
	if b {
		fatalf("You must use the native version of WireGuard on this computer.")
	}
}

func checkForAdminGroup() {
	// This is not a security check, but rather a user-confusion one.
	var processToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken)
	if err != nil {
		fatalf("Unable to open current process token: %v", err)
	}
	defer processToken.Close()
	if !elevate.TokenIsElevatedOrElevatable(processToken) {
		fatalf("WireGuard may only be used by users who are a member of the Builtin %s group.", elevate.AdminGroupName())
	}
}

func checkForAdminDesktop() {
	adminDesktop, err := elevate.IsAdminDesktop()
	if !adminDesktop && err == nil {
		fatalf("WireGuard is running, but the UI is only accessible from desktops of the Builtin %s group.", elevate.AdminGroupName())
	}
}

//TODO: remove me when dropping support for Windows 7
func checkForKB2921916() {
	maj, min, _ := windows.RtlGetNtVersionNumbers()
	if maj != 6 || min != 1 {
		return
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer key.Close()
	subkeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		return
	}
	found := false
	for i := range subkeys {
		if strings.Contains(subkeys[i], "KB2921916") {
			found = true
			break
		}
	}
	if found {
		return
	}
	var url string
	const urlTemplate = "https://download.wireguard.com/windows-toolchain/distfiles/Windows6.1-KB2921916-%s.msu"
	if runtime.GOARCH == "386" {
		url = fmt.Sprintf(urlTemplate, "x86")
	} else if runtime.GOARCH == "amd64" {
		url = fmt.Sprintf(urlTemplate, "x64")
	} else {
		return
	}
	ret, _ := windows.MessageBox(0, windows.StringToUTF16Ptr(l18n.Sprintf("Use of WireGuard on Windows 7 requires KB2921916. Would you like to download the hotfix in your web browser?")), windows.StringToUTF16Ptr(l18n.Sprintf("Missing Windows Hotfix")), windows.MB_ICONWARNING|windows.MB_YESNO)
	if ret == 6 {
		windows.ShellExecute(0, nil, windows.StringToUTF16Ptr(url), nil, nil, windows.SW_SHOWNORMAL)
	}
	os.Exit(0)
}

func execElevatedManagerServiceInstaller() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	err = elevate.ShellExecute(path, "/installmanagerservice", "", windows.SW_SHOW)
	if err != nil {
		return err
	}
	os.Exit(0)
	return windows.ERROR_ACCESS_DENIED // Not reached
}

func pipeFromHandleArgument(handleStr string) (*os.File, error) {
	handleInt, err := strconv.ParseUint(handleStr, 10, 64)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handleInt), "pipe"), nil
}

func main() {
	checkForWow64()
	checkForKB2921916()

	if len(os.Args) <= 1 {
		checkForAdminGroup()
		if ui.RaiseUI() {
			return
		}
		err := execElevatedManagerServiceInstaller()
		if err != nil {
			fatal(err)
		}
		return
	}
	switch os.Args[1] {
	case "/installmanagerservice":
		if len(os.Args) != 2 {
			usage()
		}
		go ui.WaitForRaiseUIThenQuit()
		err := manager.InstallManager()
		if err != nil {
			if err == manager.ErrManagerAlreadyRunning {
				checkForAdminDesktop()
			}
			fatal(err)
		}
		checkForAdminDesktop()
		time.Sleep(30 * time.Second)
		fatalf("WireGuard system tray icon did not appear after 30 seconds.")
		return
	case "/uninstallmanagerservice":
		if len(os.Args) != 2 {
			usage()
		}
		err := manager.UninstallManager()
		if err != nil {
			fatal(err)
		}
		return
	case "/managerservice":
		if len(os.Args) != 2 {
			usage()
		}
		err := elevate.SetDefaultObjectDacl()
		if err != nil {
			fatal(err)
		}
		err = manager.Run()
		if err != nil {
			fatal(err)
		}
		return
	case "/installtunnelservice":
		if len(os.Args) != 3 {
			usage()
		}
		err := manager.InstallTunnel(os.Args[2])
		if err != nil {
			fatal(err)
		}
		return
	case "/uninstalltunnelservice":
		if len(os.Args) != 3 {
			usage()
		}
		err := manager.UninstallTunnel(os.Args[2])
		if err != nil {
			fatal(err)
		}
		return
	case "/tunnelservice":
		if len(os.Args) != 3 {
			usage()
		}
		err := elevate.SetDefaultObjectDacl()
		if err != nil {
			fatal(err)
		}
		err = tunnel.Run(os.Args[2])
		if err != nil {
			fatal(err)
		}
		return
	case "/ui":
		if len(os.Args) != 6 {
			usage()
		}
		err := elevate.DropAllPrivileges(false)
		if err != nil {
			fatal(err)
		}
		readPipe, err := pipeFromHandleArgument(os.Args[2])
		if err != nil {
			fatal(err)
		}
		writePipe, err := pipeFromHandleArgument(os.Args[3])
		if err != nil {
			fatal(err)
		}
		eventPipe, err := pipeFromHandleArgument(os.Args[4])
		if err != nil {
			fatal(err)
		}
		ringlogger.Global, err = ringlogger.NewRingloggerFromInheritedMappingHandle(os.Args[5], "GUI")
		if err != nil {
			fatal(err)
		}
		manager.InitializeIPCClient(readPipe, writePipe, eventPipe)
		ui.RunUI()
		return
	case "/dumplog":
		if len(os.Args) != 3 {
			usage()
		}
		file, err := os.Create(os.Args[2])
		if err != nil {
			fatal(err)
		}
		defer file.Close()
		err = ringlogger.DumpTo(file, true)
		if err != nil {
			fatal(err)
		}
		return
	case "/update":
		if len(os.Args) != 2 && len(os.Args) != 3 {
			usage()
		}
		var f *os.File
		var err error
		if len(os.Args) == 2 {
			f = os.Stdout
		} else {
			f, err = os.Create(os.Args[2])
			if err != nil {
				fatal(err)
			}
			defer f.Close()
		}
		l := log.New(f, "", log.LstdFlags)
		for progress := range updater.DownloadVerifyAndExecute(0) {
			if len(progress.Activity) > 0 {
				if progress.BytesTotal > 0 || progress.BytesDownloaded > 0 {
					var percent float64
					if progress.BytesTotal > 0 {
						percent = float64(progress.BytesDownloaded) / float64(progress.BytesTotal) * 100.0
					}
					l.Printf("%s: %d/%d (%.2f%%)\n", progress.Activity, progress.BytesDownloaded, progress.BytesTotal, percent)
				} else {
					l.Println(progress.Activity)
				}
			}
			if progress.Error != nil {
				l.Printf("Error: %v\n", progress.Error)
			}
			if progress.Complete || progress.Error != nil {
				return
			}
		}
		return
	case "/removealladapters":
		if len(os.Args) != 2 && len(os.Args) != 3 {
			usage()
		}
		var f *os.File
		var err error
		if len(os.Args) == 2 {
			f = os.Stdout
		} else {
			f, err = os.Create(os.Args[2])
			if err != nil {
				fatal(err)
			}
			defer f.Close()
		}
		log.SetOutput(f)
		rebootRequired, err := tun.WintunPool.DeleteDriver()
		if err != nil {
			log.Printf("Error: %v\n", err)
		} else if rebootRequired {
			log.Println("A reboot may be required")
		}
		return
	}
	usage()
}
