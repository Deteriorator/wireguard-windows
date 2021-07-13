/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package driver

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type AdapterState uint32

const (
	AdapterStateDown AdapterState = 0
	AdapterStateUp   AdapterState = 1
)

type AllowedIP struct {
	Address       [16]byte
	AddressFamily winipcfg.AddressFamily
	Cidr          uint8
	_             [4]byte
}

type PeerFlag uint32

const (
	PeerHasPublicKey           PeerFlag = 1 << 0
	PeerHasPresharedKey        PeerFlag = 1 << 1
	PeerHasPersistentKeepalive PeerFlag = 1 << 2
	PeerHasEndpoint            PeerFlag = 1 << 3
	PeerReplaceAllowedIPs      PeerFlag = 1 << 5
	PeerRemove                 PeerFlag = 1 << 6
	PeerUpdate                 PeerFlag = 1 << 7
)

type Peer struct {
	Flags               PeerFlag
	_                   uint32
	PublicKey           [32]byte
	PresharedKey        [32]byte
	PersistentKeepalive uint16
	_                   uint16
	Endpoint            winipcfg.RawSockaddrInet
	TxBytes             uint64
	RxBytes             uint64
	LastHandshake       uint64
	AllowedIPsCount     uint32
}

type InterfaceFlag uint32

const (
	InterfaceHasPublicKey  InterfaceFlag = 1 << 0
	InterfaceHasPrivateKey InterfaceFlag = 1 << 1
	InterfaceHasListenPort InterfaceFlag = 1 << 2
	InterfaceReplacePeers  InterfaceFlag = 1 << 3
)

type Interface struct {
	Flags      InterfaceFlag
	ListenPort uint16
	PrivateKey [32]byte
	PublicKey  [32]byte
	PeerCount  uint32
	_          [4]byte
}

var (
	procWireGuardSetAdapterState  = modwireguard.NewProc("WireGuardSetAdapterState")
	procWireGuardSetConfiguration = modwireguard.NewProc("WireGuardSetConfiguration")
	procWireGuardGetConfiguration = modwireguard.NewProc("WireGuardGetConfiguration")
)

func (wireguard *Adapter) SetAdapterState(adapterState AdapterState) (err error) {
	r0, _, e1 := syscall.Syscall(procWireGuardSetAdapterState.Addr(), 2, wireguard.handle, uintptr(adapterState), 0)
	if r0 == 0 {
		err = e1
	}
	return
}

func (wireguard *Adapter) SetConfiguration(interfaze *Interface, size uint32) (err error) {
	r0, _, e1 := syscall.Syscall(procWireGuardSetConfiguration.Addr(), 3, wireguard.handle, uintptr(unsafe.Pointer(interfaze)), uintptr(size))
	if r0 == 0 {
		err = e1
	}
	return
}

func (wireguard *Adapter) GetConfiguration() (interfaze *Interface, err error) {
	size := wireguard.lastGetGuessSize
	if size == 0 {
		size = 512
	}
	for {
		buf := make([]byte, size)
		r0, _, e1 := syscall.Syscall(procWireGuardGetConfiguration.Addr(), 3, wireguard.handle, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
		if r0 != 0 {
			wireguard.lastGetGuessSize = size
			return (*Interface)(unsafe.Pointer(&buf[0])), nil
		}
		if e1 != windows.ERROR_MORE_DATA {
			return nil, e1
		}
	}
}

func (interfaze *Interface) FirstPeer() *Peer {
	return (*Peer)(unsafe.Pointer(uintptr(unsafe.Pointer(interfaze)) + unsafe.Sizeof(*interfaze)))
}

func (peer *Peer) NextPeer() *Peer {
	return (*Peer)(unsafe.Pointer(uintptr(unsafe.Pointer(peer)) + unsafe.Sizeof(*peer) + uintptr(peer.AllowedIPsCount)*unsafe.Sizeof(AllowedIP{})))
}

func (peer *Peer) FirstAllowedIP() *AllowedIP {
	return (*AllowedIP)(unsafe.Pointer(uintptr(unsafe.Pointer(peer)) + unsafe.Sizeof(*peer)))
}

func (allowedIP *AllowedIP) NextAllowedIP() *AllowedIP {
	return (*AllowedIP)(unsafe.Pointer(uintptr(unsafe.Pointer(allowedIP)) + unsafe.Sizeof(*allowedIP)))
}

type ConfigBuilder struct {
	buffer []byte
}

func (builder *ConfigBuilder) Preallocate(size uint32) {
	if builder.buffer == nil {
		builder.buffer = make([]byte, 0, size)
	}
}

func (builder *ConfigBuilder) AppendInterface(interfaze *Interface) {
	var newBytes []byte
	unsafeSlice(unsafe.Pointer(&newBytes), unsafe.Pointer(interfaze), int(unsafe.Sizeof(*interfaze)))
	builder.buffer = append(builder.buffer, newBytes...)
}

func (builder *ConfigBuilder) AppendPeer(peer *Peer) {
	var newBytes []byte
	unsafeSlice(unsafe.Pointer(&newBytes), unsafe.Pointer(peer), int(unsafe.Sizeof(*peer)))
	builder.buffer = append(builder.buffer, newBytes...)
}

func (builder *ConfigBuilder) AppendAllowedIP(allowedIP *AllowedIP) {
	var newBytes []byte
	unsafeSlice(unsafe.Pointer(&newBytes), unsafe.Pointer(allowedIP), int(unsafe.Sizeof(*allowedIP)))
	builder.buffer = append(builder.buffer, newBytes...)
}

func (builder *ConfigBuilder) Interface() (*Interface, uint32) {
	if builder.buffer == nil {
		return nil, 0
	}
	return (*Interface)(unsafe.Pointer(&builder.buffer[0])), uint32(len(builder.buffer))
}

// unsafeSlice updates the slice slicePtr to be a slice
// referencing the provided data with its length & capacity set to
// lenCap.
//
// TODO: when Go 1.16 or Go 1.17 is the minimum supported version,
// update callers to use unsafe.Slice instead of this.
func unsafeSlice(slicePtr, data unsafe.Pointer, lenCap int) {
	type sliceHeader struct {
		Data unsafe.Pointer
		Len  int
		Cap  int
	}
	h := (*sliceHeader)(slicePtr)
	h.Data = data
	h.Len = lenCap
	h.Cap = lenCap
}
