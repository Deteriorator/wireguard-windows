module golang.zx2c4.com/wireguard/windows

go 1.15

require (
	github.com/lxn/walk v0.0.0-20201110160827-18ea5e372cdb
	github.com/lxn/win v0.0.0-20201111105847-2a20daff6a55
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sys v0.0.0-20201110211018-35f3e6cf4a65
	golang.org/x/text v0.3.4
	golang.zx2c4.com/wireguard v0.0.20200321-0.20201111175144-60b3766b89b9
)

replace (
	github.com/lxn/walk => golang.zx2c4.com/wireguard/windows v0.0.0-20201110162739-c2882a58687c
	github.com/lxn/win => golang.zx2c4.com/wireguard/windows v0.0.0-20201107183008-659a4e955570
)
