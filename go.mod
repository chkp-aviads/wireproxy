// module github.com/chkp-aviads/wireproxy
module wireproxy

go 1.23.1

toolchain go1.23.5

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/akamensky/argparse v1.4.0
	github.com/go-ini/ini v1.67.0
	github.com/landlock-lsm/go-landlock v0.0.0-20250303204525-1544bccde3a3
	github.com/things-go/go-socks5 v0.0.6
	golang.org/x/net v0.40.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	suah.dev/protect v1.2.4
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250602214251-4235583ef8c6 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.76 // indirect
)

replace github.com/things-go/go-socks5 => github.com/chkp-aviads/go-socks5 v0.0.8
