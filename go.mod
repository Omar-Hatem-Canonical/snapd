module github.com/snapcore/snapd

go 1.21

toolchain go1.24.1

// maze.io/x/crypto/afis imported by github.com/snapcore/secboot/tpm2
replace maze.io/x/crypto => github.com/snapcore/maze.io-x-crypto v0.0.0-20190131090603-9b94c9afe066

require (
	github.com/bmatcuk/doublestar/v4 v4.6.1
	github.com/canonical/go-efilib v1.4.1
	github.com/canonical/go-sp800.90a-drbg v0.0.0-20210314144037-6eeb1040d6c3 // indirect
	github.com/canonical/go-tpm2 v1.12.2
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/godbus/dbus/v5 v5.1.0
	github.com/gorilla/mux v1.8.0
	github.com/gvalkov/golang-evdev v0.0.0-20191114124502-287e62b94bcb
	github.com/jessevdk/go-flags v1.5.1-0.20210607101731-3927b71304df
	github.com/juju/ratelimit v1.0.1
	github.com/mvo5/goconfigparser v0.0.0-20231016112547-05bd887f05e1
	// if below two libseccomp-golang lines are updated, one must also update packaging/ubuntu-14.04/rules
	github.com/mvo5/libseccomp-golang v0.9.1-0.20180308152521-f4de83b52afb // old trusty builds only
	github.com/seccomp/libseccomp-golang v0.9.2-0.20220502024300-f57e1d55ea18
	github.com/snapcore/go-gettext v0.0.0-20191107141714-82bbea49e785
	github.com/snapcore/secboot v0.0.0-20250326125418-bf2f40ea35c4
	golang.org/x/crypto v0.25.0
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/sys v0.22.0
	golang.org/x/text v0.16.0
	golang.org/x/xerrors v0.0.0-20220609144429-65e65417b02f
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/macaroon.v1 v1.0.0
	gopkg.in/retry.v1 v1.0.3
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cakturk/go-netstat v0.0.0-20200220111822-e5b49efee7a5
	github.com/canonical/mqtt.golang v0.1.7
	go.etcd.io/bbolt v1.3.9
	golang.org/x/sync v0.7.0
)

require github.com/gorilla/websocket v1.5.3 // indirect

require (
	github.com/caarlos0/env/v11 v11.3.1
	github.com/canonical/cpuid v0.0.0-20220614022739-219e067757cb // indirect
	github.com/canonical/go-kbkdf v0.0.0-20250104172618-3b1308f9acf9 // indirect
	github.com/canonical/tcglog-parser v0.0.0-20240924110432-d15eaf652981 // indirect
	github.com/kr/pretty v0.2.2-0.20200810074440-814ac30b4b18 // indirect
	github.com/kr/text v0.2.0 // indirect
	golang.org/x/exp v0.0.0-20240416160154-fe59bbe5cc7f // indirect
	golang.org/x/term v0.22.0 // indirect
	maze.io/x/crypto v0.0.0-20190131090603-9b94c9afe066 // indirect
)
