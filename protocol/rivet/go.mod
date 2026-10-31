module xio.local/rivet

go 1.27.3

require (
	github.com/ajg/form v1.6.1 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/apernet/quic-go v0.59.1-0.20260425001925-6c6cc9bcb716 // indirect
	github.com/cbeuw/connutil v0.0.0-20200411215123-966bfaa51ee3 // indirect
	github.com/cloudflare/circl v1.6.4 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/ghodss/yaml v1.0.1-0.20220118164431-d8423dcdf344 // indirect
	github.com/go-chi/chi/v5 v5.2.5 // indirect
	github.com/go-chi/cors v1.2.2 // indirect
	github.com/go-chi/render v1.0.3 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/gorilla/schema v1.4.1 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pion/dtls/v3 v3.1.4 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/stun/v3 v3.1.6 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pires/go-proxyproto v0.15.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/sirupsen/logrus v1.10.1 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f // indirect
	go.etcd.io/bbolt v1.4.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/mobile v0.0.0-20261011034528-197770444867 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)

tool golang.org/x/mobile/cmd/gobind

replace github.com/xtls/xray-core => ../../vendor/xray

replace github.com/wlynxg/anet => ../../vendor/anet

require (
	github.com/amnezia-vpn/amnezia-tun2socks/v2 v2.5.6
	github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814
	github.com/cbeuw/Cloak v1.1.2
	github.com/coder/websocket v1.8.15
	github.com/fxamacker/cbor/v2 v2.9.6
	github.com/quic-go/masque-go v0.6.0
	github.com/quic-go/quic-go v0.64.0
	github.com/xtls/xray-core v1.260724.0
	github.com/yosida95/uritemplate/v3 v3.0.2
	golang.org/x/net v0.61.0
	golang.org/x/sys v0.49.0
	golang.zx2c4.com/wireguard/windows v1.0.1
)

replace github.com/cbeuw/Cloak => ../../vendor/cloak

replace tailscale.com => ../../vendor/tailscale

replace github.com/amnezia-vpn/amnezia-tun2socks/v2 => ../../vendor/tun2socks

replace github.com/amnezia-vpn/amneziawg-go/v3 => ../../vendor/amneziawg-go
