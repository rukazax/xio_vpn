// Package xrayregistry registers only the Xray components the XIO helper can
// reach. The root-owned server gateway needs a superset (inbound handlers,
// stats, DNS, routing, the JSON loader); that lives in xrayregistry/gateway so
// the helper does not link it.
package xrayregistry

import (
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/trojan"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
)

// The helper builds exactly one config shape (internal/xrayclient/xrayconf.go):
// "log" plus one vless/vmess/trojan outbound over
// tcp/websocket/grpc/httpupgrade/splithttp with none/TLS/REALITY security.
// Everything outside that shape is refused by xrayclient.Parse or by
// buildConfig, so the components below can never be reached from a profile and
// are left out. Measured ablations (work/opt-registry-trim-20261104.md):
//
//	app/dns             -352 256 B   no "dns" section; core installs localdns
//	app/router          -219 648 B   no "routing" section; core installs DefaultRouter
//	proxy/vless/inbound -117 760 B   no inbounds
//	proxy/vmess/inbound  -90 112 B   no inbounds
//	proxy/freedom       -102 400 B   not an accepted outbound protocol
//	app/stats            -50 688 B   no "stats" section; core installs NoopManager
//	app/policy           -34 304 B   no "policy" section; core installs DefaultManager
//	proxy/blackhole      -14 848 B   not an accepted outbound protocol
//
// Together -989 184 B: 31 450 112 -> 30 460 928 B, 687 -> 671 packages in the
// dependency graph. transport/internet/udp is absent as well but costs nothing:
// app/proxyman/inbound links the package regardless.
//
// app/proxyman/inbound stays even though the helper has no inbounds: the
// protobuf builder always emits proxyman.InboundConfig, and this is the
// package that registers that app type.
//
// "tagged" (chained outbounds) is deliberately absent: XIO accepts only
// vless/vmess/trojan outbounds (internal/xrayclient.Parse), so the tagged
// protocol can never be reached from a profile, and leaving it out of the
// registry keeps its implementation out of the helper (-2 KiB measured).
//
// "main/json" (the JSON config loader) is deliberately absent as well: the
// helper builds its config from protobuf directly (internal/xrayclient
// xrayconf.go), and main/json is the single import that pulls
// xray-core/infra/conf plus every app, proxy and transport of xray-core into
// the binary (measured ceiling ~8 MiB, work/opt-helper-size-20261104.md;
// realised helper delta -4.1 MiB, work/opt-xray-proto-20261104.md). The JSON
// loader is restored by building with `-tags xrayjson` (registry_json.go);
// cmd/xraygateway loads JSON through xrayregistry/gateway instead.
