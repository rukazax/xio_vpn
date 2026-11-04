// Package gateway registers the Xray components the root-owned server gateway
// links from the JSON config written by the installer (server/managed/stack.py):
// a VLESS+REALITY inbound, the stats/policy apps the gateway samples counters
// from, and the JSON loader itself.
//
// It is a separate package so the helper keeps the smaller set in
// internal/xrayregistry. The difference is not cosmetic: the server-side
// inbounds, stats, DNS and routing used to be shared with the helper and cost
// it 989 184 B (31 450 112 -> 30 460 928 B, work/opt-registry-trim-20261104.md).
//
// cmd/xraygateway is the only importer.
package gateway

import (
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/transport/internet/udp"

	// The gateway loads the JSON config the server writes, so it needs the
	// legacy loader (infra/conf) directly; the helper no longer links it.
	_ "github.com/xtls/xray-core/main/json"

	// The helper-common minimum: dispatcher, proxyman, the outbounds and the
	// transports the VLESS inbound in the server config uses.
	_ "xio.local/rivet/internal/xrayregistry"
)

// Shadowsocks is deliberately absent. The server writes a
// "protocol":"shadowsocks" inbound, but XIO 0.22 removed the Shadowsocks (and
// WireGuard) JSON loader entries from xray-core/infra/conf/xray.go
// (vendor/xray/XIO-CHANGES.md), so such a config is rejected with
// "unknown config id: shadowsocks" before any handler registry is consulted;
// registering the proxy package would not make it loadable.
