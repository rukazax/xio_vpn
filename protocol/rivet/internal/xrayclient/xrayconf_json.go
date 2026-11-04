//go:build xrayjson

// Legacy config path: xray-core/main/json -> infra/conf. Built only with
// `-tags xrayjson`, and used by the equivalence test as the reference. It
// links every app, proxy and transport of xray-core (~8 MiB in the helper),
// which is exactly what the default protobuf builder avoids.

package xrayclient

import (
	"bytes"

	"github.com/xtls/xray-core/core"
)

// xrayLegacyConfig reports which implementation buildConfig uses.
const xrayLegacyConfig = true

func buildConfig(c Config) (*core.Config, error) {
	return core.LoadConfig("json", bytes.NewReader(configBytes(c)))
}
