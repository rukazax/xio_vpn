//go:build xrayjson

// Opt-in legacy build: restore the xray-core JSON config loader so
// xrayclient's legacy path (xrayconf_json.go) keeps working. Not part of the
// default helper build — see registry.go for why.

package xrayregistry

import (
	_ "github.com/xtls/xray-core/main/json"
)
