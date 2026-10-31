//go:build windows

// Package xiofirewall installs the fail-closed Windows Filtering Platform
// policy used by the XIO desktop engine.
//
// It is a project-local adaptation of
// golang.zx2c4.com/wireguard/windows/tunnel/firewall at v1.0.1 (MIT, see
// README.md). The dynamic session, filter weights, blocking rules and cleanup
// semantics are unchanged. The one behavioural change is the owning-process
// permit: upstream matched the WireGuard service SID (S-1-5-80-*), which an
// interactive desktop executable never holds, so enabling the firewall failed
// with ERROR_NO_SUCH_GROUP. This package matches the current token user SID
// together with the executable APP_ID instead.
//
// EnableFirewall installs a dynamic WFP session: every object disappears when
// DisableFirewall closes the handle or the process exits. A failed transaction
// is aborted before returning, so a caller never observes a partial policy.
package xiofirewall
