package desktop

import "strings"

func quotePowerShell(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func ipv6FirewallCleanupScript(name string) string {
	// Enumerate then compare exactly: deletion is idempotent and cannot treat
	// a missing owned rule as failure, nor remove an administrator's rule.
	q := quotePowerShell(name)
	return "$ErrorActionPreference='Stop'; try { @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.DisplayName -ceq " + q + " }) | Remove-NetFirewallRule; if (@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.DisplayName -ceq " + q + " }).Count -gt 0) { throw 'Owned IPv6 rule remains' }; exit 0 } catch { exit 1 }\n"
}
