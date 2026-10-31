package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Verify the reserved selectors disappeared before discarding the ownership
// receipt. Read table=all so an absent/empty dedicated table is not an error.
func cleanupLinuxOwned(run commandRunner) error {
	for _, family := range []string{"-4", "-6"} {
		for _, args := range [][]string{
			{family, "rule", "del", "pref", "18018", "fwmark", "0x80000/0xff0000", "lookup", "main"},
			{family, "rule", "del", "pref", "18019", "not", "fwmark", "0x580019", "lookup", routeTable},
			{family, "route", "del", "default", "dev", deviceName, "table", routeTable},
			{family, "route", "del", "blackhole", "default", "table", routeTable},
		} {
			_, _ = run("/usr/sbin/ip", args...) // Deleting an already absent row is harmless.
		}
	}
	_, _ = run("/usr/bin/resolvectl", "revert", deviceName)
	for _, family := range []string{"-4", "-6"} {
		for _, kind := range []string{"rule", "route"} {
			args := []string{family, "-j", kind, "show"}
			if kind == "route" {
				args = append(args, "table", "all")
			}
			b, err := run("/usr/sbin/ip", args...)
			var rows []map[string]any
			if err != nil || json.Unmarshal(b, &rows) != nil {
				return errors.New("could not verify owned VPN cleanup")
			}
			for _, row := range rows {
				table := fmt.Sprint(row["table"])
				if kind == "rule" {
					pref, mark := fmt.Sprint(row["priority"]), fmt.Sprint(row["fwmark"])
					if pref == "18018" && (table == "main" || table == "254") && strings.HasPrefix(mark, "0x80000") || pref == "18019" && table == routeTable && mark == "0x580019" {
						return errors.New("owned VPN policy rule remains after cleanup")
					}
				} else if table == routeTable && (row["dev"] == deviceName || row["type"] == "blackhole") {
					return errors.New("owned VPN route remains after cleanup")
				}
			}
		}
	}
	return nil
}
