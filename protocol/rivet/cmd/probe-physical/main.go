// Command probe-physical reports which IPv4 default route the desktop helper
// would treat as the physical uplink, with and without the hardware filter.
// It only reads the route table, so it runs as a normal user.
package main

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func main() {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		fmt.Println("route table error:", err)
		return
	}
	type pick struct {
		alias  string
		metric uint64
		hw     bool
	}
	var all []pick
	for _, row := range rows {
		if row.DestinationPrefix.Prefix().Bits() != 0 || !row.NextHop.Addr().Is4() {
			continue
		}
		iface, e := row.InterfaceLUID.IPInterface(windows.AF_INET)
		if e != nil {
			continue
		}
		metric := uint64(row.Metric) + uint64(iface.Metric)
		hw := false
		if adapter, e := row.InterfaceLUID.Interface(); e == nil {
			switch adapter.Type {
			case windows.IF_TYPE_ETHERNET_CSMACD, windows.IF_TYPE_IEEE80211:
				hw = true
			}
			all = append(all, pick{alias: adapter.Alias(), metric: metric, hw: hw})
		} else {
			all = append(all, pick{alias: "?", metric: metric})
		}
	}
	fmt.Println("default routes:")
	for _, p := range all {
		fmt.Printf("  %-24s metric=%-4d hardware=%v\n", p.alias, p.metric, p.hw)
	}
	var oldBest, newBest *pick
	for i := range all {
		p := &all[i]
		if oldBest == nil || p.metric < oldBest.metric {
			oldBest = p
		}
		if p.hw && (newBest == nil || p.metric < newBest.metric) {
			newBest = p
		}
	}
	if oldBest != nil {
		fmt.Printf("\nбез фильтра выбрано: %s (metric %d)\n", oldBest.alias, oldBest.metric)
	}
	if newBest != nil {
		fmt.Printf("с фильтром выбрано:  %s (metric %d)\n", newBest.alias, newBest.metric)
	} else {
		fmt.Println("с фильтром: ни одного физического адаптера не найдено")
	}
}
