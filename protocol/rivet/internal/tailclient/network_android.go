package tailclient

import (
	"encoding/json"
	"errors"
	"net"
	"sync"
	"tailscale.com/net/netmon"
)

var interfaceSource struct {
	sync.RWMutex
	n NetworkInfo
}

func init() {
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) {
		interfaceSource.RLock()
		n := interfaceSource.n
		interfaceSource.RUnlock()
		if n == nil {
			return nil, errors.New("tailscale: Android interface metadata unavailable")
		}
		raw := n.Interfaces()
		if len(raw) > 65536 {
			return nil, errors.New("tailscale: oversized interface metadata")
		}
		var snapshot struct {
			Default    string `json:"default"`
			Gateway    string `json:"gateway"`
			Interfaces []struct {
				Name      string   `json:"name"`
				Index     int      `json:"index"`
				MTU       int      `json:"mtu"`
				Addresses []string `json:"addresses"`
			} `json:"interfaces"`
		}
		if json.Unmarshal([]byte(raw), &snapshot) != nil {
			return nil, errors.New("tailscale: invalid interface metadata")
		}
		netmon.UpdateLastKnownDefaultRouteInterface(snapshot.Default)
		netmon.UpdateLastKnownDefaultGateway(snapshot.Gateway)
		var interfaces []netmon.Interface
		for _, i := range snapshot.Interfaces {
			if i.Name == "" || i.Index < 1 || len(i.Addresses) > 64 {
				continue
			}
			addresses := []net.Addr{}
			for _, s := range i.Addresses {
				ip, prefix, e := net.ParseCIDR(s)
				if e != nil {
					continue
				}
				prefix.IP = ip
				addresses = append(addresses, prefix)
			}
			interfaces = append(interfaces, netmon.Interface{Interface: &net.Interface{Index: i.Index, Name: i.Name, MTU: i.MTU, Flags: net.FlagUp | net.FlagRunning}, AltAddrs: addresses})
		}
		return interfaces, nil
	})
}
func setNetworkInfo(n NetworkInfo) {
	interfaceSource.Lock()
	interfaceSource.n = n
	interfaceSource.Unlock()
}
