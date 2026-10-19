// Root-owned XIO gateway. No public management API; counters are written to a
// private file for the existing SSH-authorized management command.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "xio.local/rivet/internal/xrayregistry"
)

type counter struct {
	Rx         int64  `json:"rx"`
	Tx         int64  `json:"tx"`
	LastRx     int64  `json:"lastRx"`
	LastTx     int64  `json:"lastTx"`
	Month      string `json:"month"`
	MonthBytes int64  `json:"monthBytes"`
	Online     bool   `json:"online"`
	SampledAt  int64  `json:"sampledAt"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "config and private stats path required")
		os.Exit(2)
	}
	raw, e := os.ReadFile(os.Args[1])
	if e != nil {
		os.Exit(1)
	}
	v, e := core.StartInstance("json", raw)
	if e != nil {
		fmt.Fprintln(os.Stderr, "gateway configuration failed")
		os.Exit(1)
	}
	defer v.Close()
	manager := v.GetFeature(stats.ManagerType()).(stats.Manager)
	totals := map[string]*counter{}
	if b, e := os.ReadFile(os.Args[2]); e == nil {
		_ = json.Unmarshal(b, &totals)
	}
	for _, c := range totals {
		c.LastRx = 0
		c.LastTx = 0
		c.Online = false
	}
	sample := func() {
		now := time.Now().UTC()
		values := map[string][2]int64{}
		online := map[string]bool{}
		manager.VisitCounters(func(name string, c stats.Counter) bool {
			p := strings.Split(name, ">>>")
			if len(p) != 4 || p[0] != "user" || p[2] != "traffic" {
				return true
			}
			uid := strings.Split(p[1], "@")[0]
			a := values[uid]
			if p[3] == "uplink" {
				a[0] += c.Value()
			} else if p[3] == "downlink" {
				a[1] += c.Value()
			}
			values[uid] = a
			if m := manager.GetOnlineMap("user>>>" + p[1] + ">>>online"); m != nil && m.Count() > 0 {
				online[uid] = true
			}
			return true
		})
		for uid, a := range values {
			c := totals[uid]
			if c == nil {
				c = &counter{}
				totals[uid] = c
			}
			if c.Month != now.Format("2006-01") {
				c.Month = now.Format("2006-01")
				c.MonthBytes = 0
			}
			rx, tx := a[0]-c.LastRx, a[1]-c.LastTx
			if rx < 0 {
				rx = a[0]
			}
			if tx < 0 {
				tx = a[1]
			}
			c.Rx += rx
			c.Tx += tx
			c.MonthBytes += rx + tx
			c.LastRx = a[0]
			c.LastTx = a[1]
			c.SampledAt = now.Unix()
			c.Online = online[uid]
		}
		b, _ := json.Marshal(totals)
		temp := os.Args[2] + ".tmp"
		if os.WriteFile(temp, b, 0600) == nil {
			_ = os.Rename(temp, os.Args[2])
		}
	}
	_ = os.MkdirAll(filepath.Dir(os.Args[2]), 0700)
	sample()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	for {
		select {
		case <-ticker.C:
			sample()
		case <-stop:
			sample()
			return
		}
	}
}
