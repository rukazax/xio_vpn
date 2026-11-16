package desktop

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

var errSetupCleanupIncomplete = errors.New("desktop: setup cleanup incomplete")

type sharingScriptRunner func(context.Context, string) ([]byte, error)

// Shared orchestration is testable without PowerShell/COM/firewall effects.
// Each next script is separately admitted; rollback is independent of setup.
func runSharingSteps(setup *setupLease, prefix string, stages []string, rollback func(bool) string, run sharingScriptRunner) error {
	if setup == nil {
		var gate sync.Mutex
		setup = newSetupLease(&gate, time.Now().Add(30*time.Second), time.Now, func() bool { return true })
		defer setup.cancel()
	}
	created, started := false, false
	cleanup := func(cause error) error {
		if !started {
			return cause
		}
		ctx, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if _, err := run(ctx, rollback(created)); err != nil {
			return errors.Join(cause, errSetupCleanupIncomplete, err)
		}
		return cause
	}
	for i, stage := range stages {
		ctx, done, err := setup.admit(30 * time.Second)
		if err != nil {
			return cleanup(err)
		}
		started = true
		out, err := run(ctx, prefix+stage)
		done()
		if err != nil {
			return cleanup(err)
		}
		if i == 0 {
			created = strings.TrimSpace(string(out)) == "CREATED"
		}
	}
	if err := setup.check(); err != nil {
		return cleanup(err)
	}
	return nil
}

func (r *Runtime) SharingStatus() (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result, e := sharingOptions()
	if e != nil {
		return nil, e
	}
	result["enabled"] = r.sharingWanted
	result["interface"] = r.sharingInterface
	if r.sharingWanted && r.current == nil {
		result["message"] = "Раздача через VPN ожидает подключения"
	}
	return result, nil
}
func (r *Runtime) SetSharing(enabled bool, iface string) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !isAdmin() {
		return nil, errors.New("Необходимы права администратора")
	}
	if enabled && r.current == nil {
		return nil, errors.New("Сначала подключите VPN и включите мобильный хот-спот Windows")
	}
	if e := applySharing(enabled, iface); e != nil {
		return nil, e
	}
	r.sharingWanted = enabled
	r.sharingInterface = iface
	result, e := sharingOptions()
	if e != nil {
		return nil, e
	}
	result["enabled"] = enabled
	result["interface"] = iface
	return result, nil
}
