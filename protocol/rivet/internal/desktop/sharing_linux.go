package desktop

import "errors"

func sharingOptions() (map[string]any, error) {
	return map[string]any{"supported": false, "enabled": false, "candidates": []any{}, "message": "VPN при раздаче в этой версии доступен на Android с root и Windows"}, nil
}
func applySharingSetup(enabled bool, iface string, setup *setupLease) error {
	if err := setup.check(); err != nil {
		return err
	}
	return applySharing(enabled, iface)
}
func applySharing(bool, string) error {
	return errors.New("VPN при раздаче не поддерживается на этой платформе")
}
