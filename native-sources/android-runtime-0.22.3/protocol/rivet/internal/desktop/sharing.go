package desktop

import (
	"encoding/json"
	"errors"
)

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
func (r *Runtime) sharingActive() bool {
	if r.current == nil {
		return false
	}
	var value map[string]any
	if json.Unmarshal([]byte(r.current.status()), &value) != nil {
		return false
	}
	active, _ := value["active"].(bool)
	return active
}
