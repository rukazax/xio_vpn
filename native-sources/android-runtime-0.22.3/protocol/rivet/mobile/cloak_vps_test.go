package mobile

import (
	"context"
	"encoding/json"
	"github.com/cbeuw/Cloak"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVPSCloakAuth(t *testing.T) {
	dir := os.Getenv("XIO_VPS_PROFILE_DIR")
	if dir == "" {
		t.Skip("requires authorized VPS fixture")
	}
	raw, e := os.ReadFile(filepath.Join(dir, "cloak-017.json"))
	if e != nil {
		t.Fatal(e)
	}
	var j struct {
		Cloak json.RawMessage `json:"cloak"`
	}
	if e = json.Unmarshal(raw, &j); e != nil {
		t.Fatal(e)
	}
	cfg, e := cloak.Decode(j.Cloak)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := cloak.Open(ctx, cfg, cloakDialer{ctx, pinnedProtector(true), []string{cfg.RemoteHost}})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.Write([]byte{0, 1, 0x38}); e != nil {
		t.Fatal("authenticated Cloak stream write failed")
	}
}
