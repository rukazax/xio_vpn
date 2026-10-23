package desktop

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"xio.local/rivet/internal/rivet"
	"xio.local/rivet/internal/xrayclient"
)

var ErrProfile = errors.New("invalid or unsupported client profile")

type Profile struct {
	Protocol, Raw, IPC string
	Addresses          []netip.Prefix
	DNS                []netip.Addr
	Endpoints          []string
	MTU                int
}

func ParseProfile(protocol, raw string) (p Profile, err error) {
	p = Profile{Protocol: protocol, Raw: raw, MTU: 1280, DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	if len(raw) > 200000 {
		return p, ErrProfile
	}
	switch protocol {
	case "rivet-h3", "rivet-s1":
		var c rivet.ClientConfig
		if json.Unmarshal([]byte(raw), &c) != nil || c.Validate() != nil || c.Protocol != protocol {
			return p, ErrProfile
		}
		p.Addresses = []netip.Prefix{netip.PrefixFrom(netip.MustParseAddr(c.IP), 32)}
		p.Endpoints = []string{c.Endpoint}
	case "awg":
		return parseWG(p)
	case "xray":
		c, e := xrayclient.Parse(raw)
		if e != nil || c.Protocol != protocol {
			return p, ErrProfile
		}
		settings, _ := c.Outbound["settings"].(map[string]any)
		key := "servers"
		if c.Outbound["protocol"] == "vless" || c.Outbound["protocol"] == "vmess" {
			key = "vnext"
		}
		a := settings[key].([]any)[0].(map[string]any)
		port := int(a["port"].(float64))
		p.Endpoints = []string{net.JoinHostPort(a["address"].(string), strconv.Itoa(port))}
		p.Addresses = []netip.Prefix{netip.MustParsePrefix("10.80.0.2/32")}
	default:
		return p, ErrProfile
	}
	return p, nil
}
func parseWG(p Profile) (Profile, error) {
	section := ""
	peer := false
	private := false
	public := false
	endpoint := false
	full := false
	seen := map[string]bool{}
	var ipc strings.Builder
	ipc.WriteString("replace_peers=true\n")
	scanner := bufio.NewScanner(strings.NewReader(p.Raw))
	scanner.Buffer(make([]byte, 4096), 200000)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		if line == "[Interface]" {
			if section != "" {
				return p, ErrProfile
			}
			section = "i"
			continue
		}
		if line == "[Peer]" {
			if section != "i" || peer {
				return p, ErrProfile
			}
			section = "p"
			peer = true
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 || section == "" {
			return p, ErrProfile
		}
		k, v := strings.ToLower(strings.TrimSpace(pair[0])), strings.TrimSpace(pair[1])
		tag := section + k
		if seen[tag] {
			return p, ErrProfile
		}
		seen[tag] = true
		key := ""
		value := v
		if section == "i" {
			switch k {
			case "privatekey":
				key = "private_key"
				private = true
			case "address":
				for _, a := range strings.Split(v, ",") {
					ip, e := netip.ParsePrefix(strings.TrimSpace(a))
					if e != nil || !ip.Addr().IsGlobalUnicast() {
						return p, ErrProfile
					}
					if ip.Addr().Is4() {
						p.Addresses = append(p.Addresses, ip)
					}
				}
				continue
			case "dns":
				p.DNS = nil
				for _, a := range strings.Split(v, ",") {
					ip, e := netip.ParseAddr(strings.TrimSpace(a))
					if e != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
						return p, ErrProfile
					}
					p.DNS = append(p.DNS, ip)
				}
				continue
			case "listenport":
				n, e := strconv.Atoi(v)
				if e != nil || n < 0 || n > 65535 {
					return p, ErrProfile
				}
				key = "listen_port"
			case "headerprotectionkey":
				if p.Protocol != "awg" {
					return p, ErrProfile
				}
				key = "header_protection_key"
			case "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts":
				names := map[string]string{"contentpaddingaddition": "content_padding_addition", "rekeyaftertime": "rekey_after_time", "rekeytimeout": "rekey_timeout", "rejectaftertime": "reject_after_time", "keepalivetimeout": "keepalive_timeout", "maxhandshakeattempts": "max_handshake_attempts"}
				low, max := uint64(1), uint64(86400)
				if k == "contentpaddingaddition" {
					low, max = 0, 1280
				}
				if k == "maxhandshakeattempts" {
					max = 128
				}
				if p.Protocol != "awg" || !boundedRange(v, low, max) {
					return p, ErrProfile
				}
				key = names[k]
			case "randomtrailers", "disablecookies":
				if p.Protocol != "awg" {
					return p, ErrProfile
				}
				flag, e := strconv.ParseBool(v)
				if e != nil {
					return p, ErrProfile
				}
				value = strconv.FormatBool(flag)
				if k == "randomtrailers" {
					key = "random_trailers"
				} else {
					key = "disable_cookies"
				}
			case "mtu":
				n, e := strconv.Atoi(v)
				if e != nil || n < 1280 || n > 1420 {
					return p, ErrProfile
				}
				p.MTU = n
				continue
			case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5":
				if p.Protocol != "awg" || strings.ContainsAny(v, "\r\n\x00") {
					return p, ErrProfile
				}
				if !validAWG(k, v) {
					return p, ErrProfile
				}
				key = k
			default:
				return p, ErrProfile
			}
		} else {
			switch k {
			case "publickey":
				key = "public_key"
				public = true
			case "presharedkey":
				key = "preshared_key"
			case "endpoint":
				host, port, e := net.SplitHostPort(v)
				n, e2 := strconv.Atoi(port)
				if e != nil || host == "" || e2 != nil || n < 1 || n > 65535 {
					return p, ErrProfile
				}
				p.Endpoints = []string{v}
				endpoint = true
				key = "endpoint"
			case "allowedips":
				ipc.WriteString("replace_allowed_ips=true\n")
				for _, a := range strings.Split(v, ",") {
					prefix, e := netip.ParsePrefix(strings.TrimSpace(a))
					if e != nil {
						return p, ErrProfile
					}
					if prefix.String() == "0.0.0.0/0" {
						full = true
					}
					ipc.WriteString("allowed_ip=" + prefix.String() + "\n")
				}
				continue
			case "persistentkeepalive":
				n, e := strconv.Atoi(v)
				if e != nil || n < 0 || n > 65535 {
					return p, ErrProfile
				}
				key = "persistent_keepalive_interval"
			default:
				return p, ErrProfile
			}
		}
		if k == "privatekey" || k == "publickey" || k == "presharedkey" || k == "headerprotectionkey" {
			b, e := base64.StdEncoding.DecodeString(v)
			if e != nil || len(b) != 32 {
				return p, ErrProfile
			}
			value = hex.EncodeToString(b)
		}
		ipc.WriteString(key + "=" + value + "\n")
	}
	if scanner.Err() != nil || !private || !public || !endpoint || !full || len(p.Addresses) == 0 || len(p.DNS) == 0 {
		return p, ErrProfile
	}
	if p.Protocol == "awg" {
		fields := map[string]int{}
		for _, line := range strings.Split(ipc.String(), "\n") {
			a := strings.SplitN(line, "=", 2)
			if len(a) == 2 {
				if n, e := strconv.Atoi(a[1]); e == nil {
					fields[a[0]] = n
				}
			}
		}
		if _, maxSet := fields["jmax"]; maxSet && fields["jmin"] > fields["jmax"] {
			return p, ErrProfile
		}
	}
	p.IPC = ipc.String()
	return p, nil
}

func validAWG(k, v string) bool {
	if strings.HasPrefix(k, "i") {
		return len(v) <= 8192 && !strings.ContainsAny(v, "\r\n\x00")
	}
	if strings.HasPrefix(k, "h") {
		parts := strings.Split(v, "-")
		if len(parts) > 2 {
			return false
		}
		var low uint64
		for i, part := range parts {
			n, e := strconv.ParseUint(part, 10, 32)
			if e != nil || (i > 0 && n < low) {
				return false
			}
			low = n
		}
		return true
	}
	n, e := strconv.Atoi(v)
	max := 1280
	if k == "jc" {
		max = 128
	}
	return e == nil && n >= 0 && n <= max
}

func boundedRange(v string, low, high uint64) bool {
	parts := strings.Split(v, "-")
	if len(parts) > 2 {
		return false
	}
	previous := low
	for _, p := range parts {
		n, e := strconv.ParseUint(p, 10, 32)
		if e != nil || n < previous || n > high {
			return false
		}
		previous = n
	}
	return true
}
