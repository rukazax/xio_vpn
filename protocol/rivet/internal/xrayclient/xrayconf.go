//go:build !xrayjson

// XIO profile -> xray-core protobuf config, without github.com/xtls/xray-core/infra/conf.
//
// The XIO helper only ever builds one shape of config:
//
//	{"log":{"loglevel":"none"},"outbounds":[<the profile's outbound>]}
//
// The legacy loader (xray-core/main/json -> infra/conf) links every app, proxy
// and transport of xray-core just to decode that, which costs ~8 MiB in the
// helper binary. Everything below is a field-for-field port of the parts of
// infra/conf that the XIO profile grammar can actually reach; anything the
// JSON loader could reject or that this port does not model fails closed
// (ErrConfig) instead of silently building a different tunnel.
//
// The legacy path is still available with `-tags xrayjson` (see
// xrayconf_json.go) and is used by the equivalence test.

package xrayclient

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/app/dispatcher"
	xlog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	xvless "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/proxy/vmess"
	xvmess "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/transport/internet"
	xgrpc "github.com/xtls/xray-core/transport/internet/grpc"
	xhttp "github.com/xtls/xray-core/transport/internet/headers/http"
	xnoop "github.com/xtls/xray-core/transport/internet/headers/noop"
	"github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/websocket"
	"google.golang.org/protobuf/proto"
)

// xrayLegacyConfig reports which implementation buildConfig uses. Tests use it
// to skip comparisons that are meaningless when both sides are the same code.
const xrayLegacyConfig = false

// buildConfig converts a validated profile into the same *core.Config that
// core.LoadConfig("json", ...) produced before.
func buildConfig(c Config) (*core.Config, error) {
	var doc xConfig
	if err := json.Unmarshal(configBytes(c), &doc); err != nil {
		return nil, ErrConfig
	}
	if len(doc.Inbounds) > 0 || len(doc.DNS) > 0 || len(doc.Routing) > 0 || len(doc.FakeDNS) > 0 ||
		len(doc.Stats) > 0 || len(doc.Policy) > 0 || len(doc.API) > 0 || len(doc.Metrics) > 0 ||
		len(doc.Reverse) > 0 || len(doc.Env) > 0 || len(doc.Version) > 0 || len(doc.Geodata) > 0 ||
		len(doc.Transport) > 0 {
		// configBytes() emits only "log" and "outbounds"; if that ever changes,
		// fail closed instead of silently ignoring the new section.
		return nil, ErrConfig
	}

	apps := []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
	}
	var logMsg *serial.TypedMessage
	if doc.Log != nil {
		logMsg = serial.ToTypedMessage(doc.Log.build())
	} else {
		logMsg = serial.ToTypedMessage(xDefaultLogConfig())
	}
	config := &core.Config{App: append([]*serial.TypedMessage{logMsg}, apps...)}

	for i := range doc.Outbounds {
		oc, err := doc.Outbounds[i].build()
		if err != nil {
			return nil, err
		}
		config.Outbound = append(config.Outbound, oc)
	}
	return config, nil
}

// xConfig mirrors the reachable subset of infra/conf.Config. Anything outside
// it is refused by buildConfig rather than ignored.
type xConfig struct {
	Log       *xLogConfig       `json:"log"`
	Inbounds  json.RawMessage   `json:"inbounds"`
	Outbounds []xOutboundConfig `json:"outbounds"`
	DNS       json.RawMessage   `json:"dns"`
	Routing   json.RawMessage   `json:"routing"`
	FakeDNS   json.RawMessage   `json:"fakeDns"`
	Stats     json.RawMessage   `json:"stats"`
	Policy    json.RawMessage   `json:"policy"`
	API       json.RawMessage   `json:"api"`
	Metrics   json.RawMessage   `json:"metrics"`
	Reverse   json.RawMessage   `json:"reverse"`
	Env       json.RawMessage   `json:"env"`
	Version   json.RawMessage   `json:"version"`
	Geodata   json.RawMessage   `json:"geodata"`
	Transport json.RawMessage   `json:"transport"`
}

// ---- log ----

type xLogConfig struct {
	AccessLog   string `json:"access"`
	ErrorLog    string `json:"error"`
	LogLevel    string `json:"loglevel"`
	DNSLog      bool   `json:"dnsLog"`
	MaskAddress string `json:"maskAddress"`
}

func xDefaultLogConfig() *xlog.Config {
	return &xlog.Config{
		AccessLogType: xlog.LogType_None,
		ErrorLogType:  xlog.LogType_Console,
		ErrorLogLevel: clog.Severity_Warning,
	}
}

func (v *xLogConfig) build() *xlog.Config {
	config := &xlog.Config{
		ErrorLogType:  xlog.LogType_Console,
		AccessLogType: xlog.LogType_Console,
		EnableDnsLog:  v.DNSLog,
	}
	if v.AccessLog == "none" {
		config.AccessLogType = xlog.LogType_None
	} else if len(v.AccessLog) > 0 {
		config.AccessLogPath = v.AccessLog
		config.AccessLogType = xlog.LogType_File
	}
	if v.ErrorLog == "none" {
		config.ErrorLogType = xlog.LogType_None
	} else if len(v.ErrorLog) > 0 {
		config.ErrorLogPath = v.ErrorLog
		config.ErrorLogType = xlog.LogType_File
	}
	switch strings.ToLower(v.LogLevel) {
	case "debug":
		config.ErrorLogLevel = clog.Severity_Debug
	case "info":
		config.ErrorLogLevel = clog.Severity_Info
	case "error":
		config.ErrorLogLevel = clog.Severity_Error
	case "none":
		config.ErrorLogType = xlog.LogType_None
		config.AccessLogType = xlog.LogType_None
	default:
		config.ErrorLogLevel = clog.Severity_Warning
	}
	config.MaskAddress = v.MaskAddress
	return config
}

// ---- scalar helpers (ported from infra/conf/common.go) ----

type xStringList []string

func (v *xStringList) UnmarshalJSON(data []byte) error {
	var strarray []string
	if err := json.Unmarshal(data, &strarray); err == nil {
		*v = strarray
		return nil
	}
	var rawstr string
	if err := json.Unmarshal(data, &rawstr); err == nil {
		*v = strings.Split(rawstr, ",")
		return nil
	}
	return ErrConfig
}

type xAddress struct {
	xnet.Address
}

func (v *xAddress) UnmarshalJSON(data []byte) error {
	var rawStr string
	if err := json.Unmarshal(data, &rawStr); err != nil {
		return ErrConfig
	}
	if strings.HasPrefix(rawStr, "env:") {
		rawStr = platform.NewEnvFlag(rawStr[4:]).GetValue(func() string { return "" })
	}
	v.Address = xnet.ParseAddress(rawStr)
	return nil
}

func (v *xAddress) build() *xnet.IPOrDomain {
	return xnet.NewIPOrDomain(v.Address)
}

type xInt32Range struct {
	Left  int32
	Right int32
	From  int32
	To    int32
}

func (v *xInt32Range) UnmarshalJSON(data []byte) error {
	defer v.ensureOrder()
	var str string
	var rawint int32
	if err := json.Unmarshal(data, &str); err == nil {
		left, right, err := xParseRangeString(str)
		if err == nil {
			v.Left, v.Right = int32(left), int32(right)
			return nil
		}
	} else if err := json.Unmarshal(data, &rawint); err == nil {
		v.Left = rawint
		v.Right = rawint
		return nil
	}
	return ErrConfig
}

func (r *xInt32Range) ensureOrder() {
	r.From, r.To = r.Left, r.Right
	if r.From > r.To {
		r.From, r.To = r.To, r.From
	}
}

func xSplitFromSecondDash(s string) []string {
	parts := strings.SplitN(s, "-", 3)
	if len(parts) < 3 {
		return []string{s}
	}
	return []string{parts[0] + "-" + parts[1], parts[2]}
}

func xParseRangeString(str string) (int, int, error) {
	if value, err := strconv.Atoi(str); err == nil {
		return value, value, nil
	}
	if str == "" {
		return 0, 0, nil
	}
	var pair []string
	if strings.HasPrefix(str, "-") {
		pair = xSplitFromSecondDash(str)
	} else {
		pair = strings.SplitN(str, "-", 2)
	}
	if len(pair) == 2 {
		left, err := strconv.Atoi(pair[0])
		right, err2 := strconv.Atoi(pair[1])
		if err == nil && err2 == nil {
			return left, right, nil
		}
	}
	return 0, 0, ErrConfig
}

// ---- outbound ----

type xMuxConfig struct {
	Enabled         bool   `json:"enabled"`
	Concurrency     int16  `json:"concurrency"`
	XudpConcurrency int16  `json:"xudpConcurrency"`
	XudpProxyUDP443 string `json:"xudpProxyUDP443"`
}

func (m *xMuxConfig) build() (*proxyman.MultiplexingConfig, error) {
	switch m.XudpProxyUDP443 {
	case "":
		m.XudpProxyUDP443 = "reject"
	case "reject", "allow", "skip":
	default:
		return nil, ErrConfig
	}
	return &proxyman.MultiplexingConfig{
		Enabled:         m.Enabled,
		Concurrency:     int32(m.Concurrency),
		XudpConcurrency: int32(m.XudpConcurrency),
		XudpProxyUDP443: m.XudpProxyUDP443,
	}, nil
}

type xOutboundConfig struct {
	Protocol       string           `json:"protocol"`
	SendThrough    *string          `json:"sendThrough"`
	Tag            string           `json:"tag"`
	Settings       *json.RawMessage `json:"settings"`
	StreamSetting  *xStreamConfig   `json:"streamSettings"`
	ProxySettings  json.RawMessage  `json:"proxySettings"`
	MuxSettings    *xMuxConfig      `json:"mux"`
	TargetStrategy string           `json:"targetStrategy"`
}

func (c *xOutboundConfig) build() (*core.OutboundHandlerConfig, error) {
	// Parse() already refuses these keys; keep the guard so a future profile
	// field cannot pass silently.
	if c.SendThrough != nil || len(c.ProxySettings) > 0 || c.TargetStrategy != "" {
		return nil, ErrConfig
	}
	senderSettings := &proxyman.SenderConfig{TargetStrategy: internet.DomainStrategy_AS_IS}
	if c.StreamSetting != nil {
		ss, err := c.StreamSetting.build()
		if err != nil {
			return nil, err
		}
		senderSettings.StreamSettings = ss
	}
	if c.MuxSettings != nil {
		ms, err := c.MuxSettings.build()
		if err != nil {
			return nil, err
		}
		senderSettings.MultiplexSettings = ms
	}
	settings := []byte("{}")
	if c.Settings != nil {
		settings = []byte(*c.Settings)
	}
	tm, err := xBuildProxy(strings.ToLower(c.Protocol), settings)
	if err != nil {
		return nil, err
	}
	return &core.OutboundHandlerConfig{
		SenderSettings: serial.ToTypedMessage(senderSettings),
		Tag:            c.Tag,
		ProxySettings:  serial.ToTypedMessage(tm),
	}, nil
}

func xBuildProxy(protocol string, settings []byte) (proto.Message, error) {
	switch protocol {
	case "vless":
		return xBuildVLESS(settings)
	case "vmess":
		return xBuildVMess(settings)
	case "trojan":
		return xBuildTrojan(settings)
	default:
		return nil, ErrConfig
	}
}

// ---- vless outbound ----

type xVLESSVnext struct {
	Address *xAddress         `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type xVLESSOutbound struct {
	Address    *xAddress       `json:"address"`
	Port       uint16          `json:"port"`
	Level      uint32          `json:"level"`
	Email      string          `json:"email"`
	Id         string          `json:"id"`
	Flow       string          `json:"flow"`
	Seed       string          `json:"seed"`
	Encryption string          `json:"encryption"`
	Reverse    json.RawMessage `json:"reverse"`
	Testpre    uint32          `json:"testpre"`
	Testseed   []uint32        `json:"testseed"`
	Vnext      []*xVLESSVnext  `json:"vnext"`
}

const xVlessVision = "xtls-rprx-vision"

func xParseVlessEncryption(account *vless.Account) error {
	ok := func() bool {
		s := strings.Split(account.Encryption, ".")
		if len(s) < 4 || s[0] != "mlkem768x25519plus" {
			return false
		}
		switch s[1] {
		case "native":
		case "xorpub":
			account.XorMode = 1
		case "random":
			account.XorMode = 2
		default:
			return false
		}
		switch s[2] {
		case "1rtt":
		case "0rtt":
			account.Seconds = 1
		default:
			return false
		}
		padding := 0
		for _, r := range s[3:] {
			if len(r) < 20 {
				padding += len(r) + 1
				continue
			}
			if b, _ := base64.RawURLEncoding.DecodeString(r); len(b) != 32 && len(b) != 1184 {
				return false
			}
		}
		account.Encryption = account.Encryption[27+len(s[2]):]
		if padding > 0 {
			account.Padding = account.Encryption[:padding-1]
			account.Encryption = account.Encryption[padding:]
		}
		return true
	}()
	if !ok && account.Encryption != "none" {
		return ErrConfig
	}
	return nil
}

func xBuildVLESS(settings []byte) (proto.Message, error) {
	c := new(xVLESSOutbound)
	if err := json.Unmarshal(settings, c); err != nil {
		return nil, ErrConfig
	}
	// The simplified "address"/"port"/"id" form is unreachable: Parse requires
	// a single "vnext" member.
	if c.Address != nil || c.Vnext == nil {
		return nil, ErrConfig
	}
	if len(c.Vnext) != 1 {
		return nil, ErrConfig
	}
	rec := c.Vnext[0]
	if rec.Address == nil {
		return nil, ErrConfig
	}
	if len(rec.Users) != 1 {
		return nil, ErrConfig
	}
	spec := &protocol.ServerEndpoint{
		Address: rec.Address.build(),
		Port:    uint32(rec.Port),
	}
	rawUser := rec.Users[0]
	user := new(protocol.User)
	if err := json.Unmarshal(rawUser, user); err != nil {
		return nil, ErrConfig
	}
	account := new(vless.Account)
	if err := json.Unmarshal(rawUser, account); err != nil {
		return nil, ErrConfig
	}
	if account.Reverse != nil {
		// infra/conf refuses "reverse" in this form as well.
		return nil, ErrConfig
	}
	u, err := uuid.ParseString(account.Id)
	if err != nil {
		return nil, ErrConfig
	}
	account.Id = u.String()
	switch account.Flow {
	case "":
	case xVlessVision, xVlessVision + "-udp443":
	default:
		return nil, ErrConfig
	}
	if err := xParseVlessEncryption(account); err != nil {
		return nil, err
	}
	user.Account = serial.ToTypedMessage(account)
	spec.User = user
	return &xvless.Config{Vnext: spec}, nil
}

// ---- vmess outbound ----

type xVMessAccount struct {
	ID          string `json:"id"`
	Security    string `json:"security"`
	Experiments string `json:"experiments"`
}

func (a *xVMessAccount) build() *vmess.Account {
	var st protocol.SecurityType
	switch strings.ToLower(a.Security) {
	case "aes-128-gcm":
		st = protocol.SecurityType_AES128_GCM
	case "chacha20-poly1305":
		st = protocol.SecurityType_CHACHA20_POLY1305
	case "auto":
		st = protocol.SecurityType_AUTO
	default:
		st = protocol.SecurityType_AUTO
	}
	return &vmess.Account{
		Id:               a.ID,
		SecuritySettings: &protocol.SecurityConfig{Type: st},
		TestsEnabled:     a.Experiments,
	}
}

type xVMessTarget struct {
	Address *xAddress         `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type xVMessOutbound struct {
	Address     *xAddress       `json:"address"`
	Port        uint16          `json:"port"`
	Level       uint32          `json:"level"`
	Email       string          `json:"email"`
	ID          string          `json:"id"`
	Security    string          `json:"security"`
	Experiments string          `json:"experiments"`
	Receivers   []*xVMessTarget `json:"vnext"`
}

func xBuildVMess(settings []byte) (proto.Message, error) {
	c := new(xVMessOutbound)
	if err := json.Unmarshal(settings, c); err != nil {
		return nil, ErrConfig
	}
	if c.Address != nil || c.Receivers == nil {
		return nil, ErrConfig
	}
	if len(c.Receivers) != 1 {
		return nil, ErrConfig
	}
	rec := c.Receivers[0]
	if len(rec.Users) != 1 {
		return nil, ErrConfig
	}
	if rec.Address == nil {
		return nil, ErrConfig
	}
	spec := &protocol.ServerEndpoint{
		Address: rec.Address.build(),
		Port:    uint32(rec.Port),
	}
	rawUser := rec.Users[0]
	user := new(protocol.User)
	if err := json.Unmarshal(rawUser, user); err != nil {
		return nil, ErrConfig
	}
	account := new(xVMessAccount)
	if err := json.Unmarshal(rawUser, account); err != nil {
		return nil, ErrConfig
	}
	u, err := uuid.ParseString(account.ID)
	if err != nil {
		return nil, ErrConfig
	}
	account.ID = u.String()
	user.Account = serial.ToTypedMessage(account.build())
	spec.User = user
	return &xvmess.Config{Receiver: spec}, nil
}

// ---- trojan outbound ----

type xTrojanTarget struct {
	Address  *xAddress `json:"address"`
	Port     uint16    `json:"port"`
	Level    byte      `json:"level"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
	Flow     string    `json:"flow"`
}

type xTrojanOutbound struct {
	Address  *xAddress        `json:"address"`
	Port     uint16           `json:"port"`
	Level    byte             `json:"level"`
	Email    string           `json:"email"`
	Password string           `json:"password"`
	Flow     string           `json:"flow"`
	Servers  []*xTrojanTarget `json:"servers"`
}

func xBuildTrojan(settings []byte) (proto.Message, error) {
	c := new(xTrojanOutbound)
	if err := json.Unmarshal(settings, c); err != nil {
		return nil, ErrConfig
	}
	if c.Address != nil || c.Servers == nil {
		return nil, ErrConfig
	}
	if len(c.Servers) != 1 {
		return nil, ErrConfig
	}
	rec := c.Servers[0]
	if rec.Address == nil || rec.Port == 0 || rec.Password == "" || rec.Flow != "" {
		return nil, ErrConfig
	}
	return &trojan.ClientConfig{
		Server: &protocol.ServerEndpoint{
			Address: rec.Address.build(),
			Port:    uint32(rec.Port),
			User: &protocol.User{
				Level: uint32(rec.Level),
				Email: rec.Email,
				Account: serial.ToTypedMessage(&trojan.Account{
					Password: rec.Password,
				}),
			},
		},
	}, nil
}

// ---- stream settings ----

type xStreamConfig struct {
	Address             *xAddress           `json:"address"`
	Port                uint16              `json:"port"`
	Method              *string             `json:"method"`
	Network             *string             `json:"network"`
	Security            string              `json:"security"`
	FinalMask           json.RawMessage     `json:"finalmask"`
	TLSSettings         *xTLSConfig         `json:"tlsSettings"`
	REALITYSettings     *xREALITYConfig     `json:"realitySettings"`
	RAWSettings         *xTCPConfig         `json:"rawSettings"`
	TCPSettings         *xTCPConfig         `json:"tcpSettings"`
	XHTTPSettings       *xSplitHTTPConfig   `json:"xhttpSettings"`
	SplitHTTPSettings   *xSplitHTTPConfig   `json:"splithttpSettings"`
	KCPSettings         json.RawMessage     `json:"kcpSettings"`
	GRPCSettings        *xGRPCConfig        `json:"grpcSettings"`
	WSSettings          *xWebSocketConfig   `json:"wsSettings"`
	HTTPUPGRADESettings *xHTTPUpgradeConfig `json:"httpupgradeSettings"`
	HysteriaSettings    json.RawMessage     `json:"hysteriaSettings"`
	SocketSettings      json.RawMessage     `json:"sockopt"`
}

// xTransportProtocol is conf.TransportProtocol.Build without mkcp/hysteria:
// those transports are not linked into the helper any more.
func xTransportProtocol(p string) (string, error) {
	switch strings.ToLower(p) {
	case "raw", "tcp":
		return "tcp", nil
	case "xhttp", "splithttp":
		return "splithttp", nil
	case "grpc":
		return "grpc", nil
	case "ws", "websocket":
		return "websocket", nil
	case "httpupgrade":
		return "httpupgrade", nil
	default:
		// "kcp"/"mkcp", "hysteria", "h2"/"h3"/"http"/"quic" and anything
		// unknown: either removed upstream or not linked here.
		return "", ErrConfig
	}
}

func (c *xStreamConfig) build() (*internet.StreamConfig, error) {
	if len(c.FinalMask) > 0 || len(c.SocketSettings) > 0 || len(c.KCPSettings) > 0 || len(c.HysteriaSettings) > 0 {
		// finalmask (all mask types), sockopt and the mkcp/hysteria transports
		// are not ported; parse refuses the profile instead of dropping fields.
		return nil, ErrConfig
	}
	config := &internet.StreamConfig{Port: uint32(c.Port), ProtocolName: "tcp"}
	if c.Address != nil {
		config.Address = c.Address.build()
	}
	if c.Method != nil {
		c.Network = c.Method
	}
	if c.Network != nil {
		protocolName, err := xTransportProtocol(*c.Network)
		if err != nil {
			return nil, err
		}
		config.ProtocolName = protocolName
	}

	switch strings.ToLower(c.Security) {
	case "", "none":
	case "tls":
		tlsSettings := c.TLSSettings
		if tlsSettings == nil {
			tlsSettings = &xTLSConfig{}
		}
		ts, err := tlsSettings.build()
		if err != nil {
			return nil, err
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "reality":
		if config.ProtocolName != "tcp" && config.ProtocolName != "splithttp" && config.ProtocolName != "grpc" {
			return nil, ErrConfig
		}
		if c.REALITYSettings == nil {
			return nil, ErrConfig
		}
		ts, err := c.REALITYSettings.build()
		if err != nil {
			return nil, err
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	default:
		return nil, ErrConfig
	}

	if c.RAWSettings != nil {
		c.TCPSettings = c.RAWSettings
	}
	if c.TCPSettings != nil {
		ts, err := c.TCPSettings.build()
		if err != nil {
			return nil, err
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.XHTTPSettings != nil {
		c.SplitHTTPSettings = c.XHTTPSettings
	}
	if c.SplitHTTPSettings != nil {
		hs, err := c.SplitHTTPSettings.build()
		if err != nil {
			return nil, err
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "splithttp",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.GRPCSettings != nil {
		gs, err := c.GRPCSettings.build()
		if err != nil {
			return nil, err
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "grpc",
			Settings:     serial.ToTypedMessage(gs),
		})
	}
	if c.WSSettings != nil {
		ts, err := c.WSSettings.build()
		if err != nil {
			return nil, err
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.HTTPUPGRADESettings != nil {
		hs, err := c.HTTPUPGRADESettings.build()
		if err != nil {
			return nil, err
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "httpupgrade",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	return config, nil
}

// ---- TCP (raw) header ----

type xTCPConfig struct {
	HeaderConfig        json.RawMessage `json:"header"`
	AcceptProxyProtocol bool            `json:"acceptProxyProtocol"`
}

type xNoOpAuthenticator struct{}

func (xNoOpAuthenticator) build() (proto.Message, error) { return new(xnoop.ConnectionConfig), nil }

type xAuthenticatorRequest struct {
	Version string                  `json:"version"`
	Method  string                  `json:"method"`
	Path    xStringList             `json:"path"`
	Headers map[string]*xStringList `json:"headers"`
}

func xSortKeys(m map[string]*xStringList) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (v *xAuthenticatorRequest) build() (*xhttp.RequestConfig, error) {
	config := &xhttp.RequestConfig{
		Uri: []string{"/"},
		Header: []*xhttp.Header{
			{Name: "Host", Value: []string{"www.baidu.com", "www.bing.com"}},
			{Name: "User-Agent", Value: []string{utils.ChromeUA}},
			{Name: "Sec-CH-UA", Value: []string{utils.ChromeUACH}},
			{Name: "Sec-CH-UA-Mobile", Value: []string{"?0"}},
			{Name: "Sec-CH-UA-Platform", Value: []string{"Windows"}},
			{Name: "Sec-Fetch-Mode", Value: []string{"no-cors", "cors", "same-origin"}},
			{Name: "Sec-Fetch-Dest", Value: []string{"empty"}},
			{Name: "Sec-Fetch-Site", Value: []string{"none"}},
			{Name: "Sec-Fetch-User", Value: []string{"?1"}},
			{Name: "Accept-Encoding", Value: []string{"gzip, deflate"}},
			{Name: "Connection", Value: []string{"keep-alive"}},
			{Name: "Pragma", Value: []string{"no-cache"}},
		},
	}
	if len(v.Version) > 0 {
		config.Version = &xhttp.Version{Value: v.Version}
	}
	if len(v.Method) > 0 {
		config.Method = &xhttp.Method{Value: v.Method}
	}
	if len(v.Path) > 0 {
		config.Uri = append([]string(nil), v.Path...)
	}
	if len(v.Headers) > 0 {
		config.Header = make([]*xhttp.Header, 0, len(v.Headers))
		for _, key := range xSortKeys(v.Headers) {
			value := v.Headers[key]
			if value == nil {
				return nil, ErrConfig
			}
			config.Header = append(config.Header, &xhttp.Header{
				Name:  key,
				Value: append([]string(nil), (*value)...),
			})
		}
	}
	return config, nil
}

type xAuthenticatorResponse struct {
	Version string                  `json:"version"`
	Status  string                  `json:"status"`
	Reason  string                  `json:"reason"`
	Headers map[string]*xStringList `json:"headers"`
}

func (v *xAuthenticatorResponse) build() (*xhttp.ResponseConfig, error) {
	config := &xhttp.ResponseConfig{
		Header: []*xhttp.Header{
			{Name: "Content-Type", Value: []string{"application/octet-stream", "video/mpeg"}},
			{Name: "Transfer-Encoding", Value: []string{"chunked"}},
			{Name: "Connection", Value: []string{"keep-alive"}},
			{Name: "Pragma", Value: []string{"no-cache"}},
			{Name: "Cache-Control", Value: []string{"private", "no-cache"}},
		},
	}
	if len(v.Version) > 0 {
		config.Version = &xhttp.Version{Value: v.Version}
	}
	if len(v.Status) > 0 || len(v.Reason) > 0 {
		config.Status = &xhttp.Status{Code: "200", Reason: "OK"}
		if len(v.Status) > 0 {
			config.Status.Code = v.Status
		}
		if len(v.Reason) > 0 {
			config.Status.Reason = v.Reason
		}
	}
	if len(v.Headers) > 0 {
		config.Header = make([]*xhttp.Header, 0, len(v.Headers))
		for _, key := range xSortKeys(v.Headers) {
			value := v.Headers[key]
			if value == nil {
				return nil, ErrConfig
			}
			config.Header = append(config.Header, &xhttp.Header{
				Name:  key,
				Value: append([]string(nil), (*value)...),
			})
		}
	}
	return config, nil
}

type xAuthenticator struct {
	Request  xAuthenticatorRequest  `json:"request"`
	Response xAuthenticatorResponse `json:"response"`
}

func (v *xAuthenticator) build() (proto.Message, error) {
	config := new(xhttp.Config)
	requestConfig, err := v.Request.build()
	if err != nil {
		return nil, err
	}
	config.Request = requestConfig
	responseConfig, err := v.Response.build()
	if err != nil {
		return nil, err
	}
	config.Response = responseConfig
	return config, nil
}

func (c *xTCPConfig) build() (proto.Message, error) {
	config := new(tcp.Config)
	if len(c.HeaderConfig) > 0 {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(c.HeaderConfig, &obj); err != nil {
			return nil, ErrConfig
		}
		rawID, found := obj["type"]
		if !found {
			return nil, ErrConfig
		}
		var id string
		if err := json.Unmarshal(rawID, &id); err != nil {
			return nil, ErrConfig
		}
		var header proto.Message
		switch strings.ToLower(id) {
		case "none":
			header = new(xnoop.ConnectionConfig)
		case "http":
			authenticator := new(xAuthenticator)
			if err := json.Unmarshal(c.HeaderConfig, authenticator); err != nil {
				return nil, ErrConfig
			}
			var err error
			if header, err = authenticator.build(); err != nil {
				return nil, err
			}
		default:
			return nil, ErrConfig
		}
		config.HeaderSettings = serial.ToTypedMessage(header)
	}
	if c.AcceptProxyProtocol {
		config.AcceptProxyProtocol = c.AcceptProxyProtocol
	}
	return config, nil
}

// ---- websocket / httpupgrade / grpc ----

type xWebSocketConfig struct {
	Host                string            `json:"host"`
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol"`
	HeartbeatPeriod     uint32            `json:"heartbeatPeriod"`
}

func (c *xWebSocketConfig) build() (proto.Message, error) {
	path := c.Path
	var ed uint32
	if u, err := url.Parse(path); err == nil {
		if q := u.Query(); q.Get("ed") != "" {
			e, _ := strconv.Atoi(q.Get("ed"))
			ed = uint32(e)
			q.Del("ed")
			u.RawQuery = q.Encode()
			path = u.String()
		}
	}
	for k, v := range c.Headers {
		if strings.ToLower(k) == "host" {
			if c.Host == "" {
				c.Host = v
			}
			delete(c.Headers, k)
		}
	}
	return &websocket.Config{
		Path:                path,
		Host:                c.Host,
		Header:              c.Headers,
		AcceptProxyProtocol: c.AcceptProxyProtocol,
		Ed:                  ed,
		HeartbeatPeriod:     c.HeartbeatPeriod,
	}, nil
}

type xHTTPUpgradeConfig struct {
	Host                string            `json:"host"`
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol"`
}

func (c *xHTTPUpgradeConfig) build() (proto.Message, error) {
	path := c.Path
	var ed uint32
	if u, err := url.Parse(path); err == nil {
		if q := u.Query(); q.Get("ed") != "" {
			e, _ := strconv.Atoi(q.Get("ed"))
			ed = uint32(e)
			q.Del("ed")
			u.RawQuery = q.Encode()
			path = u.String()
		}
	}
	for k := range c.Headers {
		if strings.ToLower(k) == "host" {
			return nil, ErrConfig
		}
	}
	return &httpupgrade.Config{
		Path:                path,
		Host:                c.Host,
		Header:              c.Headers,
		AcceptProxyProtocol: c.AcceptProxyProtocol,
		Ed:                  ed,
	}, nil
}

type xGRPCConfig struct {
	Authority           string `json:"authority"`
	ServiceName         string `json:"serviceName"`
	MultiMode           bool   `json:"multiMode"`
	IdleTimeout         int32  `json:"idle_timeout"`
	HealthCheckTimeout  int32  `json:"health_check_timeout"`
	PermitWithoutStream bool   `json:"permit_without_stream"`
	InitialWindowsSize  int32  `json:"initial_windows_size"`
	UserAgent           string `json:"user_agent"`
}

func (g *xGRPCConfig) build() (proto.Message, error) {
	if g.IdleTimeout <= 0 {
		g.IdleTimeout = 0
	}
	if g.HealthCheckTimeout <= 0 {
		g.HealthCheckTimeout = 0
	}
	if g.InitialWindowsSize < 0 {
		g.InitialWindowsSize = 0
	}
	return &xgrpc.Config{
		Authority:           g.Authority,
		ServiceName:         g.ServiceName,
		MultiMode:           g.MultiMode,
		IdleTimeout:         g.IdleTimeout,
		HealthCheckTimeout:  g.HealthCheckTimeout,
		PermitWithoutStream: g.PermitWithoutStream,
		InitialWindowsSize:  g.InitialWindowsSize,
		UserAgent:           g.UserAgent,
	}, nil
}

// ---- XHTTP / splitHTTP ----

type xXmuxConfig struct {
	MaxConcurrency   xInt32Range `json:"maxConcurrency"`
	MaxConnections   xInt32Range `json:"maxConnections"`
	CMaxReuseTimes   xInt32Range `json:"cMaxReuseTimes"`
	HMaxRequestTimes xInt32Range `json:"hMaxRequestTimes"`
	HMaxReusableSecs xInt32Range `json:"hMaxReusableSecs"`
	HKeepAlivePeriod int64       `json:"hKeepAlivePeriod"`
}

type xSplitHTTPConfig struct {
	Host                 string            `json:"host"`
	Path                 string            `json:"path"`
	Mode                 string            `json:"mode"`
	Headers              map[string]string `json:"headers"`
	XPaddingBytes        xInt32Range       `json:"xPaddingBytes"`
	XPaddingObfsMode     bool              `json:"xPaddingObfsMode"`
	XPaddingKey          string            `json:"xPaddingKey"`
	XPaddingHeader       string            `json:"xPaddingHeader"`
	XPaddingPlacement    string            `json:"xPaddingPlacement"`
	XPaddingMethod       string            `json:"xPaddingMethod"`
	UplinkHTTPMethod     string            `json:"uplinkHTTPMethod"`
	SessionIDPlacement   string            `json:"sessionIDPlacement"`
	SessionIDKey         string            `json:"sessionIDKey"`
	SessionIDTable       string            `json:"sessionIDTable"`
	SessionIDLength      xInt32Range       `json:"sessionIDLength"`
	SeqPlacement         string            `json:"seqPlacement"`
	SeqKey               string            `json:"seqKey"`
	UplinkDataPlacement  string            `json:"uplinkDataPlacement"`
	UplinkDataKey        string            `json:"uplinkDataKey"`
	UplinkChunkSize      xInt32Range       `json:"uplinkChunkSize"`
	NoGRPCHeader         bool              `json:"noGRPCHeader"`
	NoSSEHeader          bool              `json:"noSSEHeader"`
	ScMaxEachPostBytes   xInt32Range       `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs xInt32Range       `json:"scMinPostsIntervalMs"`
	ScMaxBufferedPosts   int64             `json:"scMaxBufferedPosts"`
	ScStreamUpServerSecs xInt32Range       `json:"scStreamUpServerSecs"`
	ServerMaxHeaderBytes int32             `json:"serverMaxHeaderBytes"`
	Xmux                 xXmuxConfig       `json:"xmux"`
	DownloadSettings     *xStreamConfig    `json:"downloadSettings"`
	Extra                json.RawMessage   `json:"extra"`
}

func xNewRangeConfig(input xInt32Range) *splithttp.RangeConfig {
	return &splithttp.RangeConfig{From: input.From, To: input.To}
}

func xRoomSize(tableSize int, min, max int32) *big.Int {
	base := big.NewInt(int64(tableSize))
	sum := new(big.Int)
	term := new(big.Int)
	for k := min; k <= max; k++ {
		term.Exp(base, big.NewInt(int64(k)), nil)
		sum.Add(sum, term)
	}
	return sum
}

func (c *xSplitHTTPConfig) build() (proto.Message, error) {
	if c.Extra != nil {
		var extra xSplitHTTPConfig
		if err := json.Unmarshal(c.Extra, &extra); err != nil {
			return nil, ErrConfig
		}
		extra.Host = c.Host
		extra.Path = c.Path
		extra.Mode = c.Mode
		c = &extra
	}

	switch c.Mode {
	case "":
		c.Mode = "auto"
	case "auto", "packet-up", "stream-up", "stream-one":
	default:
		return nil, ErrConfig
	}

	for k := range c.Headers {
		if strings.ToLower(k) == "host" {
			return nil, ErrConfig
		}
	}

	if c.XPaddingBytes != (xInt32Range{}) && (c.XPaddingBytes.From <= 0 || c.XPaddingBytes.To <= 0) {
		return nil, ErrConfig
	}
	if c.XPaddingKey == "" {
		c.XPaddingKey = "x_padding"
	}
	if c.XPaddingHeader == "" {
		c.XPaddingHeader = "X-Padding"
	}
	switch c.XPaddingPlacement {
	case "":
		c.XPaddingPlacement = "queryInHeader"
	case "cookie", "header", "query", "queryInHeader":
	default:
		return nil, ErrConfig
	}
	switch c.XPaddingMethod {
	case "":
		c.XPaddingMethod = "repeat-x"
	case "repeat-x", "tokenish":
	default:
		return nil, ErrConfig
	}
	switch c.UplinkDataPlacement {
	case "":
		c.UplinkDataPlacement = splithttp.PlacementAuto
	case splithttp.PlacementAuto, splithttp.PlacementBody:
	case splithttp.PlacementCookie, splithttp.PlacementHeader:
		if c.Mode != "packet-up" {
			return nil, ErrConfig
		}
	default:
		return nil, ErrConfig
	}
	if c.UplinkHTTPMethod == "" {
		c.UplinkHTTPMethod = "POST"
	}
	c.UplinkHTTPMethod = strings.ToUpper(c.UplinkHTTPMethod)
	if c.UplinkHTTPMethod == "GET" && c.Mode != "packet-up" {
		return nil, ErrConfig
	}
	switch c.SessionIDPlacement {
	case "":
		c.SessionIDPlacement = "path"
	case "path", "cookie", "header", "query":
	default:
		return nil, ErrConfig
	}
	switch c.SeqPlacement {
	case "":
		c.SeqPlacement = "path"
	case "path", "cookie", "header", "query":
	default:
		return nil, ErrConfig
	}
	if c.SessionIDPlacement != "path" && c.SessionIDKey == "" {
		switch c.SessionIDPlacement {
		case "cookie", "query":
			c.SessionIDKey = "x_session"
		case "header":
			c.SessionIDKey = "X-Session"
		}
	}
	if c.SessionIDTable != "" {
		if predefined, ok := splithttp.PredefinedTable[c.SessionIDTable]; ok {
			c.SessionIDTable = predefined
		}
		room := xRoomSize(len(c.SessionIDTable), c.SessionIDLength.From, c.SessionIDLength.To)
		if room.Cmp(big.NewInt(2<<30)) < 0 {
			return nil, ErrConfig
		}
		if c.SessionIDLength.From <= 0 {
			return nil, ErrConfig
		}
		for i := 0; i < len(c.SessionIDTable); i++ {
			if c.SessionIDTable[i] >= 0x80 {
				return nil, ErrConfig
			}
		}
	}
	if c.SeqPlacement != "path" && c.SeqKey == "" {
		switch c.SeqPlacement {
		case "cookie", "query":
			c.SeqKey = "x_seq"
		case "header":
			c.SeqKey = "X-Seq"
		}
	}
	if c.UplinkDataPlacement != splithttp.PlacementBody && c.UplinkDataKey == "" {
		switch c.UplinkDataPlacement {
		case splithttp.PlacementCookie:
			c.UplinkDataKey = "x_data"
		case splithttp.PlacementAuto, splithttp.PlacementHeader:
			c.UplinkDataKey = "X-Data"
		}
	}
	if c.ServerMaxHeaderBytes < 0 {
		return nil, ErrConfig
	}
	if c.Xmux.MaxConnections.To > 0 && c.Xmux.MaxConcurrency.To > 0 {
		return nil, ErrConfig
	}
	if c.Xmux == (xXmuxConfig{}) {
		c.Xmux.MaxConnections.From = 3
		c.Xmux.MaxConnections.To = 3
		c.Xmux.HMaxRequestTimes.From = 600
		c.Xmux.HMaxRequestTimes.To = 900
		c.Xmux.HMaxReusableSecs.From = 1800
		c.Xmux.HMaxReusableSecs.To = 3000
	}

	config := &splithttp.Config{
		Host:                 c.Host,
		Path:                 c.Path,
		Mode:                 c.Mode,
		Headers:              c.Headers,
		XPaddingBytes:        xNewRangeConfig(c.XPaddingBytes),
		XPaddingObfsMode:     c.XPaddingObfsMode,
		XPaddingKey:          c.XPaddingKey,
		XPaddingHeader:       c.XPaddingHeader,
		XPaddingPlacement:    c.XPaddingPlacement,
		XPaddingMethod:       c.XPaddingMethod,
		UplinkHTTPMethod:     c.UplinkHTTPMethod,
		SessionIDPlacement:   c.SessionIDPlacement,
		SeqPlacement:         c.SeqPlacement,
		SessionIDKey:         c.SessionIDKey,
		SeqKey:               c.SeqKey,
		UplinkDataPlacement:  c.UplinkDataPlacement,
		UplinkDataKey:        c.UplinkDataKey,
		UplinkChunkSize:      xNewRangeConfig(c.UplinkChunkSize),
		NoGRPCHeader:         c.NoGRPCHeader,
		NoSSEHeader:          c.NoSSEHeader,
		ScMaxEachPostBytes:   xNewRangeConfig(c.ScMaxEachPostBytes),
		ScMinPostsIntervalMs: xNewRangeConfig(c.ScMinPostsIntervalMs),
		ScMaxBufferedPosts:   c.ScMaxBufferedPosts,
		ScStreamUpServerSecs: xNewRangeConfig(c.ScStreamUpServerSecs),
		ServerMaxHeaderBytes: c.ServerMaxHeaderBytes,
		SessionIDTable:       c.SessionIDTable,
		SessionIDLength:      xNewRangeConfig(c.SessionIDLength),
		Xmux: &splithttp.XmuxConfig{
			MaxConcurrency:   xNewRangeConfig(c.Xmux.MaxConcurrency),
			MaxConnections:   xNewRangeConfig(c.Xmux.MaxConnections),
			CMaxReuseTimes:   xNewRangeConfig(c.Xmux.CMaxReuseTimes),
			HMaxRequestTimes: xNewRangeConfig(c.Xmux.HMaxRequestTimes),
			HMaxReusableSecs: xNewRangeConfig(c.Xmux.HMaxReusableSecs),
			HKeepAlivePeriod: c.Xmux.HKeepAlivePeriod,
		},
	}
	if c.DownloadSettings != nil {
		if c.Mode == "stream-one" {
			return nil, ErrConfig
		}
		ds, err := c.DownloadSettings.build()
		if err != nil {
			return nil, err
		}
		config.DownloadSettings = ds
	}
	return config, nil
}

// ---- TLS ----

type xTLSCertConfig struct {
	CertFile       string   `json:"certificateFile"`
	CertStr        []string `json:"certificate"`
	KeyFile        string   `json:"keyFile"`
	KeyStr         []string `json:"key"`
	Usage          string   `json:"usage"`
	OcspStapling   uint64   `json:"ocspStapling"`
	OneTimeLoading bool     `json:"oneTimeLoading"`
	BuildChain     bool     `json:"buildChain"`
}

func xReadCertOrString(file string, cert []string) ([]byte, error) {
	if len(file) > 0 {
		// File-backed certificates are rejected before this point
		// (unsafe profile check), and the helper never reads files.
		return nil, ErrConfig
	}
	if len(cert) > 0 {
		return []byte(strings.Join(cert, "\n")), nil
	}
	return nil, ErrConfig
}

func (c *xTLSCertConfig) build() (*tls.Certificate, error) {
	certificate := new(tls.Certificate)
	cert, err := xReadCertOrString(c.CertFile, c.CertStr)
	if err != nil {
		return nil, err
	}
	certificate.Certificate = cert
	certificate.CertificatePath = c.CertFile
	if len(c.KeyFile) > 0 || len(c.KeyStr) > 0 {
		key, err := xReadCertOrString(c.KeyFile, c.KeyStr)
		if err != nil {
			return nil, err
		}
		certificate.Key = key
		certificate.KeyPath = c.KeyFile
	}
	switch strings.ToLower(c.Usage) {
	case "encipherment":
		certificate.Usage = tls.Certificate_ENCIPHERMENT
	case "verify":
		certificate.Usage = tls.Certificate_AUTHORITY_VERIFY
	case "issue":
		certificate.Usage = tls.Certificate_AUTHORITY_ISSUE
	default:
		certificate.Usage = tls.Certificate_ENCIPHERMENT
	}
	if certificate.KeyPath == "" && certificate.CertificatePath == "" {
		certificate.OneTimeLoading = true
	} else {
		certificate.OneTimeLoading = c.OneTimeLoading
	}
	certificate.OcspStapling = c.OcspStapling
	certificate.BuildChain = c.BuildChain
	return certificate, nil
}

type xTLSConfig struct {
	AllowInsecure           bool              `json:"allowInsecure"`
	Certs                   []*xTLSCertConfig `json:"certificates"`
	ServerName              string            `json:"serverName"`
	ALPN                    *xStringList      `json:"alpn"`
	EnableSessionResumption bool              `json:"enableSessionResumption"`
	DisableSystemRoot       bool              `json:"disableSystemRoot"`
	MinVersion              string            `json:"minVersion"`
	MaxVersion              string            `json:"maxVersion"`
	CipherSuites            string            `json:"cipherSuites"`
	Fingerprint             string            `json:"fingerprint"`
	RejectUnknownSNI        bool              `json:"rejectUnknownSni"`
	CurvePreferences        *xStringList      `json:"curvePreferences"`
	MasterKeyLog            string            `json:"masterKeyLog"`
	PinnedPeerCertSha256    string            `json:"pinnedPeerCertSha256"`
	VerifyPeerCertByName    string            `json:"verifyPeerCertByName"`
	ECHServerKeys           string            `json:"echServerKeys"`
	ECHConfigList           string            `json:"echConfigList"`
	ECHSocketSettings       json.RawMessage   `json:"echSockopt"`
}

func (c *xTLSConfig) build() (proto.Message, error) {
	if len(c.ECHSocketSettings) > 0 {
		// echSockopt is a SocketConfig; not ported, so refuse it.
		return nil, ErrConfig
	}
	config := new(tls.Config)
	config.Certificate = make([]*tls.Certificate, len(c.Certs))
	for idx, certConf := range c.Certs {
		cert, err := certConf.build()
		if err != nil {
			return nil, err
		}
		config.Certificate[idx] = cert
	}
	if len(c.ServerName) > 0 {
		config.ServerName = c.ServerName
	}
	if c.ALPN != nil && len(*c.ALPN) > 0 {
		config.NextProtocol = []string(*c.ALPN)
	}
	if len(config.NextProtocol) > 1 {
		for _, p := range config.NextProtocol {
			if tls.IsFromMitm(p) {
				return nil, ErrConfig
			}
		}
	}
	if c.CurvePreferences != nil && len(*c.CurvePreferences) > 0 {
		config.CurvePreferences = []string(*c.CurvePreferences)
	}
	config.EnableSessionResumption = c.EnableSessionResumption
	config.DisableSystemRoot = c.DisableSystemRoot
	config.MinVersion = c.MinVersion
	config.MaxVersion = c.MaxVersion
	config.CipherSuites = c.CipherSuites
	config.Fingerprint = strings.ToLower(c.Fingerprint)
	if config.Fingerprint != "unsafe" && tls.GetFingerprint(config.Fingerprint) == nil {
		return nil, ErrConfig
	}
	config.RejectUnknownSni = c.RejectUnknownSNI
	config.MasterKeyLog = c.MasterKeyLog
	if c.AllowInsecure {
		return nil, ErrConfig
	}
	if c.PinnedPeerCertSha256 != "" {
		for v := range strings.SplitSeq(c.PinnedPeerCertSha256, ",") {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			hashValue, err := hex.DecodeString(strings.ReplaceAll(v, ":", ""))
			if err != nil {
				return nil, ErrConfig
			}
			if len(hashValue) != 32 {
				return nil, ErrConfig
			}
			config.PinnedPeerCertSha256 = append(config.PinnedPeerCertSha256, hashValue)
		}
	}
	if c.VerifyPeerCertByName != "" {
		for v := range strings.SplitSeq(c.VerifyPeerCertByName, ",") {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			config.VerifyPeerCertByName = append(config.VerifyPeerCertByName, v)
		}
	}
	if c.ECHServerKeys != "" {
		echPrivateKey, err := base64.StdEncoding.DecodeString(c.ECHServerKeys)
		if err != nil {
			return nil, ErrConfig
		}
		config.EchServerKeys = echPrivateKey
	}
	config.EchConfigList = c.ECHConfigList
	return config, nil
}

// ---- REALITY ----

type xLimitFallback struct {
	AfterBytes       uint64
	BytesPerSec      uint64
	BurstBytesPerSec uint64
}

type xREALITYConfig struct {
	MasterKeyLog string          `json:"masterKeyLog"`
	Show         bool            `json:"show"`
	Target       json.RawMessage `json:"target"`
	Dest         json.RawMessage `json:"dest"`
	Type         string          `json:"type"`
	Xver         uint64          `json:"xver"`
	ServerNames  []string        `json:"serverNames"`
	PrivateKey   string          `json:"privateKey"`
	MinClientVer string          `json:"minClientVer"`
	MaxClientVer string          `json:"maxClientVer"`
	MaxTimeDiff  uint64          `json:"maxTimeDiff"`
	ShortIds     []string        `json:"shortIds"`
	Mldsa65Seed  string          `json:"mldsa65Seed"`

	LimitFallbackUpload   xLimitFallback `json:"limitFallbackUpload"`
	LimitFallbackDownload xLimitFallback `json:"limitFallbackDownload"`

	Fingerprint   string `json:"fingerprint"`
	ServerName    string `json:"serverName"`
	Password      string `json:"password"`
	PublicKey     string `json:"publicKey"`
	ShortId       string `json:"shortId"`
	Mldsa65Verify string `json:"mldsa65Verify"`
	SpiderX       string `json:"spiderX"`
}

func (c *xREALITYConfig) build() (proto.Message, error) {
	config := new(reality.Config)
	config.MasterKeyLog = c.MasterKeyLog
	config.Show = c.Show
	var err error
	if c.Target != nil {
		c.Dest = c.Target
	}
	if c.Dest != nil {
		// server-side REALITY: not reachable from an XIO profile (Parse only
		// accepts client outbounds) and not ported.
		return nil, ErrConfig
	}
	config.Fingerprint = strings.ToLower(c.Fingerprint)
	if config.Fingerprint == "unsafe" || config.Fingerprint == "hellogolang" {
		return nil, ErrConfig
	}
	if tls.GetFingerprint(config.Fingerprint) == nil {
		return nil, ErrConfig
	}
	if len(c.ServerNames) != 0 {
		return nil, ErrConfig
	}
	if c.Password != "" {
		c.PublicKey = c.Password
	}
	if c.PublicKey == "" {
		return nil, ErrConfig
	}
	if config.PublicKey, err = base64.RawURLEncoding.DecodeString(c.PublicKey); err != nil || len(config.PublicKey) != 32 {
		return nil, ErrConfig
	}
	if len(c.ShortIds) != 0 {
		return nil, ErrConfig
	}
	if len(c.ShortId) > 16 {
		return nil, ErrConfig
	}
	config.ShortId = make([]byte, 8)
	if _, err = hex.Decode(config.ShortId, []byte(c.ShortId)); err != nil {
		return nil, ErrConfig
	}
	if c.Mldsa65Verify != "" {
		if config.Mldsa65Verify, err = base64.RawURLEncoding.DecodeString(c.Mldsa65Verify); err != nil || len(config.Mldsa65Verify) != 1952 {
			return nil, ErrConfig
		}
	}
	if c.SpiderX == "" {
		c.SpiderX = "/"
	}
	if c.SpiderX[0] != '/' {
		return nil, ErrConfig
	}
	config.SpiderY = make([]int64, 10)
	u, _ := url.Parse(c.SpiderX)
	q := u.Query()
	parse := func(param string, index int) {
		if q.Get(param) != "" {
			s := strings.Split(q.Get(param), "-")
			if len(s) == 1 {
				config.SpiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
				config.SpiderY[index+1], _ = strconv.ParseInt(s[0], 10, 64)
			} else {
				config.SpiderY[index], _ = strconv.ParseInt(s[0], 10, 64)
				config.SpiderY[index+1], _ = strconv.ParseInt(s[1], 10, 64)
			}
		}
		q.Del(param)
	}
	parse("p", 0)
	parse("c", 2)
	parse("t", 4)
	parse("i", 6)
	parse("r", 8)
	u.RawQuery = q.Encode()
	config.SpiderX = u.String()
	config.ServerName = c.ServerName
	return config, nil
}
