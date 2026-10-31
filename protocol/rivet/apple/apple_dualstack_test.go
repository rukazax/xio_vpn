package apple

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"xio.local/rivet/internal/rivet"
)

func payload4(source, destination string) []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	b[8] = 64
	b[9] = 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:16], net.ParseIP(source).To4())
	copy(b[16:20], net.ParseIP(destination).To4())
	binary.BigEndian.PutUint16(b[24:26], 8)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(b[10:12], ^uint16(sum))
	return b
}
func payload6(source, destination string) []byte {
	b := make([]byte, 48)
	b[0] = 0x60
	b[6] = 17
	b[7] = 64
	binary.BigEndian.PutUint16(b[4:6], 8)
	copy(b[8:24], net.ParseIP(source).To16())
	copy(b[24:40], net.ParseIP(destination).To16())
	binary.BigEndian.PutUint16(b[44:46], 8)
	return b
}
func fixtureTunnel(t *testing.T, ip6 string) *tunnel {
	t.Helper()
	Stop()
	ctx, cancel := context.WithCancel(context.Background())
	instance := &tunnel{cfg: rivet.ClientConfig{IP: "10.79.0.31", IP6: ip6}, ctx: ctx, cancel: cancel, phase: "connected", packets: make(chan []byte, 64)}
	global.Lock()
	global.t = instance
	global.Unlock()
	t.Cleanup(Stop)
	return instance
}
func capability(t *testing.T) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal([]byte(Status()), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestAppleInputIPv4AndIPv6(t *testing.T) {
	instance := fixtureTunnel(t, "fd79:1::1f")
	for _, packet := range [][]byte{payload4("10.79.0.31", "1.1.1.1"), payload6("fd79:1::1f", "2606:4700:4700::1111")} {
		if !Input(packet) {
			t.Errorf("valid IP version%d rejected", packet[0]>>4)
			continue
		}
		queued := <-instance.packets
		packet[0] = 0
		if queued[0] == 0 {
			t.Error("caller packet retained instead of copied")
		}
	}
	if capability(t)["ipv6Payload"] != true {
		t.Error("implemented configured IPv6 capability not advertised")
	}
}
func TestAppleInputDisabledIPv6AndUnsafePackets(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		label := "ipv4-only"
		ip6 := ""
		if enabled {
			label = "dualstack"
			ip6 = "fd79:1::1f"
		}
		t.Run(label, func(t *testing.T) {
			instance := fixtureTunnel(t, ip6)
			if capability(t)["ipv6Payload"] != enabled {
				t.Error("IPv6 capability does not match profile")
			}
			if !Input(payload4("10.79.0.31", "1.1.1.1")) {
				t.Error("IPv4 regression")
			}
			<-instance.packets
			unsafe := [][]byte{nil, {}, {0x60}, make([]byte, 1281), payload4("10.79.0.32", "1.1.1.1"), payload4("10.79.0.31", "192.168.1.1"), payload6("fd79:1::20", "2606:4700:4700::1111"), payload6("fd79:1::1f", "fd00::1")}
			truncated := payload6("fd79:1::1f", "2606:4700:4700::1111")
			unsafe = append(unsafe, truncated[:len(truncated)-1])
			if !enabled {
				unsafe = append(unsafe, payload6("fd79:1::1f", "2606:4700:4700::1111"))
			}
			for index, packet := range unsafe {
				if Input(packet) {
					t.Errorf("unsafe packet%d queued", index)
				}
			}
			if len(instance.packets) != 0 {
				t.Error("invalid input changed queue")
			}
		})
	}
}
func TestAppleInboundDestinationAndFamily(t *testing.T) {
	for _, ip6 := range []string{"", "fd79:1::1f"} {
		instance := fixtureTunnel(t, ip6)
		if !instance.inboundAllowed(payload4("1.1.1.1", "10.79.0.31")) {
			t.Error("own IPv4 return dropped")
		}
		if instance.inboundAllowed(payload4("1.1.1.1", "10.79.0.32")) {
			t.Error("another user's IPv4 accepted")
		}
		if got := instance.inboundAllowed(payload6("2606:4700:4700::1111", "fd79:1::1f")); got != (ip6 != "") {
			t.Error("own IPv6 family incorrectly handled")
		}
		if instance.inboundAllowed(payload6("2606:4700:4700::1111", "fd79:1::20")) {
			t.Error("another user's IPv6 accepted")
		}
		for _, packet := range [][]byte{nil, {0x60}, make([]byte, 1281), payload6("2606:4700:4700::1111", "fd79:1::1f")[:47]} {
			if instance.inboundAllowed(packet) {
				t.Error("malformed inbound accepted")
			}
		}
	}
}
func TestAppleCancelledInputAndCapability(t *testing.T) {
	instance := fixtureTunnel(t, "fd79:1::1f")
	instance.cancel()
	if Input(payload4("10.79.0.31", "1.1.1.1")) {
		t.Error("cancelled tunnel accepted packet")
	}
	if capability(t)["ipv6Payload"] != false {
		t.Error("cancelled tunnel capability must explicitly be false")
	}
}
