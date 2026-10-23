package main

import "encoding/binary"

func DNSPacket(ip []byte) []byte {
	dns := []byte{0x71, 0x31, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	b := make([]byte, 28+len(dns))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64
	b[9] = 17
	copy(b[12:16], ip)
	copy(b[16:20], []byte{1, 1, 1, 1})
	binary.BigEndian.PutUint16(b[20:], 47001)
	binary.BigEndian.PutUint16(b[22:], 53)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(dns)))
	copy(b[28:], dns)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(b[10:], uint16(^sum))
	return b
}
