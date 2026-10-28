package teleport

import (
	"encoding/hex"
	"net"
)

type packetLog struct {
	Direction string `json:"direction"`
	Addr      string `json:"addr"`
	Length    int    `json:"length"`
	PrefixHex string `json:"prefix_hex"`
	STUN      bool   `json:"stun"`
	STUNType  string `json:"stun_type,omitempty"`
}

func logPacket(direction string, addr *net.UDPAddr, data []byte) packetLog {
	prefixLen := len(data)
	if prefixLen > 12 {
		prefixLen = 12
	}
	entry := packetLog{Direction: direction, Length: len(data), PrefixHex: hex.EncodeToString(data[:prefixLen])}
	if addr != nil {
		entry.Addr = addr.String()
	}
	if msg, ok := parseStunMessage(data); ok {
		entry.STUN = true
		entry.STUNType = msg.Type.String()
	}
	return entry
}
