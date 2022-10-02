package quicpacket

import (
	"errors"
)

var (
	ErrInvalidPacket = errors.New("quicpacket: invalid packet")
)

const (
	MinLongPacketLen  = 7
	MinShortPacketLen = 3
)

type PacketForm uint8

const (
	LongForm  PacketForm = iota
	ShortForm PacketForm = iota
)

type LongType uint8

const (
	Initial   LongType = 0x00
	RTT0      LongType = 0x01
	Handshake LongType = 0x02
	Retry     LongType = 0x03
)

type Packet struct {
	Form PacketForm

	LongPacketType       LongType
	LongTypeSpecificBits uint8

	Version uint32

	DestinationConnectionID []byte
	SourceConnectionID      []byte

	ShortPacketNumber []byte

	Payload []byte
}

func (p *Packet) IsVersion() bool {
	return p.Form == LongForm && p.Version == 0
}

func Parse(packet []byte, shortConnectionIDLength int) (Packet, error) {
	ret := Packet{}

	if len(packet) < MinShortPacketLen {
		return ret, ErrInvalidPacket
	}

	if packet[0]&0x40 == 0 {
		return ret, ErrInvalidPacket
	}

	if packet[0]&0x80 > 0 {
		ret.Form = LongForm

		if len(packet) < MinLongPacketLen {
			return ret, ErrInvalidPacket
		}

		ret.LongPacketType = LongType((uint8(packet[0]) & 0x30) >> 4)
		ret.LongTypeSpecificBits = uint8(packet[0]) & 0x0F

		ret.Version = uint32(packet[1])<<(3*8) | uint32(packet[2])<<(2*8) | uint32(packet[3])<<(1*8) | uint32(packet[4])

		dlen := int(packet[5])
		if len(packet) < MinLongPacketLen+dlen {
			return ret, ErrInvalidPacket
		}

		ret.DestinationConnectionID = packet[6:][:dlen]

		slen := int(packet[6+dlen])
		if len(packet) < MinLongPacketLen+dlen+slen {
			return ret, ErrInvalidPacket
		}

		ret.SourceConnectionID = packet[6+dlen+1:][:slen]

		ret.Payload = packet[6+dlen+1+slen:]
	} else {
		ret.Form = ShortForm

		pnlen := 1 + (int(packet[0]) & 0x03)

		if len(packet) < MinShortPacketLen+shortConnectionIDLength+pnlen {
			return ret, ErrInvalidPacket
		}

		ret.DestinationConnectionID = packet[1:][:shortConnectionIDLength]

		ret.ShortPacketNumber = packet[1+shortConnectionIDLength:][:pnlen]

		ret.Payload = packet[1+shortConnectionIDLength+pnlen:]
	}

	return ret, nil
}
