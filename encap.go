package enip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Encapsulation commands (the 16-bit command field of the 24-byte header).
const (
	CmdNOP               uint16 = 0x0000
	CmdListServices      uint16 = 0x0004
	CmdListIdentity      uint16 = 0x0063
	CmdListInterfaces    uint16 = 0x0064
	CmdRegisterSession   uint16 = 0x0065
	CmdUnRegisterSession uint16 = 0x0066
	CmdSendRRData        uint16 = 0x006F
	CmdSendUnitData      uint16 = 0x0070
)

// Common packet format item type IDs.
const (
	ItemNullAddress      uint16 = 0x0000
	ItemIdentity         uint16 = 0x000C
	ItemConnectedAddress uint16 = 0x00A1
	ItemConnectedData    uint16 = 0x00B1
	ItemUnconnectedData  uint16 = 0x00B2
	ItemSockaddrOT       uint16 = 0x8000
	ItemSockaddrTO       uint16 = 0x8001
)

// DefaultPort is the EtherNet/IP explicit messaging port (TCP and UDP).
const DefaultPort = 44818

// HeaderLen is the size of the encapsulation header.
const HeaderLen = 24

// Header is the encapsulation header; every field is little-endian.
type Header struct {
	Command uint16
	Length  uint16 // bytes of data after the header
	Session uint32
	Status  uint32
	Context [8]byte
	Options uint32
}

// Marshal writes the header followed by data (Length is set from data).
func (h Header) Marshal(data []byte) []byte {
	b := make([]byte, HeaderLen+len(data))
	binary.LittleEndian.PutUint16(b[0:], h.Command)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(data)))
	binary.LittleEndian.PutUint32(b[4:], h.Session)
	binary.LittleEndian.PutUint32(b[8:], h.Status)
	copy(b[12:20], h.Context[:])
	binary.LittleEndian.PutUint32(b[20:], h.Options)
	copy(b[HeaderLen:], data)
	return b
}

// ParseHeader decodes the first 24 bytes of b.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, fmt.Errorf("encapsulation header needs %d bytes, got %d", HeaderLen, len(b))
	}
	var h Header
	h.Command = binary.LittleEndian.Uint16(b[0:])
	h.Length = binary.LittleEndian.Uint16(b[2:])
	h.Session = binary.LittleEndian.Uint32(b[4:])
	h.Status = binary.LittleEndian.Uint32(b[8:])
	copy(h.Context[:], b[12:20])
	h.Options = binary.LittleEndian.Uint32(b[20:])
	return h, nil
}

// ReadPacket reads one encapsulation packet from a stream.
func ReadPacket(r io.Reader) (Header, []byte, error) {
	var hb [HeaderLen]byte
	if _, err := io.ReadFull(r, hb[:]); err != nil {
		return Header{}, nil, err
	}
	h, _ := ParseHeader(hb[:])
	data := make([]byte, h.Length)
	if _, err := io.ReadFull(r, data); err != nil {
		return h, nil, err
	}
	return h, data, nil
}

// EncapStatusText names encapsulation status codes.
func EncapStatusText(s uint32) string {
	switch s {
	case 0:
		return "success"
	case 0x01:
		return "invalid or unsupported encapsulation command"
	case 0x02:
		return "insufficient memory in the target"
	case 0x03:
		return "poorly formed or incorrect data"
	case 0x64:
		return "invalid session handle"
	case 0x65:
		return "invalid length"
	case 0x69:
		return "unsupported encapsulation protocol revision"
	}
	return fmt.Sprintf("encapsulation status 0x%X", s)
}

// RegisterSessionData is the request/reply body of RegisterSession:
// protocol version 1, options 0.
func RegisterSessionData() []byte { return []byte{0x01, 0x00, 0x00, 0x00} }

// Item is one common packet format item.
type Item struct {
	Type uint16
	Data []byte
}

// MarshalCPF encodes an item count followed by the items.
func MarshalCPF(items ...Item) []byte {
	n := 2
	for _, it := range items {
		n += 4 + len(it.Data)
	}
	b := make([]byte, 0, n)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(items)))
	for _, it := range items {
		b = binary.LittleEndian.AppendUint16(b, it.Type)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(it.Data)))
		b = append(b, it.Data...)
	}
	return b
}

// ParseCPF decodes a common packet format list.
func ParseCPF(b []byte) ([]Item, error) {
	if len(b) < 2 {
		return nil, errors.New("common packet format: no item count")
	}
	n := int(binary.LittleEndian.Uint16(b))
	b = b[2:]
	items := make([]Item, 0, n)
	for i := 0; i < n; i++ {
		if len(b) < 4 {
			return nil, fmt.Errorf("common packet format: item %d truncated", i+1)
		}
		t := binary.LittleEndian.Uint16(b)
		l := int(binary.LittleEndian.Uint16(b[2:]))
		if len(b) < 4+l {
			return nil, fmt.Errorf("common packet format: item %d says %d bytes, %d left", i+1, l, len(b)-4)
		}
		items = append(items, Item{Type: t, Data: b[4 : 4+l]})
		b = b[4+l:]
	}
	return items, nil
}

// RRData builds the body of SendRRData or SendUnitData: interface handle
// 0, a timeout in seconds and the items.
func RRData(timeout uint16, items ...Item) []byte {
	b := make([]byte, 6, 6+2+8*len(items))
	binary.LittleEndian.PutUint16(b[4:], timeout)
	return append(b, MarshalCPF(items...)...)
}

// ParseRRData splits the body of SendRRData/SendUnitData into its items.
func ParseRRData(b []byte) ([]Item, error) {
	if len(b) < 6 {
		return nil, errors.New("send data body shorter than 6 bytes")
	}
	return ParseCPF(b[6:])
}

// Identity is a ListIdentity reply item (the identity object's key
// attributes plus the device's socket address).
type Identity struct {
	Protocol    uint16 `json:"protocol"`
	IP          string `json:"ip"`
	Port        uint16 `json:"port"`
	Vendor      uint16 `json:"vendor"`
	DeviceType  uint16 `json:"deviceType"`
	ProductCode uint16 `json:"productCode"`
	Revision    string `json:"revision"`
	Status      uint16 `json:"status"`
	Serial      string `json:"serial"`
	ProductName string `json:"productName"`
	State       uint8  `json:"state"`
}

// IdentityItem encodes an identity item's data (socket address fields are
// big-endian, the rest little-endian).
func IdentityItem(id Identity, major, minor uint8, serial uint32) []byte {
	b := binary.LittleEndian.AppendUint16(nil, id.Protocol)
	b = binary.BigEndian.AppendUint16(b, 2) // AF_INET
	b = binary.BigEndian.AppendUint16(b, id.Port)
	ip := net.ParseIP(id.IP).To4()
	if ip == nil {
		ip = net.IPv4zero.To4()
	}
	b = append(b, ip...)
	b = append(b, make([]byte, 8)...)
	b = binary.LittleEndian.AppendUint16(b, id.Vendor)
	b = binary.LittleEndian.AppendUint16(b, id.DeviceType)
	b = binary.LittleEndian.AppendUint16(b, id.ProductCode)
	b = append(b, major, minor)
	b = binary.LittleEndian.AppendUint16(b, id.Status)
	b = binary.LittleEndian.AppendUint32(b, serial)
	b = append(b, byte(len(id.ProductName)))
	b = append(b, id.ProductName...)
	return append(b, id.State)
}

// ParseIdentity decodes an identity item.
func ParseIdentity(b []byte) (Identity, error) {
	if len(b) < 33 {
		return Identity{}, fmt.Errorf("identity item needs at least 33 bytes, got %d", len(b))
	}
	var id Identity
	id.Protocol = binary.LittleEndian.Uint16(b)
	id.Port = binary.BigEndian.Uint16(b[4:])
	id.IP = net.IP(b[6:10]).String()
	id.Vendor = binary.LittleEndian.Uint16(b[18:])
	id.DeviceType = binary.LittleEndian.Uint16(b[20:])
	id.ProductCode = binary.LittleEndian.Uint16(b[22:])
	id.Revision = fmt.Sprintf("%d.%03d", b[24], b[25])
	id.Status = binary.LittleEndian.Uint16(b[26:])
	id.Serial = fmt.Sprintf("%08X", binary.LittleEndian.Uint32(b[28:]))
	n := int(b[32])
	if len(b) < 33+n {
		return Identity{}, errors.New("identity item: product name truncated")
	}
	id.ProductName = string(b[33 : 33+n])
	if len(b) > 33+n {
		id.State = b[33+n]
	}
	return id, nil
}

// ParseListIdentity decodes a ListIdentity reply body.
func ParseListIdentity(b []byte) ([]Identity, error) {
	items, err := ParseCPF(b)
	if err != nil {
		return nil, err
	}
	var out []Identity
	for _, it := range items {
		if it.Type != ItemIdentity {
			continue
		}
		id, err := ParseIdentity(it.Data)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}
