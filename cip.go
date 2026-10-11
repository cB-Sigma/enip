package enip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// CIP service codes used here.
const (
	SvcGetAttributesAll    byte   = 0x01
	SvcMultipleService     byte   = 0x0A
	SvcGetAttributeSingle  byte   = 0x0E
	SvcSetAttributeSingle  byte   = 0x10
	SvcForwardClose        byte   = 0x4E
	SvcReadTag             byte   = 0x4C
	SvcWriteTag            byte   = 0x4D
	SvcReadTagFragmented   byte   = 0x52 // to a symbol
	SvcUnconnectedSend     byte   = 0x52 // to the connection manager
	SvcWriteTagFragmented  byte   = 0x53
	SvcForwardOpen         byte   = 0x54
	SvcLargeForwardOpen    byte   = 0x5B
	ReplyBit               byte   = 0x80
	ClassIdentity          uint16 = 0x01
	ClassMessageRouter     uint16 = 0x02
	ClassConnectionManager uint16 = 0x06
)

// General status codes this package acts on.
const (
	StatusSuccess          byte = 0x00
	StatusConnFailure      byte = 0x01
	StatusPathSegment      byte = 0x04
	StatusPathUnknown      byte = 0x05
	StatusPartial          byte = 0x06
	StatusServiceNotSup    byte = 0x08
	StatusNotSettable      byte = 0x0E
	StatusReplyTooLarge    byte = 0x11
	StatusNotEnoughData    byte = 0x13
	StatusAttrNotSupported byte = 0x14
	StatusTooMuchData      byte = 0x15
	StatusObjectMissing    byte = 0x16
	StatusEmbeddedError    byte = 0x1E
	StatusVendor           byte = 0xFF
)

// ---- EPATH ----------------------------------------------------------------

// Logical appends class, instance and (when attr >= 0) attribute segments,
// each 8-bit when it fits and 16-bit otherwise.
func Logical(class, instance uint16, attr int) []byte {
	b := logical(nil, 0x20, uint32(class))
	b = logical(b, 0x24, uint32(instance))
	if attr >= 0 {
		b = logical(b, 0x30, uint32(attr))
	}
	return b
}

// logical appends one logical segment: base is the 8-bit format; +1 is the
// 16-bit format (pad byte), +2 the 32-bit one (pad byte).
func logical(b []byte, base byte, v uint32) []byte {
	switch {
	case v <= 0xFF:
		return append(b, base, byte(v))
	case v <= 0xFFFF:
		b = append(b, base+1, 0)
		return binary.LittleEndian.AppendUint16(b, uint16(v))
	default:
		b = append(b, base+2, 0)
		return binary.LittleEndian.AppendUint32(b, v)
	}
}

// Symbolic appends an ANSI extended symbolic segment, padded to a word.
func Symbolic(b []byte, name string) []byte {
	b = append(b, 0x91, byte(len(name)))
	b = append(b, name...)
	if len(name)%2 == 1 {
		b = append(b, 0)
	}
	return b
}

// Element appends a member (element index) segment.
func Element(b []byte, i uint32) []byte { return logical(b, 0x28, i) }

// TagPath encodes a Logix tag reference such as "Program:Main.Motor[2].Speed"
// or "Grid[1,2]": each dotted name becomes a symbolic segment and each index
// a member segment. The "Program:<name>" scope is one segment.
func TagPath(tag string) ([]byte, error) {
	if tag == "" {
		return nil, errors.New("empty tag name")
	}
	var b []byte
	rest := tag
	for rest != "" {
		// A name runs to the next '.' or '['; "Program:X" contains ':' only.
		end := strings.IndexAny(rest, ".[")
		name := rest
		if end >= 0 {
			name = rest[:end]
		}
		if name == "" || len(name) > 255 {
			return nil, fmt.Errorf("tag %q: empty or too long name part", tag)
		}
		for _, r := range name {
			if r > 0x7E || r < 0x21 || r == ']' || r == ',' {
				return nil, fmt.Errorf("tag %q: character %q is not allowed", tag, r)
			}
		}
		b = Symbolic(b, name)
		rest = rest[len(name):]
		if strings.HasPrefix(rest, "[") {
			close := strings.IndexByte(rest, ']')
			if close < 0 {
				return nil, fmt.Errorf("tag %q: missing ]", tag)
			}
			for _, part := range strings.Split(rest[1:close], ",") {
				n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
				if err != nil {
					return nil, fmt.Errorf("tag %q: index %q is not a number", tag, part)
				}
				b = Element(b, uint32(n))
			}
			rest = rest[close+1:]
		}
		if rest != "" {
			if rest[0] != '.' || len(rest) == 1 {
				return nil, fmt.Errorf("tag %q: expected .member after %q", tag, tag[:len(tag)-len(rest)])
			}
			rest = rest[1:]
		}
	}
	return b, nil
}

// Route parses a route such as "1,0" (backplane port 1, slot 0) or
// "1,0,2,10.0.0.9,1,2" into port segments. Links that are IP addresses
// (or above 255) use the extended link address form.
func Route(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	if len(parts)%2 != 0 {
		return nil, fmt.Errorf("route %q must be port,link pairs", s)
	}
	var b []byte
	for i := 0; i < len(parts); i += 2 {
		port, err := strconv.ParseUint(strings.TrimSpace(parts[i]), 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("route %q: port %q is not a number from 1", s, parts[i])
		}
		link := strings.TrimSpace(parts[i+1])
		b, err = PortSegment(b, uint16(port), link)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", s, err)
		}
	}
	return b, nil
}

// PortSegment appends one port segment.
func PortSegment(b []byte, port uint16, link string) ([]byte, error) {
	var addr []byte
	if n, err := strconv.ParseUint(link, 10, 8); err == nil {
		addr = []byte{byte(n)}
	} else if ip := net.ParseIP(link); ip != nil && ip.To4() != nil {
		addr = []byte(ip.To4().String())
	} else {
		return nil, fmt.Errorf("link %q is not a slot number or an IPv4 address", link)
	}
	seg := byte(0)
	if len(addr) > 1 {
		seg |= 0x10
	}
	if port < 15 {
		seg |= byte(port)
	} else {
		seg |= 0x0F
	}
	b = append(b, seg)
	if len(addr) > 1 {
		b = append(b, byte(len(addr)))
	}
	if port >= 15 {
		b = binary.LittleEndian.AppendUint16(b, port)
	}
	b = append(b, addr...)
	if len(addr) > 1 && len(addr)%2 == 1 {
		b = append(b, 0)
	}
	return b, nil
}

// ---- messages ---------------------------------------------------------------

// Request encodes a CIP request: service, path size in words, path, data.
func Request(service byte, path, data []byte) []byte {
	b := make([]byte, 0, 2+len(path)+len(data))
	b = append(b, service, byte(len(path)/2))
	b = append(b, path...)
	return append(b, data...)
}

// ParseRequest splits a CIP request.
func ParseRequest(b []byte) (service byte, path, data []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("CIP request shorter than 2 bytes")
	}
	n := int(b[1]) * 2
	if len(b) < 2+n {
		return 0, nil, nil, errors.New("CIP request path truncated")
	}
	return b[0], b[2 : 2+n], b[2+n:], nil
}

// Response is a decoded CIP reply.
type Response struct {
	Service byte // with the reply bit
	Status  byte
	Ext     []uint16
	Data    []byte
}

// ParseResponse decodes a CIP reply.
func ParseResponse(b []byte) (*Response, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("CIP reply needs 4 bytes, got %d", len(b))
	}
	r := &Response{Service: b[0], Status: b[2]}
	n := int(b[3])
	if len(b) < 4+2*n {
		return nil, errors.New("CIP reply: extended status truncated")
	}
	for i := 0; i < n; i++ {
		r.Ext = append(r.Ext, binary.LittleEndian.Uint16(b[4+2*i:]))
	}
	r.Data = b[4+2*n:]
	return r, nil
}

// MarshalResponse encodes a CIP reply.
func MarshalResponse(service, status byte, ext []uint16, data []byte) []byte {
	b := []byte{service | ReplyBit, 0, status, byte(len(ext))}
	for _, e := range ext {
		b = binary.LittleEndian.AppendUint16(b, e)
	}
	return append(b, data...)
}

// Err returns the reply's status as an error, or nil on success (and on
// partial transfer, which callers handle).
func (r *Response) Err() error {
	if r.Status == StatusSuccess || r.Status == StatusPartial {
		return nil
	}
	return &Error{Service: r.Service &^ ReplyBit, Status: r.Status, Ext: r.Ext}
}

// WriteErr is Err for a write service (Write Tag, Write Tag Fragmented,
// Set Attribute Single): partial transfer is not success there, since
// only reads continue in further fragments.
func (r *Response) WriteErr() error {
	if r.Status == StatusSuccess {
		return nil
	}
	return &Error{Service: r.Service &^ ReplyBit, Status: r.Status, Ext: r.Ext}
}

// Error is a CIP error status.
type Error struct {
	Service byte
	Status  byte
	Ext     []uint16
}

func (e *Error) Error() string {
	s := fmt.Sprintf("CIP status 0x%02X (%s)", e.Status, StatusText(e.Status))
	if len(e.Ext) > 0 {
		s += fmt.Sprintf(", extended 0x%04X", e.Ext[0])
		if t := ExtStatusText(e.Status, e.Ext[0]); t != "" {
			s += " (" + t + ")"
		}
	}
	return s
}

// StatusText names a general status code.
func StatusText(s byte) string {
	if t, ok := generalStatus[s]; ok {
		return t
	}
	return "unknown status"
}

var generalStatus = map[byte]string{
	0x00: "success",
	0x01: "connection failure",
	0x02: "resource unavailable",
	0x03: "invalid parameter value",
	0x04: "path segment error",
	0x05: "path destination unknown",
	0x06: "partial transfer",
	0x07: "connection lost",
	0x08: "service not supported",
	0x09: "invalid attribute value",
	0x0A: "attribute list error",
	0x0B: "already in requested mode or state",
	0x0C: "object state conflict",
	0x0D: "object already exists",
	0x0E: "attribute not settable",
	0x0F: "privilege violation",
	0x10: "device state conflict",
	0x11: "reply data too large",
	0x12: "fragmentation of a primitive value",
	0x13: "not enough data",
	0x14: "attribute not supported",
	0x15: "too much data",
	0x16: "object does not exist",
	0x17: "service fragmentation sequence not in progress",
	0x18: "no stored attribute data",
	0x19: "store operation failure",
	0x1A: "routing failure, request too large",
	0x1B: "routing failure, response too large",
	0x1C: "missing attribute list entry data",
	0x1D: "invalid attribute value list",
	0x1E: "embedded service error",
	0x1F: "vendor specific error",
	0x20: "invalid parameter",
	0x21: "write-once value already written",
	0x22: "invalid reply received",
	0x25: "key failure in path",
	0x26: "path size invalid",
	0x27: "unexpected attribute in list",
	0x28: "invalid member ID",
	0x29: "member not settable",
	0x2C: "attribute not gettable",
	0xFF: "general error (see extended status)",
}

// ExtStatusText names the extended status of connection manager errors
// (general 0x01) and Logix tag errors (general 0xFF).
func ExtStatusText(general byte, ext uint16) string {
	switch general {
	case 0x01:
		return connMgrStatus[ext]
	case 0xFF:
		return logixStatus[ext]
	}
	return ""
}

var connMgrStatus = map[uint16]string{
	0x0100: "connection in use or duplicate forward open",
	0x0103: "transport class and trigger combination not supported",
	0x0106: "ownership conflict",
	0x0107: "target connection not found",
	0x0108: "invalid network connection parameter",
	0x0109: "invalid connection size",
	0x0110: "target for connection not configured",
	0x0111: "RPI not supported",
	0x0113: "out of connections",
	0x0114: "vendor ID or product code mismatch",
	0x0115: "device type mismatch",
	0x0116: "revision mismatch",
	0x0117: "invalid produced or consumed application path",
	0x0118: "invalid or inconsistent configuration application path",
	0x011A: "target object out of connections",
	0x0203: "connection timed out",
	0x0204: "unconnected request timed out",
	0x0205: "parameter error in unconnected request",
	0x0206: "message too large for unconnected send",
	0x0301: "no buffer memory available",
	0x0302: "network bandwidth not available",
	0x0311: "invalid port in path",
	0x0312: "invalid link address in path (no module in that slot?)",
	0x0315: "invalid segment in connection path",
	0x0316: "forward close path does not match the connection",
}

var logixStatus = map[uint16]string{
	0x2104: "offset beyond the end of the tag",
	0x2105: "access beyond the end of the tag",
	0x2107: "data type does not match the tag's type",
}

// ---- multiple service packet -------------------------------------------

// MultipleService packs requests into one Multiple Service Packet body.
func MultipleService(reqs [][]byte) []byte {
	n := len(reqs)
	b := binary.LittleEndian.AppendUint16(nil, uint16(n))
	off := 2 + 2*n
	for _, r := range reqs {
		b = binary.LittleEndian.AppendUint16(b, uint16(off))
		off += len(r)
	}
	for _, r := range reqs {
		b = append(b, r...)
	}
	return b
}

// SplitMultiple splits a Multiple Service Packet body (request or reply)
// into its embedded messages.
func SplitMultiple(b []byte) ([][]byte, error) {
	if len(b) < 2 {
		return nil, errors.New("multiple service packet: no count")
	}
	n := int(binary.LittleEndian.Uint16(b))
	if len(b) < 2+2*n {
		return nil, errors.New("multiple service packet: offsets truncated")
	}
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		start := int(binary.LittleEndian.Uint16(b[2+2*i:]))
		end := len(b)
		if i+1 < n {
			end = int(binary.LittleEndian.Uint16(b[4+2*i:]))
		}
		if start > end || end > len(b) || start < 2+2*n {
			return nil, fmt.Errorf("multiple service packet: bad offset for message %d", i+1)
		}
		out[i] = b[start:end]
	}
	return out, nil
}
