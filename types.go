package enip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

// Atomic data type codes (the Logix tag type word).
const (
	TypeBOOL   uint16 = 0xC1
	TypeSINT   uint16 = 0xC2
	TypeINT    uint16 = 0xC3
	TypeDINT   uint16 = 0xC4
	TypeLINT   uint16 = 0xC5
	TypeUSINT  uint16 = 0xC6
	TypeUINT   uint16 = 0xC7
	TypeUDINT  uint16 = 0xC8
	TypeULINT  uint16 = 0xC9
	TypeREAL   uint16 = 0xCA
	TypeLREAL  uint16 = 0xCB
	TypeBYTE   uint16 = 0xD1
	TypeWORD   uint16 = 0xD2
	TypeDWORD  uint16 = 0xD3
	TypeLWORD  uint16 = 0xD4
	TypeStruct uint16 = 0x02A0 // followed by a structure handle

	// HandleSTRING is the structure handle of the built-in Logix STRING
	// (LEN DINT + DATA SINT[82], 88 bytes with padding).
	HandleSTRING uint16 = 0x0FCE
	// StringSize is the Logix STRING's size in bytes and StringChars its
	// character capacity.
	StringSize  = 88
	StringChars = 82
)

// Type is a tag's data type: an atomic code, or TypeStruct and a handle.
type Type struct {
	Code   uint16
	Handle uint16
}

// IsStruct reports a structure type.
func (t Type) IsStruct() bool { return t.Code == TypeStruct }

// Marshal encodes the type as it leads read replies and write requests.
func (t Type) Marshal() []byte {
	b := binary.LittleEndian.AppendUint16(nil, t.Code)
	if t.IsStruct() {
		b = binary.LittleEndian.AppendUint16(b, t.Handle)
	}
	return b
}

// ParseType decodes the type at the start of b and returns the rest.
func ParseType(b []byte) (Type, []byte, error) {
	if len(b) < 2 {
		return Type{}, nil, fmt.Errorf("no data type in a %d-byte reply", len(b))
	}
	t := Type{Code: binary.LittleEndian.Uint16(b)}
	b = b[2:]
	if t.IsStruct() {
		if len(b) < 2 {
			return Type{}, nil, fmt.Errorf("structure reply without a handle")
		}
		t.Handle = binary.LittleEndian.Uint16(b)
		b = b[2:]
	}
	return t, b, nil
}

var typeNames = map[string]uint16{
	"BOOL": TypeBOOL, "SINT": TypeSINT, "INT": TypeINT, "DINT": TypeDINT, "LINT": TypeLINT,
	"USINT": TypeUSINT, "UINT": TypeUINT, "UDINT": TypeUDINT, "ULINT": TypeULINT,
	"REAL": TypeREAL, "LREAL": TypeLREAL, "BYTE": TypeBYTE, "WORD": TypeWORD, "DWORD": TypeDWORD, "LWORD": TypeLWORD,
}

var typeSizes = map[uint16]int{
	TypeBOOL: 1, TypeSINT: 1, TypeINT: 2, TypeDINT: 4, TypeLINT: 8, TypeUSINT: 1, TypeUINT: 2,
	TypeUDINT: 4, TypeULINT: 8, TypeREAL: 4, TypeLREAL: 8, TypeBYTE: 1, TypeWORD: 2, TypeDWORD: 4, TypeLWORD: 8,
}

// AtomicTypeCode returns the code of the atomic type with exactly this name
// (upper case: "DINT", "REAL" …); ok is false otherwise, including for STRING.
func AtomicTypeCode(name string) (code uint16, ok bool) {
	code, ok = typeNames[name]
	return code, ok
}

// ParseTypeName turns "DINT", "REAL", "STRING" … into a Type. ok is false
// for unknown names.
func ParseTypeName(s string) (Type, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "STRING" {
		return Type{Code: TypeStruct, Handle: HandleSTRING}, true
	}
	c, ok := typeNames[s]
	return Type{Code: c}, ok
}

// Name returns the type's name.
func (t Type) Name() string {
	if t.IsStruct() {
		if t.Handle == HandleSTRING {
			return "STRING"
		}
		return fmt.Sprintf("STRUCT(0x%04X)", t.Handle)
	}
	for n, c := range typeNames {
		if c == t.Code {
			return n
		}
	}
	return fmt.Sprintf("0x%04X", t.Code)
}

// Size is one element's size in bytes, 0 when unknown (user structures).
func (t Type) Size() int {
	if t.IsStruct() {
		if t.Handle == HandleSTRING {
			return StringSize
		}
		return 0
	}
	return typeSizes[t.Code]
}

// DecodeAtomic reads one atomic value; BOOL gives a bool, integers and
// reals a float64 (LINT/ULINT beyond 2^53 lose precision).
func DecodeAtomic(code uint16, b []byte) (any, error) {
	n := typeSizes[code]
	if n == 0 {
		return nil, fmt.Errorf("type 0x%04X is not atomic", code)
	}
	if len(b) < n {
		return nil, fmt.Errorf("%s needs %d bytes, got %d", Type{Code: code}.Name(), n, len(b))
	}
	le := binary.LittleEndian
	switch code {
	case TypeBOOL:
		return b[0] != 0, nil
	case TypeSINT:
		return float64(int8(b[0])), nil
	case TypeUSINT, TypeBYTE:
		return float64(b[0]), nil
	case TypeINT:
		return float64(int16(le.Uint16(b))), nil
	case TypeUINT, TypeWORD:
		return float64(le.Uint16(b)), nil
	case TypeDINT:
		return float64(int32(le.Uint32(b))), nil
	case TypeUDINT, TypeDWORD:
		return float64(le.Uint32(b)), nil
	case TypeLINT:
		return float64(int64(le.Uint64(b))), nil
	case TypeULINT, TypeLWORD:
		return float64(le.Uint64(b)), nil
	case TypeREAL:
		return float64(math.Float32frombits(le.Uint32(b))), nil
	case TypeLREAL:
		return math.Float64frombits(le.Uint64(b)), nil
	}
	return nil, fmt.Errorf("type 0x%04X is not atomic", code)
}

// EncodeAtomic writes one atomic value (bool or number), refusing values
// out of the type's range.
func EncodeAtomic(code uint16, v any) ([]byte, error) {
	var f float64
	switch x := v.(type) {
	case bool:
		if x {
			f = 1
		}
	case float64:
		f = x
	case int:
		f = float64(x)
	default:
		return nil, fmt.Errorf("%s takes a number or boolean, not %T", Type{Code: code}.Name(), v)
	}
	le := binary.LittleEndian
	name := Type{Code: code}.Name()
	in := func(lo, hi float64) error {
		if math.IsNaN(f) || f < lo || f > hi {
			return fmt.Errorf("%v does not fit in %s", f, name)
		}
		return nil
	}
	r := math.Round(f)
	switch code {
	case TypeBOOL:
		if f != 0 {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	case TypeSINT:
		if err := in(math.MinInt8, math.MaxInt8); err != nil {
			return nil, err
		}
		return []byte{byte(int8(r))}, nil
	case TypeUSINT, TypeBYTE:
		if err := in(0, math.MaxUint8); err != nil {
			return nil, err
		}
		return []byte{byte(r)}, nil
	case TypeINT:
		if err := in(math.MinInt16, math.MaxInt16); err != nil {
			return nil, err
		}
		return le.AppendUint16(nil, uint16(int16(r))), nil
	case TypeUINT, TypeWORD:
		if err := in(0, math.MaxUint16); err != nil {
			return nil, err
		}
		return le.AppendUint16(nil, uint16(r)), nil
	case TypeDINT:
		if err := in(math.MinInt32, math.MaxInt32); err != nil {
			return nil, err
		}
		return le.AppendUint32(nil, uint32(int32(r))), nil
	case TypeUDINT, TypeDWORD:
		if err := in(0, math.MaxUint32); err != nil {
			return nil, err
		}
		return le.AppendUint32(nil, uint32(r)), nil
	case TypeLINT:
		if err := in(math.MinInt64, math.MaxInt64); err != nil {
			return nil, err
		}
		return le.AppendUint64(nil, uint64(int64(r))), nil
	case TypeULINT, TypeLWORD:
		if err := in(0, math.MaxUint64); err != nil {
			return nil, err
		}
		return le.AppendUint64(nil, uint64(r)), nil
	case TypeREAL:
		if !math.IsInf(f, 0) && !math.IsNaN(f) && math.Abs(f) > math.MaxFloat32 {
			return nil, fmt.Errorf("%v does not fit in REAL", f)
		}
		return le.AppendUint32(nil, math.Float32bits(float32(f))), nil
	case TypeLREAL:
		return le.AppendUint64(nil, math.Float64bits(f)), nil
	}
	return nil, fmt.Errorf("type 0x%04X is not atomic", code)
}

// DecodeString reads a Logix STRING (LEN then characters).
func DecodeString(b []byte) (string, error) {
	if len(b) < 4 {
		return "", fmt.Errorf("STRING needs at least 4 bytes, got %d", len(b))
	}
	n := int(int32(binary.LittleEndian.Uint32(b)))
	if n < 0 || n > StringChars || 4+n > len(b) {
		return "", fmt.Errorf("STRING length %d is out of range", n)
	}
	return string(b[4 : 4+n]), nil
}

// EncodeString writes a Logix STRING of StringSize bytes.
func EncodeString(s string) ([]byte, error) {
	if len(s) > StringChars {
		return nil, fmt.Errorf("a STRING holds at most %d characters, got %d", StringChars, len(s))
	}
	b := make([]byte, StringSize)
	binary.LittleEndian.PutUint32(b, uint32(len(s)))
	copy(b[4:], s)
	return b, nil
}

// Member is a structure member the configuration names, for decoding a
// structure's bytes without the controller's template.
type Member struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Type   string `json:"type"`
	Bit    int    `json:"bit,omitempty"` // for BOOL members packed in a host word
}

// Decode turns a read reply's data into a JSON-able value: one element is
// a scalar, several an array. A structure without members is
// {"handle": "0x…", "hex": "…"}.
func Decode(t Type, data []byte, elements int, members []Member) (any, error) {
	if elements < 1 {
		elements = 1
	}
	size := t.Size()
	if size == 0 { // user structure: split evenly
		if len(data)%elements != 0 {
			return nil, fmt.Errorf("%d bytes do not split into %d elements", len(data), elements)
		}
		size = len(data) / elements
	}
	if len(data) < size*elements {
		return nil, fmt.Errorf("%s[%d] needs %d bytes, got %d", t.Name(), elements, size*elements, len(data))
	}
	one := func(b []byte) (any, error) {
		switch {
		case !t.IsStruct():
			return DecodeAtomic(t.Code, b)
		case t.Handle == HandleSTRING:
			return DecodeString(b)
		case len(members) > 0:
			return decodeMembers(b, members)
		}
		return map[string]any{"handle": fmt.Sprintf("0x%04X", t.Handle), "hex": hex.EncodeToString(b)}, nil
	}
	if elements == 1 {
		return one(data[:size])
	}
	out := make([]any, elements)
	for i := range out {
		v, err := one(data[i*size : (i+1)*size])
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

func decodeMembers(b []byte, members []Member) (map[string]any, error) {
	out := map[string]any{}
	for _, m := range members {
		t, ok := ParseTypeName(m.Type)
		if !ok {
			return nil, fmt.Errorf("member %s: unknown type %q", m.Name, m.Type)
		}
		sz := t.Size()
		if m.Offset < 0 || m.Offset+sz > len(b) {
			return nil, fmt.Errorf("member %s at offset %d is beyond the %d-byte structure", m.Name, m.Offset, len(b))
		}
		switch {
		case t.Code == TypeBOOL && m.Bit > 0:
			out[m.Name] = b[m.Offset+m.Bit/8]&(1<<(m.Bit%8)) != 0
		case t.IsStruct():
			s, err := DecodeString(b[m.Offset : m.Offset+sz])
			if err != nil {
				return nil, fmt.Errorf("member %s: %w", m.Name, err)
			}
			out[m.Name] = s
		default:
			v, err := DecodeAtomic(t.Code, b[m.Offset:])
			if err != nil {
				return nil, err
			}
			out[m.Name] = v
		}
	}
	return out, nil
}

// Encode turns a JSON value into tag data for elements elements of type t:
// numbers/booleans for atomics, text for STRING, arrays for several
// elements, {"hex": "…"} or a hex string for structures.
func Encode(t Type, v any, elements int) ([]byte, error) {
	if elements < 1 {
		elements = 1
	}
	if elements > 1 {
		list, ok := v.([]any)
		if !ok || len(list) != elements {
			return nil, fmt.Errorf("the tag has %d elements; send an array of %d values", elements, elements)
		}
		var out []byte
		for i, x := range list {
			b, err := Encode(t, x, 1)
			if err != nil {
				return nil, fmt.Errorf("element %d: %w", i, err)
			}
			out = append(out, b...)
		}
		return out, nil
	}
	if !t.IsStruct() {
		return EncodeAtomic(t.Code, v)
	}
	if t.Handle == HandleSTRING {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("a STRING tag takes text, not %T", v)
		}
		return EncodeString(s)
	}
	var h string
	switch x := v.(type) {
	case string:
		h = x
	case map[string]any:
		h, _ = x["hex"].(string)
	}
	b, err := hex.DecodeString(h)
	if err != nil || h == "" {
		return nil, fmt.Errorf("a structure tag takes its raw bytes as hex text or {\"hex\": …}")
	}
	return b, nil
}
