package enip_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/cB-Sigma/enip"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Covers: SIG-IPE-330
func TestENIPEncapsulation(t *testing.T) {
	// RegisterSession request, hand-assembled: command 0x0065, length 4,
	// session 0, status 0, context 0, options 0, then version 1 and flags 0.
	got := enip.Header{Command: enip.CmdRegisterSession}.Marshal(enip.RegisterSessionData())
	want := unhex(t, "6500 0400 00000000 00000000 0000000000000000 00000000 0100 0000")
	if !bytes.Equal(got, want) {
		t.Errorf("RegisterSession = % x\nwant             % x", got, want)
	}
	h := enip.Header{Command: enip.CmdSendRRData, Session: 0x11223344, Status: 0x64, Context: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, Options: 0}
	b := h.Marshal([]byte{9, 9, 9})
	if !bytes.Equal(b[:8], unhex(t, "6f00 0300 44332211")) {
		t.Errorf("header prefix = % x", b[:8])
	}
	back, err := enip.ParseHeader(b)
	h.Length = 3
	if err != nil || back != h {
		t.Errorf("header round trip = %+v, %v; want %+v", back, err, h)
	}
	if _, err := enip.ParseHeader(b[:10]); err == nil {
		t.Error("a 10-byte header was accepted")
	}
	if s := enip.EncapStatusText(0x64); s != "invalid session handle" {
		t.Errorf("status 0x64 = %q", s)
	}

	// SendRRData body: interface handle 0, timeout 5, two items.
	rr := enip.RRData(5, enip.Item{Type: enip.ItemNullAddress}, enip.Item{Type: enip.ItemUnconnectedData, Data: []byte{0x0E, 0x00}})
	if want := unhex(t, "00000000 0500 0200 0000 0000 b200 0200 0e00"); !bytes.Equal(rr, want) {
		t.Errorf("SendRRData body = % x, want % x", rr, want)
	}
	items, err := enip.ParseRRData(rr)
	if err != nil || len(items) != 2 || items[1].Type != enip.ItemUnconnectedData || !bytes.Equal(items[1].Data, []byte{0x0E, 0}) {
		t.Errorf("items = %+v, %v", items, err)
	}
	if _, err := enip.ParseCPF(unhex(t, "0100 b100 0900 0102")); err == nil {
		t.Error("a truncated item was accepted")
	}

	// Identity item round trip; socket address fields are big-endian.
	id := enip.Identity{Protocol: 1, IP: "192.168.1.10", Port: 44818, Vendor: 1, DeviceType: 14, ProductCode: 166, Status: 0x3060, ProductName: "1756-L83E/B"}
	item := enip.IdentityItem(id, 33, 11, 0x00C0FFEE)
	if !bytes.Equal(item[:10], unhex(t, "0100 0002 af12 c0a8010a")) {
		t.Errorf("identity socket address = % x", item[:10])
	}
	ids, err := enip.ParseListIdentity(enip.MarshalCPF(enip.Item{Type: enip.ItemIdentity, Data: item}))
	if err != nil || len(ids) != 1 {
		t.Fatalf("list identity = %v, %v", ids, err)
	}
	want2 := id
	want2.Revision, want2.Serial = "33.011", "00C0FFEE"
	if ids[0] != want2 {
		t.Errorf("identity = %+v\nwant %+v", ids[0], want2)
	}
}

// Covers: SIG-IPE-331
func TestENIPPathsAndMessages(t *testing.T) {
	p, err := enip.TagPath("Program:Main.Tag[3]")
	if err != nil {
		t.Fatal(err)
	}
	// 0x91 len "Program:Main" (12, even) | 0x91 3 "Tag" pad | member 0x28 3.
	wantPath := unhex(t, "910c 50726f6772616d3a4d61696e 9103 546167 00 2803")
	if !bytes.Equal(p, wantPath) {
		t.Errorf("path = % x\nwant   % x", p, wantPath)
	}
	// Read Tag, 1 element: service 0x4C, 11 words of path, element count 1.
	req := enip.Request(enip.SvcReadTag, p, []byte{1, 0})
	if want := append(append([]byte{0x4C, 0x0B}, wantPath...), 1, 0); !bytes.Equal(req, want) {
		t.Errorf("Read Tag = % x, want % x", req, want)
	}
	for tag, want := range map[string]string{
		"Motor[2].Speed": "9105 4d6f746f72 00 2802 9105 5370656564 00",
		"Grid[1,300]":    "9104 47726964 2801 2900 2c01",
		"A[70000]":       "9101 41 00 2a00 70110100",
		"Flow":           "9104 466c6f77",
	} {
		got, err := enip.TagPath(tag)
		if err != nil || !bytes.Equal(got, unhex(t, want)) {
			t.Errorf("%s = % x, %v; want %s", tag, got, err, want)
		}
	}
	for _, bad := range []string{"", "A.", "A[x]", "A[1", "A..B", "A B", "A[1]B"} {
		if _, err := enip.TagPath(bad); err == nil {
			t.Errorf("tag %q was accepted", bad)
		}
	}
	if got := enip.Logical(0x6B, 0x1234, -1); !bytes.Equal(got, unhex(t, "206b 2500 3412")) {
		t.Errorf("logical 16-bit instance = % x", got)
	}
	if got := enip.Logical(1, 1, 7); !bytes.Equal(got, unhex(t, "2001 2401 3007")) {
		t.Errorf("identity attribute 7 path = % x", got)
	}
	for route, want := range map[string]string{
		"1,0":             "0100",
		"1,3":             "0103",
		"":                "",
		"1,0,2,10.0.0.9":  "0100 1208 31302e302e302e39",
		"1,1,2,10.0.0.19": "0101 1209 31302e302e302e3139 00",
	} {
		got, err := enip.Route(route)
		if err != nil || !bytes.Equal(got, unhex(t, want)) {
			t.Errorf("route %q = % x, %v; want %s", route, got, err, want)
		}
	}
	for _, bad := range []string{"1", "0,0", "1,x", "1,300"} {
		if _, err := enip.Route(bad); err == nil {
			t.Errorf("route %q was accepted", bad)
		}
	}
	// Unconnected Send pads an odd embedded message and carries the route.
	msg, route, err := enip.ParseUnconnectedSend(unhex(t, "0a0e 0300 0e0102 00 01 00 0100"))
	if err != nil || !bytes.Equal(msg, []byte{0x0E, 1, 2}) || !bytes.Equal(route, []byte{1, 0}) {
		t.Errorf("unconnected send = % x % x %v", msg, route, err)
	}
	// Replies: general status and extended status become readable errors.
	r, err := enip.ParseResponse(unhex(t, "cd00 ff01 0721"))
	if err != nil || r.Status != 0xFF || len(r.Ext) != 1 || r.Ext[0] != 0x2107 {
		t.Fatalf("reply = %+v, %v", r, err)
	}
	if e := r.Err(); e == nil || !strings.Contains(e.Error(), "data type does not match") {
		t.Errorf("type mismatch error = %v", e)
	}
	var ce *enip.Error
	if !errors.As(r.Err(), &ce) || ce.Service != 0x4D {
		t.Errorf("error service = %+v", ce)
	}
	for status, text := range map[byte]string{0x04: "path segment error", 0x05: "path destination unknown", 0x13: "not enough data",
		0x15: "too much data", 0x0F: "privilege violation", 0x16: "object does not exist", 0x0E: "attribute not settable"} {
		if got := enip.StatusText(status); got != text {
			t.Errorf("status 0x%02X = %q, want %q", status, got, text)
		}
	}
	if s := (&enip.Error{Status: 1, Ext: []uint16{0x0113}}).Error(); !strings.Contains(s, "out of connections") {
		t.Errorf("forward open refusal = %q", s)
	}
	if (&enip.Response{Status: enip.StatusPartial}).Err() != nil {
		t.Error("partial transfer was reported as an error")
	}
	// Multiple Service Packet: count, offsets from the count, messages.
	msp := enip.MultipleService([][]byte{{0x4C, 0x00}, {0x0E, 0x00, 0xAA}})
	if want := unhex(t, "0200 0600 0800 4c00 0e00aa"); !bytes.Equal(msp, want) {
		t.Errorf("multiple service = % x, want % x", msp, want)
	}
	parts, err := enip.SplitMultiple(msp)
	if err != nil || len(parts) != 2 || !bytes.Equal(parts[1], []byte{0x0E, 0, 0xAA}) {
		t.Errorf("split = % x, %v", parts, err)
	}
}

// Covers: SIG-IPE-332
func TestENIPDataTypes(t *testing.T) {
	for _, tc := range []struct {
		typ string
		v   any
		raw string
	}{
		{"BOOL", true, "01"}, {"SINT", -2.0, "fe"}, {"INT", -300.0, "d4fe"}, {"DINT", 305419896.0, "78563412"},
		{"LINT", -1.0, "ffffffffffffffff"}, {"USINT", 200.0, "c8"}, {"UINT", 65535.0, "ffff"},
		{"UDINT", 4000000000.0, "00286bee"}, {"ULINT", 1.0, "0100000000000000"}, {"REAL", 12.5, "00004841"},
		{"LREAL", math.Pi, "182d4454fb210940"}, {"BYTE", 7.0, "07"}, {"WORD", 258.0, "0201"}, {"DWORD", 1.0, "01000000"},
	} {
		ty, ok := enip.ParseTypeName(tc.typ)
		if !ok {
			t.Fatalf("type %s unknown", tc.typ)
		}
		b, err := enip.Encode(ty, tc.v, 1)
		if err != nil || hex.EncodeToString(b) != tc.raw {
			t.Errorf("%s %v = %x, %v; want %s", tc.typ, tc.v, b, err, tc.raw)
		}
		back, err := enip.Decode(ty, b, 1, nil)
		if err != nil || back != tc.v {
			t.Errorf("%s decode = %v, %v", tc.typ, back, err)
		}
	}
	for _, tc := range []struct {
		typ string
		v   float64
	}{{"SINT", 128}, {"INT", -40000}, {"USINT", -1}, {"UDINT", 5e9}, {"REAL", 1e39}} {
		ty, _ := enip.ParseTypeName(tc.typ)
		if _, err := enip.Encode(ty, tc.v, 1); err == nil {
			t.Errorf("%v was accepted as %s", tc.v, tc.typ)
		}
	}
	// Arrays.
	dint, _ := enip.ParseTypeName("DINT")
	arr, err := enip.Encode(dint, []any{1.0, -1.0, 3.0}, 3)
	if err != nil || hex.EncodeToString(arr) != "01000000ffffffff03000000" {
		t.Errorf("DINT[3] = %x, %v", arr, err)
	}
	v, _ := enip.Decode(dint, arr, 3, nil)
	if !reflect.DeepEqual(v, []any{1.0, -1.0, 3.0}) {
		t.Errorf("DINT[3] decode = %v", v)
	}
	if _, err := enip.Encode(dint, []any{1.0}, 3); err == nil {
		t.Error("a short array was accepted")
	}
	// STRING: LEN DINT then 82 characters, 88 bytes.
	st, _ := enip.ParseTypeName("string")
	if st.Code != 0x02A0 || st.Handle != 0x0FCE || !bytes.Equal(st.Marshal(), unhex(t, "a002 ce0f")) {
		t.Errorf("STRING type = %+v % x", st, st.Marshal())
	}
	sb, err := enip.Encode(st, "Pump 7", 1)
	if err != nil || len(sb) != 88 || !bytes.Equal(sb[:10], unhex(t, "06000000 50756d702037")) {
		t.Errorf("STRING = % x, %v", sb, err)
	}
	if s, _ := enip.Decode(st, sb, 1, nil); s != "Pump 7" {
		t.Errorf("STRING decode = %v", s)
	}
	if _, err := enip.Encode(st, strings.Repeat("x", 83), 1); err == nil {
		t.Error("an 83-character STRING was accepted")
	}
	// A structure: raw bytes, or members at offsets.
	udt := enip.Type{Code: enip.TypeStruct, Handle: 0x1234}
	raw := unhex(t, "07000000 0000c03f 1400 0000 00")
	raw = raw[:12]
	v, _ = enip.Decode(udt, raw, 1, nil)
	if !reflect.DeepEqual(v, map[string]any{"handle": "0x1234", "hex": "070000000000c03f14000000"}) {
		t.Errorf("raw structure = %v", v)
	}
	v, err = enip.Decode(udt, raw, 1, []enip.Member{{Name: "id", Offset: 0, Type: "DINT"}, {Name: "speed", Offset: 4, Type: "REAL"},
		{Name: "temp", Offset: 8, Type: "INT"}, {Name: "flag", Offset: 0, Type: "BOOL", Bit: 2}})
	if err != nil || !reflect.DeepEqual(v, map[string]any{"id": 7.0, "speed": 1.5, "temp": 20.0, "flag": true}) {
		t.Errorf("structure members = %v, %v", v, err)
	}
	if _, err := enip.Decode(udt, raw, 1, []enip.Member{{Name: "x", Offset: 10, Type: "DINT"}}); err == nil {
		t.Error("a member beyond the structure was accepted")
	}
	back, err := enip.Encode(udt, map[string]any{"hex": "070000000000c03f14000000"}, 1)
	if err != nil || !bytes.Equal(back, raw) {
		t.Errorf("structure encode = %x, %v", back, err)
	}
	pt, rest, err := enip.ParseType(unhex(t, "a002 3412 ff"))
	if err != nil || pt != udt || !bytes.Equal(rest, []byte{0xFF}) {
		t.Errorf("parse type = %+v % x %v", pt, rest, err)
	}
}
