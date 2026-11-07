// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/enip"
	"github.com/cB-Sigma/enip/server"
)

// startServer starts s on a free loopback port and returns a client for
// it.
func startServer(t *testing.T, s *server.Server) *enip.Client {
	t.Helper()
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	c := &enip.Client{Addr: s.Addr(), Timeout: 2 * time.Second}
	t.Cleanup(c.Close)
	return c
}

// The identity's revision follows SetIdentity (Major and Minor, or the
// Revision text), in attribute 4 and in the ListIdentity item; without
// one it stays 33.11 (issue #1).
func TestIdentityRevision(t *testing.T) {
	for _, tc := range []struct {
		id         enip.Identity
		major, min byte
		text       string
	}{
		{enip.Identity{Protocol: 1, Vendor: 1, DeviceType: 14, ProductCode: 54, ProductName: "repro"}, 33, 11, "33.011"},
		{enip.Identity{Protocol: 1, Vendor: 1, DeviceType: 14, ProductCode: 54, ProductName: "repro", Major: 20, Minor: 11}, 20, 11, "20.011"},
		{enip.Identity{Protocol: 1, Vendor: 1, DeviceType: 14, ProductCode: 54, ProductName: "repro", Revision: "2.007"}, 2, 7, "2.007"},
	} {
		s := server.New()
		s.SetIdentity(tc.id, 1)
		c := startServer(t, s)
		r, err := c.Do(ctx(t), enip.SvcGetAttributeSingle, enip.Logical(1, 1, 4), nil)
		if err != nil || r.Status != 0 || !bytes.Equal(r.Data, []byte{tc.major, tc.min}) {
			t.Errorf("%+v: attribute 4 = %+v, %v", tc.id, r, err)
		}
		r, err = c.Do(ctx(t), enip.SvcGetAttributesAll, enip.Logical(1, 1, -1), nil)
		if err != nil || r.Status != 0 || len(r.Data) < 8 || !bytes.Equal(r.Data[6:8], []byte{tc.major, tc.min}) {
			t.Errorf("%+v: Get_Attributes_All = %+v, %v", tc.id, r, err)
		}
		id, err := c.ListIdentity(ctx(t))
		if err != nil || id.Revision != tc.text || id.Major != tc.major || id.Minor != tc.min {
			t.Errorf("%+v: ListIdentity = %+v, %v", tc.id, id, err)
		}
		s.Stop()
	}
}

// class1Open is the body of a class 1 Forward Open of assemblies 1 (configuration),
// 150 (O→T, 4 bytes) and 100 (T→O, 8 bytes) at the RPI, with connection
// serial serial, vendor 0xF00D and originator serial 0x99.
func class1Open(serial uint16, rpi time.Duration) []byte {
	le := binary.LittleEndian
	b := []byte{0x0A, 0x05}
	b = le.AppendUint32(b, 0)
	b = le.AppendUint32(b, 0x55667788)
	b = le.AppendUint16(b, serial)
	b = le.AppendUint16(b, 0xF00D)
	b = le.AppendUint32(b, 0x99)
	b = append(b, 2, 0, 0, 0)
	b = le.AppendUint32(b, uint32(rpi/time.Microsecond))
	b = le.AppendUint16(b, 0x4800|(4+6))
	b = le.AppendUint32(b, uint32(rpi/time.Microsecond))
	b = le.AppendUint16(b, 0x4800|(8+2))
	return append(b, 0x01, 4, 0x20, 0x04, 0x24, 0x01, 0x2C, 0x96, 0x2C, 0x64)
}

// forwardClose is the body of a Forward Close of connection serial serial
// (vendor 0xF00D, originator serial 0x99) with the given connection path.
func forwardClose(serial uint16, path []byte) []byte {
	le := binary.LittleEndian
	b := []byte{0x0A, 0x05}
	b = le.AppendUint16(b, serial)
	b = le.AppendUint16(b, 0xF00D)
	b = le.AppendUint32(b, 0x99)
	b = append(b, byte(len(path)/2), 0)
	return append(b, path...)
}

// The Message Router and Connection Manager are recognised by their
// decoded path, so the 16-bit logical segment form works like the 8-bit
// one (issue #2).
func TestWidePathsToRouterAndConnectionManager(t *testing.T) {
	s := server.New()
	s.AddAssembly(100, 8)
	s.AddAssembly(150, 4)
	s.AddAssembly(1, 0)
	s.IOAddr = "127.0.0.1:0"
	c := startServer(t, s)
	mr16 := []byte{0x21, 0x00, 0x02, 0x00, 0x25, 0x00, 0x01, 0x00}
	cm16 := []byte{0x21, 0x00, 0x06, 0x00, 0x25, 0x00, 0x01, 0x00}
	req := enip.Request(enip.SvcGetAttributeSingle, enip.Logical(1, 1, 7), nil)
	r, err := c.Do(ctx(t), enip.SvcMultipleService, mr16, enip.MultipleService([][]byte{req}))
	if err != nil || r.Status != 0 {
		t.Fatalf("Multiple Service Packet on 21 00 02 00 25 00 01 00: %+v, %v", r, err)
	}
	if resps, err := enip.SplitMultiple(r.Data); err != nil || len(resps) != 1 || resps[0][2] != 0 {
		t.Errorf("embedded replies %x, %v", resps, err)
	}

	// A class 3 Forward Open addressed with 16-bit segments, its
	// connection path in 16-bit segments too, then a Forward Close.
	le := binary.LittleEndian
	fo := []byte{0x0A, 0x05}
	fo = le.AppendUint32(fo, 0)
	fo = le.AppendUint32(fo, 0x11223344)
	fo = le.AppendUint16(fo, 0x4242)
	fo = le.AppendUint16(fo, 0xF00D)
	fo = le.AppendUint32(fo, 0x99)
	fo = append(fo, 2, 0, 0, 0)
	fo = le.AppendUint32(fo, 1000000)
	fo = le.AppendUint16(fo, 0x43F8)
	fo = le.AppendUint32(fo, 1000000)
	fo = le.AppendUint16(fo, 0x43F8)
	fo = append(fo, 0xA3, byte(len(mr16)/2))
	fo = append(fo, mr16...)
	r, err = c.Do(ctx(t), enip.SvcForwardOpen, cm16, fo)
	if err != nil || r.Status != 0 {
		t.Fatalf("Forward Open on 21 00 06 00 25 00 01 00: %+v, %v", r, err)
	}
	r, err = c.Do(ctx(t), enip.SvcForwardClose, cm16, forwardClose(0x4242, mr16))
	if err != nil || r.Status != 0 {
		t.Fatalf("Forward Close on 21 00 06 00 25 00 01 00: %+v, %v", r, err)
	}

	// A class 1 Forward Open addressed with 16-bit segments opens an I/O
	// connection.
	r, err = c.Do(ctx(t), enip.SvcForwardOpen, cm16, class1Open(0x4343, 100*time.Millisecond))
	if err != nil || r.Status != 0 || s.IOConnections() != 1 {
		t.Fatalf("class 1 Forward Open on 21 00 06 00 25 00 01 00: %+v, %v, %d I/O connections", r, err, s.IOConnections())
	}
}

// A Forward Close of a class 1 connection closes it (its producer stops)
// and is answered with success (issue #3).
func TestForwardCloseIO(t *testing.T) {
	s := server.New()
	s.AddAssembly(100, 8)
	s.AddAssembly(150, 4)
	s.AddAssembly(1, 0)
	s.IOAddr = "127.0.0.1:0"
	c := startServer(t, s)
	cm := enip.Logical(enip.ClassConnectionManager, 1, -1)
	r, err := c.Do(ctx(t), enip.SvcForwardOpen, cm, class1Open(0x4242, 10*time.Millisecond))
	if err != nil || r.Status != 0 || s.IOConnections() != 1 {
		t.Fatalf("class 1 Forward Open: %+v, %v, %d I/O connections", r, err, s.IOConnections())
	}
	path := []byte{0x20, 0x04, 0x24, 0x00, 0x2C, 0x96, 0x2C, 0x64}
	r, err = c.Do(ctx(t), enip.SvcForwardClose, cm, forwardClose(0x4242, path))
	if err != nil || r.Status != 0 || len(r.Data) < 10 || binary.LittleEndian.Uint16(r.Data) != 0x4242 {
		t.Fatalf("Forward Close of the class 1 connection: %+v, %v", r, err)
	}
	if n := s.IOConnections(); n != 0 {
		t.Errorf("%d I/O connections after the Forward Close", n)
	}
	// Closing it again: there is no such connection any more.
	r, err = c.Do(ctx(t), enip.SvcForwardClose, cm, forwardClose(0x4242, path))
	if err != nil || r.Status != enip.StatusConnFailure || len(r.Ext) != 1 || r.Ext[0] != 0x0107 {
		t.Errorf("second Forward Close: %+v, %v", r, err)
	}
}

// Tag names are not case-sensitive, as in Logix: a tag created as
// "Counter" is read and written as "counter", also in a program scope
// and through members, while the tag list keeps its spelling (issue #4).
func TestTagNamesIgnoreCase(t *testing.T) {
	s := newController(t)
	le := binary.LittleEndian
	s.SetTag("Counter", enip.Type{Code: enip.TypeDINT}, 1, le.AppendUint32(nil, 42))
	c := &enip.Client{Addr: s.Addr(), Timeout: 2 * time.Second}
	defer c.Close()
	for _, name := range []string{"Counter", "counter", "COUNTER", "program:main.count"} {
		if ty, data, err := c.ReadTag(ctx(t), name, 1); err != nil || ty.Code != enip.TypeDINT || le.Uint32(data) != 42 {
			t.Errorf("read %q: %v %x %v", name, ty, data, err)
		}
	}
	if ty, data, err := c.ReadTag(ctx(t), "PUMP.speed", 1); err != nil || ty.Code != enip.TypeREAL || len(data) != 4 {
		t.Errorf("read a member by another case: %v %x %v", ty, data, err)
	}
	if err := c.WriteTag(ctx(t), "cOUNTER", enip.Type{Code: enip.TypeDINT}, 1, le.AppendUint32(nil, 7)); err != nil {
		t.Errorf("write: %v", err)
	}
	if d := s.TagData("COUNTER"); len(d) != 4 || le.Uint32(d) != 7 {
		t.Errorf("TagData by another case: %x", d)
	}
	s.SetReadOnly("counter", true)
	if err := c.WriteTag(ctx(t), "Counter", enip.Type{Code: enip.TypeDINT}, 1, le.AppendUint32(nil, 8)); err == nil {
		t.Error("SetReadOnly by another case had no effect")
	}
	s.SetTag("COUNTER", enip.Type{Code: enip.TypeDINT}, 1, le.AppendUint32(nil, 9))
	tags, err := c.ListTags(ctx(t), "")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, ti := range tags {
		if strings.EqualFold(ti.Name, "Counter") {
			n++
			if ti.Name != "Counter" {
				t.Errorf("listed as %q", ti.Name)
			}
		}
	}
	if n != 1 {
		t.Errorf("Counter listed %d times", n)
	}
}
