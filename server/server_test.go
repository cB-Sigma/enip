// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"encoding/binary"
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
	fc := []byte{0x0A, 0x05}
	fc = le.AppendUint16(fc, 0x4242)
	fc = le.AppendUint16(fc, 0xF00D)
	fc = le.AppendUint32(fc, 0x99)
	fc = append(fc, byte(len(mr16)/2), 0)
	fc = append(fc, mr16...)
	r, err = c.Do(ctx(t), enip.SvcForwardClose, cm16, fc)
	if err != nil || r.Status != 0 {
		t.Fatalf("Forward Close on 21 00 06 00 25 00 01 00: %+v, %v", r, err)
	}

	// A class 1 Forward Open addressed with 16-bit segments opens an I/O
	// connection.
	io := []byte{0x0A, 0x05}
	io = le.AppendUint32(io, 0)
	io = le.AppendUint32(io, 0x55667788)
	io = le.AppendUint16(io, 0x4343)
	io = le.AppendUint16(io, 0xF00D)
	io = le.AppendUint32(io, 0x99)
	io = append(io, 2, 0, 0, 0)
	io = le.AppendUint32(io, 100000)
	io = le.AppendUint16(io, 0x4800|(4+6))
	io = le.AppendUint32(io, 100000)
	io = le.AppendUint16(io, 0x4800|(8+2))
	io = append(io, 0x01, 4, 0x20, 0x04, 0x24, 0x01, 0x2C, 0x96, 0x2C, 0x64)
	r, err = c.Do(ctx(t), enip.SvcForwardOpen, cm16, io)
	if err != nil || r.Status != 0 || s.IOConnections() != 1 {
		t.Fatalf("class 1 Forward Open on 21 00 06 00 25 00 01 00: %+v, %v, %d I/O connections", r, err, s.IOConnections())
	}
}
