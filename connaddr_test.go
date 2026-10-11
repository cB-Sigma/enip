// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package enip_test

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/enip"
)

// echoTarget is a minimal target: it registers a session, accepts a
// Forward Open with O→T ID 0x11223344 and answers every SendUnitData
// with unit, the reply cpppo's server sends (its connected address item
// echoes the O→T ID of the request rather than carrying the T→O ID).
func echoTarget(t *testing.T, unit []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		for {
			h, data, err := enip.ReadPacket(c)
			if err != nil {
				return
			}
			var reply []byte
			switch h.Command {
			case enip.CmdRegisterSession:
				h.Session = 1
				reply = data
			case enip.CmdListIdentity:
				reply = []byte{0, 0}
			case enip.CmdSendRRData:
				items, _ := enip.ParseRRData(data)
				svc, _, fo, _ := enip.ParseRequest(items[1].Data)
				if svc != enip.SvcForwardOpen {
					// Forward Close on the way out
					reply = enip.RRData(0, enip.Item{Type: enip.ItemNullAddress},
						enip.Item{Type: enip.ItemUnconnectedData, Data: enip.MarshalResponse(svc, 0, nil, nil)})
					break
				}
				out := binary.LittleEndian.AppendUint32(nil, 0x11223344)
				out = append(out, fo[6:10]...)  // T→O ID as the originator chose it
				out = append(out, fo[10:18]...) // serial, vendor, originator serial
				out = append(out, fo[22:26]...) // O→T RPI
				out = append(out, fo[28:32]...) // T→O RPI
				out = append(out, 0, 0)
				reply = enip.RRData(0, enip.Item{Type: enip.ItemNullAddress},
					enip.Item{Type: enip.ItemUnconnectedData, Data: enip.MarshalResponse(enip.SvcForwardOpen, 0, nil, out)})
			case enip.CmdSendUnitData:
				reply = unit
			default:
				return
			}
			if _, err := c.Write(h.Marshal(reply)); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String()
}

// A connected reply whose address item carries our own O→T ID (as
// cpppo 5.2.5 sends it) is accepted; one naming another connection is not.
// Covers: SIG-IPE-330
func TestConnectedReplyWithEchoedOTID(t *testing.T) {
	// interface handle, timeout, 2 items: connected address 0x11223344,
	// connected data: sequence 1, Read Tag reply DINT 42.
	echoed := unhex(t, "00000000 0000 0200 a100 0400 44332211 b100 0c00 0100 cc000000 c400 2a000000")
	addr := echoTarget(t, echoed)
	c := &enip.Client{Addr: addr, Timeout: 2 * time.Second, Connected: true}
	defer c.Close()
	typ, data, err := c.ReadTag(context.Background(), "Count", 1)
	if err != nil {
		t.Fatalf("read over a connection whose replies echo the O→T ID: %v", err)
	}
	if m, _ := c.Mode(); m != "connected" {
		t.Fatalf("mode %q, want connected", m)
	}
	if typ.Code != enip.TypeDINT || binary.LittleEndian.Uint32(data) != 42 {
		t.Errorf("read %s %x", typ.Name(), data)
	}

	other := unhex(t, "00000000 0000 0200 a100 0400 88776655 b100 0c00 0100 cc000000 c400 2a000000")
	addr = echoTarget(t, other)
	c2 := &enip.Client{Addr: addr, Timeout: 2 * time.Second, Connected: true}
	defer c2.Close()
	if _, _, err := c2.ReadTag(context.Background(), "Count", 1); err == nil || !strings.Contains(err.Error(), "another connection") {
		t.Errorf("a reply for another connection gave %v", err)
	}
}
