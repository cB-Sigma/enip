// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop runs this module's client against cpppo's EtherNet/IP
// server (a simulated Logix controller, in a container): identity,
// attribute services, Read/Write Tag with fragmentation, Multiple Service
// Packets, class 3 connections (Forward Open and Large Forward Open) and
// routing to a CPU slot. The tests need Docker and are skipped unless
// SIGMA_ENIP_INTEROP=1.
package interop

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cB-Sigma/enip"
)

// tags is the tag table cpppo serves (every value starts at zero).
var tags = []string{"Flow=REAL", "Count=DINT", "Total=LREAL", "Small=SINT", "Levels=INT[10]", "Big=DINT[300]", "Label=SSTRING", "Text=STRING"}

// startCpppo runs cpppo's server with extra arguments and returns its
// host:port once it answers ListIdentity.
func startCpppo(t *testing.T, extra ...string) (*peer, string) {
	t.Helper()
	port := freePort(t)
	args := []string{"-p", fmt.Sprintf("127.0.0.1:%d:44818", port), "-p", fmt.Sprintf("127.0.0.1:%d:44818/udp", port),
		image, "python", "-u", "-m", "cpppo.server.enip", "-v", "-a", "0.0.0.0:44818"}
	args = append(args, extra...)
	args = append(args, tags...)
	p := startPeer(t, args...)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(60 * time.Second)
	for {
		c := &enip.Client{Addr: addr, Timeout: time.Second}
		_, err := c.ListIdentity(context.Background())
		c.Close()
		if err == nil {
			return p, addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("cpppo did not answer ListIdentity within 60s: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func le32(vs ...uint32) []byte {
	var b []byte
	for _, v := range vs {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}

// direct reports a client that sends unconnected requests straight to
// the target (no class 3 connection, no Unconnected Send route).
func direct(c *enip.Client) bool { return !c.Connected && c.Route == nil }

// exercise runs every tag and attribute check over one client.
func exercise(t *testing.T, c *enip.Client) {
	ctx := context.Background()
	le := binary.LittleEndian

	t.Run("ListIdentityTCP", func(t *testing.T) {
		id, err := c.ListIdentity(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if id.ProductName == "" || id.Vendor == 0 {
			t.Errorf("identity %+v", id)
		}
		t.Logf("cpppo identity: %+v", *id)
	})

	t.Run("GetAttributeSingleIdentity", func(t *testing.T) {
		v, err := c.GetAttribute(ctx, enip.ClassIdentity, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(v) != 2 {
			t.Fatalf("vendor attribute %x", v)
		}
		name, err := c.GetAttribute(ctx, enip.ClassIdentity, 1, 7)
		if err != nil {
			t.Fatal(err)
		}
		if len(name) < 1 || int(name[0]) != len(name)-1 {
			t.Fatalf("product name attribute %x", name)
		}
		id := c.Identity()
		if id != nil && string(name[1:]) != id.ProductName {
			t.Errorf("product name %q by attribute, %q by ListIdentity", name[1:], id.ProductName)
		}
	})

	t.Run("GetAttributesAllIdentity", func(t *testing.T) {
		v, err := c.GetAttribute(ctx, enip.ClassIdentity, 1, -1)
		if err != nil {
			t.Fatal(err)
		}
		if len(v) < 15 {
			t.Fatalf("identity attributes %x", v)
		}
	})

	t.Run("AtomicWriteRead", func(t *testing.T) {
		cases := []struct {
			tag  string
			code uint16
			data []byte
		}{
			{"Flow", enip.TypeREAL, le.AppendUint32(nil, math.Float32bits(12.5))},
			{"Count", enip.TypeDINT, le.AppendUint32(nil, uint32(0xFFFFFFFF-41))}, // -42
			{"Total", enip.TypeLREAL, le.AppendUint64(nil, math.Float64bits(1e10))},
			{"Small", enip.TypeSINT, []byte{0x85}},
		}
		for _, k := range cases {
			if err := c.WriteTag(ctx, k.tag, enip.Type{Code: k.code}, 1, k.data); err != nil {
				t.Fatalf("write %s: %v", k.tag, err)
			}
			typ, got, err := c.ReadTag(ctx, k.tag, 1)
			if err != nil {
				t.Fatalf("read %s: %v", k.tag, err)
			}
			if typ.Code != k.code || !bytes.Equal(got, k.data) {
				t.Errorf("%s read back as %s %x, wrote %x", k.tag, typ.Name(), got, k.data)
			}
		}
	})

	t.Run("ArrayWriteRead", func(t *testing.T) {
		var lv []byte
		for i := range 10 {
			lv = le.AppendUint16(lv, uint16(i*10+1))
		}
		if err := c.WriteTag(ctx, "Levels", enip.Type{Code: enip.TypeINT}, 10, lv); err != nil {
			t.Fatal(err)
		}
		typ, got, err := c.ReadTag(ctx, "Levels", 10)
		if err != nil {
			t.Fatal(err)
		}
		if typ.Code != enip.TypeINT || !bytes.Equal(got, lv) {
			t.Errorf("Levels read back as %s %x", typ.Name(), got)
		}
		// one element by index
		_, got, err = c.ReadTag(ctx, "Levels[3]", 1)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, lv[6:8]) {
			t.Errorf("Levels[3] = %x", got)
		}
	})

	t.Run("FragmentedWriteRead", func(t *testing.T) {
		var big []byte
		for i := range 300 {
			big = le.AppendUint32(big, uint32(i*3+1))
		}
		if err := c.WriteTag(ctx, "Big", enip.Type{Code: enip.TypeDINT}, 300, big); err != nil {
			t.Fatal(err)
		}
		// The written value, in reads that each fit one reply.
		for _, start := range []int{0, 100, 200} {
			_, got, err := c.ReadTag(ctx, fmt.Sprintf("Big[%d]", start), 100)
			if err != nil {
				t.Fatalf("Big[%d] x100: %v", start, err)
			}
			if !bytes.Equal(got, big[start*4:start*4+400]) {
				t.Errorf("Big[%d] x100 after the fragmented write: %x…", start, got[:min(16, len(got))])
			}
		}
		if direct(c) {
			// cpppo takes every unconnected service 0x52 for an Unconnected
			// Send, whatever its path, so Read Tag Fragmented sent straight
			// to it (not routed, not connected) cannot be parsed there.
			t.Log("fragmented read skipped: cpppo cannot parse an unrouted unconnected Read Tag Fragmented")
			return
		}
		typ, got, err := c.ReadTag(ctx, "Big", 300)
		if err != nil {
			t.Fatal(err)
		}
		if typ.Code != enip.TypeDINT || !bytes.Equal(got, big) {
			t.Errorf("Big read back as %s, %d bytes (want %d), equal=%v", typ.Name(), len(got), len(big), bytes.Equal(got, big))
		}
	})

	t.Run("MultipleServicePacket", func(t *testing.T) {
		reads := []*enip.TagRead{{Tag: "Flow", Elements: 1}, {Tag: "Count", Elements: 1}, {Tag: "Levels", Elements: 10}, {Tag: "NoSuchTag", Elements: 1}}
		if err := c.ReadTags(ctx, reads); err != nil {
			t.Fatal(err)
		}
		if reads[0].Err != nil || !bytes.Equal(reads[0].Data, le.AppendUint32(nil, math.Float32bits(12.5))) {
			t.Errorf("Flow in the batch: %x %v", reads[0].Data, reads[0].Err)
		}
		if reads[1].Err != nil || !bytes.Equal(reads[1].Data, le32(uint32(0xFFFFFFFF-41))) {
			t.Errorf("Count in the batch: %x %v", reads[1].Data, reads[1].Err)
		}
		if reads[2].Err != nil || len(reads[2].Data) != 20 {
			t.Errorf("Levels in the batch: %x %v", reads[2].Data, reads[2].Err)
		}
		if reads[3].Err == nil || !enip.IsCIP(reads[3].Err) {
			t.Errorf("an unknown tag in the batch gave %v, want a CIP status", reads[3].Err)
		}
	})

	t.Run("MultipleWithFragmentedMember", func(t *testing.T) {
		if direct(c) {
			t.Skip("cpppo cannot parse an unrouted unconnected Read Tag Fragmented (see FragmentedWriteRead)")
		}
		reads := []*enip.TagRead{{Tag: "Flow", Elements: 1}, {Tag: "Big", Elements: 300}}
		if err := c.ReadTags(ctx, reads); err != nil {
			t.Fatal(err)
		}
		if reads[1].Err != nil || len(reads[1].Data) != 1200 || le.Uint32(reads[1].Data[1196:]) != 299*3+1 {
			t.Errorf("Big in a batch: %d bytes, %v", len(reads[1].Data), reads[1].Err)
		}
	})

	t.Run("SSTRING", func(t *testing.T) {
		// cpppo's SSTRING is the CIP short string (type 0xDA: length
		// byte and characters), not the Logix STRING structure.
		val := append([]byte{6}, "Pump 7"...)
		if err := c.WriteTag(ctx, "Label", enip.Type{Code: 0xDA}, 1, val); err != nil {
			t.Fatal(err)
		}
		typ, got, err := c.ReadTag(ctx, "Label", 1)
		if err != nil {
			t.Fatal(err)
		}
		if typ.Code != 0xDA || !bytes.Equal(got, val) {
			t.Errorf("Label read back as %s %x", typ.Name(), got)
		}
		// cpppo's STRING is the CIP string (type 0xD0: UINT length and
		// characters). An even length: cpppo's parser wants a pad byte
		// after an odd-length CIP STRING in a Write Tag request.
		val = append([]byte{10, 0}, "Station 42"...)
		if err := c.WriteTag(ctx, "Text", enip.Type{Code: 0xD0}, 1, val); err != nil {
			t.Fatal(err)
		}
		typ, got, err = c.ReadTag(ctx, "Text", 1)
		if err != nil {
			t.Fatal(err)
		}
		if typ.Code != 0xD0 || !bytes.Equal(got, val) {
			t.Errorf("Text read back as %s %x", typ.Name(), got)
		}
	})

	t.Run("UnknownTag", func(t *testing.T) {
		_, _, err := c.ReadTag(ctx, "NoSuchTag", 1)
		switch {
		case err == nil:
			t.Error("an unknown tag read without error")
		case enip.IsCIP(err):
		case !c.Connected:
			// cpppo answers an unconnected request it cannot resolve with
			// an encapsulation status, not a CIP status (a Logix
			// controller answers path destination unknown).
			t.Logf("unknown tag, unconnected: %v (cpppo's answer)", err)
		default:
			t.Errorf("unknown tag: %v, want a CIP status", err)
		}
	})
}

// Our client against cpppo with unconnected messaging and no route.
func TestClientAgainstCpppoUnconnected(t *testing.T) {
	needDocker(t)
	_, addr := startCpppo(t)
	c := &enip.Client{Addr: addr, Timeout: 5 * time.Second}
	defer c.Close()
	exercise(t, c)
	// A new session after cpppo's answer to the unknown tag.
	if _, _, err := c.ReadTag(context.Background(), "Flow", 1); err != nil {
		t.Fatal(err)
	}
	if m, err := c.Mode(); m != "unconnected" || err != nil {
		t.Errorf("mode %q %v", m, err)
	}
}

// Our client against cpppo over a class 3 connection (Forward Open), and
// over one opened with Large Forward Open.
func TestClientAgainstCpppoConnected(t *testing.T) {
	needDocker(t)
	_, addr := startCpppo(t)
	for _, size := range []int{500, 4000} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			c := &enip.Client{Addr: addr, Timeout: 5 * time.Second, Connected: true, ConnSize: size}
			defer c.Close()
			exercise(t, c)
			if m, err := c.Mode(); m != "connected" || err != nil {
				t.Errorf("mode %q %v (cpppo refused the forward open)", m, err)
			}
			// Above 511 bytes only Large Forward Open can carry the size.
			if got := c.MaxMessage(); got != size-2 {
				t.Errorf("message size %d over the connection, want %d", got, size-2)
			}
		})
	}
}

// cpppo configured to accept only route 1/2 (backplane, slot 2): our
// client routes through Unconnected Send and in the connection path, and a
// wrong slot is refused.
func TestClientAgainstCpppoRouted(t *testing.T) {
	needDocker(t)
	_, addr := startCpppo(t, "--route-path", "1/2")
	route, err := enip.Route("1,2")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("unconnected", func(t *testing.T) {
		c := &enip.Client{Addr: addr, Timeout: 5 * time.Second, Route: route}
		defer c.Close()
		exercise(t, c)
	})
	t.Run("connected", func(t *testing.T) {
		c := &enip.Client{Addr: addr, Timeout: 5 * time.Second, Route: route, Connected: true}
		defer c.Close()
		exercise(t, c)
		if m, err := c.Mode(); m != "connected" || err != nil {
			t.Errorf("mode %q %v", m, err)
		}
	})
	t.Run("wrong slot", func(t *testing.T) {
		bad, _ := enip.Route("1,5")
		c := &enip.Client{Addr: addr, Timeout: 5 * time.Second, Route: bad}
		defer c.Close()
		_, _, err := c.ReadTag(context.Background(), "Flow", 1)
		if err == nil {
			t.Fatal("cpppo answered through a route it does not accept")
		}
		t.Logf("wrong slot: %v", err)
	})
}

// Discover's ListIdentity over UDP reaches cpppo and decodes its reply.
func TestDiscoverCpppo(t *testing.T) {
	needDocker(t)
	_, addr := startCpppo(t)
	var ids []enip.Identity
	for try := 0; try < 5 && len(ids) == 0; try++ {
		var err error
		ids, err = enip.Discover(context.Background(), addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(ids) != 1 || ids[0].ProductName == "" {
		t.Fatalf("discovered %+v", ids)
	}
	t.Logf("discovered %+v", ids[0])
}
