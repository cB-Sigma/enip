// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cB-Sigma/enip"
	"github.com/cB-Sigma/enip/server"
)

// Class 1 I/O between the client's scanner side and the adapter: outputs
// with the run/idle header reach the consumed assembly, the produced
// assembly reaches the scanner at the RPI, a wrong size is refused, and
// a silent scanner's connection times out.
func TestImplicitIO(t *testing.T) {
	s := server.New()
	s.IOAddr = "127.0.0.1:0"
	s.AddAssembly(100, 8) // inputs to the scanner (T→O)
	s.AddAssembly(150, 4) // outputs from the scanner (O→T)
	s.AddAssembly(1, 0)   // configuration
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	s.SetAssembly(100, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	c := &enip.Client{Addr: s.Addr(), Timeout: 2 * time.Second}
	defer c.Close()
	cfg := enip.IOConfig{ConfigInstance: 1, OutputInstance: 150, InputInstance: 100, OutputSize: 4, InputSize: 8,
		RPI: 20 * time.Millisecond, LocalUDP: "127.0.0.1:0", AdapterUDPPort: 1}
	io, err := c.OpenIO(ctx(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer io.Close()
	in, err := io.WaitInput(ctx(t))
	if err != nil || !bytes.Equal(in, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatalf("inputs %v %v", in, err)
	}
	s.SetAssembly(100, []byte{9, 9, 9, 9, 9, 9, 9, 9})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if in, _ = io.WaitInput(ctx(t)); in[0] == 9 {
			break
		}
	}
	if in[0] != 9 {
		t.Errorf("changed inputs did not arrive: %v", in)
	}
	io.SetOutput([]byte{0xA, 0xB, 0xC, 0xD})
	io.SetRun(true)
	var out []byte
	var run bool
	for time.Now().Before(deadline.Add(2 * time.Second)) {
		if out, run = s.Assembly(150); run && out[0] == 0xA {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !run || !bytes.Equal(out, []byte{0xA, 0xB, 0xC, 0xD}) {
		t.Errorf("outputs at the adapter %x run=%v", out, run)
	}
	if s.IOConnections() != 1 {
		t.Errorf("%d I/O connections", s.IOConnections())
	}

	// A size that does not match the assembly is refused.
	bad := cfg
	bad.OutputSize = 5
	if _, err := c.OpenIO(ctx(t), bad); err == nil {
		t.Error("a wrong O→T size was accepted")
	} else {
		var e *enip.Error
		if !errors.As(err, &e) || e.Status != enip.StatusConnFailure {
			t.Errorf("wrong size refused with %v", err)
		}
	}

	// The scanner closes the connection: its Forward Close ends it at the
	// adapter.
	io.Close()
	time.Sleep(600 * time.Millisecond)
	if n := s.IOConnections(); n != 0 {
		t.Errorf("%d I/O connections after the scanner stopped", n)
	}
}

// Closing an I/O connection sends its Forward Close: the adapter ends the
// connection at once instead of after its timeout, and a second Close
// sends no second one.
func TestIOCloseSendsForwardClose(t *testing.T) {
	s := server.New()
	s.IOAddr = "127.0.0.1:0"
	s.AddAssembly(100, 8)
	s.AddAssembly(150, 4)
	s.AddAssembly(1, 0)
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	c := &enip.Client{Addr: s.Addr(), Timeout: 2 * time.Second}
	defer c.Close()
	// RPI × 16 is 16 s: a connection gone before that was closed, not
	// timed out.
	cfg := enip.IOConfig{ConfigInstance: 1, OutputInstance: 150, InputInstance: 100, OutputSize: 4, InputSize: 8,
		RPI: time.Second, LocalUDP: "127.0.0.1:0", AdapterUDPPort: 1}
	io, err := c.OpenIO(ctx(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.IOConnections(); n != 1 {
		t.Fatalf("%d I/O connections after the Forward Open", n)
	}
	before := s.Stats().ForwardCloses
	if err := io.Shutdown(); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if n := s.IOConnections(); n != 0 {
		t.Errorf("%d I/O connections after Close", n)
	}
	if n := s.Stats().ForwardCloses - before; n != 1 {
		t.Errorf("%d Forward Closes after Close, want 1", n)
	}
	if err := io.Shutdown(); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
	io.Close()
	if n := s.Stats().ForwardCloses - before; n != 1 {
		t.Errorf("%d Forward Closes after a second Close, want 1", n)
	}
}

// An I/O connection closed after its client sends no Forward Close (there
// is no session to send it on) and does not reconnect.
func TestIOCloseAfterClientClose(t *testing.T) {
	s := server.New()
	s.IOAddr = "127.0.0.1:0"
	s.AddAssembly(100, 8)
	s.AddAssembly(150, 4)
	s.AddAssembly(1, 0)
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	c := &enip.Client{Addr: s.Addr(), Timeout: 2 * time.Second}
	cfg := enip.IOConfig{ConfigInstance: 1, OutputInstance: 150, InputInstance: 100, OutputSize: 4, InputSize: 8,
		RPI: time.Second, LocalUDP: "127.0.0.1:0", AdapterUDPPort: 1}
	io, err := c.OpenIO(ctx(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	sessions := s.Stats().Sessions
	if err := io.Shutdown(); !errors.Is(err, enip.ErrNoSession) {
		t.Errorf("Shutdown after the client's Close: %v, want ErrNoSession", err)
	}
	if n := s.Stats().ForwardCloses; n != 0 {
		t.Errorf("%d Forward Closes, want 0", n)
	}
	if n := s.Stats().Sessions; n != sessions {
		t.Errorf("Close reconnected: %d sessions, was %d", n, sessions)
	}
}

// An originator that repeats the CIP sequence count (unchanged outputs)
// while the encapsulation sequence number goes up keeps its connection
// alive; a repeated encapsulation sequence number is a duplicate and a
// new CIP sequence count brings new data (issue #8).
func TestIOWatchdogWithRepeatedSequenceCount(t *testing.T) {
	s := server.New()
	s.IOAddr = "127.0.0.1:0"
	s.AddAssembly(100, 8)
	s.AddAssembly(150, 4)
	s.AddAssembly(1, 0)
	c := startServer(t, s)
	rpi := 10 * time.Millisecond // times out after 16 × RPI = 160 ms
	r, err := c.Do(ctx(t), enip.SvcForwardOpen, enip.Logical(enip.ClassConnectionManager, 1, -1), class1Open(0x4242, rpi))
	if err != nil || r.Status != 0 || len(r.Data) < 4 {
		t.Fatalf("class 1 Forward Open: %+v, %v", r, err)
	}
	ot := binary.LittleEndian.Uint32(r.Data)
	pc, err := net.DialUDP("udp4", nil, s.IOUDPAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	data := []byte{1, 0, 0, 0, 0xA, 0xB, 0xC, 0xD} // run, then the outputs
	deadline := time.Now().Add(500 * time.Millisecond)
	for es := uint32(1); time.Now().Before(deadline); es++ {
		if _, err := pc.Write(enip.IOPacket(ot, es, 1, data)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(rpi)
	}
	if n := s.IOConnections(); n != 1 {
		t.Fatalf("%d I/O connections after 500 ms of packets with the same CIP sequence count", n)
	}
	if out, run := s.Assembly(150); !run || !bytes.Equal(out, []byte{0xA, 0xB, 0xC, 0xD}) {
		t.Errorf("outputs %x run=%v", out, run)
	}
	// A duplicate (an old encapsulation sequence number) is not applied;
	// a new CIP sequence count is.
	_, _ = pc.Write(enip.IOPacket(ot, 1, 2, []byte{1, 0, 0, 0, 9, 9, 9, 9}))
	time.Sleep(50 * time.Millisecond)
	if out, _ := s.Assembly(150); out[0] != 0xA {
		t.Errorf("a duplicate packet was applied: %x", out)
	}
	_, _ = pc.Write(enip.IOPacket(ot, 1<<16, 2, []byte{0, 0, 0, 0, 9, 9, 9, 9}))
	time.Sleep(50 * time.Millisecond)
	if out, run := s.Assembly(150); run || out[0] != 9 {
		t.Errorf("new data was not applied: %x run=%v", out, run)
	}
}
