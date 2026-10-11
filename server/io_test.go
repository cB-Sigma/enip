// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"errors"
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

	// The scanner goes silent: the adapter drops the connection after
	// RPI × 16, and the scanner's own timeout fires once inputs stop.
	io.Close()
	time.Sleep(600 * time.Millisecond)
	if n := s.IOConnections(); n != 0 {
		t.Errorf("%d I/O connections after the scanner stopped", n)
	}
}
