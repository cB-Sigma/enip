// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/binary"
	"math/rand/v2"
	"net"
	"time"

	"github.com/cB-Sigma/enip"
)

// Implicit (class 1) I/O, adapter side: assemblies the scanner's outputs
// are consumed into and the inputs are produced from, a Forward Open that
// names them, and cyclic UDP each way. Sizes in the Forward Open count
// the 16-bit sequence count (both directions) and the 32-bit run/idle
// header (O→T).

type ioConn struct {
	ot, to       uint32
	serial       uint16
	in, out      uint16 // consumed (O→T) and produced (T→O) assemblies
	peer         *net.UDPAddr
	rpi, timeout time.Duration
	last         time.Time
	run          bool
	lastSeq      uint16
	seen         bool
	stop         chan struct{}
}

// AddAssembly creates an assembly instance of size bytes (zeroed).
func (s *Server) AddAssembly(instance uint16, size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.assemblies == nil {
		s.assemblies = map[uint16][]byte{}
	}
	s.assemblies[instance] = make([]byte, size)
}

// SetAssembly writes an assembly's data (a produced assembly's next
// packets carry it).
func (s *Server) SetAssembly(instance uint16, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.assemblies[instance]; ok {
		copy(a, data)
	}
}

// Assembly returns a copy of an assembly's data, and for a consumed one
// whether the scanner is in run mode.
func (s *Server) Assembly(instance uint16) (data []byte, run bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.ioConns {
		if c.in == instance {
			run = c.run
		}
	}
	return append([]byte(nil), s.assemblies[instance]...), run
}

// IOConnections is the number of open class 1 connections.
func (s *Server) IOConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ioConns)
}

// isClass1Open reports a (Large) Forward Open of transport class 1.
func isClass1Open(msg []byte) bool {
	svc, path, d, err := enip.ParseRequest(msg)
	if err != nil || string(path) != string(cmPath) || (svc != enip.SvcForwardOpen && svc != enip.SvcLargeForwardOpen) {
		return false
	}
	n := foFixed(svc)
	return len(d) >= n && d[n-2]&0x0F == 1
}

func foFixed(svc byte) int {
	paramLen := 2
	if svc == enip.SvcLargeForwardOpen {
		paramLen = 4
	}
	return 2 + 4 + 4 + 2 + 2 + 4 + 4 + 2*(4+paramLen) + 1 + 1
}

// assemblyPath reads [route] class 0x04, instance (configuration), then
// two connection points: consumed (O→T) and produced (T→O).
func assemblyPath(p []byte) (cfg, consumed, produced uint16, ok bool) {
	var vals []uint32
	var kinds []byte
	le := binary.LittleEndian
	for len(p) >= 2 {
		seg := p[0]
		if seg&0xE0 != 0x20 {
			p = p[2:] // a port segment of a route
			continue
		}
		var v uint32
		switch seg & 0x03 {
		case 0:
			v, p = uint32(p[1]), p[2:]
		case 1:
			if len(p) < 4 {
				return 0, 0, 0, false
			}
			v, p = uint32(le.Uint16(p[2:])), p[4:]
		default:
			return 0, 0, 0, false
		}
		kinds = append(kinds, seg&^0x03)
		vals = append(vals, v)
	}
	// class, instance, point, point
	if len(vals) != 4 || kinds[0] != 0x20 || vals[0] != uint32(enip.ClassAssembly) || kinds[1] != 0x24 || kinds[2] != 0x2C || kinds[3] != 0x2C {
		return 0, 0, 0, false
	}
	return uint16(vals[1]), uint16(vals[2]), uint16(vals[3]), true
}

// forwardOpenIO opens a class 1 connection; toPort is the scanner's I/O
// port from its Sockaddr Info item (0: 2222).
func (s *Server) forwardOpenIO(msg []byte, remote net.Addr, toPort int) ([]byte, []enip.Item) {
	svc, _, d, _ := enip.ParseRequest(msg)
	le := binary.LittleEndian
	fixed := foFixed(svc)
	ident := d[10:18]
	fail := func(ext uint16) ([]byte, []enip.Item) {
		return enip.MarshalResponse(svc, enip.StatusConnFailure, []uint16{ext}, append(append([]byte(nil), ident...), 0, 0)), nil
	}
	if len(d) < fixed || len(d) < fixed+int(d[fixed-1])*2 {
		return enip.MarshalResponse(svc, enip.StatusNotEnoughData, nil, nil), nil
	}
	_, consumed, produced, ok := assemblyPath(d[fixed : fixed+int(d[fixed-1])*2])
	if !ok {
		return fail(0x0315) // invalid segment in the connection path
	}
	size := func(off int) int {
		if svc == enip.SvcLargeForwardOpen {
			return int(le.Uint32(d[off:]) & 0xFFFF)
		}
		return int(le.Uint16(d[off:]) & 0x1FF)
	}
	paramLen := (fixed - 32) / 2
	otSize, toSize := size(26), size(26+paramLen+4)
	s.mu.Lock()
	inA, okIn := s.assemblies[consumed]
	outA, okOut := s.assemblies[produced]
	ioAddr := s.ioUDP
	s.mu.Unlock()
	if !okIn || !okOut {
		return fail(0x0127) // invalid connection point (no such assembly)
	}
	if otSize != len(inA)+6 {
		return fail(0x0127) // O→T size mismatch
	}
	if toSize != len(outA)+2 {
		return fail(0x0128) // T→O size mismatch
	}
	if ioAddr == nil {
		return fail(0x0113)
	}
	host, _, _ := net.SplitHostPort(remote.String())
	if toPort == 0 {
		toPort = enip.IOPort
	}
	otRPI := time.Duration(le.Uint32(d[22:])) * time.Microsecond
	toRPI := time.Duration(le.Uint32(d[22+4+paramLen:])) * time.Microsecond
	c := &ioConn{ot: rand.Uint32() | 1, to: le.Uint32(d[6:]), serial: le.Uint16(d[10:]), in: consumed, out: produced,
		peer: &net.UDPAddr{IP: net.ParseIP(host), Port: toPort}, rpi: toRPI,
		timeout: otRPI * time.Duration(4<<min(d[18], 7)), last: time.Now(), stop: make(chan struct{})}
	s.mu.Lock()
	if s.ioConns == nil {
		s.ioConns = map[uint32]*ioConn{}
	}
	s.ioConns[c.ot] = c
	s.mu.Unlock()
	go s.produce(c)
	out := le.AppendUint32(nil, c.ot)
	out = le.AppendUint32(out, c.to)
	out = append(out, ident...)
	out = le.AppendUint32(out, uint32(otRPI/time.Microsecond))
	out = le.AppendUint32(out, uint32(toRPI/time.Microsecond))
	out = append(out, 0, 0)
	port := ioAddr.LocalAddr().(*net.UDPAddr).Port
	sa := binary.BigEndian.AppendUint16(nil, 2)
	sa = binary.BigEndian.AppendUint16(sa, uint16(port))
	sa = append(sa, make([]byte, 12)...)
	return enip.MarshalResponse(svc, 0, nil, out), []enip.Item{{Type: enip.ItemSockaddrOT, Data: sa}}
}

// produce sends the produced assembly every RPI until the connection
// ends; a consumer silent past the timeout ends it.
func (s *Server) produce(c *ioConn) {
	t := time.NewTicker(c.rpi)
	defer t.Stop()
	var seq uint32
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
		}
		s.mu.Lock()
		conn := s.ioUDP
		data := append([]byte(nil), s.assemblies[c.out]...)
		expired := time.Since(c.last) > c.timeout
		if expired {
			delete(s.ioConns, c.ot)
		}
		s.mu.Unlock()
		if expired || conn == nil {
			return
		}
		seq++
		_, _ = conn.WriteToUDP(enip.IOPacket(c.to, seq, uint16(seq), data), c.peer)
	}
}

// serveIO reads the scanners' O→T packets.
func (s *Server) serveIO(pc *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 1500)
	for {
		n, _, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		id, _, cs, data, err := enip.ParseIOPacket(buf[:n])
		if err != nil || len(data) < 4 {
			continue
		}
		s.mu.Lock()
		c := s.ioConns[id]
		if c != nil && (!c.seen || int16(cs-c.lastSeq) > 0) {
			c.seen, c.lastSeq, c.last = true, cs, time.Now()
			c.run = binary.LittleEndian.Uint32(data)&1 != 0
			copy(s.assemblies[c.in], data[4:])
		}
		s.mu.Unlock()
	}
}

// closeIO ends every class 1 connection.
func (s *Server) closeIO() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.ioConns {
		close(c.stop)
		delete(s.ioConns, k)
	}
}
