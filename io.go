// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package enip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// Implicit (class 1) I/O: a Forward Open naming assembly connection
// points, then cyclic UDP packets each way at the RPI, each a common
// packet format with a Sequenced Address item (connection ID, sequence)
// and a Connected Data item (16-bit sequence count, then the data). The
// originator's O→T data starts with the 32-bit run/idle header.

const (
	// ItemSequencedAddress is the CPF item of a class 0/1 packet.
	ItemSequencedAddress uint16 = 0x8002
	// ClassAssembly is the Assembly object.
	ClassAssembly uint16 = 0x04
	// IOPort is the UDP port of class 0/1 I/O.
	IOPort = 2222
)

// IOConfig describes a class 1 connection to an adapter's assemblies.
type IOConfig struct {
	// ConfigInstance, OutputInstance (O→T, consumed by the adapter) and
	// InputInstance (T→O, produced by it) are assembly instances.
	ConfigInstance, OutputInstance, InputInstance uint16
	// OutputSize and InputSize are the data sizes in bytes (without the
	// sequence count and run/idle header).
	OutputSize, InputSize int
	// RPI is the requested packet interval of both directions (default
	// 100 ms); the connection times out after RPI × 4 << Multiplier.
	RPI        time.Duration
	Multiplier byte // default 2 (16 × RPI)
	// LocalUDP is where this side receives T→O data (default ":2222");
	// the adapter is told the port.
	LocalUDP string
	// AdapterUDPPort is the adapter's I/O port when it does not say it in
	// its Forward Open reply (default 2222).
	AdapterUDPPort int
}

// IOConn is an open class 1 connection; this side is the scanner
// (originator). Its methods are safe for concurrent use.
type IOConn struct {
	c      *Client
	cfg    IOConfig
	udp    *net.UDPConn
	peer   *net.UDPAddr
	ot, to uint32

	mu       sync.Mutex
	out      []byte
	run      bool
	in       []byte
	inSeq    uint16
	last     time.Time
	err      error
	received chan struct{}
	done     chan struct{}
	once     sync.Once
}

// OpenIO opens a class 1 connection through the client's session (its
// Route, if any, reaches the adapter) and starts sending outputs at the
// RPI. The outputs start zeroed and in idle mode; SetOutput and SetRun
// change them.
func (c *Client) OpenIO(ctx context.Context, cfg IOConfig) (*IOConn, error) {
	if cfg.RPI <= 0 {
		cfg.RPI = 100 * time.Millisecond
	}
	if cfg.Multiplier == 0 {
		cfg.Multiplier = 2
	}
	if cfg.LocalUDP == "" {
		cfg.LocalUDP = fmt.Sprintf(":%d", IOPort)
	}
	if cfg.AdapterUDPPort == 0 {
		cfg.AdapterUDPPort = IOPort
	}
	la, err := net.ResolveUDPAddr("udp4", cfg.LocalUDP)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp4", la)
	if err != nil {
		return nil, err
	}
	io := &IOConn{c: c, cfg: cfg, udp: udp, out: make([]byte, cfg.OutputSize), to: rand.Uint32() | 1,
		received: make(chan struct{}, 1), done: make(chan struct{})}
	r, items, err := c.forwardOpenIO(ctx, io, udp.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	if err := r.Err(); err != nil {
		_ = udp.Close()
		return nil, err
	}
	if len(r.Data) < 8 {
		_ = udp.Close()
		return nil, errors.New("forward open reply too short")
	}
	io.ot = binary.LittleEndian.Uint32(r.Data)
	host, _, _ := net.SplitHostPort(c.Addr)
	ip := net.ParseIP(host)
	if ip == nil {
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			ip = ips[0]
		}
	}
	io.peer = &net.UDPAddr{IP: ip, Port: cfg.AdapterUDPPort}
	for _, it := range items {
		if it.Type == ItemSockaddrOT && len(it.Data) >= 8 {
			if p := int(binary.BigEndian.Uint16(it.Data[2:])); p != 0 {
				io.peer.Port = p
			}
		}
	}
	go io.produce()
	go io.consume()
	return io, nil
}

// sockaddr is a Sockaddr Info item body (big-endian, 16 octets).
func sockaddr(ip net.IP, port int) []byte {
	b := binary.BigEndian.AppendUint16(nil, 2)
	b = binary.BigEndian.AppendUint16(b, uint16(port))
	if ip4 := ip.To4(); ip4 != nil {
		b = append(b, ip4...)
	} else {
		b = append(b, 0, 0, 0, 0)
	}
	return append(b, make([]byte, 8)...)
}

func (c *Client) forwardOpenIO(ctx context.Context, io *IOConn, port int) (*Response, []Item, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connectLocked(ctx); err != nil {
		return nil, nil, err
	}
	cfg := io.cfg
	le := binary.LittleEndian
	serial := uint16(rand.Uint32())
	b := []byte{priorityTick, timeoutTicks}
	b = le.AppendUint32(b, 0) // O→T ID: the adapter chooses
	b = le.AppendUint32(b, io.to)
	b = le.AppendUint16(b, serial)
	b = le.AppendUint16(b, originatorVendor)
	b = le.AppendUint32(b, rand.Uint32())
	b = append(b, cfg.Multiplier, 0, 0, 0)
	rpi := uint32(cfg.RPI / time.Microsecond)
	// Point-to-point, scheduled priority, fixed size; O→T counts the
	// sequence count and the run/idle header, T→O the sequence count.
	b = le.AppendUint32(b, rpi)
	b = le.AppendUint16(b, 0x4800|uint16((cfg.OutputSize+6)&0x1FF))
	b = le.AppendUint32(b, rpi)
	b = le.AppendUint16(b, 0x4800|uint16((cfg.InputSize+2)&0x1FF))
	b = append(b, 0x01) // class 1, cyclic, client
	path := append([]byte(nil), c.Route...)
	path = append(path, logical(logical(nil, 0x20, uint32(ClassAssembly)), 0x24, uint32(cfg.ConfigInstance))...)
	path = append(path, logical(nil, 0x2C, uint32(cfg.OutputInstance))...)
	path = append(path, logical(nil, 0x2C, uint32(cfg.InputInstance))...)
	b = append(b, byte(len(path)/2))
	b = append(b, path...)
	msg := Request(SvcForwardOpen, Logical(ClassConnectionManager, 1, -1), b)
	_, body, err := c.exchangeLocked(CmdSendRRData, RRData(uint16(c.timeout()/time.Second)+1,
		Item{Type: ItemNullAddress}, Item{Type: ItemUnconnectedData, Data: msg},
		Item{Type: ItemSockaddrTO, Data: sockaddr(nil, port)}))
	if err != nil {
		return nil, nil, err
	}
	items, err := ParseRRData(body)
	if err != nil {
		return nil, nil, err
	}
	for _, it := range items {
		if it.Type == ItemUnconnectedData {
			r, err := ParseResponse(it.Data)
			return r, items, err
		}
	}
	return nil, nil, errors.New("SendRRData reply without unconnected data")
}

// IOPacket builds a class 0/1 UDP packet.
func IOPacket(connID, encapSeq uint32, cipSeq uint16, data []byte) []byte {
	addr := binary.LittleEndian.AppendUint32(nil, connID)
	addr = binary.LittleEndian.AppendUint32(addr, encapSeq)
	cd := binary.LittleEndian.AppendUint16(nil, cipSeq)
	return MarshalCPF(Item{Type: ItemSequencedAddress, Data: addr}, Item{Type: ItemConnectedData, Data: append(cd, data...)})
}

// ParseIOPacket reads a class 0/1 UDP packet.
func ParseIOPacket(b []byte) (connID, encapSeq uint32, cipSeq uint16, data []byte, err error) {
	items, err := ParseCPF(b)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	ok := false
	for _, it := range items {
		switch it.Type {
		case ItemSequencedAddress:
			if len(it.Data) != 8 {
				return 0, 0, 0, nil, errors.New("sequenced address item of the wrong length")
			}
			connID, encapSeq = binary.LittleEndian.Uint32(it.Data), binary.LittleEndian.Uint32(it.Data[4:])
			ok = true
		case ItemConnectedData:
			if len(it.Data) < 2 {
				return 0, 0, 0, nil, errors.New("connected data item too short")
			}
			cipSeq, data = binary.LittleEndian.Uint16(it.Data), it.Data[2:]
		}
	}
	if !ok {
		return 0, 0, 0, nil, errors.New("no sequenced address item")
	}
	return connID, encapSeq, cipSeq, data, nil
}

func (io *IOConn) produce() {
	t := time.NewTicker(io.cfg.RPI)
	defer t.Stop()
	var seq uint32
	for {
		select {
		case <-io.done:
			return
		case <-t.C:
		}
		seq++
		io.mu.Lock()
		hdr := uint32(0)
		if io.run {
			hdr = 1
		}
		data := binary.LittleEndian.AppendUint32(nil, hdr)
		data = append(data, io.out...)
		io.mu.Unlock()
		_, _ = io.udp.WriteToUDP(IOPacket(io.ot, seq, uint16(seq), data), io.peer)
	}
}

func (io *IOConn) consume() {
	buf := make([]byte, 1500)
	timeout := io.cfg.RPI * time.Duration(4<<io.cfg.Multiplier)
	for {
		_ = io.udp.SetReadDeadline(time.Now().Add(timeout))
		n, _, err := io.udp.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-io.done:
				return
			default:
			}
			io.fail(fmt.Errorf("no input within %v: %w", timeout, err))
			return
		}
		id, _, cs, data, err := ParseIOPacket(buf[:n])
		if err != nil || id != io.to {
			continue
		}
		io.mu.Lock()
		if !io.last.IsZero() && int16(cs-io.inSeq) <= 0 {
			io.mu.Unlock()
			continue // a duplicate or a late packet
		}
		io.in, io.inSeq, io.last = append([]byte(nil), data...), cs, time.Now()
		io.mu.Unlock()
		select {
		case io.received <- struct{}{}:
		default:
		}
	}
}

func (io *IOConn) fail(err error) {
	io.mu.Lock()
	if io.err == nil {
		io.err = err
	}
	io.mu.Unlock()
	io.once.Do(func() { close(io.done) })
}

// SetOutput sets the O→T data sent from the next RPI on.
func (io *IOConn) SetOutput(b []byte) {
	io.mu.Lock()
	defer io.mu.Unlock()
	copy(io.out, b)
}

// SetRun sets the run/idle header: true is run mode.
func (io *IOConn) SetRun(run bool) {
	io.mu.Lock()
	defer io.mu.Unlock()
	io.run = run
}

// Input is the latest T→O data, its sequence count and when it came.
func (io *IOConn) Input() ([]byte, uint16, time.Time) {
	io.mu.Lock()
	defer io.mu.Unlock()
	return append([]byte(nil), io.in...), io.inSeq, io.last
}

// WaitInput waits for the next T→O packet.
func (io *IOConn) WaitInput(ctx context.Context) ([]byte, error) {
	select {
	case <-io.received:
		b, _, _ := io.Input()
		return b, nil
	case <-io.done:
		return nil, io.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Err is why the connection ended (nil while it runs or after Close).
func (io *IOConn) Err() error {
	io.mu.Lock()
	defer io.mu.Unlock()
	return io.err
}

// Close stops sending and closes the UDP socket. The adapter drops the
// connection when its timeout passes (a Forward Close is not sent).
func (io *IOConn) Close() {
	io.once.Do(func() { close(io.done) })
	_ = io.udp.Close()
}
