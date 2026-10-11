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

	"github.com/cB-Sigma/lanbcast"
)

// Our originator identity in Forward Open (any values unique per
// originator work; the vendor ID is not a registered one).
const (
	originatorVendor = 0xF00D
	priorityTick     = 0x0A // priority normal, 1 ms tick
	timeoutTicks     = 0x0E
	unconnectedMax   = 504 // CIP message bytes Logix accepts unconnected
)

// DefaultConnSize is the class 3 connection size, in bytes, used when a
// Client does not set one.
const DefaultConnSize = 500

// Client is one EtherNet/IP session with a target, optionally with a
// class 3 connection. It is safe for concurrent use; requests are serialised.
type Client struct {
	Addr      string        // host:port
	Route     []byte        // port segments to the CPU; nil talks to the target itself
	Timeout   time.Duration // per exchange
	Connected bool          // try a Forward Open
	ConnSize  int           // connection size; above 511 uses Large Forward Open
	// KeepAlive is how long the connection must survive without traffic
	// (it sets the RPI × multiplier timeout); default 1 minute.
	KeepAlive time.Duration

	connTimeout time.Duration // the open connection's timeout (forward open)
	lastUse     time.Time     // when the session last carried a request

	mu       sync.Mutex
	conn     net.Conn
	session  uint32
	ctxN     uint64
	open     bool
	otID     uint32
	toID     uint32
	serial   uint16
	origSer  uint32
	seq      uint16
	size     int
	fallback error
	identity *Identity
}

// Mode reports "connected", "unconnected" or "" when not connected, and
// why connected messaging was refused, if it was.
func (c *Client) Mode() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.conn == nil:
		return "", nil
	case c.open:
		return "connected", nil
	}
	return "unconnected", c.fallback
}

// Identity returns the target's identity as read on connect, if any.
func (c *Client) Identity() *Identity {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.identity
}

// Close ends the connection and session.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked(true)
}

func (c *Client) closeLocked(polite bool) {
	if c.conn == nil {
		return
	}
	if polite {
		_ = c.conn.SetDeadline(time.Now().Add(c.timeout()))
		if c.open {
			_, _ = c.sendRRLocked(Request(SvcForwardClose, Logical(ClassConnectionManager, 1, -1), c.forwardCloseBody()))
		}
		_, _ = c.conn.Write(Header{Command: CmdUnRegisterSession, Session: c.session}.Marshal(nil))
	}
	_ = c.conn.Close()
	c.conn, c.open, c.session = nil, false, 0
}

func (c *Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 2 * time.Second
	}
	return c.Timeout
}

// connectLocked dials, registers a session, reads the identity and opens
// a connection when asked (falling back to unconnected messaging when the
// target refuses).
func (c *Client) connectLocked(ctx context.Context) error {
	if c.conn != nil {
		return nil
	}
	d := net.Dialer{Timeout: c.timeout()}
	conn, err := d.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return err
	}
	c.conn = conn
	h, data, err := c.exchangeLocked(CmdRegisterSession, RegisterSessionData())
	if err != nil {
		c.closeLocked(false)
		return fmt.Errorf("registering a session: %w", err)
	}
	if len(data) < 4 || h.Session == 0 {
		c.closeLocked(false)
		return errors.New("registering a session: the target returned no session handle")
	}
	c.session = h.Session
	if _, body, err := c.exchangeLocked(CmdListIdentity, nil); err == nil {
		if ids, err := ParseListIdentity(body); err == nil && len(ids) > 0 {
			c.identity = &ids[0]
		}
	}
	c.fallback = nil
	if c.Connected {
		if err := c.forwardOpenLocked(); err != nil {
			var ce *Error
			if !errors.As(err, &ce) {
				c.closeLocked(false)
				return fmt.Errorf("forward open: %w", err)
			}
			c.fallback = fmt.Errorf("forward open refused, using unconnected messaging: %w", err)
		}
	}
	return nil
}

func (c *Client) exchangeLocked(cmd uint16, data []byte) (Header, []byte, error) {
	c.ctxN++
	h := Header{Command: cmd, Session: c.session}
	binary.LittleEndian.PutUint64(h.Context[:], c.ctxN)
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout()))
	if _, err := c.conn.Write(h.Marshal(data)); err != nil {
		return Header{}, nil, err
	}
	for {
		rh, body, err := ReadPacket(c.conn)
		if err != nil {
			return Header{}, nil, err
		}
		if cmd != CmdSendUnitData && rh.Context != h.Context {
			continue // a stale reply to an earlier, timed-out request
		}
		if rh.Command != cmd {
			return rh, nil, fmt.Errorf("reply to command 0x%04X came back as 0x%04X", cmd, rh.Command)
		}
		if rh.Status != 0 {
			return rh, nil, fmt.Errorf("encapsulation error: %s", EncapStatusText(rh.Status))
		}
		return rh, body, nil
	}
}

// sendRRLocked sends an unconnected CIP message to the target itself.
func (c *Client) sendRRLocked(msg []byte) (*Response, error) {
	_, body, err := c.exchangeLocked(CmdSendRRData, RRData(uint16(c.timeout()/time.Second)+1,
		Item{Type: ItemNullAddress}, Item{Type: ItemUnconnectedData, Data: msg}))
	if err != nil {
		return nil, err
	}
	items, err := ParseRRData(body)
	if err != nil {
		return nil, err
	}
	for _, it := range items {
		if it.Type == ItemUnconnectedData {
			return ParseResponse(it.Data)
		}
	}
	return nil, errors.New("SendRRData reply without unconnected data")
}

// sendUnitLocked sends a CIP message over the open connection.
func (c *Client) sendUnitLocked(msg []byte) (*Response, error) {
	c.seq++
	seq := c.seq
	data := binary.LittleEndian.AppendUint16(nil, seq)
	addr := binary.LittleEndian.AppendUint32(nil, c.otID)
	for tries := 0; ; tries++ {
		var body []byte
		var err error
		if tries == 0 {
			_, body, err = c.exchangeLocked(CmdSendUnitData, RRData(0,
				Item{Type: ItemConnectedAddress, Data: addr}, Item{Type: ItemConnectedData, Data: append(data, msg...)}))
		} else {
			_, body, err = ReadPacket(c.conn)
		}
		if err != nil {
			return nil, err
		}
		items, err := ParseRRData(body)
		if err != nil {
			return nil, err
		}
		var cd []byte
		for _, it := range items {
			if it.Type == ItemConnectedAddress && (len(it.Data) != 4 || !c.ownConnID(binary.LittleEndian.Uint32(it.Data))) {
				return nil, errors.New("connected reply for another connection")
			}
			if it.Type == ItemConnectedData {
				cd = it.Data
			}
		}
		if len(cd) < 2 {
			return nil, errors.New("SendUnitData reply without connected data")
		}
		if got := binary.LittleEndian.Uint16(cd); got != seq {
			if tries < 3 {
				continue // a late reply to an earlier request
			}
			return nil, fmt.Errorf("sequence count %d in reply, want %d", got, seq)
		}
		return ParseResponse(cd[2:])
	}
}

// ownConnID reports whether the connected address of a reply names our
// connection. Targets put the T→O connection ID there; some (cpppo's
// server) echo the O→T ID of the request instead, which is still
// unambiguous within our session, so both are accepted.
func (c *Client) ownConnID(id uint32) bool {
	return id == c.toID || id == c.otID
}

// forwardOpenBody builds a (Large) Forward Open request body.
func (c *Client) forwardOpenBody(large bool) []byte {
	c.serial = uint16(rand.Uint32())
	c.origSer = rand.Uint32()
	c.toID = rand.Uint32()
	size := c.ConnSize
	if size <= 0 {
		size = DefaultConnSize
	}
	keep := c.KeepAlive
	if keep <= 0 {
		keep = time.Minute
	}
	const rpi = 2 * time.Second
	mult := byte(0) // timeout = RPI × 4<<mult
	for mult < 7 && rpi*time.Duration(4<<mult) < keep {
		mult++
	}
	c.connTimeout = rpi * time.Duration(4<<mult)
	b := []byte{priorityTick, timeoutTicks}
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, c.toID)
	b = binary.LittleEndian.AppendUint16(b, c.serial)
	b = binary.LittleEndian.AppendUint16(b, originatorVendor)
	b = binary.LittleEndian.AppendUint32(b, c.origSer)
	b = append(b, mult, 0, 0, 0)
	for range 2 { // O→T then T→O: RPI and point-to-point, variable size
		b = binary.LittleEndian.AppendUint32(b, uint32(rpi/time.Microsecond))
		if large {
			b = binary.LittleEndian.AppendUint32(b, 0x42000000|uint32(size))
		} else {
			b = binary.LittleEndian.AppendUint16(b, 0x4200|uint16(size&0x1FF))
		}
	}
	b = append(b, 0xA3) // class 3, application triggered, server
	path := c.connPath()
	b = append(b, byte(len(path)/2))
	return append(b, path...)
}

func (c *Client) connPath() []byte {
	return append(append([]byte(nil), c.Route...), Logical(ClassMessageRouter, 1, -1)...)
}

func (c *Client) forwardCloseBody() []byte {
	b := []byte{priorityTick, timeoutTicks}
	b = binary.LittleEndian.AppendUint16(b, c.serial)
	b = binary.LittleEndian.AppendUint16(b, originatorVendor)
	b = binary.LittleEndian.AppendUint32(b, c.origSer)
	path := c.connPath()
	b = append(b, byte(len(path)/2), 0)
	return append(b, path...)
}

func (c *Client) forwardOpenLocked() error {
	large := c.ConnSize > 511
	svc := SvcForwardOpen
	if large {
		svc = SvcLargeForwardOpen
	}
	r, err := c.sendRRLocked(Request(svc, Logical(ClassConnectionManager, 1, -1), c.forwardOpenBody(large)))
	if err != nil {
		return err
	}
	if err := r.Err(); err != nil {
		return err
	}
	if len(r.Data) < 26 {
		return errors.New("forward open reply too short")
	}
	c.otID = binary.LittleEndian.Uint32(r.Data)
	c.toID = binary.LittleEndian.Uint32(r.Data[4:])
	c.seq = 0
	c.size = c.ConnSize
	if c.size <= 0 {
		c.size = DefaultConnSize
	}
	c.open = true
	return nil
}

// MaxMessage is the largest CIP message (request or reply) the current
// transport carries.
func (c *Client) MaxMessage() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxLocked()
}

func (c *Client) maxLocked() int {
	if c.open {
		return c.size - 2
	}
	return unconnectedMax
}

// Do sends one CIP request and returns the reply. A transport failure
// closes the session (the next call reconnects); a CIP error status comes
// back in the reply, not as the error.
func (c *Client) Do(ctx context.Context, service byte, path, data []byte) (*Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open && c.connTimeout > 0 && !c.lastUse.IsZero() && time.Since(c.lastUse) > c.connTimeout*4/5 {
		// Idle near or past the connection's timeout (it cannot be longer
		// than about 17 minutes): the target has dropped it or is about to.
		// A new session and connection, rather than a failed request
		// (GRID-66).
		c.closeLocked(true)
	}
	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}
	c.lastUse = time.Now()
	msg := Request(service, path, data)
	var r *Response
	var err error
	switch {
	case c.open:
		r, err = c.sendUnitLocked(msg)
	case c.Route != nil:
		r, err = c.sendRRLocked(Request(SvcUnconnectedSend, Logical(ClassConnectionManager, 1, -1), unconnectedSend(msg, c.Route)))
	default:
		r, err = c.sendRRLocked(msg)
	}
	if err != nil {
		c.closeLocked(false)
		return nil, err
	}
	if c.open && r.Status == StatusConnFailure && len(r.Ext) > 0 && r.Ext[0] == 0x0107 {
		c.closeLocked(false) // the target dropped our connection
	}
	return r, nil
}

// unconnectedSend builds the Unconnected Send body around msg.
func unconnectedSend(msg, route []byte) []byte {
	b := []byte{priorityTick, timeoutTicks}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(msg)))
	b = append(b, msg...)
	if len(msg)%2 == 1 {
		b = append(b, 0)
	}
	b = append(b, byte(len(route)/2), 0)
	return append(b, route...)
}

// ParseUnconnectedSend splits an Unconnected Send body (for simulators).
func ParseUnconnectedSend(b []byte) (msg, route []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("unconnected send too short")
	}
	n := int(binary.LittleEndian.Uint16(b[2:]))
	b = b[4:]
	if len(b) < n+2 {
		return nil, nil, errors.New("unconnected send: message truncated")
	}
	msg = b[:n]
	b = b[n:]
	if n%2 == 1 {
		b = b[1:]
	}
	if len(b) < 2 || len(b) < 2+int(b[0])*2 {
		return nil, nil, errors.New("unconnected send: route truncated")
	}
	return msg, b[2 : 2+int(b[0])*2], nil
}

// ListIdentity asks the target for its identity over TCP.
func (c *Client) ListIdentity(ctx context.Context) (*Identity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}
	_, body, err := c.exchangeLocked(CmdListIdentity, nil)
	if err != nil {
		c.closeLocked(false)
		return nil, err
	}
	ids, err := ParseListIdentity(body)
	if err != nil || len(ids) == 0 {
		return nil, fmt.Errorf("list identity: %v", err)
	}
	return &ids[0], nil
}

// ---- Logix tag services ---------------------------------------------------

// ReadTag reads elements elements of a tag, continuing with Read Tag
// Fragmented when the value does not fit in one reply.
func (c *Client) ReadTag(ctx context.Context, tag string, elements int) (Type, []byte, error) {
	path, err := TagPath(tag)
	if err != nil {
		return Type{}, nil, err
	}
	r, err := c.Do(ctx, SvcReadTag, path, binary.LittleEndian.AppendUint16(nil, uint16(elements)))
	if err != nil {
		return Type{}, nil, err
	}
	return c.finishRead(ctx, path, elements, r)
}

// finishRead decodes a Read Tag reply and fetches the rest when partial.
func (c *Client) finishRead(ctx context.Context, path []byte, elements int, r *Response) (Type, []byte, error) {
	if err := r.Err(); err != nil {
		return Type{}, nil, err
	}
	t, data, err := ParseType(r.Data)
	if err != nil {
		return Type{}, nil, err
	}
	out := append([]byte(nil), data...)
	for r.Status == StatusPartial {
		body := binary.LittleEndian.AppendUint16(nil, uint16(elements))
		body = binary.LittleEndian.AppendUint32(body, uint32(len(out)))
		r, err = c.Do(ctx, SvcReadTagFragmented, path, body)
		if err != nil {
			return Type{}, nil, err
		}
		if err := r.Err(); err != nil {
			return Type{}, nil, err
		}
		_, data, err := ParseType(r.Data)
		if err != nil {
			return Type{}, nil, err
		}
		if len(data) == 0 && r.Status == StatusPartial {
			return Type{}, nil, errors.New("fragmented read made no progress")
		}
		out = append(out, data...)
	}
	return t, out, nil
}

// TagRead is one tag of a batched read and its result.
type TagRead struct {
	Tag      string
	Elements int
	Type     Type
	Data     []byte
	Err      error
}

// ReadTags reads several tags in one Multiple Service Packet (the caller
// keeps the batch within MaxMessage); replies that were cut short are
// completed with fragmented reads. The error is for the whole batch.
func (c *Client) ReadTags(ctx context.Context, reads []*TagRead) error {
	if len(reads) == 1 {
		r := reads[0]
		r.Type, r.Data, r.Err = c.ReadTag(ctx, r.Tag, r.Elements)
		return transportErr(r.Err)
	}
	paths := make([][]byte, len(reads))
	var reqs [][]byte
	var idx []int
	for i, r := range reads {
		p, err := TagPath(r.Tag)
		if err != nil {
			r.Err = err
			continue
		}
		paths[i] = p
		reqs = append(reqs, Request(SvcReadTag, p, binary.LittleEndian.AppendUint16(nil, uint16(r.Elements))))
		idx = append(idx, i)
	}
	if len(reqs) == 0 {
		return nil
	}
	resp, err := c.Do(ctx, SvcMultipleService, Logical(ClassMessageRouter, 1, -1), MultipleService(reqs))
	if err != nil {
		return err
	}
	if resp.Status != StatusSuccess && resp.Status != StatusEmbeddedError {
		for _, i := range idx {
			reads[i].Err = resp.Err()
		}
		return nil
	}
	parts, err := SplitMultiple(resp.Data)
	if err != nil || len(parts) != len(idx) {
		return fmt.Errorf("multiple service reply: %v (%d replies for %d requests)", err, len(parts), len(idx))
	}
	for k, i := range idx {
		r := reads[i]
		er, err := ParseResponse(parts[k])
		if err != nil {
			r.Err = err
			continue
		}
		r.Type, r.Data, r.Err = c.finishRead(ctx, paths[i], r.Elements, er)
		if te := transportErr(r.Err); te != nil {
			return te
		}
	}
	return nil
}

// transportErr returns err unless it is a CIP status (the device answered).
func transportErr(err error) error {
	var ce *Error
	if err == nil || errors.As(err, &ce) {
		return nil
	}
	return err
}

// IsCIP reports a CIP status error (the device answered and refused).
func IsCIP(err error) bool {
	var ce *Error
	return errors.As(err, &ce)
}

// WriteTag writes a tag's value, with Write Tag Fragmented when the data
// does not fit in one message.
func (c *Client) WriteTag(ctx context.Context, tag string, t Type, elements int, data []byte) error {
	path, err := TagPath(tag)
	if err != nil {
		return err
	}
	tb := t.Marshal()
	max := c.MaxMessage()
	head := 2 + len(path) + len(tb) + 2
	if head+len(data) <= max {
		body := append(append(tb, byte(elements), byte(elements>>8)), data...)
		r, err := c.Do(ctx, SvcWriteTag, path, body)
		if err != nil {
			return err
		}
		return r.WriteErr()
	}
	chunk := max - head - 4
	if sz := t.Size(); sz > 0 {
		chunk -= chunk % sz
	} else {
		chunk -= chunk % 4
	}
	if chunk <= 0 {
		return errors.New("tag path too long for the connection size")
	}
	for off := 0; off < len(data); off += chunk {
		end := min(off+chunk, len(data))
		body := append(append([]byte(nil), tb...), byte(elements), byte(elements>>8))
		body = binary.LittleEndian.AppendUint32(body, uint32(off))
		body = append(body, data[off:end]...)
		r, err := c.Do(ctx, SvcWriteTagFragmented, path, body)
		if err != nil {
			return err
		}
		if err := r.WriteErr(); err != nil {
			return err
		}
	}
	return nil
}

// GetAttribute reads one attribute (Get_Attribute_Single), or every
// attribute of the instance when attr < 0 (Get_Attribute_All).
func (c *Client) GetAttribute(ctx context.Context, class, instance uint16, attr int) ([]byte, error) {
	svc := SvcGetAttributeSingle
	if attr < 0 {
		svc = SvcGetAttributesAll
	}
	r, err := c.Do(ctx, svc, Logical(class, instance, attr), nil)
	if err != nil {
		return nil, err
	}
	if err := r.Err(); err != nil {
		return nil, err
	}
	return r.Data, nil
}

// SetAttribute writes one attribute (Set_Attribute_Single).
func (c *Client) SetAttribute(ctx context.Context, class, instance uint16, attr int, data []byte) error {
	r, err := c.Do(ctx, SvcSetAttributeSingle, Logical(class, instance, attr), data)
	if err != nil {
		return err
	}
	return r.WriteErr()
}

// ---- discovery ---------------------------------------------------------------

// Discover sends ListIdentity over UDP to addr (a broadcast or unicast
// host:port) and collects replies for wait.
func Discover(ctx context.Context, addr string, wait time.Duration) ([]Identity, error) {
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	h := Header{Command: CmdListIdentity}
	binary.LittleEndian.PutUint64(h.Context[:], rand.Uint64())
	if err := lanbcast.WriteBroadcast(pc, h.Marshal(nil), ua); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = pc.SetReadDeadline(deadline)
	var out []Identity
	seen := map[string]bool{}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			break
		}
		rh, err := ParseHeader(buf[:n])
		if err != nil || rh.Command != CmdListIdentity || rh.Context != h.Context || int(rh.Length) > n-HeaderLen {
			continue
		}
		ids, err := ParseListIdentity(buf[HeaderLen : HeaderLen+int(rh.Length)])
		if err != nil {
			continue
		}
		for _, id := range ids {
			if id.IP == "0.0.0.0" {
				id.IP = from.IP.String()
			}
			key := id.IP + "/" + id.Serial
			if !seen[key] {
				seen[key] = true
				out = append(out, id)
			}
		}
	}
	return out, nil
}
