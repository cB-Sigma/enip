// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package enip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Logix objects used to browse tags and structures.
const (
	ClassSymbol                 uint16 = 0x6B
	ClassTemplate               uint16 = 0x6C
	SvcGetAttributeList         byte   = 0x03
	SvcGetInstanceAttributeList byte   = 0x55
)

// TagInfo is one entry of a controller's (or program's) tag list.
type TagInfo struct {
	Name     string
	Instance uint32 // the Symbol object instance
	// Type is the tag's data type: an atomic code, or TypeStruct with
	// Template set (the structure's template instance; ReadTemplate gives
	// its definition and handle).
	Type     Type
	Template uint16
	Dims     [3]int // array dimensions; zero for a scalar
	ReadOnly bool   // external access read only (or none)
	// System marks entries a controller lists that are not user tags:
	// programs ("Program:<name>"), routines, tasks, module and system
	// tags.
	System bool
}

// Elements is the number of elements of the tag (1 for a scalar).
func (t TagInfo) Elements() int {
	n := 1
	for _, d := range t.Dims {
		if d > 0 {
			n *= d
		}
	}
	return n
}

// ListTags lists the tags of the controller (program "") or of one program,
// reading the Symbol object's instances (Get_Instance_Attribute_List,
// repeated until the controller says the list is complete).
func (c *Client) ListTags(ctx context.Context, program string) ([]TagInfo, error) {
	le := binary.LittleEndian
	var out []TagInfo
	attrs := []uint16{1, 2, 8, 10}
	req := le.AppendUint16(nil, uint16(len(attrs)))
	for _, a := range attrs {
		req = le.AppendUint16(req, a)
	}
	start := uint32(0)
	for {
		var path []byte
		if program != "" {
			path = Symbolic(path, "Program:"+strings.TrimPrefix(program, "Program:"))
		}
		path = append(path, logical(logical(nil, 0x20, uint32(ClassSymbol)), 0x24, start)...)
		r, err := c.Do(ctx, SvcGetInstanceAttributeList, path, req)
		if err != nil {
			return nil, err
		}
		if r.Status != StatusSuccess && r.Status != StatusPartial {
			return nil, &Error{Service: SvcGetInstanceAttributeList, Status: r.Status, Ext: r.Ext}
		}
		b := r.Data
		last := start
		for len(b) > 0 {
			if len(b) < 6 {
				return nil, errors.New("tag list entry truncated")
			}
			ti := TagInfo{Instance: le.Uint32(b)}
			n := int(le.Uint16(b[4:]))
			if len(b) < 6+n+2+12+1 {
				return nil, errors.New("tag list entry truncated")
			}
			ti.Name = string(b[6 : 6+n])
			b = b[6+n:]
			st := le.Uint16(b)
			for i := 0; i < 3; i++ {
				ti.Dims[i] = int(le.Uint32(b[2+4*i:]))
			}
			access := b[14]
			b = b[15:]
			ti.ReadOnly = access == 2 || access == 3
			if st&0x8000 != 0 {
				ti.Template = st & 0x0FFF
				ti.Type = Type{Code: TypeStruct}
			} else {
				ti.Type = Type{Code: st & 0xFF}
			}
			ti.System = st&0x1000 != 0 || strings.Contains(ti.Name, ":") || strings.HasPrefix(ti.Name, "__")
			if program != "" && !ti.System {
				ti.Name = "Program:" + strings.TrimPrefix(program, "Program:") + "." + ti.Name
			}
			out = append(out, ti)
			last = ti.Instance
		}
		if r.Status == StatusSuccess {
			return out, nil
		}
		if last < start {
			return nil, errors.New("the controller's tag list does not advance")
		}
		start = last + 1
	}
}

// TemplateMember is one member of a structure definition.
type TemplateMember struct {
	Name     string
	Type     Type   // atomic, or TypeStruct with Template set
	Template uint16 // a nested structure's template instance
	Offset   int
	Array    int // element count of an array member (0: scalar)
	Bit      int // a BOOL member's bit at Offset
	Hidden   bool
}

// Template is a structure (UDT) definition read from the controller.
type Template struct {
	Instance uint16
	Name     string
	Handle   uint16 // the structure handle in reads and writes
	Size     int    // bytes of one value
	Members  []TemplateMember
}

// ReadTemplate reads a structure's definition from its template instance
// (TagInfo.Template): its attributes, then the definition itself.
func (c *Client) ReadTemplate(ctx context.Context, instance uint16) (Template, error) {
	le := binary.LittleEndian
	t := Template{Instance: instance}
	path := Logical(ClassTemplate, instance, -1)
	req := le.AppendUint16(nil, 4)
	for _, a := range []uint16{4, 5, 2, 1} {
		req = le.AppendUint16(req, a)
	}
	r, err := c.Do(ctx, SvcGetAttributeList, path, req)
	if err != nil {
		return t, err
	}
	if r.Status != StatusSuccess {
		return t, &Error{Service: SvcGetAttributeList, Status: r.Status, Ext: r.Ext}
	}
	b := r.Data
	if len(b) < 2 {
		return t, errors.New("template attributes truncated")
	}
	var defWords uint32
	var members int
	b = b[2:]
	for len(b) >= 4 {
		id, status := le.Uint16(b), le.Uint16(b[2:])
		b = b[4:]
		if status != 0 {
			return t, fmt.Errorf("template attribute %d: status 0x%02X", id, status)
		}
		switch id {
		case 1, 2:
			if len(b) < 2 {
				return t, errors.New("template attributes truncated")
			}
			if id == 1 {
				t.Handle = le.Uint16(b)
			} else {
				members = int(le.Uint16(b))
			}
			b = b[2:]
		case 4, 5:
			if len(b) < 4 {
				return t, errors.New("template attributes truncated")
			}
			if id == 4 {
				defWords = le.Uint32(b)
			} else {
				t.Size = int(le.Uint32(b))
			}
			b = b[4:]
		default:
			return t, fmt.Errorf("template attribute %d not asked for", id)
		}
	}
	want := int(defWords)*4 - 21
	if want <= 0 {
		return t, errors.New("template definition size is zero")
	}
	var data []byte
	for len(data) < want {
		req := le.AppendUint32(nil, uint32(len(data)))
		req = le.AppendUint16(req, uint16(want-len(data)))
		r, err := c.Do(ctx, SvcReadTag, path, req)
		if err != nil {
			return t, err
		}
		if r.Status != StatusSuccess && r.Status != StatusPartial {
			return t, &Error{Service: SvcReadTag, Status: r.Status, Ext: r.Ext}
		}
		data = append(data, r.Data...)
		if r.Status == StatusSuccess || len(r.Data) == 0 {
			break
		}
	}
	return t, t.parse(data, members)
}

// parse reads the member table and the names of a template definition.
func (t *Template) parse(b []byte, members int) error {
	le := binary.LittleEndian
	if len(b) < 8*members {
		return errors.New("template definition truncated")
	}
	t.Members = make([]TemplateMember, members)
	for i := range t.Members {
		m := &t.Members[i]
		info, typ, off := le.Uint16(b[8*i:]), le.Uint16(b[8*i+2:]), le.Uint32(b[8*i+4:])
		m.Offset = int(off)
		if typ&0x8000 != 0 {
			m.Type, m.Template = Type{Code: TypeStruct}, typ&0x0FFF
		} else {
			m.Type = Type{Code: typ & 0xFF}
		}
		if m.Type.Code == TypeBOOL {
			m.Bit = int(info)
		} else {
			m.Array = int(info)
		}
	}
	names := bytes.Split(b[8*members:], []byte{0})
	if len(names) == 0 {
		return errors.New("template has no name")
	}
	name, _, _ := strings.Cut(string(names[0]), ";")
	t.Name = name
	if t.Name == "ASCIISTRING82" {
		t.Name = "STRING"
	}
	for i := range t.Members {
		if 1+i < len(names) {
			t.Members[i].Name = string(names[1+i])
		}
		n := t.Members[i].Name
		t.Members[i].Hidden = n == "" || strings.HasPrefix(n, "ZZZZZZZZZZ") || strings.HasPrefix(n, "__")
	}
	if t.Handle == HandleSTRING {
		t.Name = "STRING"
	}
	return nil
}

// DecodeStruct decodes one value of the template's structure into a map
// of member name to value, nested templates read through lookup (nil
// leaves nested structures as raw bytes). Hidden members are left out.
func (t Template) DecodeStruct(b []byte, lookup func(instance uint16) (Template, bool)) (map[string]any, error) {
	if len(b) < t.Size {
		return nil, fmt.Errorf("%s needs %d bytes, got %d", t.Name, t.Size, len(b))
	}
	out := map[string]any{}
	for _, m := range t.Members {
		if m.Hidden {
			continue
		}
		if m.Type.Code == TypeBOOL && m.Array == 0 {
			if m.Offset >= len(b) {
				return nil, fmt.Errorf("member %s beyond the structure", m.Name)
			}
			out[m.Name] = b[m.Offset]&(1<<(m.Bit%8)) != 0
			continue
		}
		n := max(m.Array, 1)
		if m.Type.IsStruct() {
			var nt Template
			ok := false
			if lookup != nil {
				nt, ok = lookup(m.Template)
			}
			if !ok || nt.Size == 0 {
				out[m.Name] = fmt.Sprintf("%x", b[m.Offset:])
				continue
			}
			var vals []any
			for i := 0; i < n; i++ {
				lo := m.Offset + i*nt.Size
				if lo+nt.Size > len(b) {
					return nil, fmt.Errorf("member %s beyond the structure", m.Name)
				}
				var v any
				var err error
				if nt.Handle == HandleSTRING {
					v, err = DecodeString(b[lo : lo+nt.Size])
				} else {
					v, err = nt.DecodeStruct(b[lo:lo+nt.Size], lookup)
				}
				if err != nil {
					return nil, err
				}
				vals = append(vals, v)
			}
			if m.Array == 0 {
				out[m.Name] = vals[0]
			} else {
				out[m.Name] = vals
			}
			continue
		}
		sz := m.Type.Size()
		if sz == 0 || m.Offset+sz*n > len(b) {
			return nil, fmt.Errorf("member %s beyond the structure", m.Name)
		}
		v, err := Decode(m.Type, b[m.Offset:m.Offset+sz*n], n, nil)
		if err != nil {
			return nil, err
		}
		out[m.Name] = v
	}
	return out, nil
}
