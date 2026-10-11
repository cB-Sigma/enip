// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cB-Sigma/enip"
)

// Logix objects for tag browsing.
const (
	ClassSymbol   uint16 = 0x6B
	ClassTemplate uint16 = 0x6C

	SvcGetAttributeList         byte = 0x03
	SvcGetInstanceAttributeList byte = 0x55
	SvcReadTemplate             byte = 0x4C // Read Tag's code, on a template instance
)

// Field is one member of a structure: a BOOL with Bit set is a bit of the
// byte at Offset (Logix packs BOOL members so, in a hidden SINT host
// member); Array is the element count of an array member (0: scalar).
type Field struct {
	Name   string
	Type   enip.Type
	Offset int
	Array  int
	Bit    int
	Hidden bool // a host member clients do not show
}

// StructDef is a structure (UDT) definition as the Template object serves
// it.
type StructDef struct {
	Name   string
	Handle uint16 // the structure handle in read replies and writes
	Size   int    // bytes
	Fields []Field
}

// StringDef is the built-in Logix STRING (its template name is
// ASCIISTRING82).
var StringDef = StructDef{Name: "ASCIISTRING82", Handle: enip.HandleSTRING, Size: enip.StringSize, Fields: []Field{
	{Name: "LEN", Type: enip.Type{Code: enip.TypeDINT}, Offset: 0},
	{Name: "DATA", Type: enip.Type{Code: enip.TypeSINT}, Offset: 4, Array: enip.StringChars},
}}

// CheckStruct reports a structure whose members do not fit: a member
// beyond Size, members overlapping (BOOL bits share their host byte), or
// a nested structure not defined yet.
func (s *Server) CheckStruct(d StructDef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	type span struct {
		lo, hi int
		name   string
	}
	var spans []span
	for _, f := range d.Fields {
		if f.Type.Code == enip.TypeBOOL && f.Array == 0 {
			if f.Offset >= d.Size || f.Bit < 0 || f.Bit > 7 {
				return fmt.Errorf("%s.%s: bit %d at %d is outside the structure", d.Name, f.Name, f.Bit, f.Offset)
			}
			continue
		}
		sz := s.sizeOf(f.Type)
		if sz == 0 {
			return fmt.Errorf("%s.%s: type %s has no known size (define nested structures first)", d.Name, f.Name, f.Type.Name())
		}
		sp := span{f.Offset, f.Offset + sz*max(f.Array, 1), f.Name}
		if sp.hi > d.Size {
			return fmt.Errorf("%s.%s: ends at %d, beyond the %d-byte structure", d.Name, f.Name, sp.hi, d.Size)
		}
		for _, o := range spans {
			if sp.lo < o.hi && o.lo < sp.hi && !(f.Hidden || strings.HasPrefix(o.name, "ZZZZZZZZZZ")) {
				return fmt.Errorf("%s.%s overlaps %s", d.Name, f.Name, o.name)
			}
		}
		spans = append(spans, sp)
	}
	return nil
}

// DefineStruct registers a structure for browsing and member access and
// returns its template instance number (CheckStruct finds layout
// mistakes first).
func (s *Server) DefineStruct(d StructDef) uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inst, ok := s.tmplInst[d.Handle]; ok {
		s.structs[d.Handle] = &d
		return inst
	}
	inst := uint16(0x100) + s.nextTmpl
	if d.Handle == enip.HandleSTRING {
		inst = 0x0FCE & 0x0FFF // a predefined type's instance, above 0xEFF
	} else {
		s.nextTmpl++
	}
	s.structs[d.Handle] = &d
	s.tmplInst[d.Handle] = inst
	return inst
}

func (s *Server) structByInstance(inst uint16) *StructDef {
	for h, i := range s.tmplInst {
		if i == inst {
			return s.structs[h]
		}
	}
	return nil
}

// sizeOf is one element's size of t; d.mu held.
func (s *Server) sizeOf(t enip.Type) int {
	if t.IsStruct() {
		if d := s.structs[t.Handle]; d != nil {
			return d.Size
		}
	}
	return t.Size()
}

// view is a tag or a member of one, resolved to its bytes.
type view struct {
	typ      enip.Type
	data     []byte // every element
	elements int
	ro       bool
	bit      int // a BOOL member's bit in data[0]; -1 otherwise
}

// resolve finds a tag, or a member path into a structure tag ("Tag.A.B");
// s.mu held.
func (s *Server) resolve(name string) (*view, bool) {
	if t := s.tags[name]; t != nil {
		return &view{typ: t.Type, data: t.Data, elements: t.Elements, ro: t.ReadOnly, bit: -1}, true
	}
	parts := strings.Split(name, ".")
	for i := len(parts) - 1; i >= 1; i-- {
		t := s.tags[strings.Join(parts[:i], ".")]
		if t == nil || !t.Type.IsStruct() {
			continue
		}
		def := s.structs[t.Type.Handle]
		data := t.Data
		if def == nil || len(data) < def.Size {
			return nil, false
		}
		data = data[:def.Size]
		for j, mn := range parts[i:] {
			var f *Field
			for k := range def.Fields {
				if strings.EqualFold(def.Fields[k].Name, mn) {
					f = &def.Fields[k]
					break
				}
			}
			if f == nil {
				return nil, false
			}
			last := j == len(parts[i:])-1
			n := max(f.Array, 1)
			sz := s.sizeOf(f.Type)
			if f.Type.Code == enip.TypeBOOL && f.Array == 0 {
				if !last || f.Offset >= len(data) {
					return nil, false
				}
				return &view{typ: f.Type, data: data[f.Offset : f.Offset+1], elements: 1, ro: t.ReadOnly, bit: f.Bit}, true
			}
			if sz == 0 || f.Offset+sz*n > len(data) {
				return nil, false
			}
			if last {
				return &view{typ: f.Type, data: data[f.Offset : f.Offset+sz*n], elements: n, ro: t.ReadOnly, bit: -1}, true
			}
			if !f.Type.IsStruct() || s.structs[f.Type.Handle] == nil {
				return nil, false
			}
			def = s.structs[f.Type.Handle]
			data = data[f.Offset : f.Offset+def.Size]
		}
	}
	return nil, false
}

// symbolType is the Symbol object's type word of a tag: an atomic code or
// 0x8000 and the template instance, with the number of dimensions in
// bits 13 and 14.
func (s *Server) symbolType(t *Tag) uint16 {
	var v uint16
	if t.Type.IsStruct() {
		v = 0x8000 | s.tmplInst[t.Type.Handle]&0x0FFF
	} else {
		v = t.Type.Code & 0xFF
	}
	if t.Elements > 1 {
		v |= 1 << 13
	}
	return v
}

// symbols are the Symbol object instances of a scope ("" for the
// controller, else a program name): instance, name and tag (nil for a
// program's own entry); s.mu held.
func (s *Server) symbols(program string) []symbol {
	var out []symbol
	programs := map[string]bool{}
	for i, name := range s.order {
		prog, short, scoped := splitProgram(name)
		switch {
		case program == "" && scoped:
			programs[prog] = true
		case program == "" && !scoped:
			out = append(out, symbol{uint32(i + 1), name, s.tags[name]})
		case scoped && strings.EqualFold(prog, program):
			out = append(out, symbol{uint32(i + 1), short, s.tags[name]})
		}
	}
	if program == "" {
		var names []string
		for p := range programs {
			names = append(names, p)
		}
		sort.Strings(names)
		for i, p := range names {
			out = append(out, symbol{uint32(len(s.order) + 1 + i), "Program:" + p, nil})
		}
	}
	return out
}

type symbol struct {
	inst uint32
	name string
	tag  *Tag
}

func splitProgram(name string) (prog, short string, ok bool) {
	rest, ok := strings.CutPrefix(name, "Program:")
	if !ok {
		return "", name, false
	}
	prog, short, ok = strings.Cut(rest, ".")
	return prog, short, ok
}

// instanceList answers Get_Instance_Attribute_List on the Symbol object:
// from instance start on, each instance with the attributes asked for,
// as many as fit in limit (status 0x06 when more remain).
func (s *Server) instanceList(program string, start uint32, d []byte, limit int) []byte {
	le := binary.LittleEndian
	if len(d) < 2 || len(d) < 2+2*int(le.Uint16(d)) {
		return enip.MarshalResponse(SvcGetInstanceAttributeList, enip.StatusNotEnoughData, nil, nil)
	}
	n := int(le.Uint16(d))
	attrs := make([]uint16, n)
	for i := range attrs {
		attrs[i] = le.Uint16(d[2+2*i:])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []byte
	status := byte(0)
	for _, sym := range s.symbols(program) {
		if sym.inst < start {
			continue
		}
		e := le.AppendUint32(nil, sym.inst)
		for _, a := range attrs {
			switch a {
			case 1:
				e = le.AppendUint16(e, uint16(len(sym.name)))
				e = append(e, sym.name...)
			case 2:
				if sym.tag == nil {
					e = le.AppendUint16(e, 0x1068) // a program: a system entry
				} else {
					e = le.AppendUint16(e, s.symbolType(sym.tag))
				}
			case 3, 5:
				e = le.AppendUint32(e, sym.inst<<4)
			case 6:
				e = le.AppendUint32(e, 1<<26) // a base tag, not an alias
			case 7:
				sz := 0
				if sym.tag != nil {
					sz = s.sizeOf(sym.tag.Type)
				}
				e = le.AppendUint16(e, uint16(sz))
			case 8:
				dim := uint32(0)
				if sym.tag != nil && sym.tag.Elements > 1 {
					dim = uint32(sym.tag.Elements)
				}
				e = le.AppendUint32(e, dim)
				e = le.AppendUint32(e, 0)
				e = le.AppendUint32(e, 0)
			case 10:
				acc := byte(0)
				if sym.tag != nil && sym.tag.ReadOnly {
					acc = 2
				}
				e = append(e, acc)
			default:
				return enip.MarshalResponse(SvcGetInstanceAttributeList, enip.StatusAttrNotSupported, nil, nil)
			}
		}
		if 4+len(out)+len(e) > limit {
			status = enip.StatusPartial
			break
		}
		out = append(out, e...)
	}
	return enip.MarshalResponse(SvcGetInstanceAttributeList, status, nil, out)
}

// templateBytes is what Read Template returns: 8 octets per member (array
// length or bit number, type word, offset), then "<name>;n" and the
// member names, each ended by a NUL.
func (s *Server) templateBytes(d *StructDef) []byte {
	le := binary.LittleEndian
	var b []byte
	for _, f := range d.Fields {
		info := uint16(f.Array)
		if f.Type.Code == enip.TypeBOOL && f.Array == 0 {
			info = uint16(f.Bit)
		}
		b = le.AppendUint16(b, info)
		if f.Type.IsStruct() {
			b = le.AppendUint16(b, 0x8000|s.tmplInst[f.Type.Handle]&0x0FFF)
		} else {
			b = le.AppendUint16(b, f.Type.Code)
		}
		b = le.AppendUint32(b, uint32(f.Offset))
	}
	b = append(b, d.Name+";n"+strconv.Itoa(len(d.Fields))...)
	b = append(b, 0)
	for _, f := range d.Fields {
		b = append(b, f.Name...)
		b = append(b, 0)
	}
	return b
}

// defSize is the template's object definition size in 32-bit words, read
// so that words×4 − 21 octets cover the template data (the way Logix
// clients ask for it).
func defSize(n int) uint32 { return uint32((n + 21 + 3) / 4) }

// templateService answers Get_Attribute_List and Read Template on a
// template instance.
func (s *Server) templateService(svc byte, inst uint16, d []byte, limit int) []byte {
	s.mu.Lock()
	def := s.structByInstance(inst)
	var tb []byte
	if def != nil {
		tb = s.templateBytes(def)
	}
	s.mu.Unlock()
	if def == nil {
		return enip.MarshalResponse(svc, enip.StatusObjectMissing, nil, nil)
	}
	le := binary.LittleEndian
	switch svc {
	case SvcGetAttributeList:
		if len(d) < 2 || len(d) < 2+2*int(le.Uint16(d)) {
			return enip.MarshalResponse(svc, enip.StatusNotEnoughData, nil, nil)
		}
		n := int(le.Uint16(d))
		out := le.AppendUint16(nil, uint16(n))
		for i := 0; i < n; i++ {
			a := le.Uint16(d[2+2*i:])
			out = le.AppendUint16(out, a)
			switch a {
			case 1:
				out = le.AppendUint16(le.AppendUint16(out, 0), def.Handle)
			case 2:
				out = le.AppendUint16(le.AppendUint16(out, 0), uint16(len(def.Fields)))
			case 4:
				out = le.AppendUint32(le.AppendUint16(out, 0), defSize(len(tb)))
			case 5:
				out = le.AppendUint32(le.AppendUint16(out, 0), uint32(def.Size))
			default:
				out = le.AppendUint16(out, uint16(enip.StatusAttrNotSupported))
			}
		}
		return enip.MarshalResponse(svc, 0, nil, out)
	case SvcReadTemplate:
		if len(d) < 6 {
			return enip.MarshalResponse(svc, enip.StatusNotEnoughData, nil, nil)
		}
		off, n := int(le.Uint32(d)), int(le.Uint16(d[4:]))
		if off > len(tb) {
			return enip.MarshalResponse(svc, enip.StatusTooMuchData, nil, nil)
		}
		chunk := tb[off:]
		status := byte(0)
		if n < len(chunk) {
			chunk = chunk[:n]
		}
		room := limit - 4
		room -= room % 4
		if len(chunk) > room {
			chunk, status = chunk[:room], enip.StatusPartial
		} else if off+len(chunk) < len(tb) {
			status = enip.StatusPartial
		}
		return enip.MarshalResponse(svc, status, nil, chunk)
	}
	return enip.MarshalResponse(svc, enip.StatusServiceNotSup, nil, nil)
}

// tagNameOfInstance is the full name of a Symbol instance; s.mu held.
func (s *Server) tagNameOfInstance(inst uint32) (string, bool) {
	if inst < 1 || int(inst) > len(s.order) {
		return "", false
	}
	return s.order[inst-1], true
}

// parsePath reads a tag path: symbolic segments, a Symbol instance
// (class 0x6B, instance n) in place of the tag's name, and element
// segments; s.mu held.
func (s *Server) parsePath(p []byte) (string, int, bool) {
	var names []string
	idx := 0
	le := binary.LittleEndian
	for len(p) > 0 {
		switch p[0] {
		case 0x91:
			if len(p) < 2 || len(p) < 2+int(p[1]) {
				return "", 0, false
			}
			n := int(p[1])
			names = append(names, string(p[2:2+n]))
			p = p[2+n+n%2:]
		case 0x20: // class
			if len(p) < 2 || uint16(p[1]) != ClassSymbol {
				return "", 0, false
			}
			p = p[2:]
			var inst uint32
			switch {
			case len(p) >= 2 && p[0] == 0x24:
				inst, p = uint32(p[1]), p[2:]
			case len(p) >= 4 && p[0] == 0x25:
				inst, p = uint32(le.Uint16(p[2:])), p[4:]
			case len(p) >= 6 && p[0] == 0x26:
				inst, p = le.Uint32(p[2:]), p[6:]
			default:
				return "", 0, false
			}
			full, ok := s.tagNameOfInstance(inst)
			if !ok {
				return "", 0, false
			}
			// A program's symbolic segment before the instance is part
			// of the full name already.
			names = []string{full}
		case 0x28:
			if len(p) < 2 {
				return "", 0, false
			}
			idx, p = int(p[1]), p[2:]
		case 0x29:
			if len(p) < 4 {
				return "", 0, false
			}
			idx, p = int(le.Uint16(p[2:])), p[4:]
		case 0x2A:
			if len(p) < 6 {
				return "", 0, false
			}
			idx, p = int(le.Uint32(p[2:])), p[6:]
		default:
			return "", 0, false
		}
	}
	return strings.Join(names, "."), idx, len(names) > 0
}

// browsePath reads [0x91 "Program:X"] class 0x6B or 0x6C, instance.
func browsePath(p []byte) (program string, class uint16, inst uint32, ok bool) {
	le := binary.LittleEndian
	if len(p) >= 2 && p[0] == 0x91 {
		n := int(p[1])
		if len(p) < 2+n {
			return "", 0, 0, false
		}
		program = strings.TrimPrefix(string(p[2:2+n]), "Program:")
		p = p[2+n+n%2:]
	}
	switch {
	case len(p) >= 2 && p[0] == 0x20:
		class, p = uint16(p[1]), p[2:]
	case len(p) >= 4 && p[0] == 0x21:
		class, p = le.Uint16(p[2:]), p[4:]
	default:
		return "", 0, 0, false
	}
	switch {
	case len(p) == 2 && p[0] == 0x24:
		inst = uint32(p[1])
	case len(p) == 4 && p[0] == 0x25:
		inst = uint32(le.Uint16(p[2:]))
	case len(p) == 6 && p[0] == 0x26:
		inst = le.Uint32(p[2:])
	default:
		return "", 0, 0, false
	}
	return program, class, inst, class == ClassSymbol || class == ClassTemplate
}
