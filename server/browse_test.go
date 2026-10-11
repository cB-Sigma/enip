// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"encoding/binary"
	"math"
	"sort"
	"testing"
	"time"

	"github.com/cB-Sigma/enip"
	"github.com/cB-Sigma/enip/server"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// A controller with a UDT that nests another, holds packed BOOLs and a
// STRING member, plus atomic, array, STRING and program-scoped tags.
func newController(t *testing.T) *server.Server {
	t.Helper()
	s := server.New()
	pid := server.StructDef{Name: "PID", Handle: 0x2001, Size: 8, Fields: []server.Field{
		{Name: "Kp", Type: enip.Type{Code: enip.TypeREAL}, Offset: 0},
		{Name: "Ki", Type: enip.Type{Code: enip.TypeREAL}, Offset: 4},
	}}
	s.DefineStruct(pid)
	motor := server.StructDef{Name: "Motor", Handle: 0x2002, Size: 116, Fields: []server.Field{
		{Name: "ZZZZZZZZZZMotor0", Type: enip.Type{Code: enip.TypeSINT}, Offset: 0, Hidden: true},
		{Name: "Running", Type: enip.Type{Code: enip.TypeBOOL}, Offset: 0, Bit: 0},
		{Name: "Fault", Type: enip.Type{Code: enip.TypeBOOL}, Offset: 0, Bit: 1},
		{Name: "Speed", Type: enip.Type{Code: enip.TypeREAL}, Offset: 4},
		{Name: "Hours", Type: enip.Type{Code: enip.TypeDINT}, Offset: 8, Array: 3},
		{Name: "Loop", Type: enip.Type{Code: enip.TypeStruct, Handle: 0x2002 - 1}, Offset: 20},
		{Name: "Label", Type: enip.Type{Code: enip.TypeStruct, Handle: enip.HandleSTRING}, Offset: 28},
	}}
	s.DefineStruct(motor)
	le := binary.LittleEndian
	m := make([]byte, 116)
	m[0] = 0b01 // running
	le.PutUint32(m[4:], math.Float32bits(1450))
	le.PutUint32(m[8:], 10)
	le.PutUint32(m[12:], 20)
	le.PutUint32(m[16:], 30)
	le.PutUint32(m[20:], math.Float32bits(0.5))
	lbl, _ := enip.EncodeString("Conveyor 3")
	copy(m[28:], lbl)
	s.SetTag("Pump", enip.Type{Code: enip.TypeStruct, Handle: 0x2002}, 1, m)
	s.SetTag("Flow", enip.Type{Code: enip.TypeREAL}, 1, le.AppendUint32(nil, math.Float32bits(12.5)))
	var lv []byte
	for i := range 10 {
		lv = le.AppendUint16(lv, uint16(i))
	}
	s.SetTag("Levels", enip.Type{Code: enip.TypeINT}, 10, lv)
	name, _ := enip.EncodeString("Line A")
	s.SetTag("Title", enip.Type{Code: enip.TypeStruct, Handle: enip.HandleSTRING}, 1, name)
	s.SetTag("Program:Main.Count", enip.Type{Code: enip.TypeDINT}, 1, le.AppendUint32(nil, 42))
	s.SetTag("Locked", enip.Type{Code: enip.TypeDINT}, 1, le.AppendUint32(nil, 1))
	s.SetReadOnly("Locked", true)
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s
}

func TestListTagsAndTemplates(t *testing.T) {
	s := newController(t)
	for _, size := range []int{0, 120} { // unconnected; a small connection that pages the lists
		c := &enip.Client{Addr: s.Addr(), Timeout: 2 * time.Second, Connected: size > 0, ConnSize: size}
		defer c.Close()
		tags, err := c.ListTags(ctx(t), "")
		if err != nil {
			t.Fatal(err)
		}
		byName := map[string]enip.TagInfo{}
		var names []string
		for _, ti := range tags {
			byName[ti.Name] = ti
			names = append(names, ti.Name)
		}
		sort.Strings(names)
		if len(tags) != 6 || !byName["Program:Main"].System || byName["Levels"].Dims[0] != 10 || !byName["Locked"].ReadOnly {
			t.Fatalf("size %d: tags %v", size, names)
		}
		prog, err := c.ListTags(ctx(t), "Main")
		if err != nil || len(prog) != 1 || prog[0].Name != "Program:Main.Count" || prog[0].Type.Code != enip.TypeDINT {
			t.Fatalf("program tags %+v %v", prog, err)
		}
		pump := byName["Pump"]
		if !pump.Type.IsStruct() || pump.Template == 0 {
			t.Fatalf("Pump %+v", pump)
		}
		cache := map[uint16]enip.Template{}
		lookup := func(inst uint16) (enip.Template, bool) {
			if tp, ok := cache[inst]; ok {
				return tp, true
			}
			tp, err := c.ReadTemplate(ctx(t), inst)
			if err != nil {
				t.Fatalf("template %d: %v", inst, err)
			}
			cache[inst] = tp
			return tp, true
		}
		tp, _ := lookup(pump.Template)
		if tp.Name != "Motor" || tp.Handle != 0x2002 || tp.Size != 116 || len(tp.Members) != 7 || !tp.Members[0].Hidden || tp.Members[2].Bit != 1 {
			t.Fatalf("Motor template %+v", tp)
		}
		ty, data, err := c.ReadTag(ctx(t), "Pump", 1)
		if err != nil || ty.Handle != 0x2002 {
			t.Fatal(ty, err)
		}
		v, err := tp.DecodeStruct(data, lookup)
		if err != nil {
			t.Fatal(err)
		}
		if v["Running"] != true || v["Fault"] != false || v["Speed"] != float64(1450) || v["Label"] != "Conveyor 3" ||
			v["Loop"].(map[string]any)["Kp"] != 0.5 || len(v["Hours"].([]any)) != 3 {
			t.Errorf("Pump decoded as %v", v)
		}
		str, _ := lookup(byName["Title"].Template)
		if str.Name != "STRING" || str.Handle != enip.HandleSTRING || str.Size != 88 {
			t.Errorf("STRING template %+v", str)
		}
	}
}

// Members of a structure tag read and written by name, a BOOL member as
// its bit, and a tag addressed by its Symbol instance.
func TestMembersAndInstances(t *testing.T) {
	s := newController(t)
	c := &enip.Client{Addr: s.Addr(), Timeout: 2 * time.Second}
	defer c.Close()
	ty, b, err := c.ReadTag(ctx(t), "Pump.Speed", 1)
	if err != nil || ty.Code != enip.TypeREAL || math.Float32frombits(binary.LittleEndian.Uint32(b)) != 1450 {
		t.Fatalf("Pump.Speed %v %x %v", ty, b, err)
	}
	if _, b, err = c.ReadTag(ctx(t), "Pump.Loop.Ki", 1); err != nil || len(b) != 4 {
		t.Fatalf("nested member %x %v", b, err)
	}
	if err := c.WriteTag(ctx(t), "Pump.Fault", enip.Type{Code: enip.TypeBOOL}, 1, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, b, _ = c.ReadTag(ctx(t), "Pump.Fault", 1); len(b) != 1 || b[0] != 1 {
		t.Errorf("Pump.Fault after the write: %x", b)
	}
	if raw := s.TagData("Pump"); raw[0] != 0b11 {
		t.Errorf("host byte %08b", raw[0])
	}
	if _, b, err = c.ReadTag(ctx(t), "Pump.Hours[2]", 1); err != nil || binary.LittleEndian.Uint32(b) != 30 {
		t.Errorf("Pump.Hours[2] %x %v", b, err)
	}
	if err := c.WriteTag(ctx(t), "Locked", enip.Type{Code: enip.TypeDINT}, 1, []byte{2, 0, 0, 0}); err == nil {
		t.Error("a read-only tag was written")
	}
	// Symbol instance addressing: class 0x6B, the instance ListTags gave.
	tags, _ := c.ListTags(ctx(t), "")
	var flow uint32
	for _, ti := range tags {
		if ti.Name == "Flow" {
			flow = ti.Instance
		}
	}
	path := append([]byte{0x20, 0x6B, 0x25, 0x00}, binary.LittleEndian.AppendUint16(nil, uint16(flow))...)
	r, err := c.Do(ctx(t), enip.SvcReadTag, path, []byte{1, 0})
	if err != nil || r.Status != 0 || math.Float32frombits(binary.LittleEndian.Uint32(r.Data[2:])) != 12.5 {
		t.Errorf("Flow by instance %d: %+v %v", flow, r, err)
	}
}
