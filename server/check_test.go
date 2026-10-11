// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"strings"
	"testing"

	"github.com/cB-Sigma/enip"
	"github.com/cB-Sigma/enip/server"
)

// CheckStruct catches overlapping members (a PID at 20 running into a
// STRING at 24, the mistake this module's own first interop test made),
// members past the end and unknown nested structures.
func TestCheckStruct(t *testing.T) {
	s := server.New()
	pid := server.StructDef{Name: "PID", Handle: 0x2001, Size: 8, Fields: []server.Field{
		{Name: "Kp", Type: enip.Type{Code: enip.TypeREAL}, Offset: 0}, {Name: "Ki", Type: enip.Type{Code: enip.TypeREAL}, Offset: 4}}}
	if err := s.CheckStruct(pid); err != nil {
		t.Fatal(err)
	}
	s.DefineStruct(pid)
	bad := server.StructDef{Name: "M", Handle: 0x2002, Size: 112, Fields: []server.Field{
		{Name: "Loop", Type: enip.Type{Code: enip.TypeStruct, Handle: 0x2001}, Offset: 20},
		{Name: "Label", Type: enip.Type{Code: enip.TypeStruct, Handle: enip.HandleSTRING}, Offset: 24}}}
	if err := s.CheckStruct(bad); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Errorf("overlap: %v", err)
	}
	bad.Fields[1].Offset, bad.Size = 28, 112
	if err := s.CheckStruct(bad); err == nil || !strings.Contains(err.Error(), "beyond") {
		t.Errorf("past the end: %v", err)
	}
	bad.Size = 116
	if err := s.CheckStruct(bad); err != nil {
		t.Errorf("good layout refused: %v", err)
	}
	bad.Fields = append(bad.Fields, server.Field{Name: "X", Type: enip.Type{Code: enip.TypeStruct, Handle: 0x7777}, Offset: 0})
	if err := s.CheckStruct(bad); err == nil {
		t.Error("an undefined nested structure passed")
	}
}
