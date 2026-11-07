// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/cB-Sigma/enip"
	"github.com/cB-Sigma/enip/server"
)

// startServer starts s on a free loopback port and returns a client for
// it.
func startServer(t *testing.T, s *server.Server) *enip.Client {
	t.Helper()
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	c := &enip.Client{Addr: s.Addr(), Timeout: 2 * time.Second}
	t.Cleanup(c.Close)
	return c
}

// The identity's revision follows SetIdentity (Major and Minor, or the
// Revision text), in attribute 4 and in the ListIdentity item; without
// one it stays 33.11 (issue #1).
func TestIdentityRevision(t *testing.T) {
	for _, tc := range []struct {
		id         enip.Identity
		major, min byte
		text       string
	}{
		{enip.Identity{Protocol: 1, Vendor: 1, DeviceType: 14, ProductCode: 54, ProductName: "repro"}, 33, 11, "33.011"},
		{enip.Identity{Protocol: 1, Vendor: 1, DeviceType: 14, ProductCode: 54, ProductName: "repro", Major: 20, Minor: 11}, 20, 11, "20.011"},
		{enip.Identity{Protocol: 1, Vendor: 1, DeviceType: 14, ProductCode: 54, ProductName: "repro", Revision: "2.007"}, 2, 7, "2.007"},
	} {
		s := server.New()
		s.SetIdentity(tc.id, 1)
		c := startServer(t, s)
		r, err := c.Do(ctx(t), enip.SvcGetAttributeSingle, enip.Logical(1, 1, 4), nil)
		if err != nil || r.Status != 0 || !bytes.Equal(r.Data, []byte{tc.major, tc.min}) {
			t.Errorf("%+v: attribute 4 = %+v, %v", tc.id, r, err)
		}
		r, err = c.Do(ctx(t), enip.SvcGetAttributesAll, enip.Logical(1, 1, -1), nil)
		if err != nil || r.Status != 0 || len(r.Data) < 8 || !bytes.Equal(r.Data[6:8], []byte{tc.major, tc.min}) {
			t.Errorf("%+v: Get_Attributes_All = %+v, %v", tc.id, r, err)
		}
		id, err := c.ListIdentity(ctx(t))
		if err != nil || id.Revision != tc.text || id.Major != tc.major || id.Minor != tc.min {
			t.Errorf("%+v: ListIdentity = %+v, %v", tc.id, id, err)
		}
		s.Stop()
	}
}
