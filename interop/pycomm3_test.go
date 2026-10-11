// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/enip"
	"github.com/cB-Sigma/enip/server"
)

// pycomm3Image is pycomm3 1.2.16 with browse.py, built from ./pycomm3.
const pycomm3Image = "sigma-enip-interop:pycomm3-1.2.16"

func needPycomm3(t *testing.T) {
	t.Helper()
	if os.Getenv(envVar) != "1" {
		t.Skip("set " + envVar + "=1 to run the interop tests (needs Docker)")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not running")
	}
	out, err := exec.Command("docker", "build", "-q", "-t", pycomm3Image, "pycomm3").CombinedOutput()
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
}

func peerJSON(t *testing.T, line, step string) any {
	t.Helper()
	i := strings.Index(line, "PEER "+step+" ")
	if i < 0 {
		t.Fatalf("no %s in %q", step, line)
	}
	var v any
	if err := json.Unmarshal([]byte(line[i+len("PEER "+step+" "):]), &v); err != nil {
		t.Fatalf("%s: %v in %q", step, err, line)
	}
	return v
}

// pycomm3's LogixDriver against the server role, uploading the tag list
// and every structure's template itself (init_tags), then reading and
// writing a UDT, its members (a REAL and a packed BOOL), a Logix STRING,
// a program-scoped tag and an array, by symbol instance.
func TestPycomm3AgainstServerRole(t *testing.T) {
	needPycomm3(t)
	s := server.New()
	s.DefineStruct(server.StructDef{Name: "PID", Handle: 0x2001, Size: 8, Fields: []server.Field{
		{Name: "Kp", Type: enip.Type{Code: enip.TypeREAL}, Offset: 0},
		{Name: "Ki", Type: enip.Type{Code: enip.TypeREAL}, Offset: 4},
	}})
	s.DefineStruct(server.StructDef{Name: "Motor", Handle: 0x2002, Size: 116, Fields: []server.Field{
		{Name: "ZZZZZZZZZZMotor0", Type: enip.Type{Code: enip.TypeSINT}, Offset: 0, Hidden: true},
		{Name: "Running", Type: enip.Type{Code: enip.TypeBOOL}, Offset: 0, Bit: 0},
		{Name: "Fault", Type: enip.Type{Code: enip.TypeBOOL}, Offset: 0, Bit: 1},
		{Name: "Speed", Type: enip.Type{Code: enip.TypeREAL}, Offset: 4},
		{Name: "Hours", Type: enip.Type{Code: enip.TypeDINT}, Offset: 8, Array: 3},
		{Name: "Loop", Type: enip.Type{Code: enip.TypeStruct, Handle: 0x2001}, Offset: 20},
		{Name: "Label", Type: enip.Type{Code: enip.TypeStruct, Handle: enip.HandleSTRING}, Offset: 28},
	}})
	le := binary.LittleEndian
	m := make([]byte, 116)
	m[0] = 1
	le.PutUint32(m[4:], math.Float32bits(1450))
	le.PutUint32(m[20:], math.Float32bits(0.5))
	lbl, _ := enip.EncodeString("Conveyor 3")
	copy(m[28:], lbl)
	s.SetTag("Pump", enip.Type{Code: enip.TypeStruct, Handle: 0x2002}, 1, m)
	title, _ := enip.EncodeString("Line A")
	s.SetTag("Title", enip.Type{Code: enip.TypeStruct, Handle: enip.HandleSTRING}, 1, title)
	var lv []byte
	for i := range 10 {
		lv = le.AppendUint16(lv, uint16(i*3))
	}
	s.SetTag("Levels", enip.Type{Code: enip.TypeINT}, 10, lv)
	s.SetTag("Program:Main.Count", enip.Type{Code: enip.TypeDINT}, 1, le.AppendUint32(nil, 42))
	s.SetTag("Locked", enip.Type{Code: enip.TypeDINT}, 1, le.AppendUint32(nil, 1))
	s.SetReadOnly("Locked", true)
	if err := s.Start("0.0.0.0:0"); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	port := s.Addr()[strings.LastIndex(s.Addr(), ":")+1:]
	p := startPeer(t, "--add-host=host.docker.internal:host-gateway", pycomm3Image, "python", "-u", "browse.py", "host.docker.internal:"+port)
	tags := fmt.Sprint(peerJSON(t, p.expect(60*time.Second, "PEER tags"), "tags"))
	if tags != "[Levels Locked Program:Main.Count Pump Title]" {
		t.Errorf("pycomm3's tag list: %s", tags)
	}
	motor := peerJSON(t, p.expect(10*time.Second, "PEER motor"), "motor").(map[string]any)
	if fmt.Sprint(motor["attributes"]) != "[Running Fault Speed Hours Loop Label]" || motor["size"] != float64(116) {
		t.Errorf("Motor as pycomm3 read its template: %v", motor)
	}
	if v := peerJSON(t, p.expect(10*time.Second, "PEER string"), "string"); v != float64(82) {
		t.Errorf("STRING as pycomm3 read its template: %v", v)
	}
	t.Logf("pycomm3 uses symbol instance ids: %v", peerJSON(t, p.expect(10*time.Second, "PEER instance-ids"), "instance-ids"))
	read := fmt.Sprint(peerJSON(t, p.expect(10*time.Second, "PEER read"), "read"))
	for _, want := range []string{"Running:true", "Speed:1450", "Label:Conveyor 3", "Kp:0.5", "value:Line A", "value:42", "value:[0 3 6 9 12 15 18 21 24 27]"} {
		if !strings.Contains(read, want) {
			t.Errorf("pycomm3 read lacks %q: %s", want, read)
		}
	}
	if w := fmt.Sprint(peerJSON(t, p.expect(10*time.Second, "PEER write"), "write")); strings.Contains(w, "error:") && !strings.Contains(w, "error:<nil>") {
		t.Errorf("pycomm3 writes: %s", w)
	}
	reread := fmt.Sprint(peerJSON(t, p.expect(10*time.Second, "PEER reread"), "reread"))
	for _, want := range []string{"Speed:99.5", "Fault:true", "value:Renamed line", "value:43"} {
		if !strings.Contains(reread, want) {
			t.Errorf("after pycomm3's writes, lacks %q: %s", want, reread)
		}
	}
	ro := fmt.Sprint(peerJSON(t, p.expect(10*time.Second, "PEER readonly"), "readonly"))
	if !strings.Contains(ro, "error:") || strings.Contains(ro, "error:<nil>") {
		t.Errorf("a write to a read-only tag: %s", ro)
	}
	p.expect(10*time.Second, "PEER done")
	if strings.Contains(p.output(), "PEER error") {
		t.Errorf("pycomm3 failed:\n%s", p.output())
	}
	// The server holds what pycomm3 wrote.
	raw := s.TagData("Pump")
	if math.Float32frombits(le.Uint32(raw[4:])) != 99.5 || raw[0] != 0b11 {
		t.Errorf("Pump bytes after pycomm3's writes: %x", raw[:8])
	}
}
