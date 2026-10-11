# enip

EtherNet/IP in pure Go: a client (scanner) and an adapter (server) for Logix controller tags, tag browsing, structures, CIP object attributes and class 1 implicit I/O.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/enip.svg)](https://pkg.go.dev/github.com/cB-Sigma/enip) [![test](https://github.com/cB-Sigma/enip/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/enip/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.22-00ADD8.svg)](go.mod)

The module reads and writes Logix controller tags by name and reads and
sets CIP object attributes on any CIP device, over a class 3 connection
(Forward Open or Large Forward Open) or unconnected, directly or through
a backplane route. It discovers devices with ListIdentity over UDP.
Since v0.2.0 it browses a controller's tags and structure definitions
(`ListTags`, `ReadTemplate`), runs class 1 I/O as a scanner (`OpenIO`),
and the `server` package is the adapter role: a Logix-like target with
tags, structures, browsing, member access and class 1 assemblies. It
has no cgo and no dependency beyond the standard library and
[lanbcast](https://github.com/cB-Sigma/lanbcast). It was written for
SigmaM2M, a oneM2M platform, where it serves the EtherNet/IP
integration; it does not depend on it.

## Features

| Feature | Status |
|---|---|
| Encapsulation: RegisterSession, UnRegisterSession, SendRRData, SendUnitData, ListIdentity over TCP and UDP | yes (tested against cpppo) |
| Unconnected Send with a route (backplane port and slot, or a network address) | yes (tested against cpppo) |
| Forward Open, Large Forward Open, Forward Close; class 3 connected messaging; reconnection after the target drops an idle connection; fallback to unconnected | yes (tested against cpppo) |
| Multiple Service Packet (`ReadTags`) | yes (tested against cpppo) |
| Logix Read Tag, Write Tag, Read Tag Fragmented, Write Tag Fragmented; program-scoped tags, members, array indexes | yes (tested against cpppo) |
| Types: atomic types, STRING, structures as raw bytes, by named member offsets, or decoded through their template (`Template.DecodeStruct`, nested structures, packed BOOLs, STRING members) | yes (Logix STRING and structures tested against pycomm3 1.2.16, which read and wrote them on this module's adapter) |
| Get_Attribute_Single, Get_Attributes_All, Set_Attribute_Single; any other service through `Do` | yes |
| Status texts for general and extended CIP status and encapsulation status | yes |
| Tag browsing: the Symbol object's tag list, controller and program scope, paged (`ListTags`); structure definitions from the Template object (`ReadTemplate`) | yes (since v0.2.0; client side against this module's adapter only, see Not yet) |
| Adapter (server) role (`server`): tag table with program scopes, structures (`DefineStruct`, `CheckStruct`), member access ("Tag.Member.Sub", BOOL bits), the Symbol and Template objects, symbol instance addressing, class 3 connections, Multiple Service Packet, fragmentation, attributes, ListIdentity | yes (since v0.2.0; was enip-sim's; pycomm3 1.2.16 browsed and used it) |
| Implicit (class 1) I/O: scanner (`OpenIO`: Forward Open on assembly connection points, cyclic O→T with the run/idle header, T→O inputs, timeouts) and adapter (`AddAssembly`, `SetAssembly`, `Assembly`) | yes (since v0.2.0; scanner and adapter against each other only, see Not yet) |

## Choosing an EtherNet/IP library

Compared from each project's source at the version named, in October
2026. "Tested" means run against this module in the interop tests
below. Check the projects themselves before relying on a row.

| | this module | gologix v0.44.0-beta | pycomm3 1.2.16 | cpppo 5.2.5 | libplctag 2.7.2 |
|---|---|---|---|---|---|
| Language | Go, no cgo | Go | Python | Python | C (Go use through cgo) |
| Licence | Apache-2.0 | MIT | MIT | GPL | MPL-2.0 or LGPL-2 |
| Logix tag read and write, fragmented | yes (tested against cpppo) | yes | yes (tested against this module's simulator) | yes | yes |
| Multiple Service Packet | yes | yes | yes | yes | yes |
| Large Forward Open | yes | yes | yes | yes | yes |
| Tag browsing, UDT definitions | yes | yes | yes | not checked | yes (tag listing) |
| Implicit I/O | yes, scanner and adapter | yes (server side) | no | not checked | not checked |
| Server (adapter) | yes, with browsing (tested with pycomm3); simulator in [enip-sim](https://github.com/cB-Sigma/enip-sim) | yes (a Logix-like server) | no | yes (tested) | no |
| PCCC, other PLC families | no | not checked | SLC/PLC-5 (PCCC) | not checked | yes |

Pick this module for a Go program without cgo that reads, writes and
browses Logix tags and structures, CIP attributes and class 1 I/O, or
that must act as an EtherNet/IP adapter a Logix-style client can browse.
Pick gologix if its I/O server has been checked against your scanner
(this module's I/O is not yet checked against another implementation);
pick libplctag when cgo is fine and you need PCCC or many PLC families;
pick pycomm3 in Python.

## Install

```
go get github.com/cB-Sigma/enip@latest
```

Requires Go 1.22 or later.

## Quick start

```go
import "github.com/cB-Sigma/enip"

route, _ := enip.Route("1,0") // backplane port 1, slot 0
c := &enip.Client{Addr: "192.0.2.20:44818", Route: route, Timeout: 2 * time.Second, Connected: true}
defer c.Close()
ty, data, err := c.ReadTag(ctx, "Program:Main.Flow", 1)
v, _ := enip.Decode(ty, data, 1, nil)
err = c.WriteTag(ctx, "Setpoint", enip.Type{Code: enip.TypeREAL}, 1, b)
id, err := c.ListIdentity(ctx)
```

Browsing and the adapter (v0.2.0):

```go
tags, _ := c.ListTags(ctx, "")              // controller scope; ListTags(ctx, "Main") for a program
tmpl, _ := c.ReadTemplate(ctx, tags[0].Template)
_, data, _ := c.ReadTag(ctx, tags[0].Name, 1)
v, _ := tmpl.DecodeStruct(data, nil)       // map of member name to value

s := server.New()
s.DefineStruct(server.StructDef{Name: "Motor", Handle: 0x2002, Size: 8, Fields: fields})
s.SetTag("Pump", enip.Type{Code: enip.TypeStruct, Handle: 0x2002}, 1, raw)
s.Start(":44818")
```

`TestListTagsAndTemplates` and `TestImplicitIO` (server/) run these. The
runnable examples in this module are `ExampleEncodeString` and
`ExampleRoute`; enip-sim has a client example against the simulated
controller.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/enip

| Package | What it does |
|---|---|
| `enip` (module root) | `Client` (`ReadTag`, `ReadTags`, `WriteTag`, `GetAttribute`, `SetAttribute`, `ListIdentity`, `Do`, `Mode`), `Discover`, `Route`, `TagPath`, `Decode`/`Encode` with `Type` and `Member`, `DecodeString`/`EncodeString`, `ParseTypeName`, `AtomicTypeCode`, the encapsulation and CIP codecs (`Header`, `Item`, `Request`, `Response`, `Error`, `StatusText`) |
| `enip` (v0.2.0 additions) | `ListTags`, `TagInfo`, `ReadTemplate`, `Template`, `TemplateMember`, `DecodeStruct`; `OpenIO`, `IOConfig`, `IOConn`, `IOPacket`, `ParseIOPacket` |
| `server` | the adapter role: `New`, `Server` (`SetTag`, `SetReadOnly`, `SetAttr`, `SetIdentity`, `DefineStruct`, `CheckStruct`, `AddAssembly`, `SetAssembly`, `Assembly`, `Start`, `Stop`, …), `StructDef`, `Field`, `StringDef` |
| `interop` (nested module, tests only) | this module's client against cpppo 5.2.5, and pycomm3 1.2.16 against the adapter, in Docker |

## Testing

```
go vet ./...
go test -race ./...
```

Tests carry `// Covers: SIG-...` comments: requirement IDs of the
SigmaM2M project's compliance report, with no meaning outside it. The
tests that drive the simulated controller are in
[enip-sim](https://github.com/cB-Sigma/enip-sim), so this module does
not depend on its simulator.

`interop/` is a nested module with its own go.mod. It runs cpppo 5.2.5
(GPL, installed from PyPI in a container, used only as a test peer) as
a simulated Logix controller and runs this module's client against it.
The tests are skipped unless `SIGMA_ENIP_INTEROP=1` is set and Docker is
running:

```
cd interop && SIGMA_ENIP_INTEROP=1 go test -race -v ./...
```

### Interop tested against

Run on 2026-10-11 on macOS with Docker Desktop; every item below passed.
cpppo 5.2.5's EtherNet/IP server, this module's client, unconnected
without a route, over Forward Open (500 octets), over Large Forward Open
(4000 octets), and through route 1/2 both unconnected and connected:

| Area | What was checked |
|---|---|
| Identity | ListIdentity over TCP, and over UDP through `Discover`; Get_Attribute_Single and Get_Attributes_All on the identity object |
| Tags | REAL, DINT, LREAL and SINT written and read back; an INT[10] array and one element of it; SSTRING and CIP STRING as raw bytes |
| Fragmentation | a DINT[300] written with Write Tag Fragmented and read with Read Tag Fragmented (the read routed or connected, see below) |
| Multiple Service Packet | several tags in one request, an unknown tag answered with its error in place, a member needing fragmentation |
| Errors | an unknown tag (cpppo answers with CIP status, or encapsulation status 0x08 unconnected); a route to an empty slot refused |
| Connections | mode reported as connected; Large Forward Open negotiated 3998 octets |

Found on the way and fixed in this module (v0.1.0): cpppo puts our own
O→T connection ID in the address item of its connected replies, where
the T→O ID is expected, and the client refused every reply. The client
now accepts either of its own two IDs and still refuses any other
connection (`TestConnectedReplyWithEchoedOTID`).

Behaviour of the reference peer met on the way (not ours): cpppo treats
any unrouted unconnected service 0x52 as Unconnected Send, so a
fragmented read sent straight to it, unrouted and unconnected, cannot be
tested; it wants a pad octet after an odd-length CIP STRING in a write.

pycomm3 1.2.16's LogixDriver against this module's adapter role
(2026-10-12, python:3.12.10-slim in Docker; `interop/pycomm3_test.go`,
our script in `interop/pycomm3`), opened with its own tag upload
(`init_tags`, `init_program_tags`); every item passed:

| Area | What was checked |
|---|---|
| Browsing | its tag list of controller and program scope (5 user tags, the program entry recognised); the Motor UDT's template (members in order, 116 bytes, a nested PID and a STRING member, packed BOOLs in a hidden host byte); the built-in STRING's template (82 characters) |
| Reads | the whole UDT decoded by pycomm3 (BOOLs, REAL, DINT[3], nested structure, STRING), a member, a STRING tag, a program-scoped DINT and an INT[10], by symbol instance (pycomm3 chose instance addressing) |
| Writes | a REAL member, a BOOL member (the bit in the host byte), a STRING tag and a program-scoped tag, read back by pycomm3 and checked in the adapter's bytes; a read-only tag refused with Permission denied |

Found on the way (in this module's own test, not in pycomm3): the test's
UDT had a member overlapping the next; `CheckStruct` now reports such
layouts (`TestCheckStruct`).

Not tested against an independent implementation:

- This module's `ListTags` and `ReadTemplate` against another adapter
  (cpppo has no Symbol or Template object; a real controller is
  hardware).
- Class 1 I/O: scanner and adapter are tested against each other only.
  gologix's I/O server binds UDP 2222 itself, which a scanner on the
  same host cannot share; a run in separate containers is next.
- Whether a route inside the Forward Open path is checked (cpppo checks
  routes on Unconnected Send only).
- Real controllers (ControlLogix, CompactLogix) and other CIP devices.
- In process: the simulated controller of enip-sim (same author, so not
  independent). pycomm3 1.2.16 is run against that simulator in
  enip-sim's interop tests.

## Not yet

| What | Why |
|---|---|
| Class 1 I/O against another implementation (gologix's server, a real adapter) | see above; planned with both peers in containers |
| Class 0 and multicast T→O, input-only and listen-only connections, Forward Close of I/O connections, configuration assembly data in the Forward Open | the point-to-point class 1 case comes first; these follow |
| ListServices, ListInterfaces, CIP Security (TLS and DTLS) | not started |
| PCCC (SLC, PLC-5, MicroLogix), Modbus | not started |
| Read-Modify-Write | not started |
| Real controllers | needs hardware |

## Related repositories

- [enip-sim](https://github.com/cB-Sigma/enip-sim): a simulated Logix
  controller, as a Go package and a command.
- [lanbcast](https://github.com/cB-Sigma/lanbcast): the LAN broadcast
  helper used by `Discover`.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam. EtherNet/IP and CIP are trademarks of ODVA; Logix,
ControlLogix and CompactLogix are trademarks of Rockwell Automation. This
project is not affiliated with or endorsed by either.
