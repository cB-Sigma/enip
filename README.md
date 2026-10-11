# enip

An EtherNet/IP client with CIP explicit messaging in pure Go, for Logix controller tags and CIP object attributes.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/enip.svg)](https://pkg.go.dev/github.com/cB-Sigma/enip) [![test](https://github.com/cB-Sigma/enip/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/enip/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.22-00ADD8.svg)](go.mod)

The module reads and writes Logix controller tags by name and reads and
sets CIP object attributes on any CIP device, over a class 3 connection
(Forward Open or Large Forward Open) or unconnected, directly or through
a backplane route. It discovers devices with ListIdentity over UDP. It
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
| Types: atomic types, STRING, structures as raw bytes or by named member offsets | yes; Logix STRING and structures only against this module's simulator |
| Get_Attribute_Single, Get_Attributes_All, Set_Attribute_Single; any other service through `Do` | yes |
| Status texts for general and extended CIP status and encapsulation status | yes |
| Tag browsing (symbol and template objects), UDT definitions | no |
| Read-Modify-Write | no |
| Implicit (class 0/1) I/O messaging | no |
| ListServices, ListInterfaces, CIP Security (TLS/DTLS) | no |
| PCCC (SLC, PLC-5, MicroLogix), Modbus | no |

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
| Tag browsing, UDT definitions | no | yes | yes | not checked | yes (tag listing) |
| Implicit I/O | no | yes (server side) | no | not checked | not checked |
| Server or simulator | separate module ([enip-sim](https://github.com/cB-Sigma/enip-sim)) | yes (a Logix-like server) | no | yes (tested) | no |
| PCCC, other PLC families | no | not checked | SLC/PLC-5 (PCCC) | not checked | yes |

Pick gologix when you need tag browsing, UDTs by definition or implicit
I/O in Go and can follow a beta API; pick libplctag when cgo is fine
and you need PCCC or many PLC families; pick pycomm3 in Python. Pick this
module for a Go program without cgo that reads and writes known tags and
CIP attributes, connected or not, through routes, with simulator-backed
tests in Go.

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

The runnable examples in this module are `ExampleEncodeString` and
`ExampleRoute`; enip-sim has a client example against the simulated
controller.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/enip

| Package | What it does |
|---|---|
| `enip` (module root) | `Client` (`ReadTag`, `ReadTags`, `WriteTag`, `GetAttribute`, `SetAttribute`, `ListIdentity`, `Do`, `Mode`), `Discover`, `Route`, `TagPath`, `Decode`/`Encode` with `Type` and `Member`, `DecodeString`/`EncodeString`, `ParseTypeName`, `AtomicTypeCode`, the encapsulation and CIP codecs (`Header`, `Item`, `Request`, `Response`, `Error`, `StatusText`) |
| `interop` (nested module, tests only) | this module's client against cpppo 5.2.5 in Docker |

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

Not tested against an independent implementation:

- Logix STRING (type 0x0FCE) and structures: cpppo has neither.
- Whether a route inside the Forward Open path is checked (cpppo checks
  routes on Unconnected Send only).
- Real controllers (ControlLogix, CompactLogix) and other CIP devices.
- In process: the simulated controller of enip-sim (same author, so not
  independent). pycomm3 1.2.16 is run against that simulator in
  enip-sim's interop tests.

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
