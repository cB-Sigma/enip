# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go. No code was ported or
copied from another implementation, and no source file of another
project was translated.

The encapsulation layer, CIP messaging and the Logix tag services follow
the published descriptions of EtherNet/IP and CIP (the ODVA CIP Networks
Library, volumes 1 and 2) and Rockwell Automation's public Logix 5000
data access manual, used as facts in our own words: command and service
codes, item types, path segment encodings, status codes, type codes, the
fragmented-service and Forward Open layouts. No text from those
documents is reproduced.

The code came with SigmaM2M's baseline (2026-09-27) and was revised in
SigmaM2M on 2026-10-06 (fixes found on real devices: idle connections and
partial writes, with the tests named after them). It became a module of
its own on 2026-10-06; the broadcast helper became the shared module
lanbcast the same day. On 2026-10-11 the simulated controller, its
command and the tests that drive it moved to the separate module
enip-sim (with `git mv`), so this module does not depend on its
simulator, and the cpppo interop tests (interop/) were added. They found
the defect fixed in v0.1.0 (CHANGELOG.md).

For v0.2.0 (2026-10-12) the simulated controller's adapter code moved
from enip-sim into the `server` package (same author; the demo tag table
stayed in the simulator), and new code was written in our own words:
tag browsing on both sides (the Symbol object's instance attribute list
and the Template object's attributes and definition), member access,
symbol instance addressing, `CheckStruct`, and class 1 I/O on both sides
(io.go, server/io.go). The browsing wire layout is what Logix
controllers serve; it was taken as facts from the ODVA and Rockwell
publications and checked by running pycomm3 1.2.16 against the adapter.
pycomm3's source was read to see which attributes and services its tag
upload asks for; no code was taken from it.

## Status texts

`StatusText`, `ExtStatusText` and `EncapStatusText` give each code a
short lower-case label of a few words. Many name the same condition the
specification's code tables name, as any implementation's must; no
descriptions or explanatory text were taken. Checked by the author on
2026-10-11.

## Sources

| Area (files) | Followed | Read for facts only (no code taken) |
|---|---|---|
| Encapsulation, CPF items, ListIdentity (encap.go) | ODVA CIP Networks Library vol. 2 (EtherNet/IP adaptation of CIP) | none |
| CIP requests, paths, status codes, Multiple Service Packet, Unconnected Send, Forward Open (cip.go, client.go) | ODVA CIP Networks Library vol. 1 | none |
| Logix tag services and type codes (types.go, client.go) | Rockwell Automation Logix 5000 Controllers Data Access programming manual | none |
| Interop peer (interop/peer) | cpppo 5.2.5's command-line options, read to start its server | cpppo's behaviour was observed as a peer, not read from its code |

## Other implementations

Open EtherNet/IP implementations include pycomm3 (Python, MIT), cpppo
(Python, GPL), libplctag (C, MPL-2.0 or LGPL-2) and gologix (Go, MIT).
None of them was read for the library code. For the comparison in
README.md the sources of gologix v0.44.0-beta and libplctag 2.7.2 were
looked at for which features they have; nothing was taken from them.
On 2026-10-11 cpppo 5.2.5 was used as an independent test peer, after
the library code existed.

## Test data

| Test | Source |
|---|---|
| codec_test.go, example_test.go | encodings built from the documents above |
| connaddr_test.go | the connected reply cpppo 5.2.5 sent in the interop tests, rebuilt by hand |
| interop/ | cpppo 5.2.5's EtherNet/IP server |

All tag names, values, serial numbers and addresses are made-up demo
values.
