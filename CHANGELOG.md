# Changelog

## Unreleased

- `IOConn.Close` sends a Forward Close for its class 1 connection through
  the client's session, so the adapter ends the connection at once
  instead of after its timeout; it now waits for the answer, for at most
  the client's `Timeout`. New `IOConn.Shutdown` does the same and returns
  the Forward Close's result; new `ErrNoSession` when the client was
  closed first. Neither reconnects. Reported and fixed by @boeboe
  (#9, #10).

## v0.2.1 (2026-11-07)

Fixes to the adapter (`server`), all found by @boeboe with the
otfabric/ethernetip-interop cross-stack harness. No API is removed;
`enip.Identity` gains `Major` and `Minor`.

- The identity's revision follows `SetIdentity` (`Identity.Major` and
  `Minor`, or the `Revision` text) in attribute 4 and in the ListIdentity
  item instead of a fixed 33.11, which stays the default (#1).
- The Message Router and Connection Manager paths are recognised by their
  decoded segments, so the 16-bit logical segment forms (`21 00 02 00 25
  00 01 00`) reach Multiple Service Packet, Forward Open, Forward Close
  and Unconnected Send instead of being answered 0x16 (#2).
- A Forward Close of a class 1 (I/O) connection closes it and answers
  success instead of 0x01/0x0107 (#3).
- Tag names are not case-sensitive, as in Logix: `counter` finds
  `Counter`, in program scopes and member paths too; the tag list keeps
  the spelling the tag was created with (#4).
- An Unconnected Send with an empty route path is answered when
  `RequireRoute` is false instead of refused with 0x01/0x0312 (#5).
- The ListIdentity item's socket address is the port the adapter listens
  on and the interface the request arrived on (the TCP connection's local
  address; over UDP the interface towards the sender), not 0.0.0.0 and
  44818 (#6).
- A template's definition size (attribute 4) covers its data in the
  words×4 − 23 reading (pylogix) as well as words×4 − 21 (pycomm3, this
  module), and a Read Template at or past the end of the data is answered
  0xFF/0x2104 instead of a success with no data (#7).
- A class 1 connection's watchdog is refreshed by every O→T packet in
  order (by the encapsulation sequence number); a repeated CIP sequence
  count is unchanged data, not a dropped packet, so an originator sending
  unchanged outputs no longer times out (#8).

## v0.2.0 (2026-10-12)

Browsing, the adapter role and implicit I/O. Only additions.

- Tag browsing: `ListTags` (controller or program scope, paged) and
  `ReadTemplate` (a structure's members, offsets, arrays, BOOL bits,
  nested structures); `Template.DecodeStruct`.
- `server`: the adapter (target) role, moved from enip-sim's simulator
  and extended: structures (`DefineStruct`, `CheckStruct`), member access
  by name and BOOL bits, the Symbol and Template objects, symbol instance
  addressing, `SetIdentity`, `SetReadOnly`, `SetAttr`.
- Class 1 implicit I/O: `OpenIO` (scanner) and assemblies on the adapter
  (`AddAssembly`, `SetAssembly`, `Assembly`, `IOAddr`), point-to-point,
  cyclic, with the run/idle header and timeouts.
- Interop: pycomm3 1.2.16's LogixDriver browsed the adapter (tag list,
  UDT and STRING templates) and read and wrote a UDT, its members, a
  STRING and program tags by symbol instance. The cpppo tests pass
  unchanged.

## v0.1.0 (2026-10-11)

First release, checked against cpppo 5.2.5's EtherNet/IP server (see
README.md, "Interop tested against").

Fixed while preparing it:

- A connected reply whose address item carried our own O→T connection
  ID (as cpppo sends it) was refused as a reply for another connection,
  so every connected request to cpppo failed. Either of the client's two
  connection IDs is now accepted; any other is still refused
  (`TestConnectedReplyWithEchoedOTID`).

The simulated controller and its command moved to
[enip-sim](https://github.com/cB-Sigma/enip-sim).
