# Changelog

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
