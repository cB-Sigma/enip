# Changelog

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
