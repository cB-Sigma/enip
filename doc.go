// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package enip is an EtherNet/IP client with CIP explicit messaging, in
// pure Go: the encapsulation layer (sessions, SendRRData, SendUnitData,
// ListIdentity over TCP and UDP), CIP requests and replies with paths,
// routes and Multiple Service Packets, Unconnected Send, Forward Open and
// Large Forward Open (class 3 connections), the Logix tag services with
// fragmentation, the attribute services, and the Logix atomic, STRING and
// structure type encodings.
//
// The simulator in package sim behaves like a Logix controller and is used
// by the tests.
package enip
