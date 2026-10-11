// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package enip_test

import (
	"fmt"

	"github.com/cB-Sigma/enip"
)

// Encode a string for a write and decode it again.
func ExampleEncodeString() {
	b, _ := enip.EncodeString("Pump 7")
	s, _ := enip.DecodeString(b)
	fmt.Println(s)
	// Output: Pump 7
}

// The route to the CPU in slot 2 of a ControlLogix chassis (backplane
// port 1), and the symbolic path of a program-scoped tag.
func ExampleRoute() {
	route, _ := enip.Route("1,2")
	path, _ := enip.TagPath("Program:Main.Count")
	fmt.Printf("% x\n% x\n", route, path)
	// Output:
	// 01 02
	// 91 0c 50 72 6f 67 72 61 6d 3a 4d 61 69 6e 91 05 43 6f 75 6e 74 00
}
