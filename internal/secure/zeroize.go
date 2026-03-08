// Package secure provides memory security utilities for sensitive data handling.
package secure

import "unsafe"

// ZeroString overwrites the backing array of a Go string with zeros.
// After calling, the original string variable still points to the (now zeroed) memory.
// This prevents sensitive data (passwords, mnemonics) from lingering in memory.
//
// IMPORTANT: Only call this on strings that are NOT string literals or interned.
// Typically safe for strings decoded from JSON request bodies.
func ZeroString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}
	// Access the backing byte array of the string via unsafe.
	// Go strings are (pointer, length); we zero the bytes at the pointer.
	b := unsafe.Slice(unsafe.StringData(*s), len(*s)) // #nosec G103 -- intentional: zero sensitive data in string backing array
	for i := range b {
		b[i] = 0
	}
	*s = ""
}
