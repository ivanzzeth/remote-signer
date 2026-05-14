package validate

import (
	"fmt"
	"regexp"
)

// dangerousJSPatterns contains regex patterns for dangerous JavaScript constructs.
// These are checked at rule creation time (ruleconfig) and before rule execution
// (chain/evm) as defense-in-depth alongside the runtime sandbox.
var dangerousJSPatterns = []*regexp.Regexp{
	// Prototype pollution / sandbox escape
	regexp.MustCompile(`__proto__`),                      // direct prototype manipulation
	regexp.MustCompile(`constructor\s*\.\s*constructor`), // sandbox escape via "".constructor.constructor("return this")()
	regexp.MustCompile(`Object\s*\.\s*getPrototypeOf`),   // prototype chain exploration
	regexp.MustCompile(`Object\s*\.\s*setPrototypeOf`),   // prototype chain modification
	regexp.MustCompile(`Object\s*\.\s*defineProperty`),   // property hijacking via getter/setter redefinition

	// Dynamic code execution
	regexp.MustCompile(`\bFunction\s*\(`), // new Function("...") is equivalent to eval
	regexp.MustCompile(`\bimport\s*\(`),   // dynamic import()

	// Node.js dangerous modules
	regexp.MustCompile(`\bchild_process\b`), // command execution via child_process
}

// ValidateJSCodeSecurity checks JavaScript code for dangerous patterns.
// Returns nil if code is safe, or an error describing the first dangerous pattern found.
func ValidateJSCodeSecurity(code string) error {
	for _, pattern := range dangerousJSPatterns {
		if pattern.MatchString(code) {
			return fmt.Errorf("dangerous pattern detected: %s - this construct is not allowed in JS rules for security reasons", pattern.String())
		}
	}
	return nil
}
