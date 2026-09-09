// Package rule — substitution.go holds the one expansion of `${var}`
// placeholders.
//
// # Why one
//
// There were two, and they were the most dangerous duplication in the
// repository. core/service/substitute.go expanded placeholders and then
// reported any that were left over as an error; core/rule/effective_config.go
// expanded them and returned whatever it had. Validation used the first,
// evaluation used the second — so the two paths that must agree about what a
// rule means were reading it through two separate pieces of code.
//
// The failure that shape produces is silent: a rule whose test cases pass
// authorizes something else at runtime, because the config the validator
// checked and the config the engine evaluated were expanded differently. No
// error, no log line, just a signature nobody intended.
//
// So the expansion lives here once, and the difference between the two callers
// is what they do afterwards — reject leftovers, or accept them — rather than
// which copy of the loop they run.
package rule

import (
	"regexp"
	"strings"
)

// placeholderRE matches any unexpanded ${...} token.
//
// ⚠️ Deliberately broad — everything up to the closing brace, not just
// [a-zA-Z0-9_:]. Detection is the safety side of this file: a validated config
// must not ship with a leftover placeholder of any shape, including
// shell-style ones like ${HOME:-/default} that a narrower pattern would let
// through. Narrowing it silently turned that case from "refused" into
// "accepted" and one test caught it.
var placeholderRE = regexp.MustCompile(`\$\{([^}]+)\}`)

// ExpandPlaceholders replaces every ${var} form in s using vars.
//
// Five forms, all derived from the same value:
//
//	${x}              the value
//	${hex:x}          the value without a leading 0x
//	${paddedhex:x}    that, left-padded with zeros to 32 bytes
//	${first:x}        the first element of a comma-separated value
//	${hex:first:x}    that, without a leading 0x
//
// ⚠️ It does not report unexpanded placeholders. That is the caller's choice —
// see UnresolvedPlaceholders — and making it a parameter here is what keeps the
// strict and lenient paths sharing one expansion instead of one each.
func ExpandPlaceholders(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "${"+k+"}", v)

		hexv := strings.TrimPrefix(v, "0x")
		s = strings.ReplaceAll(s, "${hex:"+k+"}", hexv)

		padded := hexv
		if len(hexv) < 64 {
			padded = strings.Repeat("0", 64-len(hexv)) + hexv
		}
		s = strings.ReplaceAll(s, "${paddedhex:"+k+"}", padded)

		first := FirstOfList(v)
		s = strings.ReplaceAll(s, "${first:"+k+"}", first)
		s = strings.ReplaceAll(s, "${hex:first:"+k+"}", strings.TrimPrefix(first, "0x"))
	}
	return s
}

// UnresolvedPlaceholders returns the ${...} tokens still present in s, in order
// of first appearance and without duplicates.
//
// Callers that are validating use this to refuse; callers that are evaluating
// ignore it, because a rule may legitimately carry a placeholder for a variable
// that is supplied per chain by a matrix row.
func UnresolvedPlaceholders(s string) []string {
	matches := placeholderRE.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	return out
}
