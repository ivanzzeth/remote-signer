// Package validate provides the rule-validation CLI logic for remote-signer validate.
// This file formats validation output in JSON or human-readable text.
package validate

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// interfaceMapToStringMap converts map[string]interface{} to map[string]string for variable substitution.
func interfaceMapToStringMap(m map[string]interface{}) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if v == nil {
			out[k] = ""
		} else {
			out[k] = fmt.Sprintf("%v", v)
		}
	}
	return out
}

func outputJSON(results map[string][]ValidationFileResult, total, passed, failed int) error {
	output := JSONOutput{
		Files: results,
		Summary: Summary{
			TotalRules:  total,
			PassedRules: passed,
			FailedRules: failed,
			Success:     failed == 0,
		},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	if failed > 0 {
		return fmt.Errorf("%d rule(s) failed validation", failed)
	}

	return nil
}

func outputText(results map[string][]ValidationFileResult, total, passed, failed int, verbose bool) error {
	for filePath, fileResults := range results {
		fmt.Printf("\n📄 %s\n", filePath)
		fmt.Printf("%s\n", strings.Repeat("─", 60))

		for _, result := range fileResults {
			if result.Skipped {
				if verbose {
					fmt.Printf("  ⏭️  %s (skipped: %s)\n", result.RuleName, result.SkipReason)
				}
				continue
			}

			if result.Valid {
				fmt.Printf("  ✅ %s\n", result.RuleName)
				if verbose && len(result.TestCaseResults) > 0 {
					fmt.Printf("     Test cases: %d passed\n", len(result.TestCaseResults))
					for _, tc := range result.TestCaseResults {
						status := "✓"
						if !tc.Passed {
							status = "✗"
						}
						fmt.Printf("       %s %s\n", status, tc.Name)
					}
				}
			} else {
				fmt.Printf("  ❌ %s\n", result.RuleName)
				if result.Error != "" {
					fmt.Printf("     Error: %s\n", result.Error)
				}
				if result.SyntaxError != nil {
					fmt.Printf("     Syntax error: %s\n", result.SyntaxError.Message)
				}
				if result.FailedTestCases > 0 {
					fmt.Printf("     Failed test cases: %d\n", result.FailedTestCases)
					for _, tc := range result.TestCaseResults {
						if !tc.Passed {
							fmt.Printf("       ✗ %s: %s\n", tc.Name, tc.Error)
						}
					}
				}
			}
		}
	}

	// Summary
	fmt.Printf("\n%s\n", strings.Repeat("═", 60))
	fmt.Printf("Summary: %d total, %d passed, %d failed\n", total, passed, failed)

	if failed > 0 {
		fmt.Printf("\n❌ Validation failed\n")
		return fmt.Errorf("%d rule(s) failed validation", failed)
	}

	fmt.Printf("\n✅ All rules validated successfully\n")
	return nil
}
