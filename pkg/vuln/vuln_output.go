package vuln

import (
	"encoding/json"
	"fmt"
	"os"
)

func PrintText(image string, s Summary, findings []Finding, failOn string) error {
	if failOn != "" {
		level, err := ParseSeverity(failOn)

		if err != nil {
			return err
		}

		violations := FilterBySeverity(findings, level)

		if len(violations) > 0 {
			fmt.Printf("Vulnerability policy violation (fail-on: %s)\n\n", failOn)
			for _, v := range violations {
				fmt.Println(FormatFinding(v))
			}

			PrintSummary(s)

			return fmt.Errorf("vulnerability policy violation: %d vulnerabilities found at or above severity %s", len(violations), failOn)
		}
	}
	PrintSummary(s)
	return nil
}
func PrintSummary(s Summary) {
	fmt.Println("\nVulnerability summary:")
	fmt.Printf("  Critical: %d\n", s.Critical)
	fmt.Printf("  High:     %d\n", s.High)
	fmt.Printf("  Medium:   %d\n", s.Medium)
	fmt.Printf("  Low:      %d\n", s.Low)
	fmt.Printf("  Total:    %d\n", s.Total)
}

func PrintJSON(image string, s Summary, findings []Finding, failOn string) error {
	out := struct {
		Image    string    `json:"image"`
		Summary  Summary   `json:"summary"`
		Findings []Finding `json:"findings"`
	}{
		Image:    image,
		Summary:  s,
		Findings: findings,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
