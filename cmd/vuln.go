package cmd

import (
	"fmt"
	"strings"

	"github.com/kiptoonkipkurui/provavalidator/pkg/vuln"
	"github.com/spf13/cobra"
)

var (
	failOn     string
	format     string
	ignoreFile string
)
var vulnCmd = &cobra.Command{
	Use:   "vuln IMAGE",
	Short: "Scan image vulnerabilities using SBOM + OSV",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		image := args[0]
		ctx := cmd.Context()

		findings, err := vuln.ScanVulnerabilities(ctx, image)
		if err != nil {
			return err
		}

		// Apply ignored rules

		ignored, err := vuln.LoadIgnoreFile(ignoreFile)

		if err != nil {
			return err
		}
		findings = vuln.FilterIgnored(findings, ignored)

		summary := vuln.Summarize(findings)

		switch strings.ToLower(format) {
		case "json":
			return vuln.PrintJSON(image, summary, findings, failOn)
		case "text", "":
			return vuln.PrintText(image, summary, findings, failOn)
		default:
			return fmt.Errorf("unsupported format %q (use text or json)", format)
		}
	},
}

func init() {
	vulnCmd.Flags().StringVar(&failOn, "fail-on", "", "Fail if vulnerabilities of this severity or higher are found (low|medium|high|critical)")
	vulnCmd.Flags().StringVar(&format, "format", "text", "Output format (text|json)")
	vulnCmd.Flags().StringVar(&ignoreFile, "ignore-file", "", "Path to vulnerability ignore file")

	rootCmd.AddCommand(vulnCmd)
}
