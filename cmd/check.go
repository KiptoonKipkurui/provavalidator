package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/kiptoonkipkurui/provavalidator/pkg/check"
	"github.com/kiptoonkipkurui/provavalidator/pkg/drift"
	"github.com/kiptoonkipkurui/provavalidator/pkg/sbom"
	"github.com/kiptoonkipkurui/provavalidator/pkg/vuln"
	"github.com/spf13/cobra"
)

var (
	checkFailOn       string
	checkFormat       string
	checkIgnoreFile   string
	checkBaseline     string
	checkFailOnDrift  bool
	checkAllowExtra   bool
	checkAllowMissing bool
	checkAllowReorder bool
	checkRequireProv  bool
)
var checkCmd = &cobra.Command{
	Use:   "check Image",
	Short: "Run combined supply-chain checks (vuln + drift + provenance)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := sbom.WithRuntimeConfig(cmd.Context(), appCtx.AuthConfig.Runtime)
		image := args[0]

		// if user sets baseline, default fail-on-drift true unless explicitly overriden
		if checkBaseline != "" && !cmd.Flags().Changed("fail-on-drift") {
			checkFailOnDrift = true

		}

		res, err := check.Run(ctx, check.Options{
			Image:             image,
			RequireProvenance: checkRequireProv,
			FailOnSeverity:    checkFailOn,
			IgnoreFile:        checkIgnoreFile,
			Baseline:          checkBaseline,
			FailOnDrift:       checkFailOnDrift,
			AllowExtra:        checkAllowExtra,
			AllowMissing:      checkAllowMissing,
			AllowReorder:      checkAllowReorder,
			AuthCfg:           appCtx.AuthConfig,
		})

		// print output regardless; return error for exit code
		switch strings.ToLower(checkFormat) {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(res)
		default:
			printCombinedText(res)
		}

		// exit semantics
		if err == nil {
			return nil
		}

		// Convert policy violations into a normal exit error
		var pv check.PolicyViolationError

		if ok := errors.As(err, &pv); ok {
			return fmt.Errorf("%s", pv.Error())
		}

		// Operation errors should be obvious
		return err
		// fmt.Println("Running all checks on:", image)
		// // orchestrate checks here
		// attestation.VerifyImageAttestations(ctx, image, appCtx.AuthConfig)
		// sbom.ExtractSBOM(ctx, image)
		// vuln.ScanVulnerabilities(ctx, image)
		// registry.FetchImageMetadata(ctx, image)
		// fmt.Println("All checks completed")
		// return nil
	},
}

func init() {
	checkCmd.Flags().StringVar(&checkFailOn, "fail-on", "", "Fail if vulnerabilities of this severity or higher are found (low|medium|high|critical)")
	checkCmd.Flags().StringVar(&checkFormat, "format", "text", "Output format (text|json)")
	checkCmd.Flags().StringVar(&checkIgnoreFile, "ignore-file", "", "Path to vulnerability ignore file")

	checkCmd.Flags().StringVar(&checkBaseline, "baseline", "", "Baseline image reference (digest-pinned). Enables drift check.")
	checkCmd.Flags().BoolVar(&checkFailOnDrift, "fail-on-drift", false, "Fail if drift is detected (default true when --baseline is set)")
	checkCmd.Flags().BoolVar(&checkAllowExtra, "allow-extra", false, "Allow extra layers")
	checkCmd.Flags().BoolVar(&checkAllowMissing, "allow-missing", false, "Allow missing layers")
	checkCmd.Flags().BoolVar(&checkAllowReorder, "allow-reorder", false, "Allow layer reordering")

	checkCmd.Flags().BoolVar(&checkRequireProv, "require-provenance", true, "Fail if provenance is missing or invalid")

	rootCmd.AddCommand(checkCmd)

	_ = drift.Policy{} // avoid unused imports if you refactor helpers
	_ = vuln.Summary{}
}
