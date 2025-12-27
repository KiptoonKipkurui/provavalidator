package cmd

import (
	"context"
	"fmt"

	"github.com/kiptoonkipkurui/provavalidator/pkg/attestation"
	"github.com/kiptoonkipkurui/provavalidator/pkg/drift"
	"github.com/kiptoonkipkurui/provavalidator/pkg/registry"
	"github.com/kiptoonkipkurui/provavalidator/pkg/sbom"
	"github.com/kiptoonkipkurui/provavalidator/pkg/vuln"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check Image",
	Short: "Run all provenance validation checks on the specified image",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		image := args[0]
		image = "ghcr.io/sigstore/cosign:v2.4.0"
		fmt.Println("Running all checks on:", image)
		// orchestrate checks here
		attestation.VerifyImageAttestations(ctx, image, appCtx.AuthConfig)
		sbom.ExtractSBOM(ctx, image)
		vuln.ScanVulnerabilities(ctx, image)
		drift.DetectLayerDrift(ctx, image)
		registry.FetchImageMetadata(ctx, image)
		fmt.Println("All checks completed")
		return nil
	},
}
