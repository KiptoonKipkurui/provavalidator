package cmd

import (
	"context"
	"fmt"

	"github.com/kiptoonkipkurui/provavalidator/pkg/attestation"
	"github.com/spf13/cobra"
)

var attestCmd = &cobra.Command{
	Use:   "attest IMAGE",
	Short: "Verify provenance attestations for an image",
	// Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		results, err := attestation.VerifyImageAttestations(ctx, args[0], appCtx.AuthConfig)

		if err != nil {
			return err
		}

		for _, r := range results {
			fmt.Println(" Attestation verified")
			fmt.Println("  Image:", r.ImageRef)
			fmt.Println("  Subject:", r.Subject)
			fmt.Println("  Issuer:", r.Issuer)
			fmt.Println("  Digest:", r.ImageDigest)
			fmt.Println()
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(attestCmd)
}
