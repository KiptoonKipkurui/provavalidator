package cmd

import (
	"fmt"

	"github.com/kiptoonkipkurui/provavalidator/pkg/drift"
	"github.com/spf13/cobra"
)

var (
	baseline     string
	failOnDrift  bool
	allowExtra   bool
	allowMissing bool
	allowReorder bool
)

var driftCmd = &cobra.Command{
	Use:   "drift IMAGE",
	Short: "Detect filesystem drift between container images",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		image := args[0]
		ctx := cmd.Context()

		if baseline == "" {
			return fmt.Errorf("baseline image must be specified")
		}
		res, err := drift.DetectLayerDrift(ctx, image, baseline)
		if err != nil {
			return fmt.Errorf("detect layer drift: %w", err)
		}

		fmt.Println(drift.FormatDrift(res))

		policy := drift.Policy{
			FailOnDrift:  failOnDrift,
			AllowExtra:   allowExtra,
			AllowMissing: allowMissing,
			AllowReorder: allowReorder,
		}

		if err := drift.EvaluatePolicy(res, policy); err != nil {

			if failOnDrift {
				return fmt.Errorf("drift policy evaluation failed: %w", err)
			}
		}
		return nil
	},
}

// Register flags
func init() {
	driftCmd.Flags().StringVarP(&baseline, "baseline", "b", "", "Baseline image to compare against (required)")
	driftCmd.Flags().BoolVar(&failOnDrift, "fail-on-drift", true, "Exit with non-zero code if drift is detected")
	driftCmd.Flags().BoolVar(&allowExtra, "allow-extra", false, "Allow extra layers in the actual image")
	driftCmd.Flags().BoolVar(&allowMissing, "allow-missing", false, "Allow missing layers in the actual image")
	driftCmd.Flags().BoolVar(&allowReorder, "allow-reorder", false, "Allow layers to be in a different order")
	rootCmd.AddCommand(driftCmd)
}
