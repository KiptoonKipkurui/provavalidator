package cmd

import (
	"fmt"
	"os"

	"github.com/kiptoonkipkurui/provavalidator/pkg/registryauth"
	"github.com/spf13/cobra"
)

var (
	authConfigPath string
	authDebug      bool
	appCtx         AppContext
)

var rootCmd = &cobra.Command{
	Use:   "provavalidator",
	Short: "A tool to validate software supply chain provenance",
	Long:  `Provavalidator is a command-line tool that helps validate the authenticity and integrity of software supply chain provenance.`,

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := registryauth.LoadConfig(authConfigPath)
		if err != nil {
			return err
		}

		appCtx = AppContext{
			AuthConfig: cfg,
		}

		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(checkCmd)
	rootCmd.PersistentFlags().BoolVar(&authDebug, "auth-debug", false, "Path to registry auth config YAML")
	rootCmd.PersistentFlags().StringVar(
		&authConfigPath,
		"auth-config",
		"",
		"Path to registry authentication config YAML",
	)
}
