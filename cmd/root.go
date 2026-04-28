package cmd

import (
	"fmt"
	"os"

	"github.com/kiptoonkipkurui/provavalidator/pkg/registryauth"
	"github.com/spf13/cobra"
)

var (
	authConfigPath          string
	authDebug               bool
	notationConfigDir       string
	notationTrustPolicyPath string
	notationTrustStorePath  string
	appCtx                  AppContext
)

var rootCmd = &cobra.Command{
	Use:           "provavalidator",
	Short:         "A tool to validate software supply chain provenance",
	Long:          `Provavalidator is a command-line tool that helps validate the authenticity and integrity of software supply chain provenance.`,
	SilenceUsage:  true,
	SilenceErrors: true,

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := registryauth.LoadConfig(authConfigPath)
		if err != nil {
			return err
		}

		if notationConfigDir != "" {
			cfg.Notation.ConfigDir = notationConfigDir
		}
		if notationTrustPolicyPath != "" {
			cfg.Notation.TrustPolicyPath = notationTrustPolicyPath
		}
		if notationTrustStorePath != "" {
			cfg.Notation.TrustStorePath = notationTrustStorePath
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
	rootCmd.PersistentFlags().BoolVar(&authDebug, "auth-debug", false, "Path to registry auth config YAML")
	rootCmd.PersistentFlags().StringVar(
		&authConfigPath,
		"auth-config",
		"",
		"Path to registry authentication config YAML",
	)
	rootCmd.PersistentFlags().StringVar(
		&notationConfigDir,
		"notation-config-dir",
		"",
		"Path to the Notation config root containing trustpolicy.json and truststore/",
	)
	rootCmd.PersistentFlags().StringVar(
		&notationTrustPolicyPath,
		"notation-trust-policy",
		"",
		"Path to a Notation trustpolicy.json file",
	)
	rootCmd.PersistentFlags().StringVar(
		&notationTrustStorePath,
		"notation-trust-store",
		"",
		"Path to a Notation truststore directory or config root containing truststore/",
	)
}
