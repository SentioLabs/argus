package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile      string
	dryRun       bool
	outputFormat string
	verbose      bool
)

var rootCmd = &cobra.Command{
	Use:   "patrol",
	Short: "Security vulnerability sync tool",
	Long: `Patrol syncs security vulnerabilities from GitHub Dependabot and Snyk
to Jira, creating and updating tickets based on configurable thresholds.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only returns an error for initialization issues.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.patrol.yaml)")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "preview changes without creating Jira tickets")
	rootCmd.PersistentFlags().StringVar(&outputFormat, "output", "table", "output format: json or table")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
}

func initConfig() {
	// Automatically bind matching environment variables
	viper.SetOptions(viper.ExperimentalBindStruct())
	viper.SetEnvPrefix("PATROL")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".patrol")
	}

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

// GetDryRun returns true if the dry-run flag is set.
// In dry-run mode, no changes are made to external systems (e.g. Jira).
func GetDryRun() bool {
	return dryRun
}

// GetOutput returns the configured output format (e.g., "json" or "table").
func GetOutput() string {
	return outputFormat
}

// GetVerbose returns true if verbose logging is enabled.
func GetVerbose() bool {
	return verbose
}
