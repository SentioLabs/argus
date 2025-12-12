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
	// Use ExperimentalBindStruct to automatically bind struct tags to env vars
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

func GetDryRun() bool {
	return dryRun
}

func GetOutput() string {
	return outputFormat
}

func GetVerbose() bool {
	return verbose
}
