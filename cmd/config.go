// Package cmd implements the CLI commands for argus.
package cmd

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/sentiolabs/argus/internal/config"
	"github.com/spf13/cobra"
)

//go:embed configs/example.yaml
var exampleConfig string

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create an example configuration file",
	RunE:  runConfigInit,
}

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate the configuration file",
	RunE:  runConfigValidate,
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configValidateCmd)
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	filename := ".argus.yaml"

	// Check if file already exists
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("config file %s already exists", filename)
	}

	if err := os.WriteFile(filename, []byte(exampleConfig), 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Created example configuration file: %s\n", filename)
	fmt.Println("\nNext steps:")
	fmt.Println("1. Edit the configuration file with your settings")
	fmt.Println("2. Set required environment variables")
	fmt.Println("3. Run 'argus sync --dry-run' to preview")

	return nil
}

func runConfigValidate(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	fmt.Println("Configuration is valid!")
	fmt.Printf("\nDefaults:\n")
	fmt.Printf("  Jira Project: %s\n", cfg.Defaults.Jira.Project)
	if cfg.Defaults.Jira.BoardName != "" {
		fmt.Printf("  Board Name: %s\n", cfg.Defaults.Jira.BoardName)
	} else if cfg.Defaults.Jira.BoardID > 0 {
		fmt.Printf("  Board ID: %d\n", cfg.Defaults.Jira.BoardID)
	}
	fmt.Printf("  Severity Threshold: %s\n", cfg.Defaults.Filters.SeverityThreshold)

	fmt.Printf("\nProviders:\n")
	for name := range cfg.Providers {
		p := cfg.Providers[name]
		status := "disabled"
		if p.Enabled {
			status = "enabled"
		}
		fmt.Printf("  %s: %s\n", name, status)

		// Show repos for GitHub
		if len(p.RepoIncludes) > 0 {
			fmt.Printf("    repos:\n")
			for _, repo := range p.RepoIncludes {
				fmt.Printf("      - %s\n", repo.Name)
			}
		}

		// Show projects for Snyk
		if len(p.ProjectIncludes) > 0 {
			fmt.Printf("    projects:\n")
			for _, project := range p.ProjectIncludes {
				fmt.Printf("      - %s\n", project.Name)
			}
		}
	}

	// Check for required environment variables
	fmt.Printf("\nEnvironment variables:\n")
	checkEnvVar("ARGUS_GITHUB_TOKEN", cfg.GitHubToken)
	checkEnvVar("ARGUS_SNYK_TOKEN", cfg.SnykToken)
	checkEnvVar("ARGUS_JIRA_URL", cfg.JiraURL)
	checkEnvVar("ARGUS_JIRA_USERNAME", cfg.JiraUsername)
	checkEnvVar("ARGUS_JIRA_TOKEN", cfg.JiraToken)

	return nil
}

func checkEnvVar(name, value string) {
	status := "not set"
	if value != "" {
		status = "set"
	}
	fmt.Printf("  %s: %s\n", name, status)
}
