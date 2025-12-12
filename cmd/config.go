package cmd

import (
	"fmt"
	"os"

	"github.com/sentiolabs/patrol/internal/config"
	"github.com/spf13/cobra"
)

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

const exampleConfig = `# Patrol Configuration
# Base provider config (inherited by all providers)
defaults:
  jira:
    project: "SEC"
    board_name: "Security Team Board"
    assignee: "default-user"
    labels:
      - security
      - vulnerability
    components:
      - security
  thresholds:
    priority:
      critical: "Highest"
      high: "High"
      medium: "Medium"
      low: "Low"
    sprint_min_severity: "high"  # Add to active sprint if >= this severity
  filters:
    min_severity: "medium"
    max_age_days: 90
    cvss_min: 4.0

# Provider-specific configs (override defaults)
providers:
  github:
    enabled: true
    orgs:
      - your-org
    repos: []  # Empty = all repos in org
    repo_patterns: []  # e.g., ["patrol-*", "api-*"]
    exclude_repos:
      - archived-repo
    jira:
      assignee: "github-security-lead"
      labels:
        - security
        - dependabot
    filters:
      packages: []  # Empty = all packages
      exclude_packages:
        - dev-only-pkg

  snyk:
    enabled: true
    org_id: "your-snyk-org-id"
    project_ids: []  # Empty = all projects
    jira:
      assignee: "snyk-security-lead"
      labels:
        - security
        - snyk
    filters:
      min_severity: "high"  # Override default

# Environment variables required:
# PATROL_GITHUB_TOKEN  - GitHub personal access token
# PATROL_SNYK_TOKEN    - Snyk API token
# PATROL_JIRA_URL      - Jira instance URL (e.g., https://your-domain.atlassian.net)
# PATROL_JIRA_USERNAME - Jira username/email
# PATROL_JIRA_TOKEN    - Jira API token
`

func runConfigInit(cmd *cobra.Command, args []string) error {
	filename := ".patrol.yaml"

	// Check if file already exists
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("config file %s already exists", filename)
	}

	if err := os.WriteFile(filename, []byte(exampleConfig), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Created example configuration file: %s\n", filename)
	fmt.Println("\nNext steps:")
	fmt.Println("1. Edit the configuration file with your settings")
	fmt.Println("2. Set required environment variables")
	fmt.Println("3. Run 'patrol sync --dry-run' to preview")

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
	fmt.Printf("  Board Name: %s\n", cfg.Defaults.Jira.BoardName)
	fmt.Printf("  Sprint Min Severity: %s\n", cfg.Defaults.Thresholds.SprintMinSeverity)
	fmt.Printf("  Filter Min Severity: %s\n", cfg.Defaults.Filters.MinSeverity)

	fmt.Printf("\nProviders:\n")
	for name, provider := range cfg.Providers {
		status := "disabled"
		if provider.Enabled {
			status = "enabled"
		}
		fmt.Printf("  %s: %s\n", name, status)
	}

	// Check for required environment variables
	fmt.Printf("\nEnvironment variables:\n")
	checkEnvVar("PATROL_GITHUB_TOKEN", cfg.GitHubToken)
	checkEnvVar("PATROL_SNYK_TOKEN", cfg.SnykToken)
	checkEnvVar("PATROL_JIRA_URL", cfg.JiraURL)
	checkEnvVar("PATROL_JIRA_USERNAME", cfg.JiraUsername)
	checkEnvVar("PATROL_JIRA_TOKEN", cfg.JiraToken)

	return nil
}

func checkEnvVar(name, value string) {
	status := "not set"
	if value != "" {
		status = "set"
	}
	fmt.Printf("  %s: %s\n", name, status)
}
