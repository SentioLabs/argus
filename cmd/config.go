package cmd

import (
	"fmt"
	"os"

	"github.com/sentiolabs/argus/internal/config"
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

const exampleConfig = `# Argus Configuration
# Base provider config (inherited by all providers)
defaults:
  jira:
    project: "SEC"
    board_name: "Security Team Board"
    # User aliases map friendly names to Jira account IDs
    # Use these aliases anywhere an assignee is needed
    users:
      default-user: "712020:abc12345-1234-5678-90ab-cdef01234567"
      security-lead: "712021:def12345-1234-5678-90ab-cdef01234567"
      frontend-lead: "712022:ghi12345-1234-5678-90ab-cdef01234567"
      backend-lead: "712023:jkl12345-1234-5678-90ab-cdef01234567"
    assignee: "default-user"  # Tier 1: Global default (uses alias from users map)
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
#
# Assignee hierarchy (most specific wins):
#   1. defaults.jira.assignee              - Global fallback
#   2. providers.{name}.jira.assignee      - Provider-level override
#   3. providers.{name}.repo_includes      - Repository-level override (in entry with assignee)
#
# When the same CVE is found in repos with different assignees,
# separate Jira tickets are created (one per assignee).
providers:
  github:
    enabled: true
    orgs:
      - your-org
    # repo_includes: Include specific repos/patterns with optional overrides
    # - String entries: just the repo name/pattern (e.g., "your-org/api-*")
    # - Object entries: repo with assignee override
    # If empty, all repos from orgs are scanned.
    repo_includes:
      - "your-org/api-*"              # Pattern: all api-* repos
      - name: "your-org/frontend"     # Repo with assignee override
        assignee: "frontend-lead"     # Uses alias from users map
      - name: "your-org/backend"
        assignee: "backend-lead"      # Uses alias from users map
    # repo_excludes: Exclude repos/patterns (supports glob patterns)
    repo_excludes:
      - "your-org/archived-*"
    jira:
      assignee: "security-lead"  # Tier 2: Provider-level override (uses alias)
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
    # project_includes: Include specific projects/patterns with optional overrides
    # If empty, all projects in the org are scanned.
    project_includes: []
    # project_excludes: Exclude projects/patterns
    project_excludes: []
    jira:
      assignee: "snyk-security-lead"  # Tier 2: Provider-level override
      labels:
        - security
        - snyk
    filters:
      min_severity: "high"  # Override default

# Environment variables required:
# ARGUS_GITHUB_TOKEN  - GitHub personal access token
# ARGUS_SNYK_TOKEN    - Snyk API token
# ARGUS_JIRA_URL      - Jira instance URL (e.g., https://your-domain.atlassian.net)
# ARGUS_JIRA_USERNAME - Jira username/email
# ARGUS_JIRA_TOKEN    - Jira API token
`

func runConfigInit(cmd *cobra.Command, args []string) error {
	filename := ".argus.yaml"

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
	fmt.Printf("  Sprint Min Severity: %s\n", cfg.Defaults.Thresholds.SprintMinSeverity)
	fmt.Printf("  Filter Min Severity: %s\n", cfg.Defaults.Filters.MinSeverity)

	if len(cfg.Defaults.Jira.Users) > 0 {
		fmt.Printf("\nUsers:\n")
		for name := range cfg.Defaults.Jira.Users {
			fmt.Printf("  - %s\n", name)
		}
	}

	fmt.Printf("\nProviders:\n")
	for name, provider := range cfg.Providers {
		status := "disabled"
		if provider.Enabled {
			status = "enabled"
		}
		fmt.Printf("  %s: %s\n", name, status)

		// Show repos for GitHub
		if len(provider.RepoIncludes) > 0 {
			fmt.Printf("    repos:\n")
			for _, repo := range provider.RepoIncludes {
				fmt.Printf("      - %s\n", repo.Name)
			}
		}

		// Show projects for Snyk
		if len(provider.ProjectIncludes) > 0 {
			fmt.Printf("    projects:\n")
			for _, project := range provider.ProjectIncludes {
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
