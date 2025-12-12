package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/sentiolabs/patrol/internal/config"
	"github.com/sentiolabs/patrol/internal/jira"
	"github.com/sentiolabs/patrol/internal/output"
	"github.com/sentiolabs/patrol/internal/provider"
	"github.com/spf13/cobra"
)

var (
	githubOrg  string
	githubRepo string
)

var githubCmd = &cobra.Command{
	Use:   "github",
	Short: "Sync vulnerabilities from GitHub Dependabot",
	Long: `Sync fetches Dependabot security alerts from GitHub
and creates or updates Jira tickets.`,
	RunE: runGitHub,
}

func init() {
	rootCmd.AddCommand(githubCmd)

	githubCmd.Flags().StringVar(&githubOrg, "org", "", "GitHub organization (overrides config)")
	githubCmd.Flags().StringVar(&githubRepo, "repo", "", "specific repository to sync")
}

func runGitHub(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Apply CLI overrides
	if githubOrg != "" {
		if cfg.Providers == nil {
			cfg.Providers = make(map[string]config.ProviderConfig)
		}
		providerCfg := cfg.Providers["github"]
		providerCfg.Orgs = []string{githubOrg}
		cfg.Providers["github"] = providerCfg
	}

	if githubRepo != "" {
		if cfg.Providers == nil {
			cfg.Providers = make(map[string]config.ProviderConfig)
		}
		providerCfg := cfg.Providers["github"]
		providerCfg.Repos = []string{githubRepo}
		cfg.Providers["github"] = providerCfg
	}

	// Initialize provider
	p, err := provider.New("github", cfg, GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to create GitHub provider: %w", err)
	}

	slog.Info("fetching GitHub Dependabot alerts")
	vulns, err := p.FetchVulnerabilities(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch vulnerabilities: %w", err)
	}

	slog.Info("fetched vulnerabilities", "count", len(vulns))

	// Initialize Jira client
	jiraClient, err := jira.NewClient(
		cfg.JiraURL,
		cfg.JiraUsername,
		cfg.JiraToken,
		GetVerbose(),
	)
	if err != nil {
		return fmt.Errorf("failed to create Jira client: %w", err)
	}

	// Process vulnerabilities
	results, err := processVulnerabilities(ctx, cfg, jiraClient, "github", vulns)
	if err != nil {
		return fmt.Errorf("failed to process vulnerabilities: %w", err)
	}

	return output.Print(results, GetOutput(), GetDryRun())
}
