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

var snykProjectID string

var snykCmd = &cobra.Command{
	Use:   "snyk",
	Short: "Sync vulnerabilities from Snyk",
	Long: `Sync fetches security issues from Snyk
and creates or updates Jira tickets.`,
	RunE: runSnyk,
}

func init() {
	rootCmd.AddCommand(snykCmd)

	snykCmd.Flags().StringVar(&snykProjectID, "project", "", "specific Snyk project ID to sync")
}

func runSnyk(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Apply CLI overrides
	if snykProjectID != "" {
		if cfg.Providers == nil {
			cfg.Providers = make(map[string]config.ProviderConfig)
		}
		providerCfg := cfg.Providers["snyk"]
		providerCfg.ProjectIDs = []string{snykProjectID}
		cfg.Providers["snyk"] = providerCfg
	}

	// Initialize provider
	p, err := provider.New("snyk", cfg, GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to create Snyk provider: %w", err)
	}

	slog.Info("fetching Snyk issues")
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
	results, err := processVulnerabilities(ctx, cfg, jiraClient, "snyk", vulns)
	if err != nil {
		return fmt.Errorf("failed to process vulnerabilities: %w", err)
	}

	return output.Print(results, GetOutput(), GetDryRun())
}
