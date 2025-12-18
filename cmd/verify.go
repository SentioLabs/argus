package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/sentiolabs/argus/internal/config"
	"github.com/sentiolabs/argus/internal/output"
	"github.com/sentiolabs/argus/internal/provider"
	"github.com/spf13/cobra"
)

var providerFlag string

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Preview vulnerabilities from a specific provider (informational only)",
	Long: `Verify fetches vulnerabilities from a single provider and displays
what would be synced to Jira. This command is informational only and
does not create or modify any Jira tickets.

Use this to test provider configuration or preview vulnerabilities
before running a full sync.`,
	RunE: runVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVar(&providerFlag, "provider", "", "provider to verify (required, e.g., 'github' or 'snyk')")
	verifyCmd.MarkFlagRequired("provider")
}

func runVerify(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate provider exists in config
	providerCfg, exists := cfg.Providers[providerFlag]
	if !exists {
		return fmt.Errorf("provider %q not found in config", providerFlag)
	}

	if !providerCfg.Enabled {
		slog.Warn("provider is disabled in config", "provider", providerFlag)
	}

	// Initialize provider
	p, err := provider.New(providerFlag, cfg, GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	slog.Info("fetching vulnerabilities", "provider", providerFlag)
	vulns, err := p.FetchVulnerabilities(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch vulnerabilities: %w", err)
	}

	slog.Info("fetched vulnerabilities", "provider", providerFlag, "count", len(vulns))

	// Build preview results (always dry-run style)
	var results []output.SyncResult
	for _, v := range vulns {
		results = append(results, output.SyncResult{
			Provider:   providerFlag,
			VulnID:     v.ID,
			CVE:        v.CVE,
			Severity:   v.Severity,
			Package:    v.Package,
			Repository: v.Repository,
			Action:     "would_create",
			Status:     "preview",
		})
	}

	// Always output as dry-run (informational only)
	return output.Print(results, GetOutput(), true)
}
