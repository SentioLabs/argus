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

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync vulnerabilities from all enabled providers to Jira",
	Long: `Sync fetches security vulnerabilities from all enabled providers
(GitHub Dependabot, Snyk) and creates or updates Jira tickets.`,
	RunE: runSync,
}

func init() {
	rootCmd.AddCommand(syncCmd)
}

func runSync(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

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

	var allResults []output.SyncResult

	// Process each enabled provider
	for name, providerCfg := range cfg.Providers {
		if !providerCfg.Enabled {
			slog.Info("skipping disabled provider", "provider", name)
			continue
		}

		slog.Info("processing provider", "provider", name)

		p, err := provider.New(name, cfg, GetVerbose())
		if err != nil {
			slog.Error("failed to create provider", "provider", name, "error", err)
			continue
		}

		vulns, err := p.FetchVulnerabilities(ctx)
		if err != nil {
			slog.Error("failed to fetch vulnerabilities", "provider", name, "error", err)
			continue
		}

		slog.Info("fetched vulnerabilities", "provider", name, "count", len(vulns))

		results, err := processVulnerabilities(ctx, cfg, jiraClient, name, vulns)
		if err != nil {
			slog.Error("failed to process vulnerabilities", "provider", name, "error", err)
			continue
		}

		allResults = append(allResults, results...)
	}

	// Output results
	return output.Print(allResults, GetOutput(), GetDryRun())
}

func processVulnerabilities(
	ctx context.Context,
	cfg *config.Config,
	jiraClient *jira.Client,
	providerName string,
	vulns []provider.Vulnerability,
) ([]output.SyncResult, error) {
	var results []output.SyncResult
	jiraCfg := cfg.GetProviderJira(providerName)

	for _, v := range vulns {
		result := output.SyncResult{
			Provider:    providerName,
			VulnID:      v.ID,
			CVE:         v.CVE,
			Severity:    v.Severity,
			Package:     v.Package,
			Repository:  v.Repository,
		}

		if GetDryRun() {
			result.Action = "would_create"
			result.Status = "dry_run"
			results = append(results, result)
			continue
		}

		// Check for duplicates
		ticketInfo, err := jiraClient.FindExistingTicket(ctx, jiraCfg.Project, v.ID, v.CVE)
		if err != nil {
			slog.Warn("error checking for duplicates", "error", err)
		}

		if ticketInfo != nil {
			// Add comment to existing ticket
			err = jiraClient.AddDuplicateComment(ctx, ticketInfo, v)
			if err != nil {
				result.Action = "update_failed"
				result.Status = "error"
				result.Error = err.Error()
			} else {
				result.Action = "updated"
				result.Status = "success"
				result.JiraKey = ticketInfo.Key
			}
		} else {
			// Create new ticket
			priority := cfg.GetJiraPriority(v.Severity)
			addToSprint := cfg.ShouldAddToSprint(v.Severity)

			key, err := jiraClient.CreateTicket(ctx, jiraCfg, v, priority, addToSprint)
			if err != nil {
				result.Action = "create_failed"
				result.Status = "error"
				result.Error = err.Error()
				slog.Error("failed to create Jira ticket", "vuln", v.CVE, "package", v.Package, "error", err)
			} else {
				result.Action = "created"
				result.Status = "success"
				result.JiraKey = key
			}
		}

		results = append(results, result)
	}

	return results, nil
}
