package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sentiolabs/argus/internal/config"
	"github.com/sentiolabs/argus/internal/jira"
	"github.com/sentiolabs/argus/internal/output"
	"github.com/sentiolabs/argus/internal/provider"
	"github.com/sentiolabs/argus/internal/vuln"
	"github.com/spf13/cobra"
)

const (
	// commentThrottleWindow is the minimum time between argus comments on the same ticket
	commentThrottleWindow = 24 * time.Hour
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync vulnerabilities from all enabled providers to Jira",
	Long: `Sync fetches security vulnerabilities from all enabled providers
(GitHub Dependabot, Snyk), deduplicates them by CVE, and creates or updates
Jira tickets with consolidated information.`,
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

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		allVulns  []provider.Vulnerability
		fetchErrs []error
	)

	for name, providerCfg := range cfg.Providers {
		if !providerCfg.Enabled {
			slog.Info("skipping disabled provider", "provider", name)
			continue
		}

		// Capture loop variable
		name := name

		wg.Go(func() {
			slog.Info("fetching from provider", "provider", name)

			p, err := provider.New(name, cfg, GetVerbose())
			if err != nil {
				slog.Error("failed to create provider", "provider", name, "error", err)
				mu.Lock()
				fetchErrs = append(fetchErrs, fmt.Errorf("%s: %w", name, err))
				mu.Unlock()
				return
			}

			vulns, err := p.FetchVulnerabilities(ctx)
			if err != nil {
				slog.Error("failed to fetch vulnerabilities", "provider", name, "error", err)
				mu.Lock()
				fetchErrs = append(fetchErrs, fmt.Errorf("%s: %w", name, err))
				mu.Unlock()
				return
			}

			slog.Info("fetched vulnerabilities", "provider", name, "count", len(vulns))

			mu.Lock()
			allVulns = append(allVulns, vulns...)
			mu.Unlock()
		})
	}

	wg.Wait()

	// Report any provider failures
	if len(fetchErrs) > 0 {
		slog.Warn("some providers failed", "count", len(fetchErrs), "errors", fetchErrs)
	}

	// Create assignee resolver for the three-tier hierarchy
	resolver := config.NewAssigneeResolver(cfg)

	// Merge/dedupe vulnerabilities by CVE and assignee
	// Same CVE in repos with different assignees = separate tickets
	merged := vuln.MergeWithAssignees(allVulns, resolver)
	slog.Info("merged vulnerabilities", "total", len(allVulns), "unique", len(merged))

	// Process merged vulnerabilities
	if GetDryRun() {
		return outputDryRun(cfg, merged)
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

	results, err := processMergedVulnerabilities(ctx, cfg, jiraClient, merged)
	if err != nil {
		return fmt.Errorf("failed to process vulnerabilities: %w", err)
	}

	return output.Print(results, GetOutput(), false)
}

func outputDryRun(cfg *config.Config, merged []vuln.MergedVulnerability) error {
	var results []output.SyncResult
	for _, v := range merged {
		results = append(results, output.SyncResult{
			Provider:   v.ProvidersString(),
			VulnID:     v.ID,
			CVE:        v.CVE,
			Severity:   v.Severity,
			Package:    v.Package,
			Repository: v.RepositoriesString(),
			Action:     "would_create",
			Status:     "dry_run",
			Assignee:   cfg.GetUserAlias(v.Assignee),
		})
	}
	return output.Print(results, GetOutput(), true)
}

func processMergedVulnerabilities(
	ctx context.Context,
	cfg *config.Config,
	jiraClient *jira.Client,
	merged []vuln.MergedVulnerability,
) ([]output.SyncResult, error) {
	var results []output.SyncResult

	for _, v := range merged {
		// Get base Jira config from first provider, then override with pre-resolved assignee
		jiraCfg := cfg.GetProviderJira(v.Providers[0])
		jiraCfg.Assignee = v.Assignee
		result := output.SyncResult{
			Provider:   v.ProvidersString(),
			VulnID:     v.ID,
			CVE:        v.CVE,
			Severity:   v.Severity,
			Package:    v.Package,
			Repository: v.RepositoriesString(),
			Assignee:   cfg.GetUserAlias(v.Assignee),
		}

		// Check for existing ticket
		ticketInfo, err := jiraClient.FindExistingTicket(ctx, jiraCfg.Project, v.ID, v.CVE)
		if err != nil {
			slog.Warn("error checking for duplicates", "error", err)
		}

		if ticketInfo != nil {
			result.JiraKey = ticketInfo.Key

			// Check if enough time has passed since last argus comment
			lastComment, err := jiraClient.GetLastArgusComment(ctx, ticketInfo.Key)
			if err != nil {
				slog.Warn("failed to get last comment time", "key", ticketInfo.Key, "error", err)
			}

			// Only add comment if >24 hours since last comment (or no previous comment found)
			if lastComment.IsZero() || time.Since(lastComment) > commentThrottleWindow {
				if err = jiraClient.AddMergedComment(ctx, ticketInfo, v); err != nil {
					result.Action = "update_failed"
					result.Status = "error"
					result.Error = err.Error()
				} else {
					result.Action = "updated"
					result.Status = "success"
				}
			} else {
				result.Action = "skipped"
				result.Status = "throttled"
				if GetVerbose() {
					slog.Info("skipping comment (throttled)", "key", ticketInfo.Key, "lastComment", lastComment.Format(time.RFC3339))
				}
			}
		} else {
			// Create new ticket
			priority := cfg.GetJiraPriority(v.Severity)
			addToSprint := cfg.ShouldAddToSprint(v.Severity)

			key, err := jiraClient.CreateMergedTicket(ctx, jiraCfg, v, priority, addToSprint)
			if err != nil {
				result.Action = "create_failed"
				result.Status = "error"
				result.Error = err.Error()
				slog.Error("failed to create Jira ticket", "vuln", v.DisplayID(), "package", v.Package, "error", err)
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
