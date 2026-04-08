package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentiolabs/argus/internal/cache"
	"github.com/sentiolabs/argus/internal/config"
	"github.com/sentiolabs/argus/internal/output"
	"github.com/sentiolabs/argus/internal/provider"
	"github.com/sentiolabs/argus/internal/search"
)

var (
	showAllProjects bool
	showCacheTTL    string
)

var showCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show detailed information about a specific vulnerability",
	Long: `Look up a vulnerability by its exact ID (Snyk, GHSA, or CVE) and display
detailed information including description, fix version, and URL.

If no exact match is found, falls back to semantic search and shows the
closest result.

Examples:
  argus show SNYK-RUBY-RACKSESSION-15928857
  argus show CVE-2025-27610
  argus show GHSA-xvch-r4wf-h8w9`,
	Args: cobra.ExactArgs(1),
	RunE: runShow,
}

func init() {
	rootCmd.AddCommand(showCmd)

	showCmd.Flags().BoolVar(&showAllProjects, "all-projects", false, "search across all cached projects")
	showCmd.Flags().StringVar(&showCacheTTL, "cache-ttl", "", "cache TTL duration (e.g. 24h)")
}

func runShow(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	id := args[0]

	// Parse TTL from flag, fall back to default
	ttl := cache.DefaultTTL
	if showCacheTTL != "" {
		d, err := time.ParseDuration(showCacheTTL)
		if err != nil {
			return fmt.Errorf("invalid --cache-ttl value %q: %w", showCacheTTL, err)
		}
		ttl = d
	}

	// Create cache manager
	mgr, err := cache.NewManager(ttl, GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to create cache manager: %w", err)
	}
	defer mgr.Close() //nolint:errcheck

	// Refresh cache if stale
	if !mgr.IsValid() {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		if err := mgr.Refresh(ctx, cfg, "all", GetVerbose()); err != nil {
			return fmt.Errorf("cache refresh failed: %w", err)
		}
	}

	// Determine the project key scope
	projectKey := mgr.ProjectKey()
	if showAllProjects {
		projectKey = ""
	}

	store := mgr.Store()

	// Attempt exact ID lookup
	vuln, err := store.GetByID(ctx, projectKey, id)
	if err != nil {
		return fmt.Errorf("failed to look up vulnerability: %w", err)
	}

	if vuln != nil {
		return output.PrintDetail(vulnToDetail(vuln, mgr.ProjectKey()), GetOutput())
	}

	// Fall back to semantic search
	results, err := store.Search(ctx, projectKey, search.Query{SemanticText: id}, 1)
	if err != nil {
		return fmt.Errorf("semantic search failed: %w", err)
	}

	if len(results) > 0 {
		fmt.Printf("No exact match for %s. Closest result (relevance: %.2f):\n", id, results[0].Relevance)
		pk := results[0].ProjectKey
		if pk == "" {
			pk = mgr.ProjectKey()
		}
		return output.PrintDetail(vulnToDetail(&results[0].Vulnerability, pk), GetOutput())
	}

	return fmt.Errorf("no vulnerability found matching %s", id)
}

func vulnToDetail(v *provider.Vulnerability, projectKey string) output.VulnDetail {
	discoveredAt := ""
	if !v.DiscoveredAt.IsZero() {
		discoveredAt = v.DiscoveredAt.Format("2006-01-02")
	}
	return output.VulnDetail{
		ID:           v.ID,
		CVE:          v.CVE,
		Severity:     v.Severity,
		CVSS:         v.CVSS,
		Package:      v.Package,
		Version:      v.Version,
		FixedVersion: v.FixedVersion,
		Repository:   v.Repository,
		Provider:     v.Provider,
		DiscoveredAt: discoveredAt,
		URL:          v.URL,
		Description:  v.Description,
		ProjectKey:   projectKey,
	}
}
