package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentiolabs/argus/internal/cache"
	"github.com/sentiolabs/argus/internal/config"
	"github.com/sentiolabs/argus/internal/output"
	"github.com/sentiolabs/argus/internal/search"
)

var searchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search cached vulnerabilities by keyword, ID, or field filters",
	Long: `Search vulnerabilities using semantic search, exact field filters, or both.

Examples:
  argus search "rails"                         # semantic search
  argus search "SNYK-RUBY-RACKSESSION-123"     # exact ID lookup
  argus search "severity:critical"             # field filter
  argus search "severity:high rails"           # hybrid: filter + semantic
  argus search "package:rack* provider:snyk"   # multiple field filters

Supported field prefixes: severity, package, repo, repository, provider, cve, id`,
	Args: cobra.ExactArgs(1),
	RunE: runSearch,
}

var (
	searchProvider    string
	searchRepo        string
	searchAllProjects bool
	searchRefresh     bool
	searchLimit       int
	searchCacheTTL    string
)

func init() {
	rootCmd.AddCommand(searchCmd)

	searchCmd.Flags().StringVar(&searchProvider, "provider", "", "scope to provider (snyk or github)")
	searchCmd.Flags().StringVar(&searchRepo, "repo", "", "filter by repository (case-insensitive substring match)")
	searchCmd.Flags().BoolVar(&searchAllProjects, "all-projects", false, "search all cached projects")
	searchCmd.Flags().BoolVar(&searchRefresh, "refresh", false, "force cache refresh before searching")
	searchCmd.Flags().IntVar(&searchLimit, "limit", 20, "max results")
	searchCmd.Flags().StringVar(&searchCacheTTL, "cache-ttl", "", "cache TTL duration (e.g., \"12h\")")
}

func runSearch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse TTL from --cache-ttl flag (default cache.DefaultTTL)
	ttl := cache.DefaultTTL
	if searchCacheTTL != "" {
		parsed, err := time.ParseDuration(searchCacheTTL)
		if err != nil {
			return fmt.Errorf("invalid --cache-ttl %q: %w", searchCacheTTL, err)
		}
		ttl = parsed
	}

	// Create cache manager
	mgr, err := cache.NewManager(ttl, GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to create cache manager: %w", err)
	}
	defer mgr.Close()

	// If --refresh flag OR cache not valid: load config and refresh
	if searchRefresh || !mgr.IsValid() {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		if err := mgr.Refresh(ctx, cfg, searchProvider, GetVerbose()); err != nil {
			return fmt.Errorf("failed to refresh cache: %w", err)
		}
	}

	// Parse query
	q := search.Parse(args[0])

	// If --provider flag is set, add it to query filters
	if searchProvider != "" {
		if q.Filters == nil {
			q.Filters = make(map[string]string)
		}
		q.Filters["provider"] = searchProvider
	}

	// If --repo flag is set, add case-insensitive substring match
	if searchRepo != "" {
		if q.Filters == nil {
			q.Filters = make(map[string]string)
		}
		q.Filters["repository"] = "*" + searchRepo + "*"
	}

	// Determine projectKey
	projectKey := mgr.ProjectKey()
	if searchAllProjects {
		projectKey = ""
	}

	// Run search
	results, err := mgr.Store().Search(ctx, projectKey, q, searchLimit)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	if len(results) == 0 {
		fmt.Println("No results found")
		return nil
	}

	// Convert SearchResult slice to output.SyncResult slice
	syncResults := make([]output.SyncResult, 0, len(results))
	for _, r := range results {
		action := "N/A"
		if r.Relevance != 0 {
			action = fmt.Sprintf("%.2f", r.Relevance)
		}
		syncResults = append(syncResults, output.SyncResult{
			Provider:   r.Provider,
			VulnID:     r.ID,
			CVE:        r.CVE,
			Severity:   r.Severity,
			Package:    r.Package,
			Repository: r.Repository,
			Action:     action,
			Status:     "cached",
		})
	}

	return output.Print(syncResults, GetOutput(), true)
}
