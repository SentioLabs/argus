package provider

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/go-github/v57/github"
	"github.com/sentiolabs/patrol/internal/config"
	"github.com/sentiolabs/patrol/internal/filter"
	"golang.org/x/oauth2"
)

// GitHubProvider fetches Dependabot alerts from GitHub
type GitHubProvider struct {
	client           *github.Client
	orgs             []string
	repos            []string
	repoPatterns     []string
	excludeRepos     []string
	filter           *filter.Filter
	severityMappings map[string]string
	verbose          bool
}

// NewGitHubProvider creates a new GitHub Dependabot provider
func NewGitHubProvider(token string, cfg config.ProviderConfig, filters config.FiltersConfig, severityMappings map[string]string, verbose bool) (*GitHubProvider, error) {
	if token == "" {
		return nil, fmt.Errorf("PATROL_GITHUB_TOKEN environment variable is required")
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	// Create HTTP client with timeout, then wrap with oauth2 transport
	httpClient := &http.Client{
		Timeout: HTTPTimeout,
		Transport: &oauth2.Transport{
			Source: ts,
		},
	}
	client := github.NewClient(httpClient)

	return &GitHubProvider{
		client:           client,
		orgs:             cfg.Orgs,
		repos:            cfg.Repos,
		repoPatterns:     cfg.RepoPatterns,
		excludeRepos:     cfg.ExcludeRepos,
		filter:           filter.New(filters),
		severityMappings: severityMappings,
		verbose:          verbose,
	}, nil
}

// Name returns the provider name
func (p *GitHubProvider) Name() string {
	return "github"
}

// FetchVulnerabilities retrieves Dependabot alerts from GitHub
func (p *GitHubProvider) FetchVulnerabilities(ctx context.Context) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// Get repositories to check
	repos, err := p.getRepositories(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get repositories: %w", err)
	}

	if p.verbose {
		slog.Info("found GitHub repositories", "count", len(repos))
	}

	for _, repo := range repos {
		if p.verbose {
			slog.Info("fetching Dependabot alerts", "repo", repo)
		}

		alerts, err := p.getAlertsForRepo(ctx, repo)
		if err != nil {
			slog.Warn("failed to get alerts for repo", "repo", repo, "error", err)
			continue
		}

		if p.verbose {
			slog.Info("found alerts for repo", "repo", repo, "count", len(alerts))
		}

		for _, alert := range alerts {
			v := p.alertToVulnerability(repo, alert)
			if p.filter.ShouldInclude(v) {
				vulns = append(vulns, v)
			}
		}
	}

	return vulns, nil
}

// getRepositories returns the list of repositories to check for alerts
func (p *GitHubProvider) getRepositories(ctx context.Context) ([]string, error) {
	var repos []string

	// If specific repos are configured, use those
	if len(p.repos) > 0 {
		for _, repo := range p.repos {
			// If repo doesn't contain '/', prepend the first org
			if !strings.Contains(repo, "/") && len(p.orgs) > 0 {
				repo = fmt.Sprintf("%s/%s", p.orgs[0], repo)
			}
			repos = append(repos, repo)
		}
		return repos, nil
	}

	// Otherwise, get repos from configured orgs
	for _, org := range p.orgs {
		orgRepos, err := p.getOrgRepositories(ctx, org)
		if err != nil {
			return nil, fmt.Errorf("failed to get repos for org %s: %w", org, err)
		}

		for _, repo := range orgRepos {
			fullName := fmt.Sprintf("%s/%s", org, repo)

			if p.isExcluded(repo) {
				continue
			}

			if len(p.repoPatterns) > 0 && !p.matchesPattern(repo) {
				continue
			}

			repos = append(repos, fullName)
		}
	}

	return repos, nil
}

// getOrgRepositories fetches all repositories for an organization
func (p *GitHubProvider) getOrgRepositories(ctx context.Context, org string) ([]string, error) {
	var allRepos []string
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: APIPageSize},
	}

	for {
		repos, resp, err := p.client.Repositories.ListByOrg(ctx, org, opts)
		if err != nil {
			return nil, err
		}

		for _, repo := range repos {
			if !repo.GetArchived() {
				allRepos = append(allRepos, repo.GetName())
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	return allRepos, nil
}

// getAlertsForRepo fetches Dependabot alerts for a specific repository
func (p *GitHubProvider) getAlertsForRepo(ctx context.Context, repo string) ([]*github.DependabotAlert, error) {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repo format: %s", repo)
	}

	owner, repoName := parts[0], parts[1]

	var allAlerts []*github.DependabotAlert
	opts := &github.ListAlertsOptions{
		State:       github.String("open"),
		ListOptions: github.ListOptions{PerPage: APIPageSize},
	}

	for {
		alerts, resp, err := p.client.Dependabot.ListRepoAlerts(ctx, owner, repoName, opts)
		if p.verbose {
			slog.Info("GitHub API response", "repo", repo, "status", resp.StatusCode, "alertsInPage", len(alerts))
		}
		if err != nil {
			// Check if it's a 403/404 (no access or disabled)
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				if p.verbose {
					slog.Warn("no access to Dependabot alerts", "repo", repo, "status", resp.StatusCode,
						"hint", "ensure token has 'security_events' scope or Dependabot is enabled")
				}
				return nil, nil // Skip this repo
			}
			return nil, err
		}

		allAlerts = append(allAlerts, alerts...)

		if resp.NextPage == 0 {
			break
		}
		opts.ListOptions.Page = resp.NextPage
	}

	return allAlerts, nil
}

// alertToVulnerability converts a GitHub Dependabot alert to our common Vulnerability model
func (p *GitHubProvider) alertToVulnerability(repo string, alert *github.DependabotAlert) Vulnerability {
	v := Vulnerability{
		Repository:   repo,
		Provider:     "github",
		DiscoveredAt: alert.GetCreatedAt().Time,
	}

	// Get vulnerability details from the security advisory
	if alert.SecurityAdvisory != nil {
		adv := alert.SecurityAdvisory

		v.ID = adv.GetGHSAID()
		v.Description = adv.GetSummary()

		// Get CVE if available
		v.CVE = adv.GetCVEID()

		// Get severity and normalize (e.g., "moderate" → "medium")
		v.Severity = NormalizeSeverity(adv.GetSeverity(), p.severityMappings)

		// Get CVSS score
		if adv.CVSS != nil && adv.CVSS.Score != nil {
			v.CVSS = *adv.CVSS.Score
		}
	}

	// Get package info from dependency
	if alert.Dependency != nil {
		if alert.Dependency.Package != nil {
			v.Package = alert.Dependency.Package.GetName()
		}
		// Note: Dependabot API doesn't expose the installed version directly.
		// ManifestPath is the file path (e.g., "package.json"), not a version.
		// Version is left empty; the vulnerable range is in SecurityVulnerability.
	}

	// Get fixed version from security vulnerability
	if alert.SecurityVulnerability != nil {
		if alert.SecurityVulnerability.FirstPatchedVersion != nil {
			v.FixedVersion = alert.SecurityVulnerability.FirstPatchedVersion.GetIdentifier()
		}
	}

	// Build URL
	if alert.HTMLURL != nil {
		v.URL = *alert.HTMLURL
	}

	return v
}

// isExcluded checks if a repo is in the exclusion list
func (p *GitHubProvider) isExcluded(repo string) bool {
	for _, excluded := range p.excludeRepos {
		if strings.EqualFold(excluded, repo) {
			return true
		}
	}
	return false
}

// matchesPattern checks if a repo matches any of the configured patterns
func (p *GitHubProvider) matchesPattern(repo string) bool {
	for _, pattern := range p.repoPatterns {
		if filter.MatchPattern(pattern, repo) {
			return true
		}
	}
	return false
}
