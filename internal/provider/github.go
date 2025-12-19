package provider

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/go-github/v57/github"
	"github.com/sentiolabs/argus/internal/config"
	"github.com/sentiolabs/argus/internal/filter"
	"golang.org/x/oauth2"
)

// GitHubProvider fetches Dependabot alerts from GitHub
type GitHubProvider struct {
	client           *github.Client
	cfg              *config.Config
	orgs             []string
	repoIncludes     []config.RepoInclude
	repoExcludes     []string
	severityMappings map[string]string
	verbose          bool
}

// NewGitHubProvider creates a new GitHub Dependabot provider
func NewGitHubProvider(token string, fullCfg *config.Config, providerCfg config.ProviderConfig, severityMappings map[string]string, verbose bool) (*GitHubProvider, error) {
	if token == "" {
		return nil, fmt.Errorf("ARGUS_GITHUB_TOKEN environment variable is required")
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
		cfg:              fullCfg,
		orgs:             providerCfg.Orgs,
		repoIncludes:     providerCfg.RepoIncludes,
		repoExcludes:     providerCfg.RepoExcludes,
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

		// Get repo-specific filter (applies hierarchy: defaults → provider → repo)
		filterCfg := p.cfg.GetRepoFilter("github", repo)
		filterCfg.Verbose = p.verbose
		repoFilter := filter.New(filterCfg)

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
			if repoFilter.ShouldInclude(v) {
				vulns = append(vulns, v)
			}
		}
	}

	return vulns, nil
}

// getRepositories returns the list of repositories to check for alerts
func (p *GitHubProvider) getRepositories(ctx context.Context) ([]string, error) {
	var repos []string

	// If repo_includes is specified, only include matching repos
	if len(p.repoIncludes) > 0 {
		// Fetch all repos from orgs to match against patterns
		allOrgRepos, err := p.getAllOrgRepos(ctx)
		if err != nil {
			return nil, err
		}

		for _, fullName := range allOrgRepos {
			if p.matchesInclude(fullName) && !p.matchesExclude(fullName) {
				repos = append(repos, fullName)
			}
		}
		return repos, nil
	}

	// Otherwise, get all repos from configured orgs (apply excludes only)
	for _, org := range p.orgs {
		orgRepos, err := p.getOrgRepositories(ctx, org)
		if err != nil {
			return nil, fmt.Errorf("failed to get repos for org %s: %w", org, err)
		}

		for _, repo := range orgRepos {
			fullName := fmt.Sprintf("%s/%s", org, repo)

			if p.matchesExclude(fullName) {
				continue
			}

			repos = append(repos, fullName)
		}
	}

	return repos, nil
}

// getAllOrgRepos fetches all repositories from all configured orgs
func (p *GitHubProvider) getAllOrgRepos(ctx context.Context) ([]string, error) {
	var allRepos []string
	for _, org := range p.orgs {
		orgRepos, err := p.getOrgRepositories(ctx, org)
		if err != nil {
			return nil, fmt.Errorf("failed to get repos for org %s: %w", org, err)
		}
		for _, repo := range orgRepos {
			allRepos = append(allRepos, fmt.Sprintf("%s/%s", org, repo))
		}
	}
	return allRepos, nil
}

// matchesInclude checks if a repo matches any of the repo_includes entries
func (p *GitHubProvider) matchesInclude(fullName string) bool {
	for _, include := range p.repoIncludes {
		if filter.MatchPattern(include.Name, fullName) {
			return true
		}
	}
	return false
}

// matchesExclude checks if a repo matches any of the repo_excludes patterns
func (p *GitHubProvider) matchesExclude(fullName string) bool {
	for _, pattern := range p.repoExcludes {
		if filter.MatchPattern(pattern, fullName) {
			return true
		}
	}
	return false
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
