package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sentiolabs/argus/internal/config"
	"github.com/sentiolabs/argus/internal/filter"
)

const (
	// REST API base URL (v1 API is deprecated)
	snykRESTBaseURL = "https://api.snyk.io/rest"
	// v1 API base URL (still used for issues endpoint)
	snykV1BaseURL = "https://api.snyk.io/v1"
	// defaultSnykAPIVersion is the default API version for REST endpoints
	// See https://docs.snyk.io/snyk-api/rest-api for available versions
	defaultSnykAPIVersion = "2025-11-05"
)

// SnykProvider fetches vulnerabilities from Snyk
type SnykProvider struct {
	client          *http.Client
	token           string
	orgID           string
	apiVersion      string
	projectIncludes []config.RepoInclude
	projectExcludes []string
	filter          *filter.Filter
	severityMappings map[string]string
	verbose          bool
}

// REST API response for projects (JSON:API format)
type snykRESTProjectsResponse struct {
	Data  []snykRESTProject `json:"data"`
	Links snykLinks         `json:"links,omitempty"`
}

type snykRESTProject struct {
	ID         string               `json:"id"`
	Type       string               `json:"type"`
	Attributes snykRESTProjectAttrs `json:"attributes"`
}

type snykRESTProjectAttrs struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Origin     string    `json:"origin"`
	Created    time.Time `json:"created"`
	Status     string    `json:"status"`
	TargetFile string    `json:"target_file,omitempty"`
}

type snykLinks struct {
	Next string `json:"next,omitempty"`
}

// v1 API response for issues (still works)
type snykIssuesResponse struct {
	Issues []snykIssue `json:"issues"`
}

type snykIssue struct {
	ID         string        `json:"id"`
	IssueType  string        `json:"issueType"`
	PkgName    string        `json:"pkgName"`
	PkgVersion string        `json:"pkgVersion"`
	IssueData  snykIssueData `json:"issueData"`
	IsPatched  bool          `json:"isPatched"`
	IsIgnored  bool          `json:"isIgnored"`
	// Note: introducedThrough is an array (dependency path), not a timestamp.
	// We don't parse it; DiscoveredAt defaults to time.Now() in issueToVulnerability.
}

type snykIssueData struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Severity    string          `json:"severity"`
	URL         string          `json:"url"`
	Description string          `json:"description"`
	Identifiers snykIdentifiers `json:"identifiers"`
	CVSSv3      string          `json:"cvssV3,omitempty"`
	CVSSScore   float64         `json:"cvssScore"`
	FixedIn     []string        `json:"fixedIn,omitempty"`
}

type snykIdentifiers struct {
	CVE []string `json:"CVE,omitempty"`
	CWE []string `json:"CWE,omitempty"`
}

// snykProject is our internal representation
type snykProject struct {
	ID   string
	Name string
}

// NewSnykProvider creates a new Snyk provider
func NewSnykProvider(token string, cfg config.ProviderConfig, filters config.FiltersConfig, severityMappings map[string]string, verbose bool) (*SnykProvider, error) {
	if token == "" {
		return nil, fmt.Errorf("ARGUS_SNYK_TOKEN environment variable is required")
	}

	if cfg.OrgID == "" {
		return nil, fmt.Errorf("Snyk org_id is required in config")
	}

	// Use configured API version or fall back to default
	apiVersion := cfg.APIVersion
	if apiVersion == "" {
		apiVersion = defaultSnykAPIVersion
	}

	return &SnykProvider{
		client:          &http.Client{Timeout: HTTPTimeout},
		token:           token,
		orgID:           cfg.OrgID,
		apiVersion:      apiVersion,
		projectIncludes: cfg.ProjectIncludes,
		projectExcludes: cfg.ProjectExcludes,
		filter:          filter.New(filters),
		severityMappings: severityMappings,
		verbose:          verbose,
	}, nil
}

// Name returns the provider name
func (p *SnykProvider) Name() string {
	return "snyk"
}

// FetchVulnerabilities retrieves issues from Snyk
func (p *SnykProvider) FetchVulnerabilities(ctx context.Context) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// Get projects to check
	projects, err := p.getProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get projects: %w", err)
	}

	if p.verbose {
		slog.Info("found Snyk projects", "count", len(projects))
	}

	for _, project := range projects {
		if p.verbose {
			slog.Info("fetching issues for project", "project", project.Name, "id", project.ID)
		}

		issues, err := p.getIssuesForProject(ctx, project.ID)
		if err != nil {
			slog.Warn("failed to get issues for project", "project", project.Name, "error", err)
			continue
		}

		if p.verbose {
			slog.Info("found issues for project", "project", project.Name, "count", len(issues))
		}

		for _, issue := range issues {
			v := p.issueToVulnerability(project, issue)
			if p.filter.ShouldInclude(v) {
				vulns = append(vulns, v)
			}
		}
	}

	return vulns, nil
}

// getProjects returns the list of projects to check using the REST API
func (p *SnykProvider) getProjects(ctx context.Context) ([]snykProject, error) {
	// Use REST API to get all projects in the org
	url := fmt.Sprintf("%s/orgs/%s/projects?version=%s&limit=%d", snykRESTBaseURL, p.orgID, p.apiVersion, APIPageSize)

	if p.verbose {
		slog.Info("fetching projects from Snyk REST API", "url", url)
	}

	var allProjects []snykProject

	for url != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "token "+p.token)
		req.Header.Set("Content-Type", "application/vnd.api+json")

		resp, err := p.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			if p.verbose {
				slog.Error("Snyk API error", "status", resp.Status, "body", string(body))
			}
			return nil, fmt.Errorf("Snyk API error: %s - %s", resp.Status, string(body))
		}

		var projectsResp snykRESTProjectsResponse
		if err := json.Unmarshal(body, &projectsResp); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		for _, proj := range projectsResp.Data {
			allProjects = append(allProjects, snykProject{
				ID:   proj.ID,
				Name: proj.Attributes.Name,
			})
		}

		// Handle pagination
		url = ""
		if projectsResp.Links.Next != "" {
			url = projectsResp.Links.Next
			// The next link might be relative, make it absolute
			if !strings.HasPrefix(url, "http") {
				url = "https://api.snyk.io" + url
			}
		}
	}

	// Apply project filtering
	var filteredProjects []snykProject
	for _, project := range allProjects {
		// Check exclusions first
		if p.matchesExclude(project.Name) {
			if p.verbose {
				slog.Info("excluding project", "project", project.Name)
			}
			continue
		}

		// If includes are specified, only include matching projects
		if len(p.projectIncludes) > 0 && !p.matchesInclude(project.Name) {
			continue
		}

		filteredProjects = append(filteredProjects, project)
	}

	if p.verbose && (len(p.projectIncludes) > 0 || len(p.projectExcludes) > 0) {
		slog.Info("filtered projects", "total", len(allProjects), "matched", len(filteredProjects))
	}

	return filteredProjects, nil
}

// matchesInclude checks if a project matches any of the project_includes entries
func (p *SnykProvider) matchesInclude(projectName string) bool {
	for _, include := range p.projectIncludes {
		if filter.MatchPattern(include.Name, projectName) {
			return true
		}
	}
	return false
}

// matchesExclude checks if a project matches any of the project_excludes patterns
func (p *SnykProvider) matchesExclude(projectName string) bool {
	for _, pattern := range p.projectExcludes {
		if filter.MatchPattern(pattern, projectName) {
			return true
		}
	}
	return false
}

// getIssuesForProject fetches issues for a specific project using v1 API
// (The aggregated-issues endpoint is still available in v1)
func (p *SnykProvider) getIssuesForProject(ctx context.Context, projectID string) ([]snykIssue, error) {
	url := fmt.Sprintf("%s/org/%s/project/%s/aggregated-issues", snykV1BaseURL, p.orgID, projectID)

	if p.verbose {
		slog.Info("fetching issues from Snyk v1 API", "url", url)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(`{"includeDescription": true}`))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "token "+p.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if p.verbose {
			slog.Error("Snyk API error", "status", resp.Status, "body", string(body))
		}
		return nil, fmt.Errorf("Snyk API error: %s - %s", resp.Status, string(body))
	}

	var issuesResp snykIssuesResponse
	if err := json.Unmarshal(body, &issuesResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Filter to only vulnerabilities (not license issues)
	var vulnIssues []snykIssue
	for _, issue := range issuesResp.Issues {
		if issue.IssueType == "vuln" && !issue.IsPatched && !issue.IsIgnored {
			vulnIssues = append(vulnIssues, issue)
		}
	}

	return vulnIssues, nil
}

// issueToVulnerability converts a Snyk issue to our common Vulnerability model
func (p *SnykProvider) issueToVulnerability(project snykProject, issue snykIssue) Vulnerability {
	v := Vulnerability{
		ID:          issue.IssueData.ID,
		Severity:    NormalizeSeverity(issue.IssueData.Severity, p.severityMappings),
		Package:     issue.PkgName,
		Version:     issue.PkgVersion,
		Repository:  project.Name,
		Description: issue.IssueData.Title,
		URL:         issue.IssueData.URL,
		CVSS:        issue.IssueData.CVSSScore,
		Provider:    "snyk",
		// Note: Snyk v1 API doesn't provide a discovery timestamp.
		// DiscoveredAt will be set to time.Now() below.
		DiscoveredAt: time.Now(),
	}

	// Get CVE if available
	if len(issue.IssueData.Identifiers.CVE) > 0 {
		v.CVE = issue.IssueData.Identifiers.CVE[0]
	}

	// Get fixed version if available
	if len(issue.IssueData.FixedIn) > 0 {
		v.FixedVersion = issue.IssueData.FixedIn[0]
	}

	return v
}
