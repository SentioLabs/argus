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

	"github.com/sentiolabs/patrol/internal/config"
)

const (
	// REST API base URL (v1 API is deprecated)
	snykRESTBaseURL = "https://api.snyk.io/rest"
	// v1 API base URL (still used for issues endpoint)
	snykV1BaseURL = "https://api.snyk.io/v1"
	// API version for REST endpoints (latest stable)
	snykAPIVersion = "2025-11-05"
)

// SnykProvider fetches vulnerabilities from Snyk
type SnykProvider struct {
	client          *http.Client
	token           string
	orgID           string
	projectIDs      []string
	projectPatterns []string
	excludeProjects []string
	filters         config.FiltersConfig
	verbose         bool
}

// REST API response for projects (JSON:API format)
type snykRESTProjectsResponse struct {
	Data  []snykRESTProject `json:"data"`
	Links snykLinks         `json:"links,omitempty"`
}

type snykRESTProject struct {
	ID         string                   `json:"id"`
	Type       string                   `json:"type"`
	Attributes snykRESTProjectAttrs     `json:"attributes"`
}

type snykRESTProjectAttrs struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Origin      string    `json:"origin"`
	Created     time.Time `json:"created"`
	Status      string    `json:"status"`
	TargetFile  string    `json:"target_file,omitempty"`
}

type snykLinks struct {
	Next string `json:"next,omitempty"`
}

// v1 API response for issues (still works)
type snykIssuesResponse struct {
	Issues []snykIssue `json:"issues"`
}

type snykIssue struct {
	ID           string          `json:"id"`
	IssueType    string          `json:"issueType"`
	PkgName      string          `json:"pkgName"`
	PkgVersion   string          `json:"pkgVersion"`
	IssueData    snykIssueData   `json:"issueData"`
	IsPatched    bool            `json:"isPatched"`
	IsIgnored    bool            `json:"isIgnored"`
	IntroducedAt time.Time       `json:"introducedThrough"`
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
func NewSnykProvider(token string, cfg config.ProviderConfig, filters config.FiltersConfig, verbose bool) (*SnykProvider, error) {
	if token == "" {
		return nil, fmt.Errorf("PATROL_SNYK_TOKEN environment variable is required")
	}

	if cfg.OrgID == "" {
		return nil, fmt.Errorf("Snyk org_id is required in config")
	}

	return &SnykProvider{
		client:          &http.Client{Timeout: 30 * time.Second},
		token:           token,
		orgID:           cfg.OrgID,
		projectIDs:      cfg.ProjectIDs,
		projectPatterns: cfg.ProjectPatterns,
		excludeProjects: cfg.ExcludeProjects,
		filters:         filters,
		verbose:         verbose,
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
			if p.shouldInclude(v) {
				vulns = append(vulns, v)
			}
		}
	}

	return vulns, nil
}

// getProjects returns the list of projects to check using the REST API
func (p *SnykProvider) getProjects(ctx context.Context) ([]snykProject, error) {
	// If specific project IDs are configured, use those
	if len(p.projectIDs) > 0 {
		var projects []snykProject
		for _, id := range p.projectIDs {
			projects = append(projects, snykProject{ID: id, Name: id})
		}
		return projects, nil
	}

	// Use REST API to get all projects in the org
	url := fmt.Sprintf("%s/orgs/%s/projects?version=%s&limit=100", snykRESTBaseURL, p.orgID, snykAPIVersion)

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

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

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

		for _, p := range projectsResp.Data {
			allProjects = append(allProjects, snykProject{
				ID:   p.ID,
				Name: p.Attributes.Name,
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
		if p.isProjectExcluded(project.Name) {
			if p.verbose {
				slog.Info("excluding project", "project", project.Name)
			}
			continue
		}

		// Check patterns (if configured)
		if len(p.projectPatterns) > 0 && !p.matchesProjectPattern(project.Name) {
			continue
		}

		filteredProjects = append(filteredProjects, project)
	}

	if p.verbose && len(p.projectPatterns) > 0 || len(p.excludeProjects) > 0 {
		slog.Info("filtered projects", "total", len(allProjects), "matched", len(filteredProjects))
	}

	return filteredProjects, nil
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

	body, _ := io.ReadAll(resp.Body)

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
		ID:           issue.IssueData.ID,
		Severity:     strings.ToLower(issue.IssueData.Severity),
		Package:      issue.PkgName,
		Version:      issue.PkgVersion,
		Repository:   project.Name,
		Description:  issue.IssueData.Title,
		URL:          issue.IssueData.URL,
		CVSS:         issue.IssueData.CVSSScore,
		Provider:     "snyk",
		DiscoveredAt: issue.IntroducedAt,
	}

	// Get CVE if available
	if len(issue.IssueData.Identifiers.CVE) > 0 {
		v.CVE = issue.IssueData.Identifiers.CVE[0]
	}

	// Get fixed version if available
	if len(issue.IssueData.FixedIn) > 0 {
		v.FixedVersion = issue.IssueData.FixedIn[0]
	}

	// Use current time if introduced time is zero
	if v.DiscoveredAt.IsZero() {
		v.DiscoveredAt = time.Now()
	}

	return v
}

// shouldInclude checks if a vulnerability passes the configured filters
func (p *SnykProvider) shouldInclude(v Vulnerability) bool {
	// Check severity filter
	minSeverity := strings.ToLower(p.filters.MinSeverity)
	if minSeverity != "" {
		minLevel := config.SeverityOrder[minSeverity]
		vulnLevel := config.SeverityOrder[strings.ToLower(v.Severity)]
		if vulnLevel < minLevel {
			return false
		}
	}

	// Check CVSS filter
	if p.filters.CVSSMin > 0 && v.CVSS < p.filters.CVSSMin {
		return false
	}

	// Check age filter
	if p.filters.MaxAgeDays > 0 {
		maxAge := time.Duration(p.filters.MaxAgeDays) * 24 * time.Hour
		if time.Since(v.DiscoveredAt) > maxAge {
			return false
		}
	}

	// Check package filters
	if len(p.filters.Packages) > 0 {
		matched := false
		for _, pkg := range p.filters.Packages {
			if matchPattern(pkg, v.Package) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check exclude packages
	for _, pkg := range p.filters.ExcludePackages {
		if matchPattern(pkg, v.Package) {
			return false
		}
	}

	return true
}

// isProjectExcluded checks if a project name is in the exclusion list
func (p *SnykProvider) isProjectExcluded(projectName string) bool {
	for _, excluded := range p.excludeProjects {
		if strings.EqualFold(excluded, projectName) {
			return true
		}
	}
	return false
}

// matchesProjectPattern checks if a project name matches any of the configured patterns
func (p *SnykProvider) matchesProjectPattern(projectName string) bool {
	for _, pattern := range p.projectPatterns {
		if matchPattern(pattern, projectName) {
			return true
		}
	}
	return false
}
