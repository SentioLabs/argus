package jira

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	jira "github.com/andygrunwald/go-jira/v2/cloud"
	"github.com/sentiolabs/argus/internal/config"
	"github.com/sentiolabs/argus/internal/vuln"
)

// Client wraps the Jira API client
type Client struct {
	client     *jira.Client
	verbose    bool
	emailCache map[string]string // email -> accountID cache for the session
}

// escapeJQL escapes special characters in JQL query strings to prevent injection
func escapeJQL(s string) string {
	// JQL requires escaping of special characters: \ " '
	// Order matters: escape backslash first
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		`'`, `\'`,
	)
	return replacer.Replace(s)
}

// providerToLabel maps internal provider names to Jira label names
func providerToLabel(provider string) string {
	switch provider {
	case "github":
		return "argus:dependabot"
	default:
		return "argus:" + provider
	}
}

// TicketInfo holds information about an existing Jira ticket
type TicketInfo struct {
	Key     string
	Created time.Time
	Status  string
}

// NewClient creates a new Jira client
func NewClient(url, username, token string, verbose bool) (*Client, error) {
	if url == "" || username == "" || token == "" {
		return nil, fmt.Errorf("JIRA_URL, JIRA_USERNAME, and JIRA_TOKEN environment variables are required")
	}

	tp := jira.BasicAuthTransport{
		Username: username,
		APIToken: token,
	}

	client, err := jira.NewClient(url, tp.Client())
	if err != nil {
		return nil, fmt.Errorf("failed to create Jira client: %w", err)
	}

	return &Client{
		client:     client,
		verbose:    verbose,
		emailCache: make(map[string]string),
	}, nil
}

// ResolveAssignee converts an email address to a Jira account ID.
// If the value contains "@", it's treated as an email and looked up via the Jira API.
// Otherwise, it's assumed to be a raw account ID and returned as-is.
// Results are cached for the duration of the session.
func (c *Client) ResolveAssignee(ctx context.Context, assignee string) (string, error) {
	if assignee == "" {
		return "", nil
	}

	// Not an email - return as-is (assumed to be raw account ID)
	if !strings.Contains(assignee, "@") {
		return assignee, nil
	}

	// Check cache first
	if cached, ok := c.emailCache[assignee]; ok {
		if c.verbose {
			slog.Debug("using cached email resolution", "email", assignee, "accountID", cached)
		}
		return cached, nil
	}

	// Lookup via Jira API
	if c.verbose {
		slog.Debug("looking up user by email", "email", assignee)
	}

	users, _, err := c.client.User.Find(ctx, assignee, jira.WithActive(true))
	if err != nil {
		return "", fmt.Errorf("failed to lookup user %s: %w", assignee, err)
	}

	if c.verbose {
		slog.Debug("user search returned", "query", assignee, "count", len(users))
		for i, u := range users {
			slog.Debug("user result", "index", i, "accountID", u.AccountID, "email", u.EmailAddress, "displayName", u.DisplayName)
		}
	}

	// Find exact email match (Find() does partial matching)
	for _, user := range users {
		if strings.EqualFold(user.EmailAddress, assignee) {
			c.emailCache[assignee] = user.AccountID
			if c.verbose {
				slog.Debug("resolved email to account ID", "email", assignee, "accountID", user.AccountID, "displayName", user.DisplayName)
			}
			return user.AccountID, nil
		}
	}

	// If no email match but we have exactly one result, use it
	// (Jira Cloud may hide emails for privacy, but the search matched)
	if len(users) == 1 {
		user := users[0]
		c.emailCache[assignee] = user.AccountID
		if c.verbose {
			slog.Debug("using single search result (email hidden)", "query", assignee, "accountID", user.AccountID, "displayName", user.DisplayName)
		}
		return user.AccountID, nil
	}

	return "", fmt.Errorf("user with email %s not found in Jira (found %d results, need exact match)", assignee, len(users))
}

// ResolveAssigneeWithFallback resolves an assignee using the hierarchy of candidates.
// It tries each candidate in order until one resolves successfully.
// If all candidates fail, it returns an error.
func (c *Client) ResolveAssigneeWithFallback(ctx context.Context, resolver *config.AssigneeResolver, providerName, repo string) (string, error) {
	candidates := resolver.GetCandidates(providerName, repo)

	if len(candidates) == 0 {
		return "", nil // No assignee configured
	}

	for i, candidate := range candidates {
		accountID, err := c.ResolveAssignee(ctx, candidate)
		if err == nil {
			return accountID, nil
		}

		// Log warning for non-final failures
		if i < len(candidates)-1 {
			slog.Warn("assignee lookup failed, trying fallback", "email", candidate, "error", err)
		}
	}

	return "", fmt.Errorf("all assignee lookups failed (tried: %v)", candidates)
}

// FindExistingTicket searches for an existing open ticket with the given vulnerability ID or CVE.
// It uses JQL to find tickets that are not in "Done" status and have the "argus" label.
func (c *Client) FindExistingTicket(ctx context.Context, project, vulnID, cve string) (*TicketInfo, error) {
	// Build JQL query to find existing open tickets
	var jqlParts []string

	jqlParts = append(jqlParts, fmt.Sprintf("project = %s", project))
	jqlParts = append(jqlParts, "statusCategory != Done") // Only find tickets not in Done category
	jqlParts = append(jqlParts, "labels = argus")        // Only match argus-created tickets

	if cve != "" {
		escaped := escapeJQL(cve)
		jqlParts = append(jqlParts, fmt.Sprintf("(summary ~ \"%s\" OR description ~ \"%s\")", escaped, escaped))
	} else if vulnID != "" {
		escaped := escapeJQL(vulnID)
		jqlParts = append(jqlParts, fmt.Sprintf("(summary ~ \"%s\" OR description ~ \"%s\")", escaped, escaped))
	} else {
		return nil, nil
	}

	jql := strings.Join(jqlParts, " AND ")

	if c.verbose {
		slog.Debug("searching for existing tickets", "jql", jql)
	}

	// Use the new SearchV2JQL method (uses /rest/api/2/search/jql endpoint)
	issues, _, err := c.client.Issue.SearchV2JQL(ctx, jql, &jira.SearchOptionsV2{
		MaxResults: 1,
		Fields:     []string{"key", "created", "status"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to search for existing tickets: %w", err)
	}

	if c.verbose {
		slog.Debug("found matching tickets", "count", len(issues))
	}

	if len(issues) > 0 {
		issue := issues[0]
		ticketInfo := &TicketInfo{
			Key: issue.Key,
		}

		// Get created date
		if issue.Fields != nil && !time.Time(issue.Fields.Created).IsZero() {
			ticketInfo.Created = time.Time(issue.Fields.Created)
		}

		// Get status name
		if issue.Fields != nil && issue.Fields.Status != nil {
			ticketInfo.Status = issue.Fields.Status.Name
		}

		return ticketInfo, nil
	}

	return nil, nil
}

// GetLastArgusComment returns the timestamp of the last argus comment on an issue
func (c *Client) GetLastArgusComment(ctx context.Context, issueKey string) (time.Time, error) {
	// Get issue with comments expanded
	issue, _, err := c.client.Issue.Get(ctx, issueKey, &jira.GetQueryOptions{
		Fields: "comment",
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get issue comments: %w", err)
	}

	if issue == nil || issue.Fields == nil || issue.Fields.Comments == nil {
		return time.Time{}, nil
	}

	// Find the most recent argus comment (iterate in reverse for most recent)
	comments := issue.Fields.Comments.Comments
	for i := len(comments) - 1; i >= 0; i-- {
		if strings.HasPrefix(comments[i].Body, "[argus]") {
			// Parse the created timestamp - Jira uses format like "2024-01-15T10:30:00.000+0000"
			created, err := parseJiraTimestamp(comments[i].Created)
			if err != nil {
				if c.verbose {
					slog.Warn("failed to parse comment timestamp", "timestamp", comments[i].Created, "error", err)
				}
				continue // Skip if we can't parse
			}
			return created, nil
		}
	}

	return time.Time{}, nil
}

// AddMergedComment adds a comment to an existing ticket with merged vulnerability info
func (c *Client) AddMergedComment(ctx context.Context, ticketInfo *TicketInfo, v vuln.MergedVulnerability) error {
	// Calculate days since ticket was created
	daysOpen := int(time.Since(ticketInfo.Created).Hours() / 24)

	// Build fix version string
	fixVersion := "Unknown"
	if v.FixedVersion != "" {
		fixVersion = v.FixedVersion
	}

	// Build CVSS string
	cvssStr := ""
	if v.CVSS > 0 {
		cvssStr = fmt.Sprintf(" (CVSS: %.1f)", v.CVSS)
	}

	// Build URL string
	urlStr := ""
	if v.URL != "" {
		urlStr = fmt.Sprintf("\n\nDetails: %s", v.URL)
	}

	// Build repositories list
	reposStr := strings.Join(v.Repositories, "\n- ")

	comment := fmt.Sprintf(`[argus] Vulnerability still detected

This vulnerability was first reported %d days ago and the ticket is currently %s.

Detected by: %s
Affected repositories:
- %s

Current detection:
- Package: %s@%s
- Severity: %s%s
- Fix available: %s%s`,
		daysOpen,
		ticketInfo.Status,
		v.ProvidersString(),
		reposStr,
		v.Package,
		v.Version,
		v.Severity,
		cvssStr,
		fixVersion,
		urlStr,
	)

	_, _, err := c.client.Issue.AddComment(ctx, ticketInfo.Key, &jira.Comment{
		Body: comment,
	})
	if err != nil {
		return fmt.Errorf("failed to add comment: %w", err)
	}

	return nil
}

// CreateMergedTicket creates a new Jira ticket for a merged vulnerability.
// It constructs the ticket summary, description, and applies necessary labels and components.
func (c *Client) CreateMergedTicket(ctx context.Context, jiraCfg config.JiraConfig, v vuln.MergedVulnerability, priority string, addToSprint bool) (string, error) {
	displayID := v.CVE
	if displayID == "" {
		displayID = v.ID
	}
	summary := fmt.Sprintf("[%s] %s in %s", v.Severity, displayID, v.Package)

	description := buildMergedDescription(v)

	// Build issue fields
	fields := &jira.IssueFields{
		Project: jira.Project{
			Key: jiraCfg.Project,
		},
		Summary:     summary,
		Description: description,
		Type: jira.IssueType{
			Name: "Bug",
		},
		Priority: &jira.Priority{
			Name: priority,
		},
	}

	// Set assignee if configured
	if jiraCfg.Assignee != "" {
		fields.Assignee = &jira.User{
			AccountID: jiraCfg.Assignee,
		}
	}

	// Set labels (include argus label and provider labels for tracking)
	labels := []string{"argus"}
	for _, p := range v.Providers {
		labels = append(labels, providerToLabel(p))
	}
	// Add severity label
	if v.Severity != "" {
		labels = append(labels, "argus:"+v.Severity)
	}
	if len(jiraCfg.Labels) > 0 {
		fields.Labels = append(jiraCfg.Labels, labels...)
	} else {
		fields.Labels = labels
	}

	// Set components
	if len(jiraCfg.Components) > 0 {
		components := make([]*jira.Component, len(jiraCfg.Components))
		for i, name := range jiraCfg.Components {
			components[i] = &jira.Component{Name: name}
		}
		fields.Components = components
	}

	issue := &jira.Issue{
		Fields: fields,
	}

	created, resp, err := c.client.Issue.Create(ctx, issue)
	if err != nil {
		// Try to get more details from the response body
		if resp != nil && resp.Body != nil {
			body, _ := io.ReadAll(resp.Body)
			if len(body) > 0 {
				return "", fmt.Errorf("failed to create issue: %w - details: %s", err, string(body))
			}
		}
		return "", fmt.Errorf("failed to create issue: %w", err)
	}

	// Add to sprint if required
	if addToSprint && (jiraCfg.BoardID > 0 || jiraCfg.BoardName != "") {
		if err := c.addToActiveSprint(ctx, jiraCfg.BoardID, jiraCfg.BoardName, created.Key); err != nil {
			// Log but don't fail - the ticket was still created
			slog.Warn("failed to add ticket to sprint", "key", created.Key, "error", err)
		}
	}

	return created.Key, nil
}

// addToActiveSprint adds an issue to the active sprint for the given board
func (c *Client) addToActiveSprint(ctx context.Context, boardID int, boardName string, issueKey string) error {
	var boardIDInt64 int64

	// Use board ID if provided, otherwise look up by name
	if boardID > 0 {
		boardIDInt64 = int64(boardID)
	} else if boardName != "" {
		boards, _, err := c.client.Board.GetAllBoards(ctx, &jira.BoardListOptions{
			Name: boardName,
		})
		if err != nil {
			return fmt.Errorf("failed to get boards: %w", err)
		}

		if len(boards.Values) == 0 {
			return fmt.Errorf("board %q not found", boardName)
		}

		boardIDInt64 = int64(boards.Values[0].ID)
	} else {
		return fmt.Errorf("no board ID or name provided")
	}

	// Get active sprints for the board (filter by state=active)
	sprints, _, err := c.client.Board.GetAllSprints(ctx, boardIDInt64, &jira.GetAllSprintsOptions{
		State: "active",
	})
	if err != nil {
		return fmt.Errorf("failed to get sprints for board %d: %w", boardIDInt64, err)
	}

	if len(sprints.Values) == 0 {
		// No active sprints, check what sprints exist (for debugging)
		allSprints, _, _ := c.client.Board.GetAllSprints(ctx, boardIDInt64, &jira.GetAllSprintsOptions{
			State: "active,future",
		})
		var sprintStates []string
		if allSprints != nil {
			for _, sprint := range allSprints.Values {
				sprintStates = append(sprintStates, fmt.Sprintf("%s(%s)", sprint.Name, sprint.State))
			}
		}
		return fmt.Errorf("no active sprint found for board %d, active/future sprints: %v", boardIDInt64, sprintStates)
	}

	activeSprintID := sprints.Values[0].ID
	sprintName := sprints.Values[0].Name

	if c.verbose {
		slog.Debug("adding ticket to sprint", "key", issueKey, "sprint", sprintName, "sprintID", activeSprintID)
	}

	// Move issue to sprint
	_, err = c.client.Sprint.MoveIssuesToSprint(ctx, activeSprintID, []string{issueKey})
	if err != nil {
		return fmt.Errorf("failed to move issue to sprint: %w", err)
	}

	return nil
}

// parseJiraTimestamp parses Jira's various timestamp formats
func parseJiraTimestamp(ts string) (time.Time, error) {
	// Jira uses formats like:
	// - "2024-01-15T10:30:00.000+0000" (no colon in timezone)
	// - "2024-01-15T10:30:00.000-0700" (with colon in timezone)
	// - "2024-01-15T10:30:00.000Z"     (UTC)
	formats := []string{
		"2006-01-02T15:04:05.000-0700", // with colon
		"2006-01-02T15:04:05.000Z0700", // without colon
		"2006-01-02T15:04:05.000Z",     // UTC
		time.RFC3339,                   // standard
		time.RFC3339Nano,               // with nanos
	}

	for _, format := range formats {
		if t, err := time.Parse(format, ts); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", ts)
}

func buildMergedDescription(v vuln.MergedVulnerability) string {
	var parts []string

	parts = append(parts, "*Vulnerability Details*")
	parts = append(parts, "")

	if v.CVE != "" {
		parts = append(parts, fmt.Sprintf("*CVE:* %s", v.CVE))
	}
	parts = append(parts, fmt.Sprintf("*ID:* %s", v.ID))
	parts = append(parts, fmt.Sprintf("*Severity:* %s", v.Severity))

	if v.CVSS > 0 {
		parts = append(parts, fmt.Sprintf("*CVSS:* %.1f", v.CVSS))
	}

	parts = append(parts, "")
	parts = append(parts, fmt.Sprintf("*Affected Package:* %s", v.Package))
	if v.Version != "" {
		parts = append(parts, fmt.Sprintf("*Current Version:* %s", v.Version))
	}
	if v.FixedVersion != "" {
		parts = append(parts, fmt.Sprintf("*Fixed Version:* %s", v.FixedVersion))
	}

	parts = append(parts, "")
	parts = append(parts, fmt.Sprintf("*Detected by:* %s", v.ProvidersString()))
	parts = append(parts, fmt.Sprintf("*Affected repositories:* %s", v.RepositoriesString()))
	parts = append(parts, fmt.Sprintf("*Discovered:* %s", v.DiscoveredAt.Format(time.RFC3339)))

	if v.Description != "" {
		parts = append(parts, "")
		parts = append(parts, "*Description:*")
		parts = append(parts, v.Description)
	}

	if v.URL != "" {
		parts = append(parts, "")
		parts = append(parts, fmt.Sprintf("*More Info:* %s", v.URL))
	}

	return strings.Join(parts, "\n")
}
