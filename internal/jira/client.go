package jira

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	jira "github.com/andygrunwald/go-jira/v2/cloud"
	"github.com/sentiolabs/patrol/internal/config"
	"github.com/sentiolabs/patrol/internal/provider"
)

// Client wraps the Jira API client
type Client struct {
	client    *jira.Client
	boardID   int
	boardName string
	verbose   bool
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
		client:  client,
		verbose: verbose,
	}, nil
}

// FindExistingTicket searches for an existing open ticket with the given vulnerability ID or CVE
func (c *Client) FindExistingTicket(ctx context.Context, project, vulnID, cve string) (*TicketInfo, error) {
	// Build JQL query to find existing open tickets
	var jqlParts []string

	jqlParts = append(jqlParts, fmt.Sprintf("project = %s", project))
	jqlParts = append(jqlParts, "statusCategory != Done") // Only find tickets not in Done category

	if cve != "" {
		jqlParts = append(jqlParts, fmt.Sprintf("(summary ~ \"%s\" OR description ~ \"%s\")", cve, cve))
	} else if vulnID != "" {
		jqlParts = append(jqlParts, fmt.Sprintf("(summary ~ \"%s\" OR description ~ \"%s\")", vulnID, vulnID))
	} else {
		return nil, nil
	}

	jql := strings.Join(jqlParts, " AND ")

	if c.verbose {
		fmt.Printf("Searching for existing tickets with JQL: %s\n", jql)
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
		fmt.Printf("Found %d matching tickets\n", len(issues))
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

// AddDuplicateComment adds a comment to an existing ticket about a duplicate occurrence
func (c *Client) AddDuplicateComment(ctx context.Context, ticketInfo *TicketInfo, v provider.Vulnerability) error {
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

	comment := fmt.Sprintf(`Vulnerability still detected

This vulnerability was first reported %d days ago and the ticket is currently %s.

Current detection:
- Repository: %s
- Package: %s@%s
- Severity: %s%s
- Fix available: %s%s`,
		daysOpen,
		ticketInfo.Status,
		v.Repository,
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

// CreateTicket creates a new Jira ticket for a vulnerability
func (c *Client) CreateTicket(ctx context.Context, jiraCfg config.JiraConfig, v provider.Vulnerability, priority string, addToSprint bool) (string, error) {
	// Build summary
	summary := fmt.Sprintf("[%s] %s in %s", v.Severity, v.CVE, v.Package)
	if v.CVE == "" {
		summary = fmt.Sprintf("[%s] %s in %s", v.Severity, v.ID, v.Package)
	}

	// Build description
	description := buildDescription(v)

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

	// Set labels
	if len(jiraCfg.Labels) > 0 {
		fields.Labels = jiraCfg.Labels
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
			fmt.Printf("Warning: failed to add %s to sprint: %v\n", created.Key, err)
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
		fmt.Printf("Adding %s to sprint %q (ID: %d)\n", issueKey, sprintName, activeSprintID)
	}

	// Move issue to sprint
	_, err = c.client.Sprint.MoveIssuesToSprint(ctx, activeSprintID, []string{issueKey})
	if err != nil {
		return fmt.Errorf("failed to move issue to sprint: %w", err)
	}

	return nil
}

func buildDescription(v provider.Vulnerability) string {
	var parts []string

	parts = append(parts, fmt.Sprintf("*Vulnerability Details*"))
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
	parts = append(parts, fmt.Sprintf("*Repository:* %s", v.Repository))
	parts = append(parts, fmt.Sprintf("*Provider:* %s", v.Provider))
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
