// Package output handles the formatting and display of Argus's execution results.
// It supports multiple formats such as JSON and Table.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
)

// SyncResult represents the result of processing a vulnerability
type SyncResult struct {
	Provider      string `json:"provider"`
	VulnID        string `json:"vuln_id"`
	CVE           string `json:"cve,omitempty"`
	Severity      string `json:"severity"`
	Package       string `json:"package"`
	Repository    string `json:"repository"`
	Action        string `json:"action"`
	Status        string `json:"status"`
	JiraKey       string `json:"jira_key,omitempty"`
	Assignee      string `json:"assignee,omitempty"`
	JiraAccountID string `json:"jira_account_id,omitempty"`
	Error         string `json:"error,omitempty"`
}

// Summary represents aggregated sync statistics
type Summary struct {
	Total   int `json:"total"`
	Created int `json:"created"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
	Errors  int `json:"errors"`
}

// Output wraps results with summary
type Output struct {
	Results []SyncResult `json:"results"`
	Summary Summary      `json:"summary"`
	DryRun  bool         `json:"dry_run"`
}

// Print outputs the sync results in the specified format (json or table).
// If dryRun is true, it indicates that no changes were actually made.
func Print(results []SyncResult, format string, dryRun bool) error {
	output := Output{
		Results: results,
		Summary: calculateSummary(results),
		DryRun:  dryRun,
	}

	switch strings.ToLower(format) {
	case "json":
		return printJSON(output)
	case "table":
		return printTable(output)
	default:
		return fmt.Errorf("unknown output format: %s", format)
	}
}

func calculateSummary(results []SyncResult) Summary {
	var summary Summary
	summary.Total = len(results)

	for i := range results {
		switch results[i].Action {
		case "created", "would_create":
			summary.Created++
		case "updated":
			summary.Updated++
		case "skipped":
			summary.Skipped++
		case "create_failed", "update_failed":
			summary.Errors++
		}
	}

	return summary
}

func printJSON(output Output) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func printTable(output Output) error {
	if output.DryRun {
		fmt.Println("DRY RUN - No changes will be made")
		fmt.Println()
	}

	table := tablewriter.NewTable(os.Stdout)

	// Show JIRA ID column in dry-run mode, JIRA KEY column in normal mode
	if output.DryRun {
		table.Header("Provider", "Severity", "CVE/ID", "Package", "Repository", "Action", "Assignee", "Jira ID")
	} else {
		table.Header("Provider", "Severity", "CVE/ID", "Package", "Repository", "Action", "Assignee", "Jira")
	}

	for i := range output.Results {
		r := &output.Results[i]
		vulnID := r.CVE
		if vulnID == "" {
			vulnID = r.VulnID
		}

		assignee := r.Assignee
		if r.Error != "" {
			assignee = "ERROR"
		}

		if output.DryRun {
			jiraID := r.JiraAccountID
			if jiraID == "" && r.Error != "" {
				jiraID = "ERROR"
			}
			_ = table.Append(
				r.Provider,
				r.Severity,
				truncate(vulnID, 20),
				truncate(r.Package, 25),
				truncate(r.Repository, 30),
				r.Action,
				assignee,
				truncate(jiraID, 20),
			)
		} else {
			_ = table.Append(
				r.Provider,
				r.Severity,
				truncate(vulnID, 20),
				truncate(r.Package, 25),
				truncate(r.Repository, 30),
				r.Action,
				assignee,
				r.JiraKey,
			)
		}
	}

	_ = table.Render()

	// Print summary
	fmt.Println()
	fmt.Printf("Summary: %d total, %d created, %d updated, %d skipped, %d errors\n",
		output.Summary.Total,
		output.Summary.Created,
		output.Summary.Updated,
		output.Summary.Skipped,
		output.Summary.Errors,
	)

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// SearchResultRow represents a single search result for display.
type SearchResultRow struct {
	Provider   string `json:"provider"`
	Severity   string `json:"severity"`
	ID         string `json:"id"`
	CVE        string `json:"cve,omitempty"`
	Package    string `json:"package"`
	Repository string `json:"repository"`
}

// PrintSearch outputs search results in the specified format.
func PrintSearch(results []SearchResultRow, format string) error {
	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)
	default:
		return printSearchTable(results)
	}
}

func printSearchTable(results []SearchResultRow) error {
	table := tablewriter.NewTable(os.Stdout)
	table.Header("Provider", "Severity", "ID", "CVE", "Package", "Repository")

	for i := range results {
		r := &results[i]
		_ = table.Append(
			r.Provider,
			r.Severity,
			truncate(r.ID, 38),
			truncate(r.CVE, 16),
			truncate(r.Package, 25),
			truncate(r.Repository, 32),
		)
	}

	_ = table.Render()
	fmt.Printf("\n%d results\n", len(results))
	return nil
}

// VulnDetail contains all fields for the detailed single-vulnerability view.
type VulnDetail struct {
	ID           string  `json:"id"`
	CVE          string  `json:"cve,omitempty"`
	Severity     string  `json:"severity"`
	CVSS         float64 `json:"cvss"`
	Package      string  `json:"package"`
	Version      string  `json:"version,omitempty"`
	FixedVersion string  `json:"fixed_version,omitempty"`
	Repository   string  `json:"repository"`
	Provider     string  `json:"provider"`
	DiscoveredAt string  `json:"discovered_at,omitempty"`
	URL          string  `json:"url,omitempty"`
	Description  string  `json:"description,omitempty"`
	ProjectKey   string  `json:"project_key,omitempty"`
}

// FormatDetail returns a human-readable detailed view of a single vulnerability.
func FormatDetail(d VulnDetail) string {
	var b strings.Builder

	line := func(label, value string) {
		fmt.Fprintf(&b, "  %-14s %s\n", label, value)
	}

	line("ID:", d.ID)
	if d.CVE != "" {
		line("CVE:", d.CVE)
	}
	line("Severity:", d.Severity)
	line("CVSS:", fmt.Sprintf("%.1f", d.CVSS))

	pkg := d.Package
	if d.Version != "" {
		pkg = fmt.Sprintf("%s (%s)", d.Package, d.Version)
	}
	line("Package:", pkg)

	if d.FixedVersion != "" {
		line("Fixed In:", d.FixedVersion)
	}
	line("Repository:", d.Repository)
	line("Provider:", d.Provider)
	if d.DiscoveredAt != "" {
		line("Discovered:", d.DiscoveredAt)
	}
	if d.URL != "" {
		line("URL:", d.URL)
	}
	if d.ProjectKey != "" {
		line("Project:", d.ProjectKey)
	}
	if d.Description != "" {
		fmt.Fprintf(&b, "\n  Description:\n  %s\n", d.Description)
	}

	return b.String()
}

// PrintDetail outputs a detailed vulnerability view in the specified format.
func PrintDetail(d VulnDetail, format string) error {
	if strings.ToLower(format) == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(d)
	}
	fmt.Println()
	fmt.Print(FormatDetail(d))
	return nil
}
