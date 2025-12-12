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
	Provider   string `json:"provider"`
	VulnID     string `json:"vuln_id"`
	CVE        string `json:"cve,omitempty"`
	Severity   string `json:"severity"`
	Package    string `json:"package"`
	Repository string `json:"repository"`
	Action     string `json:"action"`
	Status     string `json:"status"`
	JiraKey    string `json:"jira_key,omitempty"`
	Error      string `json:"error,omitempty"`
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

// Print outputs the sync results in the specified format
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

	for _, r := range results {
		switch r.Action {
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
	table.Header("Provider", "Severity", "CVE/ID", "Package", "Repository", "Action", "Jira")

	for _, r := range output.Results {
		vulnID := r.CVE
		if vulnID == "" {
			vulnID = r.VulnID
		}

		jiraKey := r.JiraKey
		if r.Error != "" {
			jiraKey = "ERROR"
		}

		table.Append(
			r.Provider,
			r.Severity,
			truncate(vulnID, 20),
			truncate(r.Package, 25),
			truncate(r.Repository, 30),
			r.Action,
			jiraKey,
		)
	}

	table.Render()

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
