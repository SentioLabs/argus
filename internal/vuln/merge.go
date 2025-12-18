package vuln

import (
	"fmt"
	"strings"
	"time"

	"github.com/sentiolabs/argus/internal/provider"
)

// MergedVulnerability represents a vulnerability that may have been
// detected by multiple providers across multiple repositories.
// It aggregates information to provide a unified view of the security issue.
type MergedVulnerability struct {
	// Core vulnerability info (from first detection)
	ID           string
	CVE          string
	Severity     string
	CVSS         float64
	Package      string
	Version      string
	FixedVersion string
	Description  string
	URL          string
	DiscoveredAt time.Time

	// Aggregated info from all detections
	Providers    []string // e.g., ["github", "snyk"]
	Repositories []string // all repos where detected

	// Assignee is the resolved Jira assignee account ID for this vulnerability.
	// When using MergeWithAssignees, vulnerabilities with different assignees
	// are kept as separate MergedVulnerability instances.
	Assignee string
}

// AssigneeResolver is the interface for resolving assignees based on provider and repository.
// This allows the merge logic to remain decoupled from the config package.
type AssigneeResolver interface {
	Resolve(providerName, repository string) string
}

// Merge combines vulnerabilities from multiple providers.
// It deduplicates by CVE (preferred) or by a combination of Package, Severity, and ID.
// It aggregates providers and repositories, and retains the most critical/complete information (e.g., highest CVSS, earliest discovery).
func Merge(vulns []provider.Vulnerability) []MergedVulnerability {
	byKey := make(map[string]*MergedVulnerability)

	for _, v := range vulns {
		key := dedupeKey(v)

		if existing, ok := byKey[key]; ok {
			// Add provider if not already present
			existing.Providers = appendUnique(existing.Providers, v.Provider)
			// Add repository if not already present
			existing.Repositories = appendUnique(existing.Repositories, v.Repository)

			// Keep the higher CVSS score
			if v.CVSS > existing.CVSS {
				existing.CVSS = v.CVSS
			}

			// Prefer non-empty fixed version
			if existing.FixedVersion == "" && v.FixedVersion != "" {
				existing.FixedVersion = v.FixedVersion
			}

			// Keep earliest discovery date
			if v.DiscoveredAt.Before(existing.DiscoveredAt) {
				existing.DiscoveredAt = v.DiscoveredAt
			}

			// Prefer longer description
			if len(v.Description) > len(existing.Description) {
				existing.Description = v.Description
			}

			// Prefer non-empty URL
			if existing.URL == "" && v.URL != "" {
				existing.URL = v.URL
			}
		} else {
			byKey[key] = &MergedVulnerability{
				ID:           v.ID,
				CVE:          v.CVE,
				Severity:     v.Severity,
				CVSS:         v.CVSS,
				Package:      v.Package,
				Version:      v.Version,
				FixedVersion: v.FixedVersion,
				Description:  v.Description,
				URL:          v.URL,
				DiscoveredAt: v.DiscoveredAt,
				Providers:    []string{v.Provider},
				Repositories: []string{v.Repository},
			}
		}
	}

	// Convert map to slice
	result := make([]MergedVulnerability, 0, len(byKey))
	for _, v := range byKey {
		result = append(result, *v)
	}

	return result
}

// MergeWithAssignees combines vulnerabilities with assignee-aware grouping.
// Unlike Merge, this function groups by (CVE, Assignee), so the same CVE
// in repositories with different assignees results in separate MergedVulnerability
// instances - enabling separate Jira tickets per assignee.
//
// The resolver is called for each vulnerability to determine its assignee based
// on the provider and repository. Vulnerabilities with the same CVE (or fallback key)
// and same assignee are merged together.
func MergeWithAssignees(vulns []provider.Vulnerability, resolver AssigneeResolver) []MergedVulnerability {
	byKey := make(map[string]*MergedVulnerability)

	for _, v := range vulns {
		assignee := resolver.Resolve(v.Provider, v.Repository)
		key := dedupeKeyWithAssignee(v, assignee)

		if existing, ok := byKey[key]; ok {
			// Add provider if not already present
			existing.Providers = appendUnique(existing.Providers, v.Provider)
			// Add repository if not already present
			existing.Repositories = appendUnique(existing.Repositories, v.Repository)

			// Keep the higher CVSS score
			if v.CVSS > existing.CVSS {
				existing.CVSS = v.CVSS
			}

			// Prefer non-empty fixed version
			if existing.FixedVersion == "" && v.FixedVersion != "" {
				existing.FixedVersion = v.FixedVersion
			}

			// Keep earliest discovery date
			if v.DiscoveredAt.Before(existing.DiscoveredAt) {
				existing.DiscoveredAt = v.DiscoveredAt
			}

			// Prefer longer description
			if len(v.Description) > len(existing.Description) {
				existing.Description = v.Description
			}

			// Prefer non-empty URL
			if existing.URL == "" && v.URL != "" {
				existing.URL = v.URL
			}
		} else {
			byKey[key] = &MergedVulnerability{
				ID:           v.ID,
				CVE:          v.CVE,
				Severity:     v.Severity,
				CVSS:         v.CVSS,
				Package:      v.Package,
				Version:      v.Version,
				FixedVersion: v.FixedVersion,
				Description:  v.Description,
				URL:          v.URL,
				DiscoveredAt: v.DiscoveredAt,
				Providers:    []string{v.Provider},
				Repositories: []string{v.Repository},
				Assignee:     assignee,
			}
		}
	}

	// Convert map to slice
	result := make([]MergedVulnerability, 0, len(byKey))
	for _, v := range byKey {
		result = append(result, *v)
	}

	return result
}

// dedupeKeyWithAssignee returns a unique key that includes the assignee.
// This ensures vulnerabilities with different assignees are kept separate.
func dedupeKeyWithAssignee(v provider.Vulnerability, assignee string) string {
	baseKey := dedupeKey(v)
	return baseKey + "|" + assignee
}

// dedupeKey returns a unique key for deduplication
// Prefers CVE if available, otherwise uses package+severity+ID
func dedupeKey(v provider.Vulnerability) string {
	if v.CVE != "" {
		return v.CVE
	}
	return fmt.Sprintf("%s:%s:%s", v.Package, v.Severity, v.ID)
}

// appendUnique appends a value to a slice only if it's not already present
func appendUnique(slice []string, value string) []string {
	for _, s := range slice {
		if s == value {
			return slice
		}
	}
	return append(slice, value)
}

// ProvidersString returns a comma-separated list of providers sorted and joined.
func (m *MergedVulnerability) ProvidersString() string {
	return strings.Join(m.Providers, ", ")
}

// RepositoriesString returns a formatted list of repositories
func (m *MergedVulnerability) RepositoriesString() string {
	return strings.Join(m.Repositories, ", ")
}

// DisplayID returns the most appropriate identifier for display (CVE if available, otherwise internal ID).
func (m *MergedVulnerability) DisplayID() string {
	if m.CVE != "" {
		return m.CVE
	}
	return m.ID
}
