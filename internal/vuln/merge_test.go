package vuln

import (
	"testing"
	"time"

	"github.com/sentiolabs/argus/internal/provider"
)

// mockResolver implements AssigneeResolver for testing
type mockResolver struct {
	assignees       map[string]string // key: "provider|repo"
	defaultAssignee string
}

func (m *mockResolver) Resolve(providerName, repository string) string {
	key := providerName + "|" + repository
	if assignee, ok := m.assignees[key]; ok {
		return assignee
	}
	return m.defaultAssignee
}

func TestMerge(t *testing.T) {
	now := time.Now()

	vulns := []provider.Vulnerability{
		{
			ID:           "GHSA-1234",
			CVE:          "CVE-2024-1234",
			Severity:     "high",
			CVSS:         7.5,
			Package:      "lodash",
			Version:      "4.17.20",
			FixedVersion: "4.17.21",
			Repository:   "org/repo1",
			Provider:     "github",
			DiscoveredAt: now.Add(-24 * time.Hour),
		},
		{
			ID:           "SNYK-1234",
			CVE:          "CVE-2024-1234",
			Severity:     "high",
			CVSS:         8.0, // Higher CVSS from Snyk
			Package:      "lodash",
			Version:      "4.17.20",
			Repository:   "org/repo2",
			Provider:     "snyk",
			DiscoveredAt: now,
		},
	}

	merged := Merge(vulns)

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged vulnerability, got %d", len(merged))
	}

	m := merged[0]
	if m.CVE != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", m.CVE)
	}
	if m.CVSS != 8.0 {
		t.Errorf("expected highest CVSS 8.0, got %f", m.CVSS)
	}
	if len(m.Providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(m.Providers))
	}
	if len(m.Repositories) != 2 {
		t.Errorf("expected 2 repositories, got %d", len(m.Repositories))
	}
}

func TestMergeWithAssignees_SplitsByAssignee(t *testing.T) {
	now := time.Now()

	vulns := []provider.Vulnerability{
		{
			ID:         "GHSA-1234",
			CVE:        "CVE-2024-1234",
			Severity:   "high",
			CVSS:       7.5,
			Package:    "lodash",
			Repository: "org/repo1",
			Provider:   "github",
		},
		{
			ID:         "GHSA-1234",
			CVE:        "CVE-2024-1234",
			Severity:   "high",
			CVSS:       7.5,
			Package:    "lodash",
			Repository: "org/repo2",
			Provider:   "github",
		},
		{
			ID:           "GHSA-1234",
			CVE:          "CVE-2024-1234",
			Severity:     "high",
			CVSS:         7.5,
			Package:      "lodash",
			Repository:   "org/repo3",
			Provider:     "github",
			DiscoveredAt: now,
		},
	}

	// repo1 -> team-a, repo2 -> team-b, repo3 -> team-a
	resolver := &mockResolver{
		assignees: map[string]string{
			"github|org/repo1": "team-a",
			"github|org/repo2": "team-b",
			"github|org/repo3": "team-a",
		},
	}

	merged := MergeWithAssignees(vulns, resolver)

	if len(merged) != 2 {
		t.Fatalf("expected 2 merged vulns (one per assignee), got %d", len(merged))
	}

	// Build a map by assignee for easier verification
	byAssignee := make(map[string]*MergedVulnerability)
	for i := range merged {
		byAssignee[merged[i].Assignee] = &merged[i]
	}

	teamA := byAssignee["team-a"]
	if teamA == nil {
		t.Fatal("expected merged vuln for team-a")
	}
	if len(teamA.Repositories) != 2 {
		t.Errorf("team-a should have 2 repos, got %d: %v", len(teamA.Repositories), teamA.Repositories)
	}

	teamB := byAssignee["team-b"]
	if teamB == nil {
		t.Fatal("expected merged vuln for team-b")
	}
	if len(teamB.Repositories) != 1 {
		t.Errorf("team-b should have 1 repo, got %d", len(teamB.Repositories))
	}
}

func TestMergeWithAssignees_SameAssigneeMerges(t *testing.T) {
	vulns := []provider.Vulnerability{
		{
			ID:         "GHSA-1234",
			CVE:        "CVE-2024-1234",
			Severity:   "high",
			Package:    "lodash",
			Repository: "org/repo1",
			Provider:   "github",
		},
		{
			ID:         "SNYK-1234",
			CVE:        "CVE-2024-1234",
			Severity:   "high",
			Package:    "lodash",
			Repository: "org/repo2",
			Provider:   "snyk",
		},
	}

	// Both repos have same assignee
	resolver := &mockResolver{
		defaultAssignee: "same-assignee",
	}

	merged := MergeWithAssignees(vulns, resolver)

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged vuln (same assignee), got %d", len(merged))
	}

	if len(merged[0].Repositories) != 2 {
		t.Errorf("expected 2 repos merged, got %d", len(merged[0].Repositories))
	}

	if len(merged[0].Providers) != 2 {
		t.Errorf("expected 2 providers merged, got %d", len(merged[0].Providers))
	}

	if merged[0].Assignee != "same-assignee" {
		t.Errorf("expected assignee 'same-assignee', got %q", merged[0].Assignee)
	}
}

func TestMergeWithAssignees_EmptyAssignee(t *testing.T) {
	vulns := []provider.Vulnerability{
		{
			ID:         "GHSA-1234",
			CVE:        "CVE-2024-1234",
			Severity:   "high",
			Package:    "lodash",
			Repository: "org/repo1",
			Provider:   "github",
		},
	}

	resolver := &mockResolver{
		defaultAssignee: "", // No assignee configured
	}

	merged := MergeWithAssignees(vulns, resolver)

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged vuln, got %d", len(merged))
	}

	if merged[0].Assignee != "" {
		t.Errorf("expected empty assignee, got %q", merged[0].Assignee)
	}
}

func TestMergeWithAssignees_PreservesHighestCVSS(t *testing.T) {
	vulns := []provider.Vulnerability{
		{
			ID:         "GHSA-1234",
			CVE:        "CVE-2024-1234",
			Severity:   "high",
			CVSS:       7.5,
			Package:    "lodash",
			Repository: "org/repo1",
			Provider:   "github",
		},
		{
			ID:         "SNYK-1234",
			CVE:        "CVE-2024-1234",
			Severity:   "high",
			CVSS:       9.0, // Higher
			Package:    "lodash",
			Repository: "org/repo2",
			Provider:   "snyk",
		},
	}

	resolver := &mockResolver{
		defaultAssignee: "same-assignee",
	}

	merged := MergeWithAssignees(vulns, resolver)

	if merged[0].CVSS != 9.0 {
		t.Errorf("expected highest CVSS 9.0, got %f", merged[0].CVSS)
	}
}

func TestMergeWithAssignees_DifferentCVEsWithSameAssignee(t *testing.T) {
	vulns := []provider.Vulnerability{
		{
			ID:         "GHSA-1111",
			CVE:        "CVE-2024-1111",
			Severity:   "high",
			Package:    "lodash",
			Repository: "org/repo1",
			Provider:   "github",
		},
		{
			ID:         "GHSA-2222",
			CVE:        "CVE-2024-2222",
			Severity:   "medium",
			Package:    "axios",
			Repository: "org/repo1",
			Provider:   "github",
		},
	}

	resolver := &mockResolver{
		defaultAssignee: "same-assignee",
	}

	merged := MergeWithAssignees(vulns, resolver)

	// Different CVEs should still be separate, even with same assignee
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged vulns (different CVEs), got %d", len(merged))
	}
}

func TestDedupeKeyWithAssignee(t *testing.T) {
	v := provider.Vulnerability{
		CVE:      "CVE-2024-1234",
		Package:  "lodash",
		Severity: "high",
		ID:       "GHSA-1234",
	}

	key1 := dedupeKeyWithAssignee(v, "team-a")
	key2 := dedupeKeyWithAssignee(v, "team-b")

	if key1 == key2 {
		t.Error("different assignees should produce different keys")
	}

	if key1 != "CVE-2024-1234|team-a" {
		t.Errorf("unexpected key format: %s", key1)
	}
}

func TestDedupeKeyWithAssignee_FallbackKey(t *testing.T) {
	v := provider.Vulnerability{
		CVE:      "", // No CVE
		Package:  "lodash",
		Severity: "high",
		ID:       "GHSA-1234",
	}

	key := dedupeKeyWithAssignee(v, "team-a")

	if key != "lodash:high:GHSA-1234|team-a" {
		t.Errorf("unexpected fallback key format: %s", key)
	}
}
