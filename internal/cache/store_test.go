package cache

import (
	"context"
	"testing"
	"time"

	"github.com/sentiolabs/argus/internal/provider"
	"github.com/sentiolabs/argus/internal/search"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testVulns() []provider.Vulnerability {
	return []provider.Vulnerability{
		{
			ID: "SNYK-RUBY-RACKSESSION-15928857", CVE: "CVE-2025-27610",
			Severity: "high", CVSS: 7.5, Package: "rack-session",
			Version: "2.0.0", FixedVersion: "2.1.0",
			Repository:   "bactrack/my-rails-app",
			Description:  "Rack::Session cookie handling vulnerability",
			Provider:     "snyk",
			DiscoveredAt: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			ID: "GHSA-xvch-r4wf-h8w9", CVE: "CVE-2025-12345",
			Severity: "critical", CVSS: 9.8, Package: "rails",
			Version: "7.0.0", FixedVersion: "7.0.1",
			Repository:   "bactrack/my-rails-app",
			Description:  "Remote code execution in Action Pack",
			Provider:     "github",
			DiscoveredAt: time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
		},
		{
			ID: "SNYK-JS-LODASH-1234567", Severity: "medium", CVSS: 5.3,
			Package: "lodash", Version: "4.17.20",
			Repository:   "bactrack/node-api",
			Description:  "Prototype pollution in lodash merge function",
			Provider:     "snyk",
			DiscoveredAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		},
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open("memory://")
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStore_WriteAndGetByID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	vulns := testVulns()
	err := s.WriteVulnerabilities(ctx, "proj1", vulns, []string{"snyk", "github"})
	require.NoError(t, err)

	t.Run("lookup by ID", func(t *testing.T) {
		got, err := s.GetByID(ctx, "proj1", "SNYK-RUBY-RACKSESSION-15928857")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "SNYK-RUBY-RACKSESSION-15928857", got.ID)
		assert.Equal(t, "rack-session", got.Package)
	})

	t.Run("lookup by CVE", func(t *testing.T) {
		got, err := s.GetByID(ctx, "proj1", "CVE-2025-12345")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "GHSA-xvch-r4wf-h8w9", got.ID)
	})

	t.Run("lookup missing returns nil", func(t *testing.T) {
		got, err := s.GetByID(ctx, "proj1", "NONEXISTENT-ID")
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

func TestStore_WriteAndSearch_FieldFilter(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	vulns := testVulns()
	err := s.WriteVulnerabilities(ctx, "proj1", vulns, []string{"snyk", "github"})
	require.NoError(t, err)

	t.Run("search by severity:high", func(t *testing.T) {
		q := search.Parse("severity:high")
		results, err := s.Search(ctx, "proj1", q, 10)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "SNYK-RUBY-RACKSESSION-15928857", results[0].ID)
	})

	t.Run("search by provider:snyk", func(t *testing.T) {
		q := search.Parse("provider:snyk")
		results, err := s.Search(ctx, "proj1", q, 10)
		require.NoError(t, err)
		assert.Len(t, results, 2)
		for _, r := range results {
			assert.Equal(t, "snyk", r.Provider)
		}
	})

	t.Run("search by severity:critical", func(t *testing.T) {
		q := search.Parse("severity:critical")
		results, err := s.Search(ctx, "proj1", q, 10)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "GHSA-xvch-r4wf-h8w9", results[0].ID)
	})
}

func TestStore_WriteAndSearch_IDLookup(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	vulns := testVulns()
	err := s.WriteVulnerabilities(ctx, "proj1", vulns, []string{"snyk", "github"})
	require.NoError(t, err)

	q := search.Parse("GHSA-xvch-r4wf-h8w9")
	assert.True(t, q.IsIDLookup)

	results, err := s.Search(ctx, "proj1", q, 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "GHSA-xvch-r4wf-h8w9", results[0].ID)
}

func TestStore_Clear(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	vulns := testVulns()
	err := s.WriteVulnerabilities(ctx, "proj1", vulns, []string{"snyk", "github"})
	require.NoError(t, err)
	err = s.WriteVulnerabilities(ctx, "proj2", vulns[:1], []string{"snyk"})
	require.NoError(t, err)

	// Clear proj1 only
	err = s.Clear(ctx, "proj1")
	require.NoError(t, err)

	count1, err := s.ProjectCount(ctx, "proj1")
	require.NoError(t, err)
	assert.Equal(t, 0, count1, "proj1 should be empty after clear")

	count2, err := s.ProjectCount(ctx, "proj2")
	require.NoError(t, err)
	assert.Equal(t, 1, count2, "proj2 should still have data")
}

func TestStore_ClearAll(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	vulns := testVulns()
	err := s.WriteVulnerabilities(ctx, "proj1", vulns, []string{"snyk", "github"})
	require.NoError(t, err)
	err = s.WriteVulnerabilities(ctx, "proj2", vulns[:2], []string{"snyk", "github"})
	require.NoError(t, err)

	// Clear all (empty projectKey)
	err = s.Clear(ctx, "")
	require.NoError(t, err)

	total, err := s.TotalCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, total, "all rows should be cleared")
}

func TestStore_WriteReplacesExistingProvider(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// Write initial snyk vulns (2 of 3 are snyk)
	vulns := testVulns()
	err := s.WriteVulnerabilities(ctx, "proj1", vulns, []string{"snyk", "github"})
	require.NoError(t, err)

	count, err := s.ProjectCount(ctx, "proj1")
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Write only snyk with 1 vuln now
	newSnyk := []provider.Vulnerability{
		{
			ID:           "SNYK-NEW-1",
			Severity:     "low",
			CVSS:         3.1,
			Package:      "newpkg",
			Repository:   "bactrack/new-repo",
			Description:  "New low severity",
			Provider:     "snyk",
			DiscoveredAt: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	err = s.WriteVulnerabilities(ctx, "proj1", newSnyk, []string{"snyk"})
	require.NoError(t, err)

	// Should now have 2: 1 github (unchanged) + 1 new snyk
	count, err = s.ProjectCount(ctx, "proj1")
	require.NoError(t, err)
	assert.Equal(t, 2, count, "should have 1 github + 1 new snyk")
}

func TestStore_Meta(t *testing.T) {
	s := openTestStore(t)

	// Set and get
	err := s.SetMeta("proj1", "fetched_at", "2026-04-08T00:00:00Z")
	require.NoError(t, err)

	val, err := s.GetMeta("proj1", "fetched_at")
	require.NoError(t, err)
	assert.Equal(t, "2026-04-08T00:00:00Z", val)

	// Overwrite
	err = s.SetMeta("proj1", "fetched_at", "2026-04-09T00:00:00Z")
	require.NoError(t, err)

	val, err = s.GetMeta("proj1", "fetched_at")
	require.NoError(t, err)
	assert.Equal(t, "2026-04-09T00:00:00Z", val)

	// Cross-project isolation
	val2, err := s.GetMeta("proj2", "fetched_at")
	require.NoError(t, err)
	assert.Equal(t, "", val2, "proj2 should not have proj1's meta")
}

func TestStore_AllProjectSearch(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	vulns := testVulns()
	err := s.WriteVulnerabilities(ctx, "proj1", vulns[:2], []string{"snyk", "github"})
	require.NoError(t, err)
	err = s.WriteVulnerabilities(ctx, "proj2", vulns[2:], []string{"snyk"})
	require.NoError(t, err)

	// Search with empty projectKey => all projects
	q := search.Parse("severity:medium")
	results, err := s.Search(ctx, "", q, 10)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "SNYK-JS-LODASH-1234567", results[0].ID)
	assert.Equal(t, "proj2", results[0].ProjectKey)
}
