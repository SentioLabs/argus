# Cache & Search Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add persistent disk cache with semantic search to the Argus CLI, enabling targeted vulnerability lookups by ID, keyword, or natural-language queries.

**Architecture:** New `internal/cache/` and `internal/search/` packages provide the storage and query layers. Three new cobra commands (`cache`, `search`, `show`) wire them into the CLI. The cache uses Stoolap (embedded SQL + semantic search) with a single shared database at `~/.cache/argus/vulns.db`, partitioned by project key.

**Tech Stack:** Go 1.25, Stoolap via `github.com/stoolap/stoolap-go` (`database/sql` driver), Cobra CLI, existing `provider.FetchVulnerabilities()` for data fetching.

**Spec:** `docs/superpowers/specs/2026-04-08-cache-and-search-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `internal/search/search.go` | Create | Query parser: splits raw input into field filters + semantic text |
| `internal/search/search_test.go` | Create | Unit tests for query parsing |
| `internal/cache/cache.go` | Create | Cache manager: project key, DB path, TTL, auto-fetch orchestration |
| `internal/cache/cache_test.go` | Create | Unit tests for ProjectKey, DBPath, TTL logic |
| `internal/cache/store.go` | Create | Stoolap database operations: schema, write, search, getByID, clear |
| `internal/cache/store_test.go` | Create | Integration tests using in-memory Stoolap |
| `internal/output/output.go` | Modify | Add SearchResult type and detailed single-vuln format for `show` |
| `cmd/cache.go` | Create | `argus cache refresh/status/clear` subcommands |
| `cmd/search.go` | Create | `argus search` command |
| `cmd/show.go` | Create | `argus show` command |
| `go.mod` / `go.sum` | Modify | Add `stoolap-go` dependency |

---

### Task 1: Add Stoolap Dependency

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add the stoolap-go dependency**

```bash
cd /home/bfirestone/devspace/personal/sentiolabs/argus
go get github.com/stoolap/stoolap-go
```

- [ ] **Step 2: Verify it resolves**

```bash
go mod tidy
```

Expected: clean exit, `go.mod` and `go.sum` updated with stoolap-go entry.

- [ ] **Step 3: Verify build still passes**

```bash
go build .
```

Expected: clean build, no errors.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add stoolap-go dependency for cache storage"
```

---

### Task 2: Search Query Parser

**Files:**
- Create: `internal/search/search.go`
- Create: `internal/search/search_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/search/search_test.go`:

```go
package search

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse_BareWords(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Query
	}{
		{
			name:  "single word",
			input: "rails",
			want:  Query{SemanticText: "rails"},
		},
		{
			name:  "multiple words",
			input: "session handling auth bypass",
			want:  Query{SemanticText: "session handling auth bypass"},
		},
		{
			name:  "empty input",
			input: "",
			want:  Query{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParse_FieldFilters(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Query
	}{
		{
			name:  "severity filter",
			input: "severity:critical",
			want:  Query{Filters: map[string]string{"severity": "critical"}},
		},
		{
			name:  "multiple filters",
			input: "package:rack* provider:snyk",
			want:  Query{Filters: map[string]string{"package": "rack*", "provider": "snyk"}},
		},
		{
			name:  "repo alias",
			input: "repo:bactrack/*",
			want:  Query{Filters: map[string]string{"repository": "bactrack/*"}},
		},
		{
			name:  "repository long form",
			input: "repository:bactrack/*",
			want:  Query{Filters: map[string]string{"repository": "bactrack/*"}},
		},
		{
			name:  "cve filter",
			input: "cve:CVE-2024-*",
			want:  Query{Filters: map[string]string{"cve": "CVE-2024-*"}},
		},
		{
			name:  "id filter",
			input: "id:SNYK-RUBY-*",
			want:  Query{Filters: map[string]string{"id": "SNYK-RUBY-*"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParse_Hybrid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Query
	}{
		{
			name:  "filter plus bare words",
			input: "severity:critical session handling",
			want: Query{
				SemanticText: "session handling",
				Filters:      map[string]string{"severity": "critical"},
			},
		},
		{
			name:  "bare words between filters",
			input: "severity:high rails provider:snyk",
			want: Query{
				SemanticText: "rails",
				Filters:      map[string]string{"severity": "high", "provider": "snyk"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParse_IDLookup(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Query
	}{
		{
			name:  "snyk ID",
			input: "SNYK-RUBY-RACKSESSION-15928857",
			want: Query{
				IsIDLookup: true,
				RawID:      "SNYK-RUBY-RACKSESSION-15928857",
			},
		},
		{
			name:  "ghsa ID",
			input: "GHSA-xvch-r4wf-h8w9",
			want: Query{
				IsIDLookup: true,
				RawID:      "GHSA-xvch-r4wf-h8w9",
			},
		},
		{
			name:  "cve ID",
			input: "CVE-2025-27610",
			want: Query{
				IsIDLookup: true,
				RawID:      "CVE-2025-27610",
			},
		},
		{
			name:  "not an ID - just starts with C",
			input: "cookie vulnerability",
			want: Query{
				SemanticText: "cookie vulnerability",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Parse(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/search/ -v
```

Expected: compilation error — package and `Parse` function don't exist yet.

- [ ] **Step 3: Implement the query parser**

Create `internal/search/search.go`:

```go
package search

import (
	"strings"
)

// validFields defines recognized field prefixes for search queries.
var validFields = map[string]string{
	"severity":   "severity",
	"package":    "package",
	"repo":       "repository", // alias
	"repository": "repository",
	"provider":   "provider",
	"cve":        "cve",
	"id":         "id",
}

// Query represents a parsed search input.
type Query struct {
	SemanticText string            // bare words for EMBED()
	Filters      map[string]string // field:value pairs for WHERE clauses
	IsIDLookup   bool              // true if query looks like SNYK-*/GHSA-*/CVE-*
	RawID        string            // the raw ID for direct lookup
}

// Parse splits a raw query string into a structured Query.
// Tokens matching "field:value" (where field is recognized) become filters.
// Remaining tokens become the semantic search text.
// If the entire query is a single token that looks like a vulnerability ID
// (starts with SNYK-, GHSA-, or CVE-), it is treated as an ID lookup.
func Parse(raw string) Query {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Query{}
	}

	// Check for single-token ID lookup
	if !strings.Contains(raw, " ") && isVulnID(raw) {
		return Query{
			IsIDLookup: true,
			RawID:      raw,
		}
	}

	tokens := strings.Fields(raw)
	var bareWords []string
	filters := make(map[string]string)

	for _, token := range tokens {
		if field, value, ok := parseFieldToken(token); ok {
			filters[field] = value
		} else {
			bareWords = append(bareWords, token)
		}
	}

	q := Query{}
	if len(bareWords) > 0 {
		q.SemanticText = strings.Join(bareWords, " ")
	}
	if len(filters) > 0 {
		q.Filters = filters
	}
	return q
}

// parseFieldToken checks if a token matches "field:value" where field is recognized.
func parseFieldToken(token string) (field, value string, ok bool) {
	idx := strings.IndexByte(token, ':')
	if idx <= 0 || idx == len(token)-1 {
		return "", "", false
	}

	key := strings.ToLower(token[:idx])
	val := token[idx+1:]

	canonical, recognized := validFields[key]
	if !recognized {
		return "", "", false
	}

	return canonical, val, true
}

// isVulnID returns true if the string looks like a vulnerability identifier.
func isVulnID(s string) bool {
	upper := strings.ToUpper(s)
	return strings.HasPrefix(upper, "SNYK-") ||
		strings.HasPrefix(upper, "GHSA-") ||
		strings.HasPrefix(upper, "CVE-")
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/search/ -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/search/search.go internal/search/search_test.go
git commit -m "feat: add search query parser with field filters and ID detection"
```

---

### Task 3: Cache Manager (ProjectKey, DBPath, TTL)

**Files:**
- Create: `internal/cache/cache.go`
- Create: `internal/cache/cache_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/cache/cache_test.go`:

```go
package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectKeyFromPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "absolute path",
			path: "/home/bfirestone/devspace/personal/sentiolabs/argus",
			want: "-home-bfirestone-devspace-personal-sentiolabs-argus",
		},
		{
			name: "root path",
			path: "/",
			want: "-",
		},
		{
			name: "short path",
			path: "/tmp/myproject",
			want: "-tmp-myproject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProjectKeyFromPath(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDBPath_Default(t *testing.T) {
	// Unset XDG to test default behavior
	orig := os.Getenv("XDG_CACHE_HOME")
	t.Cleanup(func() { os.Setenv("XDG_CACHE_HOME", orig) })
	os.Unsetenv("XDG_CACHE_HOME")

	got := DBPath()
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	expected := filepath.Join(home, ".cache", "argus", "vulns.db")
	assert.Equal(t, expected, got)
}

func TestDBPath_XDG(t *testing.T) {
	orig := os.Getenv("XDG_CACHE_HOME")
	t.Cleanup(func() { os.Setenv("XDG_CACHE_HOME", orig) })
	t.Setenv("XDG_CACHE_HOME", "/custom/cache")

	got := DBPath()
	assert.Equal(t, "/custom/cache/argus/vulns.db", got)
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/cache/ -v
```

Expected: compilation error — package doesn't exist yet.

- [ ] **Step 3: Implement the cache manager**

Create `internal/cache/cache.go`:

```go
package cache

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sentiolabs/argus/internal/config"
	"github.com/sentiolabs/argus/internal/provider"
)

const (
	// DefaultTTL is the default cache time-to-live.
	DefaultTTL = 24 * time.Hour
)

// Manager handles cache lifecycle for a project.
type Manager struct {
	projectKey string
	dbPath     string
	ttl        time.Duration
	store      *Store
	verbose    bool
}

// NewManager creates a new cache manager for the current working directory.
func NewManager(ttl time.Duration, verbose bool) (*Manager, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}

	dbPath := DBPath()
	store, err := Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache database: %w", err)
	}

	return &Manager{
		projectKey: ProjectKeyFromPath(wd),
		dbPath:     dbPath,
		ttl:        ttl,
		store:      store,
		verbose:    verbose,
	}, nil
}

// ProjectKey returns this manager's project key.
func (m *Manager) ProjectKey() string {
	return m.projectKey
}

// DBPathValue returns the database file path.
func (m *Manager) DBPathValue() string {
	return m.dbPath
}

// Store returns the underlying store for direct queries.
func (m *Manager) Store() *Store {
	return m.store
}

// Close closes the underlying store.
func (m *Manager) Close() error {
	if m.store != nil {
		return m.store.Close()
	}
	return nil
}

// IsValid checks if the current project's cache exists and is within TTL.
func (m *Manager) IsValid() bool {
	fetchedAt, err := m.store.GetMeta(m.projectKey, "fetched_at")
	if err != nil || fetchedAt == "" {
		return false
	}

	t, err := time.Parse(time.RFC3339, fetchedAt)
	if err != nil {
		return false
	}

	return time.Since(t) < m.ttl
}

// EnsureFresh auto-fetches if cache is missing or expired for the current project.
// providerScope: "all", "snyk", or "github"
func (m *Manager) EnsureFresh(ctx context.Context, cfg *config.Config, providerScope string, verbose bool) error {
	if m.IsValid() {
		if verbose {
			slog.Info("cache is valid, skipping fetch", "project", m.projectKey)
		}
		return nil
	}

	slog.Info("cache expired or missing, fetching vulnerabilities", "project", m.projectKey)
	return m.Refresh(ctx, cfg, providerScope, verbose)
}

// Refresh fetches vulnerabilities from providers and writes to cache.
func (m *Manager) Refresh(ctx context.Context, cfg *config.Config, providerScope string, verbose bool) error {
	providers := enabledProviders(cfg, providerScope)
	if len(providers) == 0 {
		return fmt.Errorf("no enabled providers found for scope %q", providerScope)
	}

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		allVulns  []provider.Vulnerability
		fetchErrs []error
	)

	for _, name := range providers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			slog.Info("fetching from provider", "provider", name)
			p, err := provider.New(name, cfg, verbose)
			if err != nil {
				mu.Lock()
				fetchErrs = append(fetchErrs, fmt.Errorf("%s: %w", name, err))
				mu.Unlock()
				return
			}

			vulns, err := p.FetchVulnerabilities(ctx)
			if err != nil {
				mu.Lock()
				fetchErrs = append(fetchErrs, fmt.Errorf("%s: %w", name, err))
				mu.Unlock()
				return
			}

			slog.Info("fetched vulnerabilities", "provider", name, "count", len(vulns))
			mu.Lock()
			allVulns = append(allVulns, vulns...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	if len(fetchErrs) > 0 {
		slog.Warn("some providers failed", "errors", fetchErrs)
	}

	// If all providers failed, return error
	if len(fetchErrs) == len(providers) {
		return fmt.Errorf("all providers failed: %v", fetchErrs)
	}

	return m.store.WriteVulnerabilities(ctx, m.projectKey, allVulns, providers)
}

// enabledProviders returns the list of provider names to fetch from.
func enabledProviders(cfg *config.Config, scope string) []string {
	var names []string
	for name, p := range cfg.Providers {
		if !p.Enabled {
			continue
		}
		if scope == "all" || scope == name {
			names = append(names, name)
		}
	}
	return names
}

// ProjectKeyFromPath converts a filesystem path to a hyphenated cache key.
// "/home/user/projects/my-app" -> "-home-user-projects-my-app"
func ProjectKeyFromPath(path string) string {
	return strings.ReplaceAll(path, string(filepath.Separator), "-")
}

// DBPath returns the shared database path.
// Respects $XDG_CACHE_HOME, defaults to ~/.cache/argus/vulns.db
func DBPath() string {
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			cacheDir = filepath.Join(os.TempDir(), ".cache")
		} else {
			cacheDir = filepath.Join(home, ".cache")
		}
	}
	return filepath.Join(cacheDir, "argus", "vulns.db")
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/cache/ -run 'TestProjectKey|TestDBPath' -v
```

Expected: all 5 tests PASS. (Other tests in the file may fail since `Store` doesn't exist yet — that's fine, we're only running ProjectKey and DBPath tests.)

- [ ] **Step 5: Commit**

```bash
git add internal/cache/cache.go internal/cache/cache_test.go
git commit -m "feat: add cache manager with project key derivation and XDG path resolution"
```

---

### Task 4: Cache Store (Stoolap Database Operations)

**Files:**
- Create: `internal/cache/store.go`
- Create: `internal/cache/store_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/cache/store_test.go`:

```go
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

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open("memory://")
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return store
}

func testVulns() []provider.Vulnerability {
	return []provider.Vulnerability{
		{
			ID:           "SNYK-RUBY-RACKSESSION-15928857",
			CVE:          "CVE-2025-27610",
			Severity:     "high",
			CVSS:         7.5,
			Package:      "rack-session",
			Version:      "2.0.0",
			FixedVersion: "2.1.0",
			Repository:   "bactrack/my-rails-app",
			Description:  "Rack::Session cookie handling vulnerability allowing session fixation",
			URL:          "https://security.snyk.io/vuln/SNYK-RUBY-RACKSESSION-15928857",
			Provider:     "snyk",
			DiscoveredAt: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:           "GHSA-xvch-r4wf-h8w9",
			CVE:          "CVE-2025-12345",
			Severity:     "critical",
			CVSS:         9.8,
			Package:      "rails",
			Version:      "7.0.0",
			FixedVersion: "7.0.1",
			Repository:   "bactrack/my-rails-app",
			Description:  "Remote code execution in Action Pack",
			URL:          "https://github.com/advisories/GHSA-xvch-r4wf-h8w9",
			Provider:     "github",
			DiscoveredAt: time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:          "SNYK-JS-LODASH-1234567",
			Severity:    "medium",
			CVSS:        5.3,
			Package:     "lodash",
			Version:     "4.17.20",
			Repository:  "bactrack/node-api",
			Description: "Prototype pollution in lodash merge function",
			Provider:    "snyk",
			DiscoveredAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		},
	}
}

func TestStore_WriteAndGetByID(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	vulns := testVulns()
	err := store.WriteVulnerabilities(ctx, "test-project", vulns, []string{"snyk", "github"})
	require.NoError(t, err)

	// Exact match on ID
	result, err := store.GetByID(ctx, "test-project", "SNYK-RUBY-RACKSESSION-15928857")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "rack-session", result.Package)
	assert.Equal(t, "CVE-2025-27610", result.CVE)

	// Exact match on CVE
	result, err = store.GetByID(ctx, "test-project", "CVE-2025-12345")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "rails", result.Package)

	// Not found
	result, err = store.GetByID(ctx, "test-project", "SNYK-NONEXISTENT")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestStore_WriteAndSearch_FieldFilter(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.WriteVulnerabilities(ctx, "test-project", testVulns(), []string{"snyk", "github"})
	require.NoError(t, err)

	// Search by severity
	results, err := store.Search(ctx, "test-project", search.Query{
		Filters: map[string]string{"severity": "critical"},
	}, 20)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "rails", results[0].Package)

	// Search by provider
	results, err = store.Search(ctx, "test-project", search.Query{
		Filters: map[string]string{"provider": "snyk"},
	}, 20)
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestStore_WriteAndSearch_IDLookup(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.WriteVulnerabilities(ctx, "test-project", testVulns(), []string{"snyk", "github"})
	require.NoError(t, err)

	results, err := store.Search(ctx, "test-project", search.Query{
		IsIDLookup: true,
		RawID:      "SNYK-RUBY-RACKSESSION-15928857",
	}, 20)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "rack-session", results[0].Package)
}

func TestStore_Clear(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.WriteVulnerabilities(ctx, "project-a", testVulns(), []string{"snyk", "github"})
	require.NoError(t, err)
	err = store.WriteVulnerabilities(ctx, "project-b", testVulns()[:1], []string{"snyk"})
	require.NoError(t, err)

	// Clear only project-a
	err = store.Clear(ctx, "project-a")
	require.NoError(t, err)

	// project-a should be empty
	results, err := store.Search(ctx, "project-a", search.Query{
		Filters: map[string]string{"provider": "snyk"},
	}, 20)
	require.NoError(t, err)
	assert.Empty(t, results)

	// project-b should still have data
	results, err = store.Search(ctx, "project-b", search.Query{
		Filters: map[string]string{"provider": "snyk"},
	}, 20)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

func TestStore_ClearAll(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.WriteVulnerabilities(ctx, "project-a", testVulns(), []string{"snyk", "github"})
	require.NoError(t, err)
	err = store.WriteVulnerabilities(ctx, "project-b", testVulns()[:1], []string{"snyk"})
	require.NoError(t, err)

	// Clear all
	err = store.Clear(ctx, "")
	require.NoError(t, err)

	// Both should be empty
	results, err := store.Search(ctx, "", search.Query{
		Filters: map[string]string{"provider": "snyk"},
	}, 20)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestStore_WriteReplacesExistingProvider(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Write initial data
	err := store.WriteVulnerabilities(ctx, "test-project", testVulns(), []string{"snyk", "github"})
	require.NoError(t, err)

	// Write new snyk data (should replace old snyk data, keep github)
	newVulns := []provider.Vulnerability{
		{
			ID:       "SNYK-NEW-1",
			Severity: "low",
			Package:  "new-package",
			Repository: "bactrack/new-repo",
			Description: "New vulnerability",
			Provider: "snyk",
			DiscoveredAt: time.Now(),
		},
	}
	err = store.WriteVulnerabilities(ctx, "test-project", newVulns, []string{"snyk"})
	require.NoError(t, err)

	// Should have 1 snyk vuln (new) + 1 github vuln (kept)
	results, err := store.Search(ctx, "test-project", search.Query{
		Filters: map[string]string{"provider": "snyk"},
	}, 20)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "SNYK-NEW-1", results[0].ID)

	results, err = store.Search(ctx, "test-project", search.Query{
		Filters: map[string]string{"provider": "github"},
	}, 20)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "GHSA-xvch-r4wf-h8w9", results[0].ID)
}

func TestStore_Meta(t *testing.T) {
	store := newTestStore(t)

	err := store.SetMeta("test-project", "fetched_at", "2026-04-08T14:30:00Z")
	require.NoError(t, err)

	val, err := store.GetMeta("test-project", "fetched_at")
	require.NoError(t, err)
	assert.Equal(t, "2026-04-08T14:30:00Z", val)

	// Different project should not see it
	val, err = store.GetMeta("other-project", "fetched_at")
	require.NoError(t, err)
	assert.Empty(t, val)
}

func TestStore_AllProjectSearch(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	err := store.WriteVulnerabilities(ctx, "project-a", testVulns()[:1], []string{"snyk"})
	require.NoError(t, err)
	err = store.WriteVulnerabilities(ctx, "project-b", testVulns()[1:2], []string{"github"})
	require.NoError(t, err)

	// Search all projects (empty project key)
	results, err := store.Search(ctx, "", search.Query{
		Filters: map[string]string{"severity": "high"},
	}, 20)
	require.NoError(t, err)
	// Should find the high severity vuln from project-a
	assert.Len(t, results, 1)
	assert.Equal(t, "project-a", results[0].ProjectKey)
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/cache/ -run 'TestStore' -v
```

Expected: compilation error — `Store`, `Open`, etc. don't exist yet.

- [ ] **Step 3: Implement the store**

Create `internal/cache/store.go`:

```go
package cache

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/stoolap/stoolap-go"

	"github.com/sentiolabs/argus/internal/provider"
	"github.com/sentiolabs/argus/internal/search"
)

// SearchResult extends Vulnerability with search metadata.
type SearchResult struct {
	provider.Vulnerability
	Relevance  float64 // cosine distance (lower = more relevant)
	ProjectKey string  // which project this result came from
}

// Store wraps Stoolap database operations.
type Store struct {
	db *sql.DB
}

// Open opens or creates the shared cache database, ensuring schema exists.
func Open(dsn string) (*Store, error) {
	// Ensure parent directory exists for file-based DSNs
	if strings.HasPrefix(dsn, "file://") || (!strings.HasPrefix(dsn, "memory://") && !strings.Contains(dsn, "://")) {
		dir := filepath.Dir(strings.TrimPrefix(dsn, "file://"))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	db, err := sql.Open("stoolap", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &Store{db: db}
	if err := store.ensureSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return store, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) ensureSchema() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			project_key TEXT NOT NULL,
			id TEXT NOT NULL,
			cve TEXT,
			severity TEXT NOT NULL,
			cvss FLOAT,
			package TEXT NOT NULL,
			version TEXT,
			fixed_version TEXT,
			repository TEXT NOT NULL,
			description TEXT,
			url TEXT,
			discovered_at TIMESTAMP,
			provider TEXT NOT NULL,
			embedding VECTOR(384)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_project ON vulnerabilities(project_key)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_id ON vulnerabilities(id)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_package ON vulnerabilities(package)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_provider ON vulnerabilities(provider)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_repository ON vulnerabilities(repository)`,
		`CREATE TABLE IF NOT EXISTS cache_meta (
			project_key TEXT NOT NULL,
			key TEXT NOT NULL,
			value TEXT NOT NULL,
			PRIMARY KEY (project_key, key)
		)`,
	}

	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("schema statement failed: %w\nSQL: %s", err, stmt)
		}
	}

	return nil
}

// WriteVulnerabilities clears existing data for the given project+providers
// and inserts new vulnerabilities with embeddings.
func (s *Store) WriteVulnerabilities(ctx context.Context, projectKey string, vulns []provider.Vulnerability, providers []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete existing data for this project + providers
	for _, prov := range providers {
		_, err := tx.ExecContext(ctx,
			"DELETE FROM vulnerabilities WHERE project_key = ? AND provider = ?",
			projectKey, prov)
		if err != nil {
			return fmt.Errorf("failed to clear provider %s: %w", prov, err)
		}
	}

	// Insert new vulnerabilities
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO vulnerabilities (project_key, id, cve, severity, cvss, package, version,
			fixed_version, repository, description, url, discovered_at, provider, embedding)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, EMBED(?))`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert: %w", err)
	}
	defer stmt.Close()

	for i := range vulns {
		v := &vulns[i]
		embedText := buildEmbedText(v)
		_, err := stmt.ExecContext(ctx,
			projectKey, v.ID, v.CVE, v.Severity, v.CVSS, v.Package, v.Version,
			v.FixedVersion, v.Repository, v.Description, v.URL, v.DiscoveredAt,
			v.Provider, embedText)
		if err != nil {
			return fmt.Errorf("failed to insert vulnerability %s: %w", v.ID, err)
		}
	}

	// Update metadata
	now := time.Now().UTC().Format(time.RFC3339)
	provList := strings.Join(providers, ",")
	count := fmt.Sprintf("%d", len(vulns))

	for _, kv := range [][2]string{
		{"fetched_at", now},
		{"providers", provList},
		{"count", count},
	} {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO cache_meta (project_key, key, value) VALUES (?, ?, ?)
			 ON CONFLICT (project_key, key) DO UPDATE SET value = ?`,
			projectKey, kv[0], kv[1], kv[1])
		if err != nil {
			// Stoolap may not support ON CONFLICT — fall back to delete+insert
			tx.ExecContext(ctx, "DELETE FROM cache_meta WHERE project_key = ? AND key = ?",
				projectKey, kv[0])
			_, err = tx.ExecContext(ctx,
				"INSERT INTO cache_meta (project_key, key, value) VALUES (?, ?, ?)",
				projectKey, kv[0], kv[1])
			if err != nil {
				return fmt.Errorf("failed to set meta %s: %w", kv[0], err)
			}
		}
	}

	return tx.Commit()
}

// buildEmbedText creates the text used to generate the semantic embedding.
func buildEmbedText(v *provider.Vulnerability) string {
	parts := []string{v.ID}
	if v.CVE != "" {
		parts = append(parts, v.CVE)
	}
	parts = append(parts, v.Package, v.Repository)
	if v.Description != "" {
		parts = append(parts, v.Description)
	}
	return strings.Join(parts, " ")
}

// Search executes a parsed query against a project (or all projects).
// If projectKey is empty, searches all projects.
func (s *Store) Search(ctx context.Context, projectKey string, q search.Query, limit int) ([]SearchResult, error) {
	if q.IsIDLookup {
		v, err := s.GetByID(ctx, projectKey, q.RawID)
		if err != nil {
			return nil, err
		}
		if v != nil {
			return []SearchResult{{Vulnerability: *v, ProjectKey: projectKey}}, nil
		}
		// Fall through to semantic search if no exact match
		q.SemanticText = q.RawID
		q.IsIDLookup = false
	}

	return s.executeSearch(ctx, projectKey, q, limit)
}

func (s *Store) executeSearch(ctx context.Context, projectKey string, q search.Query, limit int) ([]SearchResult, error) {
	var (
		conditions []string
		args       []any
	)

	// Project scoping
	if projectKey != "" {
		conditions = append(conditions, "v.project_key = ?")
		args = append(args, projectKey)
	}

	// Field filters
	for field, value := range q.Filters {
		if strings.ContainsAny(value, "*?") {
			// Glob pattern — convert to SQL LIKE
			likePattern := strings.ReplaceAll(value, "*", "%")
			likePattern = strings.ReplaceAll(likePattern, "?", "_")
			conditions = append(conditions, fmt.Sprintf("v.%s LIKE ?", field))
			args = append(args, likePattern)
		} else {
			conditions = append(conditions, fmt.Sprintf("v.%s = ?", field))
			args = append(args, value)
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	var query string
	if q.SemanticText != "" {
		// Semantic search with optional field filters
		query = fmt.Sprintf(`
			WITH query AS (
				SELECT EMBED(?) AS vec
			)
			SELECT v.project_key, v.id, v.cve, v.severity, v.cvss, v.package, v.version,
				v.fixed_version, v.repository, v.description, v.url, v.discovered_at, v.provider,
				VEC_DISTANCE_COSINE(v.embedding, query.vec) AS relevance
			FROM vulnerabilities v, query
			%s
			ORDER BY relevance
			LIMIT ?`, whereClause)
		args = append([]any{q.SemanticText}, args...)
		args = append(args, limit)
	} else {
		// Field-only search, ordered by severity
		query = fmt.Sprintf(`
			SELECT v.project_key, v.id, v.cve, v.severity, v.cvss, v.package, v.version,
				v.fixed_version, v.repository, v.description, v.url, v.discovered_at, v.provider,
				0.0 AS relevance
			FROM vulnerabilities v
			%s
			ORDER BY CASE v.severity
				WHEN 'critical' THEN 0
				WHEN 'high' THEN 1
				WHEN 'medium' THEN 2
				WHEN 'low' THEN 3
				ELSE 4
			END
			LIMIT ?`, whereClause)
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("search query failed: %w", err)
	}
	defer rows.Close()

	return scanResults(rows)
}

func scanResults(rows *sql.Rows) ([]SearchResult, error) {
	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var discoveredAt sql.NullTime
		var cve, version, fixedVersion, description, url sql.NullString

		err := rows.Scan(
			&r.ProjectKey, &r.ID, &cve, &r.Severity, &r.CVSS,
			&r.Package, &version, &fixedVersion, &r.Repository,
			&description, &url, &discoveredAt, &r.Provider, &r.Relevance,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		r.CVE = cve.String
		r.Version = version.String
		r.FixedVersion = fixedVersion.String
		r.Description = description.String
		r.URL = url.String
		if discoveredAt.Valid {
			r.DiscoveredAt = discoveredAt.Time
		}

		results = append(results, r)
	}
	return results, rows.Err()
}

// GetByID looks up a vulnerability by exact ID or CVE match.
// If projectKey is empty, searches all projects.
func (s *Store) GetByID(ctx context.Context, projectKey string, id string) (*provider.Vulnerability, error) {
	var condition string
	var args []any

	if projectKey != "" {
		condition = "AND project_key = ?"
		args = append(args, id, projectKey, id, projectKey)
	} else {
		args = append(args, id, id)
	}

	query := fmt.Sprintf(`
		SELECT project_key, id, cve, severity, cvss, package, version, fixed_version,
			repository, description, url, discovered_at, provider
		FROM vulnerabilities
		WHERE (id = ? %s) OR (cve = ? %s)
		LIMIT 1`,
		condition, condition)

	// Fix args for the dual-condition query
	if projectKey != "" {
		args = []any{id, projectKey, id, projectKey}
	} else {
		args = []any{id, id}
	}

	row := s.db.QueryRowContext(ctx, query, args...)

	var v provider.Vulnerability
	var pk string
	var discoveredAt sql.NullTime
	var cve, version, fixedVersion, description, url sql.NullString

	err := row.Scan(&pk, &v.ID, &cve, &v.Severity, &v.CVSS,
		&v.Package, &version, &fixedVersion, &v.Repository,
		&description, &url, &discoveredAt, &v.Provider)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability: %w", err)
	}

	v.CVE = cve.String
	v.Version = version.String
	v.FixedVersion = fixedVersion.String
	v.Description = description.String
	v.URL = url.String
	if discoveredAt.Valid {
		v.DiscoveredAt = discoveredAt.Time
	}

	return &v, nil
}

// Clear deletes cached data for a project, or all data if projectKey is empty.
func (s *Store) Clear(ctx context.Context, projectKey string) error {
	if projectKey == "" {
		_, err := s.db.ExecContext(ctx, "DELETE FROM vulnerabilities")
		if err != nil {
			return err
		}
		_, err = s.db.ExecContext(ctx, "DELETE FROM cache_meta")
		return err
	}

	_, err := s.db.ExecContext(ctx, "DELETE FROM vulnerabilities WHERE project_key = ?", projectKey)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "DELETE FROM cache_meta WHERE project_key = ?", projectKey)
	return err
}

// GetMeta retrieves a metadata value for a project.
func (s *Store) GetMeta(projectKey, key string) (string, error) {
	var value string
	err := s.db.QueryRow(
		"SELECT value FROM cache_meta WHERE project_key = ? AND key = ?",
		projectKey, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// SetMeta stores a metadata value for a project.
func (s *Store) SetMeta(projectKey, key, value string) error {
	// Delete then insert (portable across SQL engines)
	s.db.Exec("DELETE FROM cache_meta WHERE project_key = ? AND key = ?", projectKey, key)
	_, err := s.db.Exec(
		"INSERT INTO cache_meta (project_key, key, value) VALUES (?, ?, ?)",
		projectKey, key, value)
	return err
}

// ProjectCount returns the number of cached vulnerabilities for a project.
func (s *Store) ProjectCount(ctx context.Context, projectKey string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM vulnerabilities WHERE project_key = ?",
		projectKey).Scan(&count)
	return count, err
}

// TotalCount returns the total number of cached vulnerabilities across all projects.
func (s *Store) TotalCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerabilities").Scan(&count)
	return count, err
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/cache/ -v
```

Expected: all tests PASS. Note: tests using `EMBED()` for semantic search require the stoolap semantic feature. If in-memory Stoolap doesn't support `EMBED()`, the WriteVulnerabilities tests will need adjustment — see Task 4a below.

- [ ] **Step 4a: Adjust for EMBED() availability (if needed)**

If tests fail because `EMBED()` is not available in the test environment, modify `WriteVulnerabilities` to skip embedding generation when it fails, and update the test to not rely on semantic search. The non-semantic paths (field filters, ID lookup) should all work without `EMBED()`.

Add a package-level variable to `store.go`:

```go
// embedAvailable tracks whether the EMBED() function is available.
// Set during schema initialization.
var embedAvailable bool
```

And in `ensureSchema()`, probe for it:

```go
// Check if EMBED() is available
_, err := s.db.Exec("SELECT EMBED('test')")
embedAvailable = err == nil
```

Then in the INSERT, conditionally use `EMBED(?)` or `NULL`:

```go
if embedAvailable {
    // INSERT ... EMBED(?)
} else {
    // INSERT ... NULL for embedding column
}
```

- [ ] **Step 5: Commit**

```bash
git add internal/cache/store.go internal/cache/store_test.go
git commit -m "feat: add Stoolap-backed cache store with write, search, and clear"
```

---

### Task 5: Output Helpers for Search and Show

**Files:**
- Modify: `internal/output/output.go`

- [ ] **Step 1: Write the failing test**

Create `internal/output/output_test.go`:

```go
package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatDetail_AllFields(t *testing.T) {
	detail := VulnDetail{
		ID:           "SNYK-RUBY-RACKSESSION-15928857",
		CVE:          "CVE-2025-27610",
		Severity:     "high",
		CVSS:         7.5,
		Package:      "rack-session",
		Version:      "2.0.0",
		FixedVersion: "2.1.0",
		Repository:   "bactrack/my-rails-app",
		Provider:     "snyk",
		URL:          "https://security.snyk.io/vuln/SNYK-RUBY-RACKSESSION-15928857",
		Description:  "Session fixation vulnerability",
		DiscoveredAt: "2026-03-15",
	}

	text := FormatDetail(detail)
	assert.Contains(t, text, "SNYK-RUBY-RACKSESSION-15928857")
	assert.Contains(t, text, "CVE-2025-27610")
	assert.Contains(t, text, "rack-session")
	assert.Contains(t, text, "2.1.0")
}

func TestFormatDetail_MissingOptionalFields(t *testing.T) {
	detail := VulnDetail{
		ID:         "SNYK-JS-LODASH-1234567",
		Severity:   "medium",
		CVSS:       5.3,
		Package:    "lodash",
		Repository: "bactrack/node-api",
		Provider:   "snyk",
	}

	text := FormatDetail(detail)
	assert.Contains(t, text, "SNYK-JS-LODASH-1234567")
	assert.Contains(t, text, "lodash")
	// Should not contain empty labels for missing fields
	assert.NotContains(t, text, "CVE:")
	assert.NotContains(t, text, "Fixed In:")
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/output/ -run TestFormatDetail -v
```

Expected: compilation error — `VulnDetail` and `FormatDetail` don't exist yet.

- [ ] **Step 3: Add VulnDetail type and FormatDetail function**

Add to the end of `internal/output/output.go` (before the `truncate` function):

```go
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

	b.WriteString(fmt.Sprintf("  ID:            %s\n", d.ID))
	if d.CVE != "" {
		b.WriteString(fmt.Sprintf("  CVE:           %s\n", d.CVE))
	}
	b.WriteString(fmt.Sprintf("  Severity:      %s\n", d.Severity))
	b.WriteString(fmt.Sprintf("  CVSS:          %.1f\n", d.CVSS))

	pkgLine := d.Package
	if d.Version != "" {
		pkgLine += " (" + d.Version + ")"
	}
	b.WriteString(fmt.Sprintf("  Package:       %s\n", pkgLine))

	if d.FixedVersion != "" {
		b.WriteString(fmt.Sprintf("  Fixed In:      %s\n", d.FixedVersion))
	}
	b.WriteString(fmt.Sprintf("  Repository:    %s\n", d.Repository))
	b.WriteString(fmt.Sprintf("  Provider:      %s\n", d.Provider))
	if d.DiscoveredAt != "" {
		b.WriteString(fmt.Sprintf("  Discovered:    %s\n", d.DiscoveredAt))
	}
	if d.URL != "" {
		b.WriteString(fmt.Sprintf("  URL:           %s\n", d.URL))
	}
	if d.ProjectKey != "" {
		b.WriteString(fmt.Sprintf("  Project:       %s\n", d.ProjectKey))
	}
	if d.Description != "" {
		b.WriteString(fmt.Sprintf("\n  Description:\n  %s\n", d.Description))
	}

	return b.String()
}

// PrintDetail outputs a detailed vulnerability view in the specified format.
func PrintDetail(d VulnDetail, format string) error {
	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(d)
	default:
		fmt.Println()
		fmt.Print(FormatDetail(d))
		return nil
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/output/ -run TestFormatDetail -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/output/output.go internal/output/output_test.go
git commit -m "feat: add detailed vulnerability view format for show command"
```

---

### Task 6: Cache Command (refresh / status / clear)

**Files:**
- Create: `cmd/cache.go`

- [ ] **Step 1: Create the cache command with subcommands**

Create `cmd/cache.go`:

```go
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentiolabs/argus/internal/cache"
	"github.com/sentiolabs/argus/internal/config"
)

var (
	cacheProviderFlag string
	cacheClearAll     bool
	cacheTTLFlag      string
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the vulnerability cache",
}

var cacheRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Fetch vulnerabilities and update the cache",
	RunE:  runCacheRefresh,
}

var cacheStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cache state for the current project",
	RunE:  runCacheStatus,
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear cached vulnerability data",
	RunE:  runCacheClear,
}

func init() {
	rootCmd.AddCommand(cacheCmd)
	cacheCmd.AddCommand(cacheRefreshCmd)
	cacheCmd.AddCommand(cacheStatusCmd)
	cacheCmd.AddCommand(cacheClearCmd)

	cacheRefreshCmd.Flags().StringVar(&cacheProviderFlag, "provider", "all",
		"provider to refresh: all, snyk, or github")
	cacheClearCmd.Flags().BoolVar(&cacheClearAll, "all", false,
		"clear all projects' data (not just current project)")
}

func parseTTL() time.Duration {
	if cacheTTLFlag != "" {
		d, err := time.ParseDuration(cacheTTLFlag)
		if err == nil {
			return d
		}
	}
	return cache.DefaultTTL
}

func runCacheRefresh(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	mgr, err := cache.NewManager(parseTTL(), GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer mgr.Close()

	scope := cacheProviderFlag
	if scope == "" {
		scope = "all"
	}

	fmt.Printf("Refreshing cache for project: %s\n", mgr.ProjectKey())
	if err := mgr.Refresh(ctx, cfg, scope, GetVerbose()); err != nil {
		return fmt.Errorf("cache refresh failed: %w", err)
	}

	count, err := mgr.Store().ProjectCount(ctx, mgr.ProjectKey())
	if err != nil {
		return err
	}

	fmt.Printf("Cached %d vulnerabilities\n", count)
	return nil
}

func runCacheStatus(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	mgr, err := cache.NewManager(parseTTL(), GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer mgr.Close()

	projectCount, err := mgr.Store().ProjectCount(ctx, mgr.ProjectKey())
	if err != nil {
		return err
	}

	totalCount, err := mgr.Store().TotalCount(ctx)
	if err != nil {
		return err
	}

	fetchedAt, _ := mgr.Store().GetMeta(mgr.ProjectKey(), "fetched_at")
	providers, _ := mgr.Store().GetMeta(mgr.ProjectKey(), "providers")

	fmt.Printf("Project:    %s\n", mgr.ProjectKey())
	fmt.Printf("Database:   %s\n", mgr.DBPathValue())
	fmt.Printf("Cached:     %d vulnerabilities (this project)\n", projectCount)
	fmt.Printf("Total:      %d vulnerabilities (all projects)\n", totalCount)

	if providers != "" {
		fmt.Printf("Providers:  %s\n", providers)
	}

	if fetchedAt != "" {
		t, err := time.Parse(time.RFC3339, fetchedAt)
		if err == nil {
			ago := time.Since(t).Truncate(time.Minute)
			valid := "valid"
			if !mgr.IsValid() {
				valid = "expired"
			}
			fmt.Printf("Fetched:    %s (%s ago)\n", t.Format("2006-01-02 15:04:05 UTC"), ago)
			fmt.Printf("TTL:        %s (%s)\n", parseTTL(), valid)
		}
	} else {
		fmt.Println("Fetched:    never")
	}

	return nil
}

func runCacheClear(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	mgr, err := cache.NewManager(parseTTL(), GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer mgr.Close()

	projectKey := mgr.ProjectKey()
	if cacheClearAll {
		projectKey = ""
	}

	if err := mgr.Store().Clear(ctx, projectKey); err != nil {
		return fmt.Errorf("failed to clear cache: %w", err)
	}

	if cacheClearAll {
		fmt.Println("Cleared all cached data")
	} else {
		fmt.Printf("Cleared cache for project: %s\n", mgr.ProjectKey())
	}

	return nil
}
```

- [ ] **Step 2: Verify build passes**

```bash
go build .
```

Expected: clean build.

- [ ] **Step 3: Verify commands are registered**

```bash
./argus cache --help
./argus cache refresh --help
./argus cache status --help
./argus cache clear --help
```

Expected: help text for each command.

- [ ] **Step 4: Commit**

```bash
git add cmd/cache.go
git commit -m "feat: add cache refresh/status/clear CLI commands"
```

---

### Task 7: Search Command

**Files:**
- Create: `cmd/search.go`

- [ ] **Step 1: Create the search command**

Create `cmd/search.go`:

```go
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sentiolabs/argus/internal/cache"
	"github.com/sentiolabs/argus/internal/config"
	"github.com/sentiolabs/argus/internal/output"
	"github.com/sentiolabs/argus/internal/search"
)

var (
	searchProviderFlag  string
	searchAllProjects   bool
	searchRefresh       bool
	searchLimit         int
	searchCacheTTLFlag  string
)

var searchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search cached vulnerabilities by keyword, ID, or field filters",
	Long: `Search vulnerabilities using semantic search, exact field filters, or both.

Examples:
  argus search "rails"                         # semantic search
  argus search "SNYK-RUBY-RACKSESSION-123"     # exact ID lookup
  argus search "severity:critical"             # field filter
  argus search "severity:high rails"           # hybrid: filter + semantic
  argus search "package:rack* provider:snyk"   # multiple field filters

Supported field prefixes: severity, package, repo, repository, provider, cve, id`,
	Args: cobra.ExactArgs(1),
	RunE: runSearch,
}

func init() {
	rootCmd.AddCommand(searchCmd)

	searchCmd.Flags().StringVar(&searchProviderFlag, "provider", "",
		"scope search to provider: snyk or github")
	searchCmd.Flags().BoolVar(&searchAllProjects, "all-projects", false,
		"search across all cached projects")
	searchCmd.Flags().BoolVar(&searchRefresh, "refresh", false,
		"force cache refresh before searching")
	searchCmd.Flags().IntVar(&searchLimit, "limit", 20,
		"maximum number of results to return")
	searchCmd.Flags().StringVar(&searchCacheTTLFlag, "cache-ttl", "",
		"cache TTL duration (e.g., 12h, 30m)")
}

func runSearch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	rawQuery := args[0]

	ttl := cache.DefaultTTL
	if searchCacheTTLFlag != "" {
		var err error
		ttl, err = parseDuration(searchCacheTTLFlag)
		if err != nil {
			return fmt.Errorf("invalid cache-ttl: %w", err)
		}
	}

	mgr, err := cache.NewManager(ttl, GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer mgr.Close()

	// Auto-fetch or forced refresh
	if searchRefresh || !mgr.IsValid() {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		scope := "all"
		if searchProviderFlag != "" {
			scope = searchProviderFlag
		}
		if err := mgr.Refresh(ctx, cfg, scope, GetVerbose()); err != nil {
			return fmt.Errorf("cache refresh failed: %w", err)
		}
	}

	// Parse the query
	q := search.Parse(rawQuery)

	// Add --provider flag as an additional filter if specified
	if searchProviderFlag != "" && q.Filters == nil {
		q.Filters = map[string]string{"provider": searchProviderFlag}
	} else if searchProviderFlag != "" {
		q.Filters["provider"] = searchProviderFlag
	}

	// Determine project scope
	projectKey := mgr.ProjectKey()
	if searchAllProjects {
		projectKey = ""
	}

	results, err := mgr.Store().Search(ctx, projectKey, q, searchLimit)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	if len(results) == 0 {
		fmt.Println("No results found")
		return nil
	}

	// Convert to SyncResult for output compatibility
	syncResults := make([]output.SyncResult, len(results))
	for i, r := range results {
		syncResults[i] = output.SyncResult{
			Provider:   r.Provider,
			VulnID:     r.ID,
			CVE:        r.CVE,
			Severity:   r.Severity,
			Package:    r.Package,
			Repository: r.Repository,
			Action:     fmt.Sprintf("%.2f", r.Relevance),
			Status:     "cached",
		}
	}

	return output.Print(syncResults, GetOutput(), true)
}

func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}
```

- [ ] **Step 2: Verify build passes**

```bash
go build .
```

Expected: clean build.

- [ ] **Step 3: Verify command is registered**

```bash
./argus search --help
```

Expected: help text showing usage, examples, and flags.

- [ ] **Step 4: Commit**

```bash
git add cmd/search.go
git commit -m "feat: add search command with hybrid semantic + field filter queries"
```

---

### Task 8: Show Command

**Files:**
- Create: `cmd/show.go`

- [ ] **Step 1: Create the show command**

Create `cmd/show.go`:

```go
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentiolabs/argus/internal/cache"
	"github.com/sentiolabs/argus/internal/config"
	"github.com/sentiolabs/argus/internal/output"
	"github.com/sentiolabs/argus/internal/search"
)

var (
	showAllProjects  bool
	showCacheTTLFlag string
)

var showCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show detailed information about a specific vulnerability",
	Long: `Look up a vulnerability by its exact ID (Snyk, GHSA, or CVE) and display
detailed information including description, fix version, and URL.

If no exact match is found, falls back to semantic search and shows the
closest result.

Examples:
  argus show SNYK-RUBY-RACKSESSION-15928857
  argus show CVE-2025-27610
  argus show GHSA-xvch-r4wf-h8w9`,
	Args: cobra.ExactArgs(1),
	RunE: runShow,
}

func init() {
	rootCmd.AddCommand(showCmd)

	showCmd.Flags().BoolVar(&showAllProjects, "all-projects", false,
		"search across all cached projects")
	showCmd.Flags().StringVar(&showCacheTTLFlag, "cache-ttl", "",
		"cache TTL duration (e.g., 12h, 30m)")
}

func runShow(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	id := args[0]

	ttl := cache.DefaultTTL
	if showCacheTTLFlag != "" {
		var err error
		ttl, err = parseDuration(showCacheTTLFlag)
		if err != nil {
			return fmt.Errorf("invalid cache-ttl: %w", err)
		}
	}

	mgr, err := cache.NewManager(ttl, GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer mgr.Close()

	// Auto-fetch if needed
	if !mgr.IsValid() {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		if err := mgr.Refresh(ctx, cfg, "all", GetVerbose()); err != nil {
			return fmt.Errorf("cache refresh failed: %w", err)
		}
	}

	projectKey := mgr.ProjectKey()
	if showAllProjects {
		projectKey = ""
	}

	// Try exact ID lookup first
	v, err := mgr.Store().GetByID(ctx, projectKey, id)
	if err != nil {
		return fmt.Errorf("lookup failed: %w", err)
	}

	if v != nil {
		return printVulnDetail(v, projectKey)
	}

	// Fall back to semantic search
	q := search.Query{SemanticText: id}
	results, err := mgr.Store().Search(ctx, projectKey, q, 1)
	if err != nil {
		return fmt.Errorf("semantic search failed: %w", err)
	}

	if len(results) == 0 {
		return fmt.Errorf("no vulnerability found matching %q", id)
	}

	r := &results[0]
	fmt.Printf("No exact match for %q. Closest result (relevance: %.2f):\n", id, r.Relevance)
	return printVulnDetail(&r.Vulnerability, r.ProjectKey)
}

func printVulnDetail(v *provider.Vulnerability, projectKey string) error {
	discoveredAt := ""
	if !v.DiscoveredAt.IsZero() {
		discoveredAt = v.DiscoveredAt.Format("2006-01-02")
	}

	detail := output.VulnDetail{
		ID:           v.ID,
		CVE:          v.CVE,
		Severity:     v.Severity,
		CVSS:         v.CVSS,
		Package:      v.Package,
		Version:      v.Version,
		FixedVersion: v.FixedVersion,
		Repository:   v.Repository,
		Provider:     v.Provider,
		DiscoveredAt: discoveredAt,
		URL:          v.URL,
		Description:  v.Description,
		ProjectKey:   projectKey,
	}

	return output.PrintDetail(detail, GetOutput())
}
```

- [ ] **Step 2: Add missing import**

The `show.go` file references the `provider` package. Add the import:

```go
import (
	// ... existing imports ...
	"github.com/sentiolabs/argus/internal/provider"
)
```

Note: Remove any unused imports (e.g., `time` if not used directly).

- [ ] **Step 3: Verify build passes**

```bash
go build .
```

Expected: clean build.

- [ ] **Step 4: Verify command is registered**

```bash
./argus show --help
```

Expected: help text with usage and examples.

- [ ] **Step 5: Commit**

```bash
git add cmd/show.go
git commit -m "feat: add show command for detailed vulnerability lookup"
```

---

### Task 9: Add --cache-ttl and --refresh Flags to Root

**Files:**
- Modify: `cmd/root.go`

- [ ] **Step 1: Add the persistent flags to root command**

In `cmd/root.go`, add new variables and flags in `init()`:

Add to the `var` block at the top:

```go
var (
	// ... existing vars ...
	cacheTTL    string
	forceRefresh bool
)
```

Add to `init()`:

```go
rootCmd.PersistentFlags().StringVar(&cacheTTL, "cache-ttl", "",
	"cache TTL duration (e.g., 12h, 30m). Default: 24h")
rootCmd.PersistentFlags().BoolVar(&forceRefresh, "refresh", false,
	"force cache refresh before search/show")
```

Add getter functions:

```go
// GetCacheTTL returns the configured cache TTL duration.
func GetCacheTTL() string {
	return cacheTTL
}

// GetRefresh returns true if a forced cache refresh was requested.
func GetRefresh() bool {
	return forceRefresh
}
```

- [ ] **Step 2: Update search.go and show.go to use root flags**

In `cmd/search.go`, remove the local `searchCacheTTLFlag` and `searchRefresh` variables and their flag registrations from `init()`. Update `runSearch` to use `GetCacheTTL()` and `GetRefresh()` instead.

In `cmd/show.go`, remove the local `showCacheTTLFlag` variable and its flag registration from `init()`. Update `runShow` to use `GetCacheTTL()`.

- [ ] **Step 3: Verify build passes**

```bash
go build .
```

Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add cmd/root.go cmd/search.go cmd/show.go
git commit -m "refactor: move cache-ttl and refresh flags to root command"
```

---

### Task 10: HNSW Index Creation

**Files:**
- Modify: `internal/cache/store.go`

The HNSW index for vector search was deferred from the schema creation in Task 4 because it may require data to exist first, and Stoolap's `CREATE INDEX IF NOT EXISTS` behavior with HNSW needs verification.

- [ ] **Step 1: Add HNSW index creation after data is written**

In `store.go`, add a method and call it at the end of `WriteVulnerabilities`, after the transaction commits:

```go
// ensureHNSWIndex creates the HNSW index if it doesn't exist.
// Called after data writes since some engines need data present for HNSW.
func (s *Store) ensureHNSWIndex() {
	_, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_vuln_embedding 
		ON vulnerabilities(embedding) USING HNSW WITH (metric = 'cosine')`)
	if err != nil {
		// HNSW may not be available (e.g., semantic feature disabled)
		// Log but don't fail — queries will fall back to brute-force scan
		slog.Debug("HNSW index creation skipped", "error", err)
	}
}
```

Add `"log/slog"` to the imports if not already present.

Call `s.ensureHNSWIndex()` at the end of `WriteVulnerabilities`, after `tx.Commit()`:

```go
	if err := tx.Commit(); err != nil {
		return err
	}

	s.ensureHNSWIndex()
	return nil
```

- [ ] **Step 2: Verify build passes**

```bash
go build .
```

Expected: clean build.

- [ ] **Step 3: Run all tests**

```bash
go test ./... -v
```

Expected: all existing tests plus new tests pass.

- [ ] **Step 4: Commit**

```bash
git add internal/cache/store.go
git commit -m "feat: add HNSW index creation for semantic search acceleration"
```

---

### Task 11: Integration Smoke Test

**Files:**
- No new files — this is a manual verification task.

- [ ] **Step 1: Run the full test suite**

```bash
go test ./... -v
```

Expected: all tests PASS.

- [ ] **Step 2: Build and verify CLI help**

```bash
go build . && ./argus --help
```

Expected: shows cache, search, show alongside existing sync/verify/config commands.

- [ ] **Step 3: Verify cache commands**

```bash
./argus cache status
./argus cache clear
```

Expected: `status` shows "never" for fetched time; `clear` succeeds cleanly.

- [ ] **Step 4: Verify search with empty cache**

```bash
./argus search "test" --output json 2>/dev/null || echo "expected: auto-fetch or no results"
```

Expected: either auto-fetches (if config exists) or returns "No results found".

- [ ] **Step 5: Commit any fixes needed**

If any fixes were needed during smoke testing, commit them:

```bash
git add -A
git commit -m "fix: address issues found during integration smoke test"
```

---

## Task Dependency Graph

```
Task 1 (dependency) ─┐
                      ├── Task 2 (search parser, no deps)
                      ├── Task 3 (cache manager, no deps)
                      │
Task 2 + Task 3 ──────┤
                      └── Task 4 (store, needs search + cache)
                            │
                      Task 5 (output helpers, independent)
                            │
Task 4 + Task 5 ──────┬── Task 6 (cache command)
                      ├── Task 7 (search command)
                      ├── Task 8 (show command)
                      └── Task 9 (root flags refactor)
                            │
                      Task 10 (HNSW index)
                            │
                      Task 11 (integration smoke test)
```

Tasks 2, 3, and 5 can run in parallel after Task 1.
Tasks 6, 7, and 8 can run in parallel after Task 4.
