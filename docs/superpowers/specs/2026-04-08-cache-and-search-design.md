# Argus Cache & Search Design

## Problem

Argus can fetch vulnerabilities from Snyk and GitHub Dependabot, but only in batch — there is no way to look up a specific issue by ID, search by keyword, or query across fields. Users working in Claude Code or during a "security fix day" across multiple projects need targeted lookups without re-fetching from APIs every time.

## Solution

Add a persistent disk cache backed by Stoolap (embedded SQL database with built-in semantic search) and new CLI commands for search, show, and cache management. The cache stores fetched vulnerabilities locally and supports both exact field queries and natural-language semantic search via Stoolap's native `EMBED()` function.

## Design Decisions

These decisions were made during brainstorming and are final:

1. **Search strategy: Hybrid (Option C)** — bare words trigger semantic search via `EMBED()` + cosine distance; field prefixes (`severity:critical`, `package:rack*`) use SQL WHERE clauses; both can combine in a single query.

2. **Cache location: XDG-compliant** — `$XDG_CACHE_HOME/argus/<project-key>/` (defaults to `~/.cache/argus/<project-key>/`).

3. **Project key: Path-derived** — the repo root (or cwd) full path converted to a hyphenated directory name (e.g., `/home/bfirestone/devspace/personal/sentiolabs/argus` becomes `-home-bfirestone-devspace-personal-sentiolabs-argus`). Fully automatic, zero config, deterministic.

4. **Multi-project support** — per-project cache directories with `--all-projects` flag to search across all cached projects.

5. **Storage engine: Stoolap** — embedded Rust-based SQL database with native `EMBED()` function (all-MiniLM-L6-v2 sentence transformer, 384 dimensions, runs locally, no external APIs). Provides semantic search for bare-word queries and standard SQL for field-aware queries.

6. **TTL: 24 hours default** — overridable via `--cache-ttl` flag. `--refresh` forces a fresh fetch regardless of TTL.

7. **Auto-fetch** — `search` and `show` commands check cache validity; if missing or expired, they fetch transparently before executing the query.

## Database Schema

Single Stoolap database per project at `~/.cache/argus/<project-key>/vulns.db`.

```sql
CREATE TABLE vulnerabilities (
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
);

CREATE INDEX idx_vuln_id ON vulnerabilities(id);
CREATE INDEX idx_vuln_cve ON vulnerabilities(cve);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_package ON vulnerabilities(package);
CREATE INDEX idx_vuln_provider ON vulnerabilities(provider);
CREATE INDEX idx_vuln_repository ON vulnerabilities(repository);
CREATE INDEX idx_vuln_embedding ON vulnerabilities(embedding)
    USING HNSW WITH (metric = 'cosine');

CREATE TABLE cache_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Stores: fetched_at, providers, count, ttl_hours
```

### Embedding Content

When inserting a vulnerability, the embedding is generated from a concatenation of the most searchable fields:

```sql
-- In Go, the embedding text is constructed before the INSERT:
--   embedText = id + " " + cve + " " + package + " " + repository + " " + description
-- Then passed as a single parameter:
INSERT INTO vulnerabilities (id, cve, severity, cvss, package, version,
    fixed_version, repository, description, url, discovered_at, provider, embedding)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, EMBED($13));
-- $13 = concatenated search text built in Go
```

This ensures semantic search matches against vulnerability identifiers, package names, repo context, and description text.

## CLI Commands

### `argus cache refresh`

Fetches vulnerabilities from providers and writes to cache.

```
argus cache refresh                    # all enabled providers
argus cache refresh --provider snyk    # snyk only
argus cache refresh --provider github  # github/dependabot only
```

**Behavior:**
- Reuses existing `provider.FetchVulnerabilities()` — same code path as `sync` and `verify`
- Existing config filters (severity threshold, package includes/excludes, etc.) are applied during fetch, same as today
- Clears existing cache data for the fetched provider(s) before writing (full replace, not append)
- Writes `cache_meta` entries: `fetched_at`, `providers`, `count`, `ttl_hours`

### `argus cache status`

Shows cache state for the current project.

```
$ argus cache status
Project:    -home-bfirestone-devspace-personal-sentiolabs-argus
Location:   /home/bfirestone/.cache/argus/-home-bfirestone-devspace-personal-sentiolabs-argus/vulns.db
Cached:     142 vulnerabilities
Providers:  snyk, github
Fetched:    2026-04-08 14:30:00 UTC (2 hours ago)
TTL:        24h (valid)
```

### `argus cache clear`

```
argus cache clear          # clear current project cache
argus cache clear --all    # clear all project caches
```

### `argus search <query>`

Searches cached vulnerabilities with hybrid matching.

```
argus search "rails"                                   # semantic search
argus search "session handling auth bypass"             # semantic search
argus search "SNYK-RUBY-RACKSESSION-15928857"           # exact ID match
argus search "severity:critical"                        # field filter
argus search "severity:critical session handling"       # hybrid: filter + semantic
argus search "package:rack* provider:snyk"              # multiple field filters
argus search "repo:bactrack/* severity:high"            # field filters with glob
argus search "rails" --provider snyk                    # scope to provider
argus search "rails" --all-projects                     # search all cached projects
argus search "rails" --refresh                          # force fetch before search
argus search "rails" --output json                      # JSON output
argus search "rails" --limit 50                         # override default result limit
```

**Query parsing rules:**
1. Tokens matching `field:value` are extracted as SQL WHERE clauses
2. Remaining bare tokens are joined and used as the semantic search query via `EMBED()`
3. If the query is *only* field filters (no bare words), results are ordered by severity (critical > high > medium > low)
4. If the query looks like an exact ID (starts with `SNYK-`, `GHSA-`, or `CVE-`), match against `id` or `cve` columns directly before falling back to semantic search

**Supported field prefixes:**
- `severity:` — exact match (critical, high, medium, low)
- `package:` — glob match via LIKE
- `repo:` or `repository:` — glob match via LIKE
- `provider:` — exact match (snyk, github)
- `cve:` — glob match via LIKE
- `id:` — glob match via LIKE

**Semantic search SQL pattern:**
```sql
WITH query AS (
    SELECT EMBED('session handling auth bypass') AS vec
)
SELECT id, cve, severity, cvss, package, repository, description, url, provider,
       VEC_DISTANCE_COSINE(embedding, query.vec) AS relevance
FROM vulnerabilities, query
WHERE severity = 'critical'  -- from field prefix, if any
ORDER BY relevance
LIMIT 20;
```

**Auto-fetch:** If cache is missing or expired (past TTL), fetch from all providers (or `--provider` if specified) before searching.

**`--all-projects`:** Opens each project's `vulns.db` sequentially, runs the search query, and merges results. Results include a `project` column showing which project-key the result came from.

### `argus show <id>`

Displays detailed view of a single vulnerability.

```
$ argus show SNYK-RUBY-RACKSESSION-15928857

  ID:            SNYK-RUBY-RACKSESSION-15928857
  CVE:           CVE-2025-27610
  Severity:      high
  CVSS:          7.5
  Package:       rack-session (v2.0.0)
  Fixed In:      2.1.0
  Repository:    bactrack/my-rails-app
  Provider:      snyk
  Discovered:    2026-03-15
  URL:           https://security.snyk.io/vuln/SNYK-RUBY-RACKSESSION-15928857

  Description:
  Rack::Session cookie handling vulnerability allowing session fixation
  through crafted cookie values...
```

**Behavior:**
1. Exact match on `id` column first
2. If no exact match, try exact match on `cve` column
3. If still no match, fall back to semantic search and present the top result with a prompt: "No exact match. Closest result (relevance: 0.85):" followed by the result
4. Supports `--output json` for structured output
5. Auto-fetches if cache is missing/expired
6. Supports `--all-projects` to search across all cached projects

## Package Structure

```
internal/
  cache/
    cache.go          # Cache manager: project key derivation, TTL checks,
                      #   cache directory management, meta read/write
    store.go          # Stoolap database operations: schema creation,
                      #   bulk insert, clear, query execution
  search/
    search.go         # Query parser: splits input into field filters
                      #   and bare-word semantic query
    search_test.go    # Query parsing tests

cmd/
  cache.go            # cache refresh / status / clear subcommands
  search.go           # search command
  show.go             # show command
```

### Key types

```go
// internal/cache/cache.go

// Manager handles cache lifecycle for a project.
type Manager struct {
    projectKey string
    cacheDir   string
    ttl        time.Duration
}

// ProjectKey derives the cache key from the working directory.
// "/home/user/projects/my-app" -> "-home-user-projects-my-app"
func ProjectKey() string

// IsValid checks if the cache exists and is within TTL.
func (m *Manager) IsValid() bool

// EnsureFresh auto-fetches if cache is missing or expired.
// providerScope: "all", "snyk", or "github"
func (m *Manager) EnsureFresh(ctx context.Context, cfg *config.Config, providerScope string, verbose bool) error
```

```go
// internal/cache/store.go

// Store wraps Stoolap database operations.
type Store struct {
    db *stoolap.DB  // or *sql.DB via database/sql driver
}

// Open opens or creates the cache database, ensuring schema exists.
func Open(dbPath string) (*Store, error)

// WriteVulnerabilities clears existing data for the given providers
// and inserts new vulnerabilities with embeddings.
func (s *Store) WriteVulnerabilities(ctx context.Context, vulns []provider.Vulnerability, providers []string) error

// Search executes a parsed query and returns matching vulnerabilities.
func (s *Store) Search(ctx context.Context, q search.Query, limit int) ([]SearchResult, error)

// GetByID looks up a vulnerability by exact ID or CVE match.
func (s *Store) GetByID(ctx context.Context, id string) (*provider.Vulnerability, error)
```

```go
// internal/search/search.go

// Query represents a parsed search input.
type Query struct {
    SemanticText string            // bare words for EMBED()
    Filters      map[string]string // field:value pairs for WHERE clauses
    IsIDLookup   bool              // true if query looks like SNYK-*/GHSA-*/CVE-*
    RawID        string            // the raw ID for direct lookup
}

// Parse splits a raw query string into structured Query.
func Parse(raw string) Query
```

```go
// SearchResult extends Vulnerability with search metadata.
type SearchResult struct {
    provider.Vulnerability
    Relevance  float64 // cosine distance (lower = more relevant)
    ProjectKey string  // populated for --all-projects queries
}
```

## Dependencies

**New dependency:**
- `github.com/stoolap/stoolap-go` — Go driver for Stoolap. Prebuilt shared libraries bundled for macOS (arm64), Linux (x64), Windows (x64). No CGo required. Uses `database/sql` interface.

**No other new dependencies.** All query building uses string formatting with parameterized queries (no ORM, no query builder).

## Build Considerations

- Stoolap's Go driver bundles prebuilt `libstoolap.so` for supported platforms. This may increase binary size.
- The `semantic` feature (EMBED function) requires the Stoolap engine to be built with the `semantic` feature flag. Need to verify that the prebuilt shared libraries in the Go driver include this feature.
- First invocation of `EMBED()` downloads the all-MiniLM-L6-v2 model (~90MB) to `~/.cache/huggingface/hub/`. Subsequent calls use the cached model.
- Docker builds: the model download happens at runtime, not build time. For Docker images, consider pre-warming the model cache in the Dockerfile.

## What Stays the Same

- `sync` command — unchanged, still creates/updates Jira tickets
- `verify` command — unchanged, still previews without Jira side effects
- `Provider` interface — unchanged, `FetchVulnerabilities()` is reused by cache refresh
- Filter logic — unchanged, applied during fetch before caching
- Config file format — no new fields required
- Output formatting — `search` reuses existing `output.Print()` for table/JSON rendering; `show` adds a new detailed vertical format

## Testing Strategy

- **`internal/search/`**: Unit tests for query parsing — field extraction, bare-word separation, ID detection, glob patterns
- **`internal/cache/`**: Integration tests using in-memory Stoolap (`memory://`) — schema creation, write/read round-trip, TTL validation, project key derivation
- **`cmd/`**: Table-driven tests for command flag parsing and output formatting
- Semantic search accuracy is not tested (model quality is Stoolap's concern) — tests verify the query is constructed correctly

## Open Questions

1. **Stoolap Go driver + semantic feature**: Do the prebuilt shared libraries in `stoolap-go` include the `semantic` feature flag? If not, we may need custom builds or to check with the stoolap maintainers.
2. ~~**Result limit defaults**: `search` defaults to 20 results. Should this be configurable via `--limit`?~~ **Resolved:** Yes, `--limit` flag added with default of 20.
3. **Cache size management**: Should there be a max cache age beyond TTL that auto-purges old project caches? (Leaning no for v1 — `cache clear --all` is sufficient.)
