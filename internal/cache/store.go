package cache

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/sentiolabs/argus/internal/provider"
	"github.com/sentiolabs/argus/internal/search"

	_ "github.com/stoolap/stoolap-go/pkg/driver"
)

// Store wraps a Stoolap database connection for vulnerability caching.
type Store struct {
	db             *sql.DB
	embedAvailable bool // whether EMBED() function works in this environment
}

// SearchResult is a vulnerability with search metadata.
type SearchResult struct {
	provider.Vulnerability
	Relevance  float64 // cosine distance (lower = more relevant); 0 for non-semantic searches
	ProjectKey string  // which project this result came from
}

// Open opens (or creates) the Stoolap database at the given DSN.
// Use "memory://" for ephemeral in-memory stores (tests) or "file:///path" for persistent storage.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("stoolap", dsn)
	if err != nil {
		return nil, fmt.Errorf("open stoolap db: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping stoolap db: %w", err)
	}

	s := &Store{db: db}

	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	s.embedAvailable = s.detectEmbedSupport()

	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// initSchema creates tables and indexes, skipping statements that fail gracefully.
func (s *Store) initSchema() error {
	stmts := []string{
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
			meta_key TEXT NOT NULL,
			value TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_meta_project_key ON cache_meta(project_key)`,
		`CREATE INDEX IF NOT EXISTS idx_meta_meta_key ON cache_meta(meta_key)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			// If VECTOR type is not recognized or index fails, try without embedding column.
			if strings.Contains(stmt, "embedding VECTOR") {
				// Retry without the embedding column
				stmt = strings.Replace(stmt, "\n\t\t\tembedding VECTOR(384)\n\t\t", "", 1)
				if _, err2 := s.db.Exec(stmt); err2 != nil {
					return fmt.Errorf("create vulnerabilities table: %w", err2)
				}
			}
			// For index creation failures, continue — non-fatal
		}
	}

	return nil
}

// detectEmbedSupport probes whether the EMBED() SQL function is available.
func (s *Store) detectEmbedSupport() bool {
	row := s.db.QueryRow(`SELECT EMBED('test')`)
	var v interface{}
	if err := row.Scan(&v); err != nil {
		return false
	}
	return v != nil
}

// WriteVulnerabilities replaces all vulnerabilities for the given project+providers
// with the provided slice, then updates metadata.
func (s *Store) WriteVulnerabilities(ctx context.Context, projectKey string, vulns []provider.Vulnerability, providers []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Delete existing rows for each provider in this project
	for _, p := range providers {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM vulnerabilities WHERE project_key = ? AND provider = ?`,
			projectKey, p,
		); err != nil {
			return fmt.Errorf("delete old vulns for provider %s: %w", p, err)
		}
	}

	// Insert new rows
	for _, v := range vulns {
		embedText := strings.Join([]string{v.ID, v.CVE, v.Package, v.Repository, v.Description}, " ")

		var discoveredAt *time.Time
		if !v.DiscoveredAt.IsZero() {
			t := v.DiscoveredAt
			discoveredAt = &t
		}

		if s.embedAvailable {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO vulnerabilities
					(project_key, id, cve, severity, cvss, package, version, fixed_version,
					 repository, description, url, discovered_at, provider, embedding)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, EMBED(?))`,
				projectKey, v.ID, v.CVE, v.Severity, v.CVSS, v.Package, v.Version, v.FixedVersion,
				v.Repository, v.Description, v.URL, discoveredAt, v.Provider, embedText,
			)
		} else {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO vulnerabilities
					(project_key, id, cve, severity, cvss, package, version, fixed_version,
					 repository, description, url, discovered_at, provider)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				projectKey, v.ID, v.CVE, v.Severity, v.CVSS, v.Package, v.Version, v.FixedVersion,
				v.Repository, v.Description, v.URL, discoveredAt, v.Provider,
			)
		}
		if err != nil {
			return fmt.Errorf("insert vuln %s: %w", v.ID, err)
		}
	}

	// Update metadata: delete-then-insert
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM cache_meta WHERE project_key = ? AND meta_key IN ('fetched_at', 'providers', 'count')`,
		projectKey,
	); err != nil {
		return fmt.Errorf("delete old meta: %w", err)
	}

	fetchedAt := time.Now().UTC().Format(time.RFC3339)
	providerList := strings.Join(providers, ",")
	count := len(vulns)

	metaRows := [][2]string{
		{"fetched_at", fetchedAt},
		{"providers", providerList},
		{"count", fmt.Sprintf("%d", count)},
	}
	for _, row := range metaRows {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO cache_meta (project_key, meta_key, value) VALUES (?, ?, ?)`,
			projectKey, row[0], row[1],
		); err != nil {
			return fmt.Errorf("insert meta %s: %w", row[0], err)
		}
	}

	return tx.Commit()
}

// globToLike converts glob-style wildcards to SQL LIKE patterns.
func globToLike(s string) string {
	s = strings.ReplaceAll(s, "%", "\\%") // escape existing % first
	s = strings.ReplaceAll(s, "_", "\\_") // escape existing _ first
	s = strings.ReplaceAll(s, "*", "%")
	s = strings.ReplaceAll(s, "?", "_")
	return s
}

// Search runs a structured query and returns matching vulnerabilities.
func (s *Store) Search(ctx context.Context, projectKey string, q search.Query, limit int) ([]SearchResult, error) {
	if q.IsIDLookup {
		v, err := s.GetByID(ctx, projectKey, q.RawID)
		if err != nil {
			return nil, err
		}
		if v == nil {
			return nil, nil
		}
		return []SearchResult{{Vulnerability: *v, ProjectKey: projectKey}}, nil
	}

	var args []interface{}
	var where []string

	if projectKey != "" {
		where = append(where, "project_key = ?")
		args = append(args, projectKey)
	}

	// Field filters
	for field, value := range q.Filters {
		switch field {
		case "severity", "provider":
			where = append(where, field+" = ?")
			args = append(args, value)
		case "package", "repository", "cve", "id":
			if strings.ContainsAny(value, "*?") {
				where = append(where, field+" LIKE ?")
				args = append(args, globToLike(value))
			} else {
				where = append(where, field+" = ?")
				args = append(args, value)
			}
		}
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	useSemanticSearch := q.SemanticText != "" && s.embedAvailable

	var rows *sql.Rows
	var err error

	if useSemanticSearch {
		querySQL := fmt.Sprintf(`
			WITH ranked AS (
				SELECT project_key, id, cve, severity, cvss, package, version, fixed_version,
					   repository, description, url, discovered_at, provider,
					   VEC_DISTANCE_COSINE(embedding, EMBED(?)) AS relevance
				FROM vulnerabilities
				%s
			)
			SELECT project_key, id, cve, severity, cvss, package, version, fixed_version,
				   repository, description, url, discovered_at, provider, relevance
			FROM ranked
			ORDER BY relevance ASC
			LIMIT ?`, whereClause)

		allArgs := append([]interface{}{q.SemanticText}, args...)
		allArgs = append(allArgs, limit)
		rows, err = s.db.QueryContext(ctx, querySQL, allArgs...)
	} else {
		querySQL := fmt.Sprintf(`
			SELECT project_key, id, cve, severity, cvss, package, version, fixed_version,
				   repository, description, url, discovered_at, provider
			FROM vulnerabilities
			%s
			ORDER BY CASE severity
				WHEN 'critical' THEN 0
				WHEN 'high' THEN 1
				WHEN 'medium' THEN 2
				ELSE 3
			END ASC
			LIMIT ?`, whereClause)

		allArgs := append(args, limit)
		rows, err = s.db.QueryContext(ctx, querySQL, allArgs...)
	}

	if err != nil {
		return nil, fmt.Errorf("search query: %w", err)
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var cve, version, fixedVersion, description, url sql.NullString
		var cvss sql.NullFloat64
		var discoveredAt sql.NullTime

		if useSemanticSearch {
			err = rows.Scan(
				&r.ProjectKey, &r.ID, &cve, &r.Severity, &cvss, &r.Package, &version, &fixedVersion,
				&r.Repository, &description, &url, &discoveredAt, &r.Provider, &r.Relevance,
			)
		} else {
			err = rows.Scan(
				&r.ProjectKey, &r.ID, &cve, &r.Severity, &cvss, &r.Package, &version, &fixedVersion,
				&r.Repository, &description, &url, &discoveredAt, &r.Provider,
			)
		}
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		r.CVE = cve.String
		r.Version = version.String
		r.FixedVersion = fixedVersion.String
		r.Description = description.String
		r.URL = url.String
		r.CVSS = cvss.Float64
		if discoveredAt.Valid {
			r.DiscoveredAt = discoveredAt.Time
		}

		results = append(results, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return results, nil
}

// GetByID fetches a single vulnerability by ID or CVE, with optional project filter.
// Returns nil, nil if not found.
func (s *Store) GetByID(ctx context.Context, projectKey string, id string) (*provider.Vulnerability, error) {
	// Try exact id match first, then cve match
	for _, col := range []string{"id", "cve"} {
		var args []interface{}
		var where []string

		where = append(where, col+" = ?")
		args = append(args, id)

		if projectKey != "" {
			where = append(where, "project_key = ?")
			args = append(args, projectKey)
		}

		querySQL := fmt.Sprintf(`
			SELECT project_key, id, cve, severity, cvss, package, version, fixed_version,
				   repository, description, url, discovered_at, provider
			FROM vulnerabilities
			WHERE %s
			LIMIT 1`, strings.Join(where, " AND "))

		row := s.db.QueryRowContext(ctx, querySQL, args...)

		var v provider.Vulnerability
		var pk string
		var cve, version, fixedVersion, description, url sql.NullString
		var cvss sql.NullFloat64
		var discoveredAt sql.NullTime

		err := row.Scan(&pk, &v.ID, &cve, &v.Severity, &cvss, &v.Package, &version, &fixedVersion,
			&v.Repository, &description, &url, &discoveredAt, &v.Provider)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("scan GetByID: %w", err)
		}

		v.CVE = cve.String
		v.Version = version.String
		v.FixedVersion = fixedVersion.String
		v.Description = description.String
		v.URL = url.String
		v.CVSS = cvss.Float64
		if discoveredAt.Valid {
			v.DiscoveredAt = discoveredAt.Time
		}

		return &v, nil
	}

	return nil, nil
}

// Clear deletes all vulnerabilities (and metadata) for the given project.
// If projectKey is empty, deletes everything.
func (s *Store) Clear(ctx context.Context, projectKey string) error {
	if projectKey == "" {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM vulnerabilities`); err != nil {
			return fmt.Errorf("clear all vulnerabilities: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM cache_meta`); err != nil {
			return fmt.Errorf("clear all meta: %w", err)
		}
		return nil
	}

	if _, err := s.db.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE project_key = ?`, projectKey); err != nil {
		return fmt.Errorf("clear vulnerabilities for %s: %w", projectKey, err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM cache_meta WHERE project_key = ?`, projectKey); err != nil {
		return fmt.Errorf("clear meta for %s: %w", projectKey, err)
	}
	return nil
}

// GetMeta returns a metadata value for a project key+name. Returns "" if not found.
func (s *Store) GetMeta(projectKey, key string) (string, error) {
	row := s.db.QueryRow(`SELECT value FROM cache_meta WHERE project_key = ? AND meta_key = ? LIMIT 1`, projectKey, key)
	var val string
	if err := row.Scan(&val); err == sql.ErrNoRows {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("get meta %s/%s: %w", projectKey, key, err)
	}
	return val, nil
}

// SetMeta sets a metadata value for a project key+name (upsert via delete-then-insert).
func (s *Store) SetMeta(projectKey, key, value string) error {
	if _, err := s.db.Exec(`DELETE FROM cache_meta WHERE project_key = ? AND meta_key = ?`, projectKey, key); err != nil {
		return fmt.Errorf("delete meta %s/%s: %w", projectKey, key, err)
	}
	if _, err := s.db.Exec(`INSERT INTO cache_meta (project_key, meta_key, value) VALUES (?, ?, ?)`, projectKey, key, value); err != nil {
		return fmt.Errorf("insert meta %s/%s: %w", projectKey, key, err)
	}
	return nil
}

// ProjectCount returns the number of vulnerabilities stored for a project.
func (s *Store) ProjectCount(ctx context.Context, projectKey string) (int, error) {
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE project_key = ?`, projectKey)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("project count: %w", err)
	}
	return count, nil
}

// TotalCount returns the total number of vulnerabilities across all projects.
func (s *Store) TotalCount(ctx context.Context) (int, error) {
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM vulnerabilities`)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("total count: %w", err)
	}
	return count, nil
}
