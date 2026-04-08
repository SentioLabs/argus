package cache

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/sentiolabs/argus/internal/provider"
	"github.com/sentiolabs/argus/internal/search"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database connection for vulnerability caching.
type Store struct {
	db *sql.DB
}

// SearchResult is a vulnerability with search metadata.
type SearchResult struct {
	provider.Vulnerability
	Relevance  float64 // FTS5 rank (lower = more relevant); 0 for non-FTS searches
	ProjectKey string  // which project this result came from
}

// Open opens (or creates) the SQLite database at the given DSN.
// Use ":memory:" for ephemeral in-memory stores (tests) or a file path for persistent storage.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// Enable WAL mode for better concurrent read performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	s := &Store{db: db}

	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// initSchema creates tables, indexes, and the FTS5 virtual table.
func (s *Store) initSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			project_key TEXT NOT NULL,
			id TEXT NOT NULL,
			cve TEXT,
			severity TEXT NOT NULL,
			cvss REAL,
			package TEXT NOT NULL,
			version TEXT,
			fixed_version TEXT,
			repository TEXT NOT NULL,
			description TEXT,
			url TEXT,
			discovered_at TEXT,
			provider TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_project ON vulnerabilities(project_key)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_id ON vulnerabilities(id)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_package ON vulnerabilities(package)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_provider ON vulnerabilities(provider)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_repository ON vulnerabilities(repository)`,
		// FTS5 virtual table for full-text search across key fields
		`CREATE VIRTUAL TABLE IF NOT EXISTS vuln_fts USING fts5(content)`,
		`CREATE TABLE IF NOT EXISTS cache_meta (
			project_key TEXT NOT NULL,
			meta_key TEXT NOT NULL,
			value TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_meta_pk ON cache_meta(project_key, meta_key)`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("schema exec: %w\nSQL: %s", err, stmt)
		}
	}

	return nil
}

// WriteVulnerabilities replaces all vulnerabilities for the given project+providers
// with the provided slice, then updates metadata.
func (s *Store) WriteVulnerabilities(ctx context.Context, projectKey string, vulns []provider.Vulnerability, providers []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Delete existing FTS entries for rows we're about to remove
	for _, p := range providers {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM vuln_fts WHERE rowid IN (
				SELECT rowid FROM vulnerabilities WHERE project_key = ? AND provider = ?
			)`, projectKey, p); err != nil {
			return fmt.Errorf("delete fts for provider %s: %w", p, err)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM vulnerabilities WHERE project_key = ? AND provider = ?`,
			projectKey, p); err != nil {
			return fmt.Errorf("delete vulns for provider %s: %w", p, err)
		}
	}

	// Insert new rows + FTS entries
	insertVuln, err := tx.PrepareContext(ctx, `
		INSERT INTO vulnerabilities
			(project_key, id, cve, severity, cvss, package, version, fixed_version,
			 repository, description, url, discovered_at, provider)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer insertVuln.Close()

	insertFTS, err := tx.PrepareContext(ctx, `INSERT INTO vuln_fts (rowid, content) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare fts insert: %w", err)
	}
	defer insertFTS.Close()

	for _, v := range vulns {
		var discoveredAt *string
		if !v.DiscoveredAt.IsZero() {
			s := v.DiscoveredAt.Format(time.RFC3339)
			discoveredAt = &s
		}

		result, err := insertVuln.ExecContext(ctx,
			projectKey, v.ID, v.CVE, v.Severity, v.CVSS, v.Package, v.Version, v.FixedVersion,
			v.Repository, v.Description, v.URL, discoveredAt, v.Provider)
		if err != nil {
			return fmt.Errorf("insert vuln %s: %w", v.ID, err)
		}

		rowID, _ := result.LastInsertId()

		// Build FTS content: concatenate searchable fields
		ftsContent := strings.Join([]string{v.ID, v.CVE, v.Package, v.Repository, v.Description}, " ")
		if _, err := insertFTS.ExecContext(ctx, rowID, ftsContent); err != nil {
			return fmt.Errorf("insert fts for %s: %w", v.ID, err)
		}
	}

	// Update metadata: delete-then-insert
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM cache_meta WHERE project_key = ? AND meta_key IN ('fetched_at', 'providers', 'count')`,
		projectKey); err != nil {
		return fmt.Errorf("delete old meta: %w", err)
	}

	fetchedAt := time.Now().UTC().Format(time.RFC3339)
	providerList := strings.Join(providers, ",")
	count := len(vulns)

	for _, row := range [][2]string{
		{"fetched_at", fetchedAt},
		{"providers", providerList},
		{"count", fmt.Sprintf("%d", count)},
	} {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO cache_meta (project_key, meta_key, value) VALUES (?, ?, ?)`,
			projectKey, row[0], row[1]); err != nil {
			return fmt.Errorf("insert meta %s: %w", row[0], err)
		}
	}

	return tx.Commit()
}

// globToLike converts glob-style wildcards to SQL LIKE patterns.
func globToLike(s string) string {
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
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
		where = append(where, "v.project_key = ?")
		args = append(args, projectKey)
	}

	// Field filters
	for field, value := range q.Filters {
		switch field {
		case "severity", "provider":
			where = append(where, "v."+field+" = ?")
			args = append(args, value)
		case "package", "repository", "cve", "id":
			if strings.ContainsAny(value, "*?") {
				where = append(where, "LOWER(v."+field+") LIKE LOWER(?)")
				args = append(args, globToLike(value))
			} else {
				where = append(where, "LOWER(v."+field+") = LOWER(?)")
				args = append(args, value)
			}
		}
	}

	useFTS := q.SemanticText != ""

	if useFTS {
		// FTS5 search: join with FTS table, order by rank
		where = append(where, "f.content MATCH ?")
		args = append(args, ftsQuery(q.SemanticText))

		whereClause := ""
		if len(where) > 0 {
			whereClause = "WHERE " + strings.Join(where, " AND ")
		}

		querySQL := fmt.Sprintf(`
			SELECT v.project_key, v.id, v.cve, v.severity, v.cvss, v.package, v.version,
				   v.fixed_version, v.repository, v.description, v.url, v.discovered_at,
				   v.provider, f.rank
			FROM vuln_fts f
			JOIN vulnerabilities v ON v.rowid = f.rowid
			%s
			ORDER BY f.rank
			LIMIT ?`, whereClause)

		args = append(args, limit)
		return s.queryResults(ctx, querySQL, args, true)
	}

	// Non-FTS: field filters only, ordered by severity
	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	querySQL := fmt.Sprintf(`
		SELECT v.project_key, v.id, v.cve, v.severity, v.cvss, v.package, v.version,
			   v.fixed_version, v.repository, v.description, v.url, v.discovered_at,
			   v.provider
		FROM vulnerabilities v
		%s
		ORDER BY CASE v.severity
			WHEN 'critical' THEN 0
			WHEN 'high' THEN 1
			WHEN 'medium' THEN 2
			ELSE 3
		END ASC
		LIMIT ?`, whereClause)

	args = append(args, limit)
	return s.queryResults(ctx, querySQL, args, false)
}

// ftsQuery converts a bare search string into an FTS5 query.
// Each word becomes a prefix match token: "rails rack" -> "rails* OR rack*"
func ftsQuery(text string) string {
	words := strings.Fields(text)
	terms := make([]string, len(words))
	for i, w := range words {
		// Escape FTS5 special characters
		w = strings.ReplaceAll(w, `"`, `""`)
		terms[i] = `"` + w + `"*`
	}
	return strings.Join(terms, " OR ")
}

func (s *Store) queryResults(ctx context.Context, query string, args []interface{}, hasRank bool) ([]SearchResult, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("search query: %w", err)
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var cve, version, fixedVersion, description, url, discoveredAtStr sql.NullString
		var cvss sql.NullFloat64

		if hasRank {
			err = rows.Scan(
				&r.ProjectKey, &r.ID, &cve, &r.Severity, &cvss, &r.Package, &version, &fixedVersion,
				&r.Repository, &description, &url, &discoveredAtStr, &r.Provider, &r.Relevance)
		} else {
			err = rows.Scan(
				&r.ProjectKey, &r.ID, &cve, &r.Severity, &cvss, &r.Package, &version, &fixedVersion,
				&r.Repository, &description, &url, &discoveredAtStr, &r.Provider)
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
		if discoveredAtStr.Valid {
			if t, err := time.Parse(time.RFC3339, discoveredAtStr.String); err == nil {
				r.DiscoveredAt = t
			}
		}

		results = append(results, r)
	}

	return results, rows.Err()
}

// GetByID fetches a single vulnerability by ID or CVE, with optional project filter.
// Returns nil, nil if not found.
func (s *Store) GetByID(ctx context.Context, projectKey string, id string) (*provider.Vulnerability, error) {
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
		var cve, version, fixedVersion, description, url, discoveredAtStr sql.NullString
		var cvss sql.NullFloat64

		err := row.Scan(&pk, &v.ID, &cve, &v.Severity, &cvss, &v.Package, &version, &fixedVersion,
			&v.Repository, &description, &url, &discoveredAtStr, &v.Provider)
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
		if discoveredAtStr.Valid {
			if t, err := time.Parse(time.RFC3339, discoveredAtStr.String); err == nil {
				v.DiscoveredAt = t
			}
		}

		return &v, nil
	}

	return nil, nil
}

// Clear deletes all vulnerabilities (and metadata) for the given project.
// If projectKey is empty, deletes everything.
func (s *Store) Clear(ctx context.Context, projectKey string) error {
	if projectKey == "" {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM vuln_fts`); err != nil {
			return fmt.Errorf("clear fts: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM vulnerabilities`); err != nil {
			return fmt.Errorf("clear vulnerabilities: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM cache_meta`); err != nil {
			return fmt.Errorf("clear meta: %w", err)
		}
		return nil
	}

	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM vuln_fts WHERE rowid IN (
			SELECT rowid FROM vulnerabilities WHERE project_key = ?
		)`, projectKey); err != nil {
		return fmt.Errorf("clear fts for %s: %w", projectKey, err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM vulnerabilities WHERE project_key = ?`, projectKey); err != nil {
		return fmt.Errorf("clear vulns for %s: %w", projectKey, err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM cache_meta WHERE project_key = ?`, projectKey); err != nil {
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
