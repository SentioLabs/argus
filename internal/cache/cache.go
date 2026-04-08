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

const DefaultTTL = 24 * time.Hour

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
	store, err := Open("file://" + dbPath)
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
func (m *Manager) ProjectKey() string { return m.projectKey }

// DBPathValue returns the database file path.
func (m *Manager) DBPathValue() string { return m.dbPath }

// Store returns the underlying store for direct queries.
func (m *Manager) Store() *Store { return m.store }

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
// Respects $XDG_CACHE_HOME, defaults to ~/.cache/argus/vulns.db.
// Falls back to os.TempDir()/.cache/argus/vulns.db if the home dir cannot be determined.
func DBPath() string {
	var base string

	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		base = xdg
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			base = filepath.Join(os.TempDir(), ".cache")
		} else {
			base = filepath.Join(home, ".cache")
		}
	}

	return filepath.Join(base, "argus", "vulns.db")
}
