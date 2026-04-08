package cache

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultTTL = 24 * time.Hour

// Store is defined in store.go
type Store struct{}

// Manager holds the configuration for cache operations.
type Manager struct {
	projectKey string
	dbPath     string
	ttl        time.Duration
	store      *Store // Will be nil until store.go is created
	verbose    bool
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
