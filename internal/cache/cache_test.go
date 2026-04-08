package cache

import (
	"os"
	"path/filepath"
	"strings"
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
	// Ensure XDG_CACHE_HOME is not set
	orig, wasSet := os.LookupEnv("XDG_CACHE_HOME")
	if wasSet {
		require.NoError(t, os.Unsetenv("XDG_CACHE_HOME"))
		t.Cleanup(func() { os.Setenv("XDG_CACHE_HOME", orig) })
	}

	got := DBPath()

	// Should end with argus/vulns.db
	assert.True(t, strings.HasSuffix(got, filepath.Join("argus", "vulns.db")),
		"expected path to end with argus/vulns.db, got: %s", got)

	// Should contain .cache somewhere in the path
	assert.Contains(t, got, ".cache",
		"expected path to contain .cache, got: %s", got)
}

func TestDBPath_XDG(t *testing.T) {
	tmpDir := t.TempDir()

	orig, wasSet := os.LookupEnv("XDG_CACHE_HOME")
	require.NoError(t, os.Setenv("XDG_CACHE_HOME", tmpDir))
	t.Cleanup(func() {
		if wasSet {
			os.Setenv("XDG_CACHE_HOME", orig)
		} else {
			os.Unsetenv("XDG_CACHE_HOME")
		}
	})

	got := DBPath()
	expected := filepath.Join(tmpDir, "argus", "vulns.db")
	assert.Equal(t, expected, got)
}
