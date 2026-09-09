package update_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentiolabs/selfupdate-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sentiolabs/argus/internal/update"
)

// --- Contract assertions ---
// These verify the design spec. Do NOT modify without updating the approved plan.

// FileStore satisfies selfupdate.Store.
var _ selfupdate.Store = update.FileStore{}

// --- Behavior tests ---

func TestFileStore_MissingFileReadsEmpty(t *testing.T) {
	s := update.FileStore{Path: filepath.Join(t.TempDir(), "update-channel")}
	ch, err := s.Channel()
	require.NoError(t, err)
	assert.Equal(t, selfupdate.Channel(""), ch)
}

func TestFileStore_RoundTrip(t *testing.T) {
	s := update.FileStore{Path: filepath.Join(t.TempDir(), "nested", "argus", "update-channel")}
	require.NoError(t, s.SetChannel(selfupdate.ChannelRC))
	ch, err := s.Channel()
	require.NoError(t, err)
	assert.Equal(t, selfupdate.ChannelRC, ch)
}

func TestFileStore_SetChannelCreatesDirAndModes(t *testing.T) {
	s := update.FileStore{Path: filepath.Join(t.TempDir(), "argus", "update-channel")}
	require.NoError(t, s.SetChannel(selfupdate.ChannelStable))
	info, err := os.Stat(s.Path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(filepath.Dir(s.Path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
}

func TestFileStore_TrimsWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update-channel")
	require.NoError(t, os.WriteFile(path, []byte("  rc \n"), 0o600))
	ch, err := update.FileStore{Path: path}.Channel()
	require.NoError(t, err)
	assert.Equal(t, selfupdate.ChannelRC, ch)
}

func TestFileStore_EmptyPath(t *testing.T) {
	s := update.FileStore{}
	ch, err := s.Channel()
	require.NoError(t, err)
	assert.Equal(t, selfupdate.Channel(""), ch)
	assert.ErrorIs(t, s.SetChannel(selfupdate.ChannelRC), update.ErrNoPath)
}

func TestFileStore_ReadErrorIsWrapped(t *testing.T) {
	// A directory at Path makes ReadFile fail with something other than ErrNotExist.
	s := update.FileStore{Path: t.TempDir()}
	_, err := s.Channel()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read update channel")
}

func TestDefaultPath(t *testing.T) {
	p, err := update.DefaultPath()
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(p, filepath.Join("argus", "update-channel")), p)
	assert.True(t, filepath.IsAbs(p), p)
}
