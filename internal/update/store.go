// Package update persists the self-update release channel for the argus CLI.
package update

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentiolabs/selfupdate-go"
)

// ErrNoPath is returned by SetChannel when Path is empty.
var ErrNoPath = errors.New("update: no channel file path (is HOME set?)")

const (
	dirMode  = 0o700
	fileMode = 0o600
)

// FileStore keeps the channel as the trimmed contents of a single file.
// A missing file, or an empty Path, reads as the empty channel, which the
// updater treats as stable. Writes need a Path.
type FileStore struct{ Path string }

// DefaultPath returns <os.UserConfigDir()>/argus/update-channel.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "argus", "update-channel"), nil
}

// Channel reads Path. An empty Path or a missing file yields "" and a nil
// error. Any other read error is wrapped and returned.
func (s FileStore) Channel() (selfupdate.Channel, error) {
	if s.Path == "" {
		return "", nil
	}
	data, err := os.ReadFile(s.Path) //nolint:gosec // Path comes from os.UserConfigDir, not user input
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read update channel %s: %w", s.Path, err)
	}
	return selfupdate.Channel(strings.TrimSpace(string(data))), nil
}

// SetChannel returns ErrNoPath when Path is empty. Otherwise it creates the
// parent directory with mode 0o700 when missing and writes c to Path with
// mode 0o600.
func (s FileStore) SetChannel(c selfupdate.Channel) error {
	if s.Path == "" {
		return ErrNoPath
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), dirMode); err != nil {
		return fmt.Errorf("create update channel dir: %w", err)
	}
	if err := os.WriteFile(s.Path, []byte(string(c)+"\n"), fileMode); err != nil {
		return fmt.Errorf("write update channel %s: %w", s.Path, err)
	}
	return nil
}
