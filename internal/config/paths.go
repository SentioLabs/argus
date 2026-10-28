package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Dir returns the argus config directory.
// Respects $XDG_CONFIG_HOME, defaults to ~/.config/argus on every platform.
// os.UserConfigDir is deliberately avoided: on macOS it returns
// ~/Library/Application Support, and argus keeps dotfiles in ~/.config there too.
func Dir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "argus"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}

	return filepath.Join(home, ".config", "argus"), nil
}

// LocalFile is the per-project config file, read from the working directory.
const LocalFile = ".argus.yaml"

// File returns the global config file path, <Dir()>/config.yaml.
func File() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// candidatePaths returns the config file locations to search, highest
// precedence first. The first one that exists wins: a project-local
// .argus.yaml overrides the global config.
func candidatePaths() []string {
	paths := []string{LocalFile}
	// Without a resolvable home dir the local file is still usable.
	if global, err := File(); err == nil {
		paths = append(paths, global)
	}
	return paths
}

// FindConfigFile returns the first existing path from candidatePaths.
// It returns "" and a nil error when no config file exists, so callers can
// fall back to environment variables alone.
func FindConfigFile() (string, error) {
	for _, p := range candidatePaths() {
		_, err := os.Stat(p)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("stat config file %s: %w", p, err)
		}
	}

	return "", nil
}
