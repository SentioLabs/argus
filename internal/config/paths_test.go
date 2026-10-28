package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDir_XDG(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)

	got, err := Dir()
	if err != nil {
		t.Fatalf("Dir() error = %v", err)
	}
	if want := filepath.Join(xdg, "argus"); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}
}

func TestDir_DefaultsToDotConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	got, err := Dir()
	if err != nil {
		t.Fatalf("Dir() error = %v", err)
	}
	if want := filepath.Join(home, ".config", "argus"); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}
}

func TestFindConfigFile_NoneExist(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Chdir(t.TempDir())

	got, err := FindConfigFile()
	if err != nil {
		t.Fatalf("FindConfigFile() error = %v", err)
	}
	if got != "" {
		t.Errorf("FindConfigFile() = %q, want empty", got)
	}
}

func TestFindConfigFile_XDG(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Chdir(t.TempDir())

	want := filepath.Join(xdg, "argus", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(want), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte("defaults: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := FindConfigFile()
	if err != nil {
		t.Fatalf("FindConfigFile() error = %v", err)
	}
	if got != want {
		t.Errorf("FindConfigFile() = %q, want %q", got, want)
	}
}

func TestFindConfigFile_LocalWinsOverGlobal(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Chdir(t.TempDir())

	global := filepath.Join(xdg, "argus", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(global), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{global, LocalFile} {
		if err := os.WriteFile(p, []byte("defaults: {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := FindConfigFile()
	if err != nil {
		t.Fatalf("FindConfigFile() error = %v", err)
	}
	if got != LocalFile {
		t.Errorf("FindConfigFile() = %q, want %q", got, LocalFile)
	}
}
