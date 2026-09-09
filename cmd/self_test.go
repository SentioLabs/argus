package cmd

import (
	"bytes"
	"testing"

	"github.com/sentiolabs/selfupdate-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sentiolabs/argus/internal/update"
)

func TestNewSelfUpdater(t *testing.T) {
	u := newSelfUpdater()
	assert.Equal(t, "argus", u.Name)
	assert.Equal(t, Version, u.Version)

	src, ok := u.Source.(*selfupdate.GitHubSource)
	require.True(t, ok, "Source should be *selfupdate.GitHubSource, got %T", u.Source)
	assert.Equal(t, "sentiolabs", src.Owner)
	assert.Equal(t, "argus", src.Repo)

	assert.IsType(t, &selfupdate.ArchiveInstaller{}, u.Installer)
	assert.IsType(t, update.FileStore{}, u.Store)
	assert.Nil(t, u.PreInstall, "argus has no daemon to stop; no PreInstall hook")
	assert.Nil(t, u.PostInstall, "argus has no daemon to start; no PostInstall hook")
}

func TestChannelStore_UsesDefaultPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	s, ok := channelStore().(update.FileStore)
	require.True(t, ok, "channelStore should return update.FileStore, got %T", channelStore())
	want, err := update.DefaultPath()
	require.NoError(t, err)
	assert.Equal(t, want, s.Path)
	assert.NotEmpty(t, s.Path)
}

func TestSelfHelpListsSubcommands(t *testing.T) {
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"self", "--help"})
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})

	require.NoError(t, rootCmd.Execute())
	help := out.String()
	assert.Contains(t, help, "update")
	assert.Contains(t, help, "channel")
	assert.Contains(t, help, "Manage the argus CLI itself")
}

func TestSelfUpdateHasCheckShorthand(t *testing.T) {
	updateCmd, _, err := rootCmd.Find([]string{"self", "update"})
	require.NoError(t, err)
	f := updateCmd.Flags().Lookup("check")
	require.NotNil(t, f, "self update should define --check")
	assert.Equal(t, "c", f.Shorthand)
}
