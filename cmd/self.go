package cmd

import (
	"github.com/sentiolabs/selfupdate-go"
	"github.com/sentiolabs/selfupdate-go/cobracmd"

	"github.com/sentiolabs/argus/internal/update"
)

// selfCmd is the go-selfupdate command tree: `argus self update` and
// `argus self channel`. The -c shorthand for --check is free on the root
// command (--config has no shorthand, -v is verbose).
var selfCmd = cobracmd.New(newSelfUpdater(), cobracmd.WithCheckShorthand("c"))

func init() {
	rootCmd.AddCommand(selfCmd)
}

// newSelfUpdater wires GitHub releases of sentiolabs/argus to the zero-value
// ArchiveInstaller, whose defaults match .goreleaser.yaml: the archive is
// argus_<version>_<os>_<arch>.tar.gz and checksums.txt is sha256. Version is
// the ldflags value from version.go: "0.7.0", "0.7.0-rc.1", or "dev". No
// hooks: argus has no daemon to stop and nothing to back up around the swap.
func newSelfUpdater() *selfupdate.Updater {
	return &selfupdate.Updater{
		Name:      "argus",
		Version:   Version,
		Source:    &selfupdate.GitHubSource{Owner: "sentiolabs", Repo: "argus"},
		Store:     channelStore(),
		Installer: &selfupdate.ArchiveInstaller{},
	}
}

// channelStore returns a FileStore at update.DefaultPath(). When the user
// config directory cannot be resolved (no HOME or XDG_CONFIG_HOME), Path is
// left empty: `self update` reads stable and `self channel <name>` fails
// with update.ErrNoPath instead of pretending to persist.
func channelStore() selfupdate.Store {
	path, err := update.DefaultPath()
	if err != nil {
		return update.FileStore{}
	}
	return update.FileStore{Path: path}
}
