# Changelog

## [0.4.0](https://github.com/SentioLabs/argus/compare/v0.3.1...v0.4.0) (2026-04-08)


### Features

* add --repo flag to search command for case-insensitive repo filtering ([992f976](https://github.com/SentioLabs/argus/commit/992f97679ba763573e4927d3e29948c5cbab852f))
* add cache command with refresh, status, and clear subcommands ([d78591f](https://github.com/SentioLabs/argus/commit/d78591fc84f22eeeb5ef099b5ab5d3151a719ae5))
* add cache, search, and show commands with Stoolap-backed persistent cache ([994387c](https://github.com/SentioLabs/argus/commit/994387cbe29a604663b26a8a01a27e9df3a30ee8))
* add darwin builds and curl-based install script ([1f96ff7](https://github.com/SentioLabs/argus/commit/1f96ff78d3b2fce4caf0f947537bd9c0278dd71a))
* add dedicated search output format with both ID and CVE columns ([ad3703e](https://github.com/SentioLabs/argus/commit/ad3703e93c45849a2262448945dad0f33f79071e))
* add search command for querying cached vulnerabilities ([6edcbeb](https://github.com/SentioLabs/argus/commit/6edcbeb4a0ef20ea9d83b2886bad7412c7910b73))
* add show command for looking up vulnerabilities by ID ([2b7d4d0](https://github.com/SentioLabs/argus/commit/2b7d4d0df409ca91c022068bd7a26e0efed366eb))
* **cache:** add ProjectKeyFromPath, DBPath, and Manager stub ([fd658d5](https://github.com/SentioLabs/argus/commit/fd658d53ff84d9815d4d527d23ed73240820441b))
* implement Stoolap cache store for vulnerability persistence ([47c00f7](https://github.com/SentioLabs/argus/commit/47c00f7dcbff4cb47c6023999b365c8d66b67fd8))
* **output:** add VulnDetail type with FormatDetail and PrintDetail helpers ([e97ac9c](https://github.com/SentioLabs/argus/commit/e97ac9c2de7bb563509d526e1f282dca1426c70e))
* **search:** add query parser for cache/search feature ([976db7d](https://github.com/SentioLabs/argus/commit/976db7dde3593654f6af7ea36f03b90b5fae38ad))
* wire up cache Manager with NewManager, IsValid, Refresh, and EnsureFresh ([215a1cc](https://github.com/SentioLabs/argus/commit/215a1cca9cd7c849dab1aa56e06bde678ccf7afc))


### Bug Fixes

* restore goreleaser config alongside release-please ([4e27afb](https://github.com/SentioLabs/argus/commit/4e27afb3128502a1717f21523a151f454f9354a6))

## [0.3.1] - 2025-12-19

### Bug Fixes

- Use short commit hash in docker version output

## [0.3.0] - 2025-12-19

### Features

- Bake version info into binaries and docker images

## [0.2.2] - 2025-12-19

### Performance

- Use scratch image and native cross-compilation

## [0.2.1] - 2025-12-19

### Bug Fixes

- Add arm64 docker image support
- Updating gitignore

## [0.2.0] - 2025-12-19

### Bug Fixes

- Golangci-lint v2 schema and goimports local-prefix

### Features

- Add verbose filter logging to diagnose excluded vulnerabilities

### Miscellaneous

- Add golangci-lint config and fix all lint errors

### Refactor

- Move priority_map and sprint_threshold under jira config
- Rename min_severity to severity_threshold and embed example config

## [0.1.3] - 2025-12-18

### Bug Fixes

- Switch to GitHub-hosted runners

## [0.1.2] - 2025-12-18

### Bug Fixes

- Changing runners to 2cpu

## [0.1.1] - 2025-12-18

### Bug Fixes

- Updating to use blacksmith runner for releases
- Updating ghcr visibility to match repo

## [0.1.0] - 2025-12-18

### Bug Fixes

- Handle Jira Cloud email privacy in user lookup

### Features

- Add severity normalization and namespaced Jira labels
- Add Jira user alias map for readable assignee config
- Replace user alias map with direct email assignees
- Add Jira ID column to dry-run output for assignee validation
- Adding automated releases using goreleaser
