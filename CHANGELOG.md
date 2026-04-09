# Changelog

## [0.6.0](https://github.com/SentioLabs/argus/compare/v0.5.0...v0.6.0) (2026-04-08)


### Features

* add prerelease workflow for rc/beta/alpha tags ([5faefae](https://github.com/SentioLabs/argus/commit/5faefaef14a7d6675a56c144e366f574f8483d75))
* swap stoolap for SQLite (modernc.org/sqlite) with FTS5 ([5fc9b09](https://github.com/SentioLabs/argus/commit/5fc9b09b7d253c66b08af33db78cab0f0778b3b9))


### Bug Fixes

* drop linux/arm64 from release builds ([ff5c631](https://github.com/SentioLabs/argus/commit/ff5c6313eb2f974534102785c421d7fe8cb0a3a5))
* install libstoolap.so to /usr/local/lib for arm64 builds ([7090b6c](https://github.com/SentioLabs/argus/commit/7090b6c77fe298f663893831508760d63f307300))
* replace goreleaser split/merge with native go build ([21844d8](https://github.com/SentioLabs/argus/commit/21844d8751d03f56476f3df497483945921c09d8))
* set CGO_LDFLAGS and LD_LIBRARY_PATH for stoolap arm64 builds ([9bf8148](https://github.com/SentioLabs/argus/commit/9bf81487cf3854432acc98cb2cdf4ef2cf10dd92))


### Refactoring

* simplify to goreleaser with --single-target per runner ([fbdcbfb](https://github.com/SentioLabs/argus/commit/fbdcbfb49f7f8fcd3edb04680c650dd3673ef2cb))

## [0.5.0](https://github.com/SentioLabs/argus/compare/v0.4.0...v0.5.0) (2026-04-08)


### Features

* add linux/arm64 builds by compiling stoolap from source in CI ([a041dde](https://github.com/SentioLabs/argus/commit/a041ddef9de2140f8b1e4d54a093406b41d664a7))


### Bug Fixes

* enable CGo for stoolap-go and limit goreleaser to linux/amd64 ([7110ee8](https://github.com/SentioLabs/argus/commit/7110ee8b543d78be4478922f45830573f14db1ee))
* use goreleaser split/merge pattern for native CGo builds ([505c19b](https://github.com/SentioLabs/argus/commit/505c19b5d22e7adaec6e928bf76b91b561cbe09b))
* use matrix runners for native CGo builds across platforms ([9a3a54c](https://github.com/SentioLabs/argus/commit/9a3a54c97ee58f340031ba75cf73cea0a58e49d9))

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
