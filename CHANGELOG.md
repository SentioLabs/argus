# Changelog

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


