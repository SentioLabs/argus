.PHONY: help build run test lint clean release release-dry-run changelog

BINARY_NAME := argus
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w \
	-X github.com/sentiolabs/argus/cmd.Version=$(VERSION) \
	-X github.com/sentiolabs/argus/cmd.Commit=$(COMMIT) \
	-X github.com/sentiolabs/argus/cmd.BuildDate=$(BUILD_DATE)

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'

## build: Build the argus binary
build:
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) .

## run: Run argus sync in dry-run mode
run: build
	./$(BINARY_NAME) sync --dry-run

## test: Run all tests
test:
	go test ./...

## test-verbose: Run all tests with verbose output
test-verbose:
	go test -v ./...

## test-coverage: Run tests with coverage report
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run golangci-lint
lint:
	golangci-lint run

## lint-fix: Run golangci-lint with auto-fix
lint-fix:
	golangci-lint run --fix

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

## verify: Validate config and check environment
verify: build
	./$(BINARY_NAME) config validate

## version: Show version information
version: build
	./$(BINARY_NAME) version

## changelog: Generate changelog for unreleased changes
changelog:
	@git-cliff --unreleased

## release-dry-run: Preview what the next release would look like
release-dry-run:
	@echo "Current version: $$(git describe --tags --abbrev=0 2>/dev/null || echo 'none')"
	@echo "Next version: $$(git-cliff --bumped-version 2>/dev/null || echo 'v0.0.1')"
	@echo ""
	@echo "Changelog preview:"
	@git-cliff --unreleased --strip header

## release: Create a new release (auto-bump version based on commits)
release:
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "Error: Working directory not clean. Commit or stash changes first."; \
		exit 1; \
	fi
	@NEXT_VERSION=$$(git-cliff --bumped-version 2>/dev/null || echo "v0.0.1"); \
	echo "Creating release $$NEXT_VERSION..."; \
	git-cliff --tag $$NEXT_VERSION -o CHANGELOG.md; \
	git add CHANGELOG.md; \
	git commit -m "chore(release): $$NEXT_VERSION"; \
	git tag -a $$NEXT_VERSION -m "Release $$NEXT_VERSION"; \
	echo ""; \
	echo "Release $$NEXT_VERSION created!"; \
	echo "Run 'git push && git push --tags' to publish"
