.PHONY: help build run test lint clean

BINARY_NAME := argus

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'

## build: Build the argus binary
build:
	go build -o $(BINARY_NAME) .

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
