# Makefile for go-auth-sdk
# Standard commands for building, testing, and maintaining the SDK

.PHONY: help test test-coverage build lint format vet security-check clean install tidy

# Default target
help:
	@echo "go-auth-sdk Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  test            - Run all unit tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  clean          - Clean build artifacts"

# Run all unit tests
test:
	go test -v -race ./...

# Run tests with coverage
test-coverage:
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Clean build artifacts
clean:
	rm -f coverage.out coverage.html