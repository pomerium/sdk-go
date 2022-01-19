# Setup name variables for the package/tool
PREFIX?=$(shell pwd)

NAME := sdk
PKG := github.com/pomerium/$(NAME)

BUILDDIR := ${PREFIX}/dist
BINDIR := ${PREFIX}/bin
GOLANGCI_VERSION = v1.43.0


.PHONY: all
all: clean cover lint build

.PHONY: clean
clean: ## Cleanup any build binaries or packages.
	@echo "==> $@"
	$(RM) -r $(BINDIR)
	$(RM) coverage.txt

.PHONY: build-deps
build-deps: ## Install build dependencies
	@echo "==> $@"
	@cd /tmp; GO111MODULE=on go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_VERSION}

.PHONY: build
build: ## Builds dynamic executables and/or packages.
	@echo "==> $@"
	@go build -o $(BINDIR)/$(NAME)

.PHONY: lint
lint: build-deps ## Verifies `golint` passes.
	@echo "==> $@"
	@golangci-lint run ./...

.PHONY: cover
cover: ## Runs go test with coverage
	@echo "==> $@"
	@go test -race -coverprofile=coverage.txt -tags "$(BUILDTAGS)" ./...
	@sort -o coverage.txt coverage.txt

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
