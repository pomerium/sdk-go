# Setup name variables for the package/tool
PREFIX?=$(shell pwd)

NAME := sdk
PKG := github.com/pomerium/$(NAME)

BUILDDIR := ${PREFIX}/dist
BINDIR := ${PREFIX}/bin


.PHONY: all
all: clean cover lint build

.PHONY: clean
clean: ## Cleanup any build binaries or packages.
	@echo "==> $@"
	$(RM) -r $(BINDIR)
	$(RM) coverage.txt

.PHONY: build
build: ## Builds dynamic executables and/or packages.
	@echo "==> $@"
	@go build -o $(BINDIR)/$(NAME)

.PHONY: lint
lint:
	@echo "==> $@"
	@VERSION=$$(go run github.com/mikefarah/yq/v4@v4.34.1 '.jobs.lint.steps[] | select(.uses == "golangci/golangci-lint-action*") | .with.version' .github/workflows/lint.yaml) && \
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$$VERSION run ./...

.PHONY: cover
cover: ## Runs go test with coverage
	@echo "==> $@"
	@go test -race -coverprofile=coverage.txt -tags "$(BUILDTAGS)" ./...
	@sort -o coverage.txt coverage.txt

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
