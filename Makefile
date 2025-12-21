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
	golangci-lint run --fix ./...

.PHONY: cover
cover: ## Runs go test with coverage
	@echo "==> $@"
	@go test -race -coverprofile=coverage.txt -tags "$(BUILDTAGS)" ./...
	@sort -o coverage.txt coverage.txt

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
