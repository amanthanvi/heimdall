SHELL := /bin/bash

BINARY := heimdall
DIST_DIR := dist
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X github.com/amanthanvi/heimdall/internal/version.Version=$(VERSION) \
	-X github.com/amanthanvi/heimdall/internal/version.Commit=$(COMMIT) \
	-X github.com/amanthanvi/heimdall/internal/version.BuildTime=$(BUILD_TIME)

.PHONY: build build-nofido2 test lint generate completions man

build:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=1 go build -tags fido2 -trimpath -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY) ./cmd/heimdall

build-nofido2:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 go build -tags nofido2 -trimpath -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY)-nofido2 ./cmd/heimdall

test:
	go test -race ./...

lint:
	golangci-lint run ./...

generate:
	go generate ./...

completions:
	@mkdir -p $(DIST_DIR)/completions
	go run ./cmd/heimdall completion bash > $(DIST_DIR)/completions/heimdall.bash
	go run ./cmd/heimdall completion zsh > $(DIST_DIR)/completions/_heimdall
	go run ./cmd/heimdall completion fish > $(DIST_DIR)/completions/heimdall.fish

man:
	@mkdir -p $(DIST_DIR)/man
	go run ./cmd/heimdall-man -out $(DIST_DIR)/man
