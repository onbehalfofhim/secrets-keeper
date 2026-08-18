APP_NAME := secrets-keeper
CLI_NAME := secrets-cli

SERVER_DIR := ./cmd/server
CLI_DIR := ./cmd/secrets-cli

MIGRATIONS_DIR := ./migrations

VERSION ?= dev
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

BUILDINFO_PACKAGE := github.com/onbehalfofhim/secrets-keeper/internal/buildinfo

CLI_LDFLAGS := \
	-X $(BUILDINFO_PACKAGE).Version=$(VERSION) \
	-X $(BUILDINFO_PACKAGE).BuildDate=$(BUILD_DATE)

.PHONY: all \
	build run \
	cli-build \
	cli-build-linux \
	cli-build-linux-arm64 \
	cli-build-windows \
	cli-build-macos \
	cli-build-macos-amd64 \
	cli-build-all \
	cli-run \
	test test-race coverage \
	fmt vet lint check \
	proto \
	migrate-up migrate-down migrate-version \
	tidy clean 

# ------------------------------------------------------------
# Build
# ------------------------------------------------------------

all: build

build:
	go build -o bin/$(APP_NAME) $(SERVER_DIR)

cli-build:
	go build \
		-ldflags "$(CLI_LDFLAGS)" \
		-o bin/$(CLI_NAME) \
		$(CLI_DIR)

cli-build-linux:
	GOOS=linux GOARCH=amd64 \
	go build \
		-ldflags "$(CLI_LDFLAGS)" \
		-o bin/$(CLI_NAME)-linux-amd64 \
		$(CLI_DIR)

cli-build-linux-arm64:
	GOOS=linux GOARCH=arm64 \
	go build \
		-ldflags "$(CLI_LDFLAGS)" \
		-o bin/$(CLI_NAME)-linux-arm64 \
		$(CLI_DIR)

cli-build-windows:
	GOOS=windows GOARCH=amd64 \
	go build \
		-ldflags "$(CLI_LDFLAGS)" \
		-o bin/$(CLI_NAME)-windows-amd64.exe \
		$(CLI_DIR)

cli-build-macos:
	GOOS=darwin GOARCH=arm64 \
	go build \
		-ldflags "$(CLI_LDFLAGS)" \
		-o bin/$(CLI_NAME)-darwin-arm64 \
		$(CLI_DIR)

cli-build-macos-amd64:
	GOOS=darwin GOARCH=amd64 \
	go build \
		-ldflags "$(CLI_LDFLAGS)" \
		-o bin/$(CLI_NAME)-darwin-amd64 \
		$(CLI_DIR)

cli-build-all: \
	cli-build-linux \
	cli-build-linux-arm64 \
	cli-build-windows \
	cli-build-macos \
	cli-build-macos-amd64

# ------------------------------------------------------------
# Run
# ------------------------------------------------------------

run:
	go run $(SERVER_DIR)

cli-run:
	go run $(CLI_DIR)

# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------

test:
	go test ./...

test-race:
	go test -race ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

# ------------------------------------------------------------
# E2E / Integration scenarios
# ------------------------------------------------------------

scenarios:
	go run ./cmd/client

# ------------------------------------------------------------
# Code quality
# ------------------------------------------------------------

fmt:
	gofmt -w .

vet:
	go vet ./...

lint:
	go vet ./...
	go test ./...

check: fmt vet test-race

# ------------------------------------------------------------
# Protobuf
# ------------------------------------------------------------

proto:
	protoc \
		-I api/proto \
		--go_out=api/proto \
		--go_opt=paths=source_relative \
		--go_opt=default_api_level=API_OPAQUE \
		--go-grpc_out=api/proto \
		--go-grpc_opt=paths=source_relative \
		api/proto/*.proto

# ------------------------------------------------------------
# Database migrations
# DATABASE_URL must be provided through environment.
# ------------------------------------------------------------

migrate-up:
	migrate \
		-path $(MIGRATIONS_DIR) \
		-database "$$DATABASE_URL" \
		up

migrate-down:
	migrate \
		-path $(MIGRATIONS_DIR) \
		-database "$$DATABASE_URL" \
		down 1

migrate-version:
	migrate \
		-path $(MIGRATIONS_DIR) \
		-database "$$DATABASE_URL" \
		version

# ------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------

tidy:
	go mod tidy

# ------------------------------------------------------------
# Clean
# ------------------------------------------------------------

clean:
	rm -rf bin
	rm -f coverage.out