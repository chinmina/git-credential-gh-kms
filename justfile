binary := "git-credential-gh-kms"

default:
    @just --list --justfile {{justfile()}}

build:
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/{{binary}} .

vet:
    go vet ./...

fmt:
    gofmt -w .

fmt-check:
    #!/usr/bin/env bash
    set -euo pipefail
    unformatted=$(gofmt -l .)
    test -z "$unformatted" || { echo "$unformatted"; exit 1; }

lint:
    golangci-lint run ./...

test:
    go test -race ./...

check: fmt-check vet lint test
