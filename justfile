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

# Build Linux binaries of the helper and the unshipped test-support tool for the system tests.
system-artifact-build:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p bin/linux
    export CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)"
    go build -trimpath -o bin/linux/{{binary}} .
    go build -trimpath -o bin/linux/test-support ./cmd/test-support

# Run the containerized system tests against a fresh Local KMS instance.
# Leaves Compose resources running for inspection; use system-cleanup to remove them.
system-run: system-artifact-build
    docker compose -f test/system/compose.yaml --project-name gh-kms-system up --abort-on-container-exit --exit-code-from bats

# Remove containers, networks, and volumes created by system-run / test-system.
system-cleanup:
    docker compose -f test/system/compose.yaml --project-name gh-kms-system down --volumes --remove-orphans

# Run the system tests and always clean up Compose resources afterwards.
test-system:
    #!/usr/bin/env bash
    set -euo pipefail
    trap 'just system-cleanup' EXIT
    just system-run
