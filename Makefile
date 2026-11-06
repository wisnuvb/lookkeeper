.PHONY: build test test-integration lint vuln fmt check-fmt ci clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/wisnuvb/lockkeeper/internal/cli.Version=$(VERSION)
GOBIN   ?= $(shell go env GOPATH)/bin

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o lockkeeper ./cmd/lockkeeper

test:
	go test -race -count=1 ./...

# Needs Docker. Starts throwaway Postgres containers on loopback only.
# LK_TEST_PG_IMAGE selects the server version, e.g. postgres:14-alpine.
test-integration:
	LK_TEST_REQUIRE_DOCKER=1 go test -race -tags integration -count=1 -timeout 15m ./...

lint:
	go vet ./... && go vet -tags integration ./...
	$(GOBIN)/staticcheck ./...
	$(GOBIN)/staticcheck -tags integration ./...

vuln:
	$(GOBIN)/govulncheck ./...

fmt:
	gofmt -w cmd internal

check-fmt:
	@test -z "$$(gofmt -l cmd internal)" || (echo "gofmt needed:"; gofmt -l cmd internal; exit 1)

ci: check-fmt lint vuln test

clean:
	rm -f lockkeeper
