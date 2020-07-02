commit: format lint test

format:
	@goimports -w $(find . -type f -name '*.go')

GOLANGCI_VERSION=v1.23.8
lint:
	@docker run --rm -t --user $$(id -u):$$(id -g) -v $$(go env GOCACHE):/cache/go -e GOCACHE=/cache/go -e GOLANGCI_LINT_CACHE=/cache/go -v $$(go env GOPATH)/pkg:/go/pkg -v ${PWD}:/app -w /app golangci/golangci-lint:${GOLANGCI_VERSION}-alpine golangci-lint run ./...

test:
	@go test ./...

tools: format-tools lint-tools

format-tools:
	@go get -u golang.org/x/tools/cmd/goimports

check-version:
	./scripts/check-version/check-version.sh
