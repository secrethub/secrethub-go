commit: format lint test

format:
	@goimports -w $(find . -type f -name '*.go')

lint:
	@gometalinter.v2 --config=metalinter.config ./...

test:
	@go test ./...

tools: format-tools lint-tools

format-tools:
	@go get -u golang.org/x/tools/cmd/goimports

lint-tools:
	@go get -u gopkg.in/alecthomas/gometalinter.v2
	@gometalinter.v2 --install
