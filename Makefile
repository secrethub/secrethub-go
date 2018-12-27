commit: format lint test

format:
	@goimports -w $(find . -type f -name '*.go')

lint:
	@gometalinter.v2 --config=metalinter.config ./...

test:
	@go test ./...
