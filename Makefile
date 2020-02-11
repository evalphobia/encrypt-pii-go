
.PHONY: init lint test bench

GO111MODULE=on

init:
	go get -v ./...
	go get -v github.com/stretchr/testify

lint:
	@type golangci-lint > /dev/null || go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
	golangci-lint run ./...

test:
	go test ./... -count=1

bench:
	go test ./... -run=^_ -bench . -benchmem | grep -e '^Bench'
