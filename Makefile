
.PHONY: init lint test bench

GO111MODULE=on
LINT_OPT := -E gofmt \
            -E golint \
			-E gosec \
			-E misspell \
			-E whitespace \
			-E stylecheck

init:
	go get -v ./...
	go get -v github.com/stretchr/testify

lint:
	@type golangci-lint > /dev/null || go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
	golangci-lint run $(LINT_OPT) ./...

test:
	go test -covermode atomic -coverprofile=coverage.out -count=1 ./...

send-coverage:
	@type goveralls > /dev/null || go get github.com/mattn/goveralls
	goveralls -coverprofile=coverage.out -service=github

bench:
	go test ./... -run=^_ -bench . -benchmem | grep -e '^Bench'
