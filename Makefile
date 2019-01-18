all: test

.PHONY: fmt
fmt:
	@gofmt -s -l -w *.go

.PHONY: test
test:
	go test -v -coverprofile .cover.out ./...
	@go tool cover -func=.cover.out
	@go tool cover -html=.cover.out -o .cover.html
	@rm .cover.out
