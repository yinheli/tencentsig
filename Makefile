SRC_DIR := $(shell ls -d */|grep -vE 'vendor|script')

all: test

.PHONY: deps
deps:
	# install deps
	@hash dep > /dev/null 2>&1; if [ $$? -ne 0 ]; then \
		go get -u github.com/golang/dep/cmd/dep; \
	fi
	@dep ensure -v

.PHONY: fmt
fmt:
	@gofmt -s -l -w *.go $(SRC_DIR)
	@go tool vet *.go $(SRC_DIR)

.PHONY: test
test:
	go test -v -coverprofile .cover.out ./...
	@go tool cover -func=.cover.out
	@go tool cover -html=.cover.out -o .cover.html
