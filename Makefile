.PHONY: all lint test race memory_sanitizer dep build clean help

PROJECT_NAME := "wg-cc"
PKG := "github.com/badu/$(PROJECT_NAME)"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)
GO_FILES := $(shell find . -name '*.go' | grep -v /vendor/ | grep -v _test.go)

all: build

lint: ## Lint the files - requires golint tool
	@golint -set_exit_status ${PKG_LIST}

test: ## Run unittests
	@go test -short ${PKG_LIST}

race: dep ## Run data race detector
	@go test -race -short ${PKG_LIST}

memory_sanitizer: dep ## Run memory sanitizer
	@go test -msan -short ${PKG_LIST}

dep: ## Get the dependencies
	@go mod download -x

build: dep ## Build the binary file
	CGO_ENABLED=0 go build -v -o ./build/service ${PKG}/cmd/oauth2-server

clean: ## Remove previous build
	@rm -f $(PROJECT_NAME)

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

swagger:
	go install github.com/swaggo/swag/cmd/swag@v1.7.1
	swag init -g cmd/oauth2-server/main.go
