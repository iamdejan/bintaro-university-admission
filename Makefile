.PHONY: vendor
vendor:
	go mod tidy && go mod vendor

.PHONY: fmt
fmt:
	golines -w .
	gofmt -w .
	templ fmt .
	templ generate

.PHONY: lint
lint:
	golangci-lint cache clean && golangci-lint run ./...

.PHONY: start
start: fmt
	go run main.go
