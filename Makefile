.PHONY: vendor
vendor:
	go mod tidy && go mod vendor

.PHONY: fmt
fmt:
	templ fmt . && templ generate

.PHONY: start
start: fmt
	go run ./...
