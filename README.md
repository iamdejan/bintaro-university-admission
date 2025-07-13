# Bintaro University Admission

This is a dummy project for a fake university. My goal here is to learn:
- Cookie-based authentication (especially HttpOnly cookies); and
- [Time-based one-time password](https://en.wikipedia.org/wiki/Time-based_one-time_password), which is based on [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html).

# Pre-requisites

Programming language:
- Go 1.24.5 or higher: `brew install go`

Development:
- `golangci-lint`: `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.2.1`
- `golines`: `go install github.com/segmentio/golines@latest`
- `templ`: `go install github.com/a-h/templ/cmd/templ@v0.3.906`

# Run Server

Run `make start`. Then, you can access the website at `http://localhost:9000`.
