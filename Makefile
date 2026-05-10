.PHONY: test test-race lint vet tidy

test:
	go test ./...

test-race:
	go test -race -coverprofile=coverage.out ./...

vet:
	go vet ./...

tidy:
	go mod tidy

lint:
	golangci-lint run ./...
