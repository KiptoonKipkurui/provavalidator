BINARY=provavalidator

all: build

build:
	go build -o $(BINARY) .

run:
	go run .

test:
	go test ./...

clean:
	rm -f $(BINARY)

lint:
	golangci-lint run

.PHONY: all build run test clean lint
