VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= kartal-gozu:$(VERSION)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test image demo

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/kartal-server ./cmd/kartal-server
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/kartal-agent ./cmd/kartal-agent

test:
	go vet ./...
	go test -race -count=1 ./...

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

# Runs the server with agents watching simulated clusters: http://127.0.0.1:8080/
demo:
	go run ./cmd/kartal-demo
