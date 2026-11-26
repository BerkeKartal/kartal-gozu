VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= kartal-gozu:$(VERSION)
SCANNER_IMAGE ?= kartal-scanner:$(VERSION)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test image scanner-image demo

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/kartal-server ./cmd/kartal-server
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/kartal-agent ./cmd/kartal-agent
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/kartal-registry ./cmd/kartal-registry
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/kartal-scanner ./cmd/kartal-scanner

test:
	go vet ./...
	go test -race -count=1 ./...

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

# The registry's vulnerability scanner: Trivy's image with kartal-scanner.
scanner-image:
	docker build -f Dockerfile.scanner --build-arg VERSION=$(VERSION) -t $(SCANNER_IMAGE) .

# Runs the server with agents watching simulated clusters: http://127.0.0.1:8080/
demo:
	go run ./cmd/kartal-demo
