# Base images can be pointed at a private mirror, e.g.
#   --build-arg GO_IMAGE=harbor.example.org/library/golang:1.27-alpine
ARG GO_IMAGE=golang:1.27-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/kartal-server ./cmd/kartal-server \
 && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/kartal-agent ./cmd/kartal-agent

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/ /usr/local/bin/
USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/kartal-server"]
