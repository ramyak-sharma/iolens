# build stage compiles the bpf object (arch independent, bpfel) and cross
# compiles the go binary for whatever TARGETARCH buildx asks for
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
RUN go generate ./internal/bpfsrc/ \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
       go build -trimpath -ldflags '-s -w' -o /out/iolens ./cmd/iolens

# just the binary, no shell no package manager
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/iolens /iolens
# needs root for bpf, the daemonset sets runAsUser 0
USER 0
EXPOSE 9187
ENTRYPOINT ["/iolens"]
CMD ["serve"]
