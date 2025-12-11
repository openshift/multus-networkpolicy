FROM golang:1.24 as builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY cmd/main.go cmd/main.go
COPY pkg/ pkg/

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o multi-networkpolicy-nftables cmd/main.go

FROM fedora:42
WORKDIR /

RUN dnf install -y nftables
COPY --from=builder /workspace/multi-networkpolicy-nftables .
ENTRYPOINT ["/multi-networkpolicy-nftables"]
