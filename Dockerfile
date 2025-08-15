# syntax=docker/dockerfile:1

ARG GO_VERSION=1.22
ARG LDFLAGS=""

FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w ${LDFLAGS}" -o /out/telegen ./cmd/telegen

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/telegen /usr/local/bin/telegen
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/telegen"]
