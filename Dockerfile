FROM golang:1.23 as build
WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/telegen ./cmd/telegen

FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=build /out/telegen /telegen
COPY api/config.example.yaml /etc/telegen/config.yaml
USER 65532:65532
EXPOSE 19090
ENTRYPOINT ["/telegen","--config","/etc/telegen/config.yaml"]
