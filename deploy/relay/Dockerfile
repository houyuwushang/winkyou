FROM golang:1.22 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/wink-relay ./cmd/wink-relay

FROM gcr.io/distroless/static-debian12
COPY --from=builder /out/wink-relay /usr/local/bin/wink-relay
EXPOSE 3478/udp
ENTRYPOINT ["/usr/local/bin/wink-relay"]
