FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /sbproxy ./cmd/sbproxy/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /sbproxy /usr/local/bin/sbproxy
RUN mkdir -p /etc/sbproxy
VOLUME /etc/sbproxy
EXPOSE 8080/tcp
EXPOSE 8443/tcp
EXPOSE 8443/udp
ENTRYPOINT ["sbproxy"]
CMD ["serve", "-c", "/etc/sbproxy"]
