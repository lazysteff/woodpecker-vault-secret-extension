# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/woodpecker-vault-secret-extension ./cmd/woodpecker-vault-secret-extension

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="woodpecker-vault-secret-extension" \
      org.opencontainers.image.description="Woodpecker CI secret extension backed by HashiCorp Vault or OpenBao KV v2" \
      org.opencontainers.image.source="https://github.com/stephan/woodpecker-vault-secret-extension" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV CONFIG_FILE=/config/config.yml
EXPOSE 8080

USER nonroot:nonroot
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/woodpecker-vault-secret-extension /woodpecker-vault-secret-extension

ENTRYPOINT ["/woodpecker-vault-secret-extension"]
