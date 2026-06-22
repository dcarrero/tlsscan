# syntax=docker/dockerfile:1
#
# headerforge-tls — microservicio TLS (Go nativo, solo stdlib).
# Build multi-stage: compila estático y empaqueta en distroless mínimo.
#
# El binario escucha por defecto en 127.0.0.1:8081 (ver cmd/headerforge-tls/main.go).
# DENTRO DEL CONTENEDOR hay que forzar 0.0.0.0:8081 para que sea alcanzable desde
# la red de compose. Eso se hace con la env TLS_SCAN_LISTEN (ya fijada abajo, y
# reafirmada en deploy/docker-compose.yml).

# ---- Stage 1: build ----
FROM golang:1.22-alpine AS build

WORKDIR /src

# Sin dependencias externas (solo stdlib): copiamos go.mod para cachear y el código.
COPY go.mod ./
COPY . .

# Compilación estática, sin CGO, para correr en una imagen distroless/static.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/headerforge-tls ./cmd/headerforge-tls

# ---- Stage 2: runtime mínimo ----
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/headerforge-tls /usr/local/bin/headerforge-tls

# Escuchar en todas las interfaces dentro del contenedor (no en loopback).
ENV TLS_SCAN_LISTEN=0.0.0.0:8081

EXPOSE 8081

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/headerforge-tls"]
