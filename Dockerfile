# syntax=docker/dockerfile:1.7

FROM golang:1.26-alpine AS gateway-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/beebox-gateway ./cmd/beebox-gateway

FROM golang:1.26-alpine AS identity-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/beebox-identity ./cmd/beebox-identity

FROM gcr.io/distroless/static-debian12:nonroot AS gateway
COPY --from=gateway-build /out/beebox-gateway /beebox-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/beebox-gateway"]

FROM gcr.io/distroless/static-debian12:nonroot AS identity
COPY --from=identity-build /out/beebox-identity /beebox-identity
EXPOSE 8081
USER nonroot:nonroot
ENTRYPOINT ["/beebox-identity"]
