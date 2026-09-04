FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY libs/shared ./libs/shared
COPY beebox-gateway ./beebox-gateway
WORKDIR /src/beebox-gateway
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/gateway /usr/local/bin/gateway
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gateway"]
