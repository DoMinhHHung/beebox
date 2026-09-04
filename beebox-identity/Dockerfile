FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY libs/shared ./libs/shared
COPY beebox-identity ./beebox-identity
WORKDIR /src/beebox-identity
RUN CGO_ENABLED=0 go build -o /out/identity ./cmd/identity

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/identity /usr/local/bin/identity
EXPOSE 8083
ENTRYPOINT ["/usr/local/bin/identity"]
