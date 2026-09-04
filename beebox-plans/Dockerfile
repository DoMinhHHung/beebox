FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY libs/shared ./libs/shared
COPY beebox-plans ./beebox-plans
WORKDIR /src/beebox-plans
RUN CGO_ENABLED=0 go build -o /out/plans ./cmd/plans

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/plans /usr/local/bin/plans
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/plans"]
