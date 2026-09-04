FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY libs/shared ./libs/shared
COPY beebox-projects ./beebox-projects
WORKDIR /src/beebox-projects
RUN CGO_ENABLED=0 go build -o /out/projects ./cmd/projects

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/projects /usr/local/bin/projects
EXPOSE 8082
ENTRYPOINT ["/usr/local/bin/projects"]
