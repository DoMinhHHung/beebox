# BeeBox

BeeBox is an open-source identity and access platform implemented primarily in Go.

This repository currently contains the initial runtime foundation only. Product capabilities such as users, authentication, sessions, organizations, and persistence are not implemented yet.

## Prerequisites

- Go 1.26.x
- Git

The module declares Go 1.26.0 as its minimum supported Go version.

## Run locally

Start BeeBox with the default configuration:

```bash
go run ./cmd/beebox
```