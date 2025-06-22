# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

**Build:**
```bash
go build -o github-mcp-server ./cmd/github-mcp-server
```

**Run server:**
```bash
GITHUB_PERSONAL_ACCESS_TOKEN=<token> ./github-mcp-server stdio
```

**Run tests:**
```bash
go test ./...
```

**Run tests with toolsnap updates:**
```bash
UPDATE_TOOLSNAPS=true go test ./...
```

**Run e2e tests:**
```bash
cd e2e && go test -v
```

**Lint:**
```bash
go mod tidy
go mod verify
golangci-lint run
```

## Architecture Overview

This is a **Model Context Protocol (MCP) server** that provides GitHub API access to AI tools. The server communicates via JSON-RPC over stdio.

### Core Structure

- **`cmd/github-mcp-server/`** - Main binary entry point using Cobra CLI
- **`internal/ghmcp/`** - Server initialization and configuration
- **`pkg/github/`** - Main GitHub API integration and tool implementations
- **`pkg/toolsets/`** - Modular tool organization system
- **`pkg/translations/`** - i18n support for tool descriptions

### Key Components

**Toolsets System**: Tools are organized into logical groups (`repos`, `issues`, `pull_requests`, `code_security`, `users`, `experiments`) that can be selectively enabled/disabled via `--toolsets` flag or `GITHUB_TOOLSETS` env var.

**Dynamic Toolsets**: When `--dynamic-toolsets` is enabled, toolsets can be discovered and enabled at runtime based on user prompts.

**Authentication**: Requires `GITHUB_PERSONAL_ACCESS_TOKEN` environment variable. Supports GitHub Enterprise via `GITHUB_HOST` or `--gh-host`.

**Dual API Support**: Uses both GitHub REST API (via `go-github/v72`) and GraphQL API (via `githubv4`) depending on the operation.

### Testing Strategy

- **Unit tests**: Located alongside implementation files (`*_test.go`)
- **Tool snapshots**: Schema changes tracked via `toolsnaps` utility in `__toolsnaps__/*.snap` files
- **E2E tests**: In `e2e/` directory for integration testing
- **Mocking**: Uses `go-github-mock` for REST API and `githubv4mock` for GraphQL

### Configuration

The server supports extensive configuration via CLI flags and environment variables:
- Tool selection via toolsets
- Read-only mode restriction
- Custom GitHub hosts for Enterprise
- Translation overrides via JSON config files
- Command logging and debug options