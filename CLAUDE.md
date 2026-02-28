# CLAUDE.md

This file provides context for Claude Code when working in this repository.

## Project Overview

LazySSH is a Go TUI SSH manager built with tview. It reads and writes `~/.ssh/config` directly, with a separate JSON metadata file for tags, pins, and usage stats.

## Build & Development

```bash
make build          # Build binary for current platform
make run            # Run from source
make test           # Unit tests with race detector + coverage
make test-verbose   # Verbose test output
make fmt            # Format with gofumpt
make lint           # Run golangci-lint
make lint-fix       # Lint with auto-fix
make quality        # All quality checks (fmt + vet + lint)
make coverage       # HTML coverage report
make tools          # Install dev tools (golangci-lint, gofumpt, staticcheck)
```

Run a single test: `go test -race -run TestName ./internal/path/to/package/...`

## Architecture

Hexagonal (ports & adapters) layout:

```
cmd/main.go                          # Entry point (Cobra CLI, wires everything)
internal/
  core/
    domain/server.go                 # Server struct (100+ SSH config fields + metadata)
    ports/services.go                # ServerService interface
    ports/repositories.go            # ServerRepository interface
    services/server_service.go       # Business logic implementation
  adapters/
    ui/                              # tview TUI (server list, forms, handlers, search)
    data/ssh_config_file/            # SSH config persistence + metadata JSON
  logger/                            # Zap structured logging → ~/.lazyssh/lazyssh.log
```

Data flow: `main.go` → loads SSH config + metadata → creates `Repository` → creates `ServerService` → creates `TUI` → runs.

## Conventions

- Apache 2.0 license header required on all Go files (enforced by golangci-lint goheader)
- gofumpt for formatting, golangci-lint with 50+ linters enabled
- Semantic PR titles: `type(scope): description` — types: feat, fix, improve, refactor, docs, test, ci, chore
- Platform-specific files use build tags: `sysprocattr_unix.go` (`//go:build !windows`), `sysprocattr_windows.go` (`//go:build windows`)
- Table-driven tests with subtests (`t.Run`)
- Version/commit injected via LDFLAGS at build time

## Domain Model

`domain.Server` has standard SSH fields (Host, User, Port, IdentityFiles, ProxyJump, forwarding, auth, ciphers, etc.) plus LazySSH metadata: `Tags`, `PinnedAt`, `LastSeen`, `SSHCount`.

## Data Persistence

- SSH config: reads/writes `~/.ssh/config` via `kevinburke/ssh_config` parser. Non-destructive — preserves comments, spacing, ordering. Atomic writes (temp file → rename).
- Backups: one-time `~/.ssh/config.original.backup` + rolling timestamped backups (max 10).
- Metadata: `~/.lazyssh/metadata.json` (tags, pins, last seen, SSH count). Permissions 0600.

## Key Dependencies

- `rivo/tview` + `gdamore/tcell` — TUI framework
- `kevinburke/ssh_config` — SSH config parsing
- `uber-go/zap` — structured logging
- `spf13/cobra` — CLI
