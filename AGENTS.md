# Repository Guidelines

## Project Structure & Module Organization
- Entry point: `cmd/main.go`.
- Core business logic lives under `internal/core/`:
  - `domain/` for entities,
  - `services/` for use cases,
  - `ports/` for interfaces.
- Adapters are in `internal/adapters/`:
  - `ui/` for TUI behavior and input handling,
  - `data/ssh_config_file/` for `~/.ssh/config` persistence and backups.
- Shared logging utilities: `internal/logger/`.
- Screenshots and static docs assets: `docs/`.
- Keep new code in the matching layer; avoid cross-layer shortcuts that bypass `ports`.

## Build, Test, and Development Commands
- `make run`: run the app from source.
- `make build`: format, lint, and build `./bin/lazyssh`.
- `make test`: run unit tests with race detector and coverage (`coverage.out`).
- `make coverage`: generate `coverage.html` from test coverage.
- `make lint` / `make lint-fix`: run `golangci-lint` (with optional auto-fixes).
- `make fmt`: run `gofumpt` and `go fmt`.
- `make quality`: run formatting, vetting, and linting as a pre-PR baseline.

## Coding Style & Naming Conventions
- Follow idiomatic Go with tabs and `gofumpt` formatting.
- Use short, lowercase package names (`ui`, `ports`, `domain`).
- Exported identifiers use `CamelCase`; unexported helpers use `camelCase`.
- File names should be descriptive and snake_case where established (for example, `server_form.go`, `crud_test.go`).
- Respect enabled linters in `.golangci.yml`; fix warnings before opening a PR.

## Testing Guidelines
- Use Go’s standard `testing` package.
- Place tests next to code as `*_test.go` (examples: `validation_test.go`, `crud_test.go`).
- Prefer table-driven tests for parser, validation, and mapping behavior.
- Run `make test` locally before pushing; include race-safe changes.

## Commit & Pull Request Guidelines
- Use conventional commit style seen in history: `feat(...)`, `fix(...)`, `improve(...)`, `refactor(...)`, `test`, `docs`, `ci`, `chore`, `revert`.
- Keep commit subjects imperative and specific, e.g. `fix(parser): preserve trailing blank lines`.
- PR titles must be semantic (CI-enforced); optional scopes: `ui`, `cli`, `config`, `parser`.
- PRs should include: purpose, key changes, test evidence (`make test` output), and UI screenshots/GIFs for TUI-visible changes.

## Security & Configuration Tips
- Never commit real hosts, usernames, keys, or SSH config secrets.
- Validate changes that touch config writing/backups carefully; this project edits `~/.ssh/config` and aims for non-destructive writes.
