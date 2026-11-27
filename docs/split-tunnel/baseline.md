# Split tunnel baseline

Reproducible upstream baseline for the fork's split-tunnel work. Recorded on
2026-11-27 from the `feature/m00-baseline-guardrails` worktree.

## Baseline

| Item | Value |
| --- | --- |
| Date recorded | 2026-11-27 (UTC) |
| Baseline branch | `develop` |
| Baseline commit | `22eac80ddcb056b2c4738309240bda2711bafd98` |
| Upstream tag at commit | `v0.84.0` (`git tag --points-at HEAD`) |
| `origin` remote | `git@github.com:alexsherkhan/netbird-split.git` |
| `upstream` remote | `https://github.com/netbirdio/netbird.git` |

The baseline is pinned by commit SHA. The `v0.84.0` tag happens to point at the
same commit; no tag was created or moved for this milestone.

## Toolchain

From `go.mod`:

- `go` directive: `1.26.0`
- `toolchain` directive: `go1.26.10`
- Module path: `github.com/netbirdio/netbird`

Local toolchain used for verification: `go version go1.26.10 linux/amd64`.

## Build commands

### Linux client

```bash
cd client
CGO_ENABLED=0 go build .
```

Result: succeeded (exit 0) and produced `client/client`. The binary was removed
after verification so the worktree stays clean.

This builds the client only. It does not build management, signal, relay, proxy,
or the desktop GUI.

### Desktop GUI

Prerequisites from `CONTRIBUTING.md`:

- Go 1.26 or newer.
- Node 20 or newer and `pnpm` (`corepack enable && corepack prepare pnpm@latest --activate`).
- Wails v3 CLI: `go install github.com/wailsapp/wails/v3/cmd/wails3@latest`.
- Task runner: `go install github.com/go-task/task/v3/cmd/task@latest`.
- Linux packages: `libwebkitgtk-6.0-dev`, `libgtk-4-dev`, `libsoup-3.0-dev`.

Production build (frontend assets embedded into `client/ui/bin/netbird-ui`):

```bash
cd client/ui
task build
```

Live-reload development build:

```bash
cd client/ui
task dev
```

## Verification run

| Command | Result |
| --- | --- |
| `gofmt -l client/internal/splittunnel/` | Clean, no files listed |
| `go test ./client/internal/splittunnel/...` | Passed |
| `cd client && CGO_ENABLED=0 go build .` | Passed (exit 0) |
| `make lint` | Failed: `client/ui` typecheck could not import GTK/WebKit cgo packages because `gtk4`, `webkitgtk-6.0`, and `libsoup-3.0` are not installed on this host |
| `./bin/golangci-lint run ./client/internal/splittunnel/... --timeout=2m` | `0 issues` |
| GUI `task build` | Not run |

The `make lint` failure is environmental. On this host `pnpm`, `wails3`, and
`task` are absent, and `pkg-config` cannot find `gtk4`, `webkitgtk-6.0`, or
`libsoup-3.0`. The linter reported no findings in the new package; its only
errors were the `client/ui` cgo imports.

## Scope

No management, signal, relay, proxy, or other server sources were changed. The
only code change is the inert `client/internal/splittunnel` package, which is not
wired into the client and does not change runtime behavior.

## Known gaps and unverified items

- `make lint` is not green on this host because the GUI system dependencies are
  missing. It needs a host with the prerequisites above or the project CI image.
- The GUI build could not be attempted because `pnpm`, `wails3`, `task`, and the
  GTK/WebKitGTK/libsoup development packages are not installed.
- Privileged network tests were not run.
- `go build ./...` for the whole repository was not run; only the Linux client
  build above was verified.
- Fork CI status on `develop` was not observed as part of this baseline.
- No upstream tag was created or inferred beyond `v0.84.0` pointing at the
  recorded commit.
