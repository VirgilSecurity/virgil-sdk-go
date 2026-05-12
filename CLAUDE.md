# VirgilSDKGo

Go SDK for Virgil Security platform (v7). Provides card management, JWT auth, encrypted storage, and a high-level crypto API backed by `virgil-crypto-c/wrappers/go`.

## Quick Reference

- **Module**: `github.com/VirgilSecurity/virgil-sdk-go/v7`
- **Crypto dependency**: `github.com/VirgilSecurity/virgil-crypto-c/wrappers/go v0.19.0-rc.8`
- **Go version**: 1.21

## Build

```bash
go build ./...
```

## Test

```bash
go test ./...
```

Integration tests (require API credentials) use the `integration` build tag:

```bash
go test -tags integration -count=1 ./...
```

## Key Directories

| Directory        | Purpose                                              |
| ---------------- | ---------------------------------------------------- |
| `crypto/`        | High-level crypto API wrapping `wrappers/go/foundation` |
| `sdk/`           | Card management (CardManager, CardVerifier, etc.)    |
| `session/`       | JWT generation, validation, and token providers      |
| `storage/`       | Encrypted private key storage                        |
| `common/client/` | HTTP client for Virgil Cards Service                 |

## Important Notes

- Pre-built CGo static libs are shipped in `virgil-crypto-c/wrappers/go/pkg/<os>_<arch>/`. Do not copy or vendor them locally — the Go module dependency handles this.
- `crypto/wrapper/` was removed in v7. All foundation/phe types are now imported directly from `github.com/VirgilSecurity/virgil-crypto-c/wrappers/go/foundation` and `/phe`.
- Round5 post-quantum key types (`Curve25519Round5`, `Curve25519Round5Ed25519Falcon`) were removed in v7; Round5 was replaced by ML-KEM-768 in `virgil-crypto-c` v0.19.0.

## Development Workflow

- **Branch naming**: `feat/<topic>` for features, `fix/<topic>` for bug fixes, `chore/<topic>` for maintenance.
- **Base and target**: branch off `master`, open PRs targeting `master`. There is no `develop` branch.
- **Before pushing**: run `go build ./...` and `go test ./...` locally. Push only after confirming no regressions.
- **Docs-only commits**: append `[skip ci]` to the commit message when the commit touches only `.md` or `docs/` files.

## Forbidden

- **Do not push without a local build and test check**.
- **Do not add co-author lines** to commit messages.
- **Do not force-push to `master`**.
