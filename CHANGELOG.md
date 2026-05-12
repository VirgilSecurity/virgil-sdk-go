# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [7.0.0] - 2026-05-12

### Added
- `Algorithm` enum (`AlgEd25519`, `AlgCurve25519`, `AlgP256r1`, `AlgFalcon`, `AlgMlKem768`, `AlgMlDsa65`) for composing key types.
- `HybridKEM(classical, postQuantum Algorithm) KeyType` constructor for hybrid KEM key types.
- `CompoundKey(cipher, pqCipher, signer, pqSigner Algorithm) KeyType` constructor for arbitrary compound key types.
- `RsaKey(bitlen uint) KeyType` constructor for RSA keys (replaces named `Rsa*` vars).
- Named var `Curve25519MlKem768Ed25519Falcon` — recommended post-quantum hybrid compound key type.
- GitHub Actions CI workflow (replaces Travis CI).
- `CLAUDE.md` with build, test, workflow, and versioning guidance.

### Changed
- **Breaking**: module path bumped from `github.com/VirgilSecurity/virgil-sdk-go/v6` to `.../v7`.
- **Breaking**: `KeyType` changed from `int` iota to a comparable struct; arithmetic and range loops over `KeyType` values no longer compile.
- **Breaking**: `Rsa2048`, `Rsa3072`, `Rsa4096`, `Rsa8192` named vars removed; use `RsaKey(bitlen)` instead.
- Crypto dependency migrated from embedded `crypto/wrapper/` sources to the standalone Go module `github.com/VirgilSecurity/virgil-crypto-c/wrappers/go v0.19.0-rc.8`. No local C build required; pre-built static libs are bundled in the module.
- Default branch renamed from `master` to `main`.
- Minimum Go version: 1.21.

### Removed
- `Curve25519Round5`, `Curve25519Round5Ed25519Falcon` key types — Round5 was removed from `virgil-crypto-c` v0.19.0 and replaced by ML-KEM-768.
- Embedded `crypto/wrapper/foundation/`, `crypto/wrapper/phe/`, `crypto/wrapper/pkg/`, `crypto/wrapper/build/` directories.
- `legacy` build tag support (`linux_amd64__legacy_os` variant no longer exists upstream).
- Travis CI configuration (`.travis.yml` retained for reference but CI is now GitHub Actions).

[Unreleased]: https://github.com/VirgilSecurity/virgil-sdk-go/compare/v7.0.0...HEAD
[7.0.0]: https://github.com/VirgilSecurity/virgil-sdk-go/releases/tag/v7.0.0
