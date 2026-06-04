# Release Process

This document defines the v0.1 release build path for WinkYou.

## Artifacts

The release workflow builds these files:

- `wink-windows-amd64.exe`
- `wink-linux-amd64`
- `wink-coordinator-linux-amd64`
- `wink-relay-linux-amd64`
- `SHA256SUMS`

Artifacts are uploaded from the workflow run. Tag builds also publish a GitHub release.

## Version Metadata

Release builds inject:

- `version`: tag name or workflow input
- `commit`: short commit SHA
- `build_time`: UTC build timestamp

Verify locally:

```bash
dist/wink-linux-amd64 version
dist/wink-coordinator-linux-amd64 --version
dist/wink-relay-linux-amd64 --version
```

On Windows:

```powershell
dist\wink-windows-amd64.exe version
```

## Local Release Check

Before tagging:

```bash
go fmt ./...
go vet ./...
go test ./... -count=1
make build-all VERSION=v0.1.0
make checksum-release VERSION=v0.1.0
```

Confirm expected files:

```bash
ls dist
cat dist/SHA256SUMS
```

Do not commit `bin/`, `dist/`, or release binaries.

## Tag Release

Use an annotated or lightweight tag following `v*`:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The `Release` workflow will:

1. run `go test ./... -count=1`
2. build the four release artifacts
3. create `SHA256SUMS`
4. upload workflow artifacts
5. create a GitHub release for the tag

Manual dispatch can build the same artifacts without creating a tag release.

## Release Checklist

- README points to current self-host and long-running client docs.
- `docs/V0.1-FREEZE.md` exists before the final v0.1 tag.
- `make test-phase2d` passes.
- `make test-phase3a` passes.
- `make test-phase4a` passes.
- `wink doctor` shows useful output for a configured node.
- `docs/SELFHOST-QUICKSTART.md` can be followed on a clean Linux server.
- `dist/SHA256SUMS` matches the uploaded files.

## Rollback

If a release is bad:

1. Mark the GitHub release as a pre-release or delete it if it should not be used.
2. Leave the Git tag in place unless the tag itself points to the wrong commit.
3. Create a patch tag, for example `v0.1.1`, from the fixed commit.
4. Document the issue in release notes.

Do not rewrite published history for a normal release bug.
