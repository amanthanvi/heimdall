# Release Verification

Before release:

```sh
go test ./...
go vet ./...
goreleaser check
```

Artifacts should include checksums and, where practical, signatures and SBOMs. Public release notes must list bridge limitations and the no-private-key-custody boundary.

