# Contributing

## Build and test

Requires Go 1.26.9 (the `go` directive in `go.mod`) and Python 3.9+.
`ip4scout` needs libpcap development headers (`libpcap-dev`); `certscout`
is pure Go and builds with `CGO_ENABLED=0`.

```bash
make build        # both binaries for the host platform
make test         # go test -race ./... + Python suite
make vet          # go vet + gofmt check
make lint         # vet + Python byte-compile check
make termux       # Android ARM64 certscout into bin/
make release      # full release matrix into bin/ (linux host with libpcap-dev)
```

`make release` builds the `ip4scout` linux/amd64 binary with cgo, so it
needs a linux/amd64 host with libpcap-dev. Tagged `v*` pushes build the same
matrix in CI (see `.github/workflows/release.yml`).

## Commit style

- One logical change per commit, with a short imperative subject
  (e.g. `feat: batch 2 — Python tools (part 1/3)`).
- Do not commit build artifacts (`bin/`, `certscout`, `ip4scout`), SQLite
  databases, or scan output (`services.jsonl`, `domains.txt`,
  `evidence.jsonl`) — they are gitignored.
- Never commit credentials, tokens, or real scan targets.

## PR checks

Every PR runs the same checks as `make test` + `make vet` plus
`govulncheck ./...` in CI, and builds linux/amd64, linux/arm64, and
darwin/arm64 artifacts (retained 30 days). A PR should:

- Keep `gofmt -l .` empty and `git diff --check` clean.
- Add regression tests for behavior changes (Go and/or Python, as applicable).
- Update the README flags tables and CHANGELOG `Unreleased` section when
  flags, protocols, or profiles change.
- Keep the Go and Python `--list-ports` output in agreement for both
  profiles — verify with both generators before opening the PR.

## Fuzzing

Go native fuzz targets live in `certificates/fuzz_test.go`
(`FuzzNormalizeName`, `FuzzParseTarget`, `FuzzReplyReader`) and the root
`fuzz_test.go` (`FuzzParseExclusion`). Run each briefly:

```bash
go test ./certificates/ -run=FuzzNormalizeName -fuzz=FuzzNormalizeName -fuzztime=10s
go test ./certificates/ -run=FuzzParseTarget -fuzz=FuzzParseTarget -fuzztime=10s
go test ./certificates/ -run=FuzzReplyReader -fuzz=FuzzReplyReader -fuzztime=10s
go test . -run=FuzzParseExclusion -fuzz=FuzzParseExclusion -fuzztime=10s
```

Longer runs are welcome before a release. If a fuzzer finds a crash,
reproduce it from the `testdata/fuzz/` corpus entry, fix the parser, and
keep the crashing input as a regression seed. Python property tests
(`TestNormalizeProperties`, `TestParseProperties`) use fixed seed 42 and
must stay fast (<2s of the suite's property portion).
