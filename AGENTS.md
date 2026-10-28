# wellhead

wellhead is a spec, a Go CLI and an admission policy pack that make every External Secrets Operator
ExternalSecret declare where its value comes from. `development` is trunk and `main` holds stable
releases. Run `mise run setup` once and every tool through `mise exec --`. Start at
[docs/index.md](docs/index.md).

## Commits

Conventional Commits; stage only the paths you changed, never `git add -A`, `git add .` or
`git commit -a`. Sign off every commit with `git commit -s` (DCO, checked in CI). Releases are cut from
commit types by semantic-release; do not edit versions in `Chart.yaml` or anywhere else.

## Facts the tree won't tell you

- `deploy/charts/wellhead/files/rules.yaml` is the only rule source. The chart renders it and
  `wellhead lint` embeds it through `deploy/embed.go`. A rule change lands with a fail fixture in
  `testdata/policy/fail/` named `<RULE>-<what>.yaml` that breaks that rule and no other.
- `cmd/wellhead` is only environment-to-config wiring; logic lives in `internal/`.
- No comments in Go code. Doc comments that tools read are fine.
- Never print, log or put a secret value in an error, a URL or argv. Route errors through
  `internal/redact`.
- Tests fake external services with `net/http/httptest`. A bug fix lands with a test that fails on the
  old code.
- The project names no estate, company or person that uses it.

## Before opening a pull request

Run `mise run verify` and put its result in the pull request. `mise run admission` needs a cluster;
CI runs it on two Kubernetes minors.

## Decisions

Decisions go in [docs/adrs/](docs/adrs/README.md) (MADR 4.0, append-only, each with a
`### Confirmation`). Evidence goes in `docs/research/YYYY-MM-DD-<topic>.md`.
