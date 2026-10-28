# Feature backlog, 2026-10-27

Collected before the first commit, from two GitOps estates that run External Secrets Operator on
OpenBao, and from prior-art research. Feeds ADR-0001 (the spec) and the v0.1 scope.

## Why

- A value a person must provide sits unseeded with nothing alerting. One estate found a path
  unseeded for 11 days; a fail-soft consumer logged "not present yet; skipping".
- Bootstrapping a vault is handwork that "cannot be expressed in a chart":
  [external-secrets#6988](https://github.com/external-secrets/external-secrets/issues/6988).
- The knowledge of where a value comes from lives in YAML comments, runbooks and per-secret
  recipes that print a prompt; nothing machine-reads it.

Prior art covers pieces only: ESO generators (in-cluster entropy), SecretSpec and Varlock
(application env schemas), TruffleHog verifiers (AGPL, scanning-oriented), Vault KV custom
metadata (storage). None joins declaration, discovery, seeding, verification and enforcement for
ExternalSecrets.

## Spec (annotations on ExternalSecret, prefix `wellhead.dev/`)

- `origin`: `provided` (a person supplies it), `minted` (something in the cluster writes it),
  `projected` (another ExternalSecret already seeds the path). Variants worth modelling:
  `preserve` (at-rest key: provided or generated once, never regenerate) and `rolled` (provided
  once, then rotated by a controller).
- `how`: where a person gets the value, one paragraph. `docs`: a URL.
- `fields`: field names at the path when `dataFrom.extract` hides them. `plain`: fields shown while
  typed.
- `verify`: an open set of checks, see below; `none` is an explicit, reviewed exception.
- `expires` / `lifetime`: for values issued with an expiry ("shown once, valid 365 days").
- `rotate-on-compromise`: whether regenerating is safe in a break-glass.
- Annotation values stay flat strings: CEL cannot parse JSON inside an annotation.

## CLI

- `wellhead missing`: every ExternalSecret whose vault paths or fields do not exist, read from the
  vault itself, not from ESO status (ESO stops at the first failing `data[]` entry and hides the
  rest). Three states per field: missing, rejected, ok.
- `wellhead seed <ns>/<name>`: show `how`, ask each field hidden (`plain` shown), confirm twice for
  a value a person chooses, offer generate-if-empty where the spec allows, run `verify`, write as
  JSON on stdin (never argv, never a URL), then force an ESO sync and wait for Ready
  (`refreshInterval: "0"` never picks up a late write otherwise).
- File-backed fields: `private_key=@path`, read once, never echoed; offer to delete the source file
  after a verified write.
- `wellhead lint`: the spec over manifests in CI, the same CEL as admission.
- `wellhead verify --all`: re-run every check on a schedule (CronJob mode), export metrics, warn
  before expiry (for example GitHub's token-expiration header under 14 days).
- After a seed, write vault KV custom metadata: `seeded-by`, `seeded-at`, `expires`.

## Verifiers (own code, Apache-2.0)

- `http`: method, URL, bearer / header / basic auth from fields, expected status; 429 is
  "unknown, retry", not "rejected".
- `format`: a regex per field (catches the wrong paste where no API exists, such as a Slack signing
  secret).
- Providers: GitLab token self-lookup (name, scopes, expiry); Slack `auth.test` plus the
  `x-oauth-scopes` header against required scopes; GitHub token expiration header; Cloudflare
  `tokens/verify`.
- **GitHub App credentials** (first real case, 2026-10-27): fields `app_id`, `installation_id`,
  `private_key` (file). Verify by signing an RS256 JWT with the key, calling
  `GET /app/installations/{installation_id}`, and checking that the installation belongs to the app,
  is not suspended, covers the expected repositories and grants the expected permissions. Proves
  the three values belong together before anything is written.

## Enforcement

- Native ValidatingAdmissionPolicy (CEL), shipped in the Helm chart: Warn + Audit with
  `failurePolicy: Ignore` while an estate is annotating, Deny + Fail afterwards. CRDs get no CEL
  type checking, so fixtures test every expression.
- Optional Kyverno ValidatingPolicy for estates that want PolicyReports (Kyverno also reports on
  native policies).
- The same fixtures run through `wellhead lint` and through a kind matrix, so the two cannot drift.

## Distribution

- Helm chart over OCI on GHCR, signed keylessly; CLI binaries for linux and darwin, amd64 and
  arm64, signed, with SBOM.
