---
status: "accepted"
date: "2026-10-28"
review-by: "2027-04-28"
---

# An ExternalSecret declares where its value comes from (spec v1alpha1)

## Context and Problem Statement

External Secrets Operator (ESO) copies values from a vault into Kubernetes Secrets. It says nothing
about how a value gets into the vault in the first place. For a value the outside world issues, such
as an API token, a person has to put it there, and nothing records who, how, or whether it happened.

Two failure modes recur:

- A value a person must provide sits unseeded with nothing alerting. In one estate a path stayed
  unseeded for 11 days because a fail-soft consumer logged "not present yet; skipping".
- Bootstrapping a vault is handwork that "cannot be expressed in a chart"
  ([external-secrets#6988](https://github.com/external-secrets/external-secrets/issues/6988)). The
  knowledge lives in YAML comments, runbooks and per-secret scripts that nothing machine-reads.

ESO's own status does not answer "what is missing": it stops at the first failing `data[]` entry and
hides the rest, and an ExternalSecret with `refreshInterval: "0"` never notices a late write.

How does an ExternalSecret say where its value comes from, in a form a CLI, an admission policy and a
person can all read?

## Decision Drivers

- The declaration sits on the manifest that consumes the value, not in a table that drifts from it.
- The same rules run before merge (CLI), at admission (CEL) and in a background scan.
- Admission CEL cannot parse JSON inside an annotation, so every value is a flat string.
- An exception is explicit and reviewable, never an absence.
- What is missing is read from the vault, not inferred from ESO status.
- No copyleft code: verifiers are written for this project under Apache-2.0.

## Considered Options

- Annotations under `wellhead.dev/` on each ExternalSecret.
- A central seed table (one file listing every path and how to fill it).
- A JSON document in a single annotation.
- Adopt an existing tool: ESO generators, SecretSpec, Varlock, TruffleHog verifiers, Vault KV
  custom metadata alone.

## Decision Outcome

Chosen option: "Annotations under `wellhead.dev/` on each ExternalSecret", because it keeps the
declaration next to its consumer, it is readable by CEL at admission, and it needs nothing installed
for the declaration itself to exist.

### The spec, version v1alpha1

The version is `v1alpha1`. Keys are unversioned; a breaking change to their meaning makes a new spec
version and a new ADR that supersedes this one. The chart records the version it enforces in its
`wellhead.dev/spec-version` annotation and the rule file's `specVersion`.

| Annotation | Value | Required |
| --- | --- | --- |
| `wellhead.dev/origin` | `provided`, `preserve`, `rolled`, `minted` or `projected` | always |
| `wellhead.dev/how` | One paragraph: where a person gets the value | when a person enters it |
| `wellhead.dev/docs` | An `https://` URL with more detail | no |
| `wellhead.dev/fields` | Field names at the vault path, separated by single spaces | when a person enters it and `dataFrom.extract` hides the names |
| `wellhead.dev/plain` | Fields shown while typed, such as a username | no |
| `wellhead.dev/generate` | Fields that may be left empty to generate 32 random bytes; a value typed for one of them is asked twice | no |
| `wellhead.dev/verify` | Check kinds separated by single spaces, or `none` | when a person enters it |
| `wellhead.dev/verify.<kind>.<param>` | A parameter of that check | per check |
| `wellhead.dev/expires` | The date the current value expires, `YYYY-MM-DD` | no |
| `wellhead.dev/lifetime` | How long a freshly issued value lives: `36h`, `90d`, `12w` | no |
| `wellhead.dev/rotate-on-compromise` | `true` or `false`: whether regenerating in a break-glass is safe | no |

Origins:

| Origin | Who writes the value | `wellhead seed` |
| --- | --- | --- |
| `provided` | A person, from an issuer outside the cluster | asks for missing fields; `--rotate` asks again |
| `preserve` | A person, or generated once; never regenerated (an at-rest encryption key) | asks only when missing; never overwrites |
| `rolled` | A person once, then a controller rotates it | asks only when missing; never overwrites |
| `minted` | A controller in the cluster | refuses; `missing` says it waits for its writer |
| `projected` | Another ExternalSecret already seeds the path | refuses; seed the owner instead |

`preserve` and `rolled` are origins rather than a separate modifier key so that one closed set answers
"who writes it", and so that CEL can reject `preserve` with `rotate-on-compromise: "true"` in one rule.

Verify kinds form an open set. Known kinds: `http`, `format`, `github-app`, `github-token`,
`gitlab-token`, `slack-bot-token`, `cloudflare-token`, and `none`, the reviewed exception, which may
not be combined with another kind. A kind outside this list starts with `x-`; the CLI reports it as
unknown until it implements it. A check concludes one of `accepted`, `rejected` or `unknown` (HTTP 429,
5xx, network errors); `unknown` is never treated as `rejected`.

Field states, as `wellhead missing` reports them: `missing` (the path or field does not exist in the
vault), `rejected` (present, but a check refuses it; with `--verify`), `ok`.

### Rules

Rules WH001 to WH015 live in one file, `deploy/charts/wellhead/files/rules.yaml`, as CEL. The chart
renders them into the admission policies and `wellhead lint` embeds and evaluates the same file
(ADR-0002, ADR-0003). Every message starts with its rule id.

### Consequences

- Good, because what a person needs to know travels with the manifest and changes in the same review.
- Good, because `missing` reads every remoteRef from the vault, so one missing field cannot hide another.
- Good, because a check proves a value before it is written, and records an expiry where the issuer
  reports one.
- Bad, because annotating every existing ExternalSecret is work; the chart defaults to Warn and Audit
  for that period.
- Bad, because flat strings limit expressiveness: parameters become one annotation each.
- Neutral, because pods see nothing new: the Secrets ESO writes are unchanged.

### Confirmation

- `go test ./internal/policy/` passes: every pass fixture in `testdata/policy/pass` has no violation,
  every fail fixture in `testdata/policy/fail` breaks exactly the rule its file name starts with, and
  every rule has a fail fixture.
- `scripts/check-policy-offline.sh` and the `admission` CI job agree with the same fixtures.

## Pros and Cons of the Options

### Annotations under `wellhead.dev/` (chosen)

- Good, because CEL reads annotations directly.
- Bad, because annotation values are untyped strings; the rules carry the typing.

### A central seed table

- Good, because every path is visible in one file.
- Bad, because it drifts from the manifests, the same way runbook lines do.

### A JSON document in one annotation

- Good, because it can nest.
- Bad, because admission CEL has no JSON parser for annotation values, so the policy could not check it.

### Adopt an existing tool

- ESO generators: good for in-cluster entropy (`minted`), silent on provided values.
- SecretSpec and Varlock: application environment schemas; they do not know ExternalSecrets or vault
  paths.
- TruffleHog verifiers: broad coverage, but AGPL-3.0 and built for scanning leaked strings, not for
  checking that three values belong together before a write. wellhead writes its own verifiers.
- Vault KV custom metadata: storage for who and when, used by `seed`, but no declaration or
  enforcement.

## More Information

- Feature backlog and prior art: [2026-10-27 feature backlog](../research/2026-10-27-feature-backlog.md).
- Re-evaluate when ESO ships a declaration of its own for provided values, or when admission CEL can
  parse structured annotation values.
- 2026-10-28: accepted with the v0.1 scope.
