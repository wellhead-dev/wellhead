# wellhead

wellhead makes every [External Secrets Operator](https://external-secrets.io/) `ExternalSecret`
declare where its value comes from, so a missing value is found, seeded by a person with a check
before it is written, and enforced in CI and at admission.

**Status: v0.1, alpha.** The annotation spec is `v1alpha1` and may change before v1. The vault side
supports Vault and OpenBao KV version 2.

## Why

ESO copies values out of a vault. Nothing records how a value gets into the vault, so:

- a value a person must provide can sit unseeded for days while a fail-soft consumer logs
  "not present yet; skipping";
- bootstrapping a vault "cannot be expressed in a chart"
  ([external-secrets#6988](https://github.com/external-secrets/external-secrets/issues/6988)), so the
  knowledge lives in comments and runbooks;
- ESO's status stops at the first failing `data[]` entry and hides the rest.

Existing tools cover pieces: ESO generators make in-cluster entropy, SecretSpec and Varlock describe
application environments, TruffleHog verifies leaked strings (AGPL), and Vault KV custom metadata
stores who wrote what. None joins declaration, discovery, seeding, verification and enforcement for
ExternalSecrets. wellhead does, with annotations on the ExternalSecret itself.

## The spec

| Annotation | Value |
| --- | --- |
| `wellhead.dev/origin` | **Required.** `provided` (a person supplies it), `preserve` (provided or generated once, never regenerated), `rolled` (provided once, then a controller rotates it), `minted` (a controller in the cluster writes it), `projected` (another ExternalSecret seeds the path) |
| `wellhead.dev/how` | Where a person gets the value, one paragraph. Required for `provided`, `preserve`, `rolled` |
| `wellhead.dev/docs` | An `https://` URL |
| `wellhead.dev/fields` | Field names at the path, space-separated; needed with `dataFrom.extract` |
| `wellhead.dev/plain` | Fields shown while typed |
| `wellhead.dev/generate` | Fields that may be left empty to generate; a typed value is asked twice |
| `wellhead.dev/verify` | Checks: `http`, `format`, `github-app`, `github-token`, `gitlab-token`, `slack-bot-token`, `cloudflare-token`, `x-...`, or `none` as a reviewed exception. Required when a person enters the value |
| `wellhead.dev/verify.<kind>.<param>` | A parameter of a check ([verifiers](docs/verifiers.md)) |
| `wellhead.dev/expires` | Expiry of the current value, `YYYY-MM-DD` |
| `wellhead.dev/lifetime` | Lifetime of a freshly issued value: `36h`, `90d`, `12w` |
| `wellhead.dev/rotate-on-compromise` | `"true"` or `"false"` |

Values are flat strings because admission CEL cannot parse JSON inside an annotation. The rules
(WH001 to WH015) and the reasoning are in
[ADR-0001](docs/adrs/0001-an-externalsecret-declares-where-its-value-comes-from.md).

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: registry
  namespace: apps
  annotations:
    wellhead.dev/origin: provided
    wellhead.dev/how: Registry, robot accounts, create one with pull rights on the apps project.
    wellhead.dev/fields: username password
    wellhead.dev/plain: username
    wellhead.dev/verify: http
    wellhead.dev/verify.http.url: https://registry.example.com/v2/
    wellhead.dev/verify.http.auth: basic:username:password
    wellhead.dev/lifetime: 365d
spec:
  refreshInterval: "0"
  secretStoreRef: { kind: ClusterSecretStore, name: vault }
  target: { name: registry }
  dataFrom:
    - extract: { key: apps/registry }
```

## Quickstart

Install the CLI from a [release](https://github.com/wellhead-dev/wellhead/releases), or
`go install github.com/wellhead-dev/wellhead/cmd/wellhead@latest`.

Lint manifests in CI; the exit status is 1 when a rule is broken:

```sh
wellhead lint kubernetes/
```

Find what the vault does not hold, reading every path and field from the vault itself:

```sh
export VAULT_ADDR=https://vault.example.com VAULT_TOKEN=...   # or BAO_ADDR and BAO_TOKEN
wellhead missing            # add --verify to run each check on the values that exist
```

Seed one ExternalSecret. wellhead shows `how`, asks each missing field without echo (`plain` fields
are shown), runs the checks, writes with check-and-set, records `seeded-by`, `seeded-at` and
`expires` as KV custom metadata, then forces ESO to sync and waits for Ready:

```sh
wellhead seed apps/registry
wellhead seed apps/github-app private_key=@./app.pem   # a file, read once; values never go on argv
```

Install the admission policy (Kubernetes 1.30 or newer). It warns and audits by default:

```sh
helm install wellhead oci://ghcr.io/wellhead-dev/charts/wellhead
# once every ExternalSecret is annotated:
helm upgrade wellhead oci://ghcr.io/wellhead-dev/charts/wellhead --set 'admissionPolicy.validationActions={Deny}'
```

Set `kyverno.enabled=true` (and `admissionPolicy.enabled=false`) for a Kyverno `ValidatingPolicy`
with background PolicyReports instead.

## Develop

```sh
mise run setup     # pinned toolchain
mise run verify    # gofmt, vet, build, test, golangci-lint, helm lint, offline policy fixtures, actionlint
mise run admission # the fixtures against the cluster in your current context
```

Start at [docs/index.md](docs/index.md). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Code: [Apache-2.0](LICENSE). Documentation: [CC-BY-4.0](LICENSES/CC-BY-4.0.txt).
