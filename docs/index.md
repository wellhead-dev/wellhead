# wellhead documentation

- [README](../README.md): what wellhead is, quickstart and the annotation table.
- [Spec v1alpha1](adrs/0001-an-externalsecret-declares-where-its-value-comes-from.md): every annotation,
  origin and rule, and why.
- [Verifiers](verifiers.md): the check kinds and their parameters.
- [Releasing](releasing.md): branches, tags, the seed tag, and how to verify a download.
- [Decisions](adrs/README.md): the ADR ledger.
- [Research](research/2026-10-27-feature-backlog.md): the feature backlog the v0.1 scope came from.

## Layout

| Path | What |
| --- | --- |
| `cmd/wellhead` | Environment-to-config wiring only |
| `internal/policy` | Compiles and evaluates the rule file with CEL |
| `internal/manifest` | Finds ExternalSecrets in plain multi-document YAML |
| `internal/spec` | Reads the annotations and the vault paths an ExternalSecret reads |
| `internal/kube` | Kubeconfig loader and the few Kubernetes calls wellhead makes |
| `internal/vault` | KV v2 over HTTP |
| `internal/verify` | The verifiers |
| `internal/cli` | The `lint`, `missing` and `seed` commands |
| `deploy/charts/wellhead` | The Helm chart; `files/rules.yaml` is the one rule source |
| `testdata/policy` | Pass and fail fixtures shared by lint tests, the Kyverno CLI and the kind matrix |
