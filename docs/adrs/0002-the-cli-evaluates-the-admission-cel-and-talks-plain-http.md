---
status: "accepted"
date: "2026-10-28"
review-by: "2027-04-28"
---

# The CLI evaluates the admission CEL itself and talks plain HTTP to Kubernetes and the vault

## Context and Problem Statement

`wellhead lint` must apply the same rules as the admission policy, and `wellhead missing` and
`wellhead seed` need the Kubernetes API (list ExternalSecrets, read stores, force a sync) and the KV v2
API of Vault or OpenBao. Which libraries does the CLI depend on?

## Decision Drivers

- Lint and admission must not drift: a rule written twice drifts.
- A small dependency set: fewer modules to review, update and license-check.
- Real clusters authenticate with exec credential plugins (cloud CLIs, OIDC login helpers).

## Considered Options

- Evaluate the chart's CEL with `github.com/google/cel-go`; plain HTTP to the API server with a small
  kubeconfig loader; plain HTTP to KV v2.
- Reimplement the rules in Go; plain HTTP as above.
- `k8s.io/client-go` and the Vault Go client.
- Shell out to `kubectl` and `bao`/`vault`.

## Decision Outcome

Chosen option: "Evaluate the chart's CEL with cel-go; plain HTTP to both APIs", because one rule file
then serves admission and lint, and the HTTP surface wellhead needs is five Kubernetes calls and four
KV v2 calls.

- `deploy/embed.go` embeds `deploy/charts/wellhead/files/rules.yaml`; `internal/policy` compiles it
  with cel-go, optional types and the strings extension, the libraries the API server enables.
- `internal/kube` reads a kubeconfig (token, token file, client certificate, CA, exec plugin) or the
  in-cluster service account. Legacy `auth-provider` entries are refused with a message.
- `internal/vault` speaks KV v2: read, check-and-set write, merge custom metadata, token lookup.
  Values travel in request bodies, never in a URL or on a command line.

Direct dependencies: cel-go, go.yaml.in/yaml/v3, golang.org/x/term.

### Consequences

- Good, because a rule change is one edit, and the fixtures prove CLI, Kyverno and the API server agree.
- Good, because the module graph stays small (cel-go brings antlr and protobuf; nothing else of note).
- Bad, because the kubeconfig loader is ours to maintain; merged multi-file kubeconfigs are read as
  the first existing file, not merged.
- Bad, because cel-go's version can differ from the API server's; the kind matrix catches a divergence.

### Confirmation

- `go mod graph` lists no `k8s.io/` module.
- `go test ./internal/kube/` covers token and exec-plugin kubeconfigs against an httptest API server.

## Pros and Cons of the Options

### Reimplement the rules in Go

- Good, because no CEL dependency.
- Bad, because two implementations of every rule drift, which is the failure the project exists to stop.

### client-go and the Vault client

- Good, because every kubeconfig feature works.
- Bad, because client-go pulls in the Kubernetes API machinery, tens of modules, for five calls.

### Shell out

- Good, because authentication is the tools' problem.
- Bad, because it needs both CLIs installed at compatible versions, and passing values safely to a
  child process is easy to get wrong.

## More Information

- Re-evaluate when a user needs a kubeconfig feature the loader lacks (merged files, proxy-url,
  plugin-issued client certificates).
- 2026-10-28: accepted with the v0.1 scope.
