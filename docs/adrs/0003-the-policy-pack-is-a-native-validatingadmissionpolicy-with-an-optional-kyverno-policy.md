---
status: "accepted"
date: "2026-10-28"
review-by: "2027-04-28"
---

# The policy pack is a native ValidatingAdmissionPolicy, with an optional Kyverno ValidatingPolicy

## Context and Problem Statement

The spec (ADR-0001) is enforced at admission so that an ExternalSecret without a declaration is
noticed when it is applied, not when its value goes missing. Which admission mechanism ships in the
Helm chart, and how does an estate move from finding gaps to refusing them?

## Decision Drivers

- No extra controller for the common case.
- Estates already running Kyverno want PolicyReports from its background scan.
- An estate with hundreds of unannotated ExternalSecrets must be able to adopt without breaking
  reconciliation.
- One rule source for every enforcement point.

## Considered Options

- Native ValidatingAdmissionPolicy (VAP) by default, Kyverno ValidatingPolicy (`policies.kyverno.io/v1`)
  behind a value, both rendered from `files/rules.yaml`.
- Kyverno only.
- A validating webhook served by wellhead.

## Decision Outcome

Chosen option: "Native VAP by default, Kyverno ValidatingPolicy behind a value", because the API server
evaluates VAP itself (GA since Kubernetes 1.30, so the chart requires 1.30 or newer) and Kyverno users
get reports without a second rule source.

- `admissionPolicy.validationActions` defaults to `[Warn, Audit]`. `failurePolicy` defaults to `Ignore`
  while the actions lack `Deny`, so an evaluation error cannot turn into a rejected ExternalSecret and
  a stuck GitOps reconciliation; with `Deny` it becomes `Fail`. Both can be set explicitly.
- `storeNames` limits the policy to ExternalSecrets on named stores.
- `kyverno.enabled` renders the same rules as a Kyverno ValidatingPolicy (`Audit`, background scan on).
  Kyverno also reports on native policies, so an estate enables one of the two to avoid duplicate
  warnings.
- ExternalSecrets are custom resources, so the API server does not type-check the CEL. Fixtures cover
  every rule instead, and run three ways: `wellhead lint` (Go tests), the Kyverno CLI offline against
  both rendered policies (`scripts/check-policy-offline.sh`), and a live API server on the oldest and
  newest supported Kubernetes minor (`scripts/admission-test.sh` in the CI `admission` job), in Warn and
  in Deny.

### Consequences

- Good, because nothing runs in the cluster for the default install.
- Good, because adoption is a values change: Warn and Audit, then Deny.
- Bad, because ClusterExternalSecret is not covered: its annotations sit on a template, and the
  generated ExternalSecrets are checked when created.
- Bad, because VAP warnings are only seen by whoever applies; a GitOps controller swallows them. The
  Audit annotation and `wellhead lint` in CI are where most estates see violations.

### Confirmation

- `helm lint` and `helm template` pass for the default values and for Deny with Kyverno and store names.
- `scripts/check-policy-offline.sh` passes for both rendered policies.
- The `admission` job passes on both kind legs.

## Pros and Cons of the Options

### Kyverno only

- Good, because reports and exceptions come built in.
- Bad, because it makes Kyverno a prerequisite for a policy the API server can run alone.

### A wellhead webhook

- Good, because it could check the vault at admission.
- Bad, because a webhook is a service to run, secure and keep available, and admission would then
  depend on the vault being reachable.

## More Information

- Re-evaluate when ESO adds a CEL-checkable schema for annotations, or when MutatingAdmissionPolicy
  could add defaults worth having.
- 2026-10-28: accepted with the v0.1 scope.
