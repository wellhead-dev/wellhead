# Architecture Decision Records

Decisions that outlive the change that prompted them are recorded here, in
[MADR 4.0](https://adr.github.io/madr/) with two local rules:

1. **Supersession is append-only.** An accepted record's `status:` is never flipped. A new record
   carries `supersedes: NNNN` in its front matter, and the table below shows the current view. Files
   are never renamed and numbers are never reused. A record's own history is appended, dated, under
   *More Information*.
2. **Every record says how it is checked.** A `### Confirmation` section names the test, CI job or
   script that fails when the decision is not followed. A decision that can change carries
   `review-by:` and names what would reopen it.

Evidence stays out of the record: research goes in `docs/research/YYYY-MM-DD-<topic>.md` and is linked.

## Records

| No. | Decision | Status |
| --- | --- | --- |
| [0001](0001-an-externalsecret-declares-where-its-value-comes-from.md) | An ExternalSecret declares where its value comes from (spec v1alpha1) | accepted |
| [0002](0002-the-cli-evaluates-the-admission-cel-and-talks-plain-http.md) | The CLI evaluates the admission CEL itself and talks plain HTTP | accepted |
| [0003](0003-the-policy-pack-is-a-native-validatingadmissionpolicy-with-an-optional-kyverno-policy.md) | The policy pack is a native ValidatingAdmissionPolicy, with an optional Kyverno policy | accepted |
| [0004](0004-semantic-release-cuts-tags-and-goreleaser-publishes-them.md) | semantic-release cuts tags, GoReleaser and Helm publish them, signed keylessly | accepted |
