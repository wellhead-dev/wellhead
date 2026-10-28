#!/usr/bin/env bash
# Runs testdata/policy through a live API server: installs the External Secrets Operator CRDs and the
# chart into the cluster of the current kubectl context (a disposable kind cluster in CI), then applies
# every fixture with --dry-run=server. With Warn, a fail fixture is admitted with a warning naming its
# rule; with Deny, it is refused with that rule. A pass fixture is admitted without a warning both times.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ESO_VERSION:?set ESO_VERSION to the External Secrets Operator release whose CRDs to install}"

kubectl apply --server-side -f "https://raw.githubusercontent.com/external-secrets/external-secrets/v${ESO_VERSION}/deploy/crds/bundle.yaml" >/dev/null
kubectl wait --for condition=established --timeout=120s crd/externalsecrets.external-secrets.io

probe=testdata/policy/fail/WH001-no-origin.yaml

install() {
  helm upgrade --install wellhead deploy/charts/wellhead --wait --set "admissionPolicy.validationActions={$1}"
  local out code
  for _ in $(seq 1 60); do
    code=0
    out="$(kubectl apply --dry-run=server -f "$probe" 2>&1)" || code=$?
    if grep -q 'WH001: ' <<<"$out" && { [ "$1" != Deny ] || [ "$code" -ne 0 ]; }; then
      return 0
    fi
    sleep 2
  done
  echo "the policy did not take effect within two minutes" >&2
  exit 1
}

status=0
check() {
  local mode="$1" fixture out code rule
  for fixture in testdata/policy/pass/*.yaml testdata/policy/fail/*.yaml; do
    code=0
    out="$(kubectl apply --dry-run=server -f "$fixture" 2>&1)" || code=$?
    rule="$(basename "$fixture")"
    rule="${rule%%-*}"
    case "$fixture" in
      */pass/*)
        if [ "$code" -ne 0 ] || grep -qE 'WH[0-9]{3}: ' <<<"$out"; then
          echo "$mode: $fixture should be admitted without a warning:" >&2
          echo "$out" >&2
          status=1
        fi
        ;;
      */fail/*)
        local want_code=0
        [ "$mode" = Deny ] && want_code=1
        if [ "$((code != 0))" -ne "$want_code" ] || ! grep -q "$rule: " <<<"$out" || [ "$(grep -oE 'WH[0-9]{3}: ' <<<"$out" | sort -u | wc -l)" -ne 1 ]; then
          echo "$mode: $fixture should be $([ "$mode" = Deny ] && echo refused || echo warned) with $rule only (exit $code):" >&2
          echo "$out" >&2
          status=1
        fi
        ;;
    esac
  done
}

install "Warn,Audit"
check Warn
install "Deny"
check Deny

if [ "$status" -eq 0 ]; then
  echo "admission: Kubernetes $(kubectl version -o json | yq -p json '.serverVersion.gitVersion') agrees with testdata/policy in Warn and Deny"
fi
exit "$status"
