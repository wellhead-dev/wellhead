#!/usr/bin/env bash
# Renders the chart and runs every fixture in testdata/policy through the Kyverno CLI,
# once with the native ValidatingAdmissionPolicy and once with the Kyverno ValidatingPolicy.
# A pass fixture must pass; a fail fixture must fail with its own rule id (the file name prefix).
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
crd=testdata/crd/externalsecret-stub.yaml
helm template wellhead deploy/charts/wellhead >"$work/native.yaml"
helm template wellhead deploy/charts/wellhead --set admissionPolicy.enabled=false --set kyverno.enabled=true >"$work/kyverno.yaml"
status=0
for flavour in native kyverno; do
  for fixture in testdata/policy/pass/*.yaml testdata/policy/fail/*.yaml; do
    out="$(kyverno apply "$work/$flavour.yaml" --resource "$fixture" --crd-paths "$crd" --remove-color 2>&1 || true)"
    name="$(basename "$fixture")"
    case "$fixture" in
      */pass/*)
        if ! grep -q 'pass: 1, fail: 0' <<<"$out"; then
          echo "$flavour: $name should pass:" >&2
          echo "$out" >&2
          status=1
        fi
        ;;
      */fail/*)
        rule="${name%%-*}"
        if ! grep -q 'fail: 1' <<<"$out" || ! grep -q "$rule: " <<<"$out" || [ "$(grep -cE 'WH[0-9]{3}: ' <<<"$out")" -ne 1 ]; then
          echo "$flavour: $name should fail with $rule only:" >&2
          echo "$out" >&2
          status=1
        fi
        ;;
    esac
  done
done
if [ "$status" -eq 0 ]; then
  echo "policy fixtures: native and Kyverno policies agree with testdata/policy"
fi
exit "$status"
