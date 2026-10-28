package policy_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/wellhead-dev/wellhead/internal/manifest"
	"github.com/wellhead-dev/wellhead/internal/policy"
)

func load(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Load()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func fixtures(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "policy", dir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures in %s: %v", dir, err)
	}
	return files
}

func evaluate(t *testing.T, p *policy.Policy, file string) []policy.Violation {
	t.Helper()
	docs, err := manifest.ScanFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("%s: want one ExternalSecret, got %d", file, len(docs))
	}
	return p.Evaluate(docs[0].Object)
}

func TestPassFixturesHaveNoViolations(t *testing.T) {
	p := load(t)
	for _, f := range fixtures(t, "pass") {
		for _, v := range evaluate(t, p, f) {
			t.Errorf("%s: %s", filepath.Base(f), v.Message)
		}
	}
}

func TestFailFixturesBreakExactlyTheirRule(t *testing.T) {
	p := load(t)
	for _, f := range fixtures(t, "fail") {
		want := strings.SplitN(filepath.Base(f), "-", 2)[0]
		var got []string
		for _, v := range evaluate(t, p, f) {
			got = append(got, v.Rule)
			if !strings.HasPrefix(v.Message, v.Rule+": ") {
				t.Errorf("%s: message %q does not start with its rule id", filepath.Base(f), v.Message)
			}
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: want only %s, got %v", filepath.Base(f), want, got)
		}
	}
}

func TestEveryRuleHasAFailFixture(t *testing.T) {
	p := load(t)
	covered := map[string]bool{}
	for _, f := range fixtures(t, "fail") {
		covered[strings.SplitN(filepath.Base(f), "-", 2)[0]] = true
	}
	for _, id := range p.RuleIDs() {
		if !covered[id] {
			t.Errorf("rule %s has no fixture in testdata/policy/fail", id)
		}
	}
}

func TestMessagesNameTheOffenders(t *testing.T) {
	p := load(t)
	cases := map[string]string{
		"WH005-unknown-verify-kind.yaml":      "githubapp",
		"WH013-unknown-annotation.yaml":       "wellhead.dev/feilds",
		"WH015-plain-names-unread-field.yaml": "user",
		"WH002-unknown-origin.yaml":           `"generated"`,
	}
	for file, want := range cases {
		vs := evaluate(t, p, filepath.Join("..", "..", "testdata", "policy", "fail", file))
		if len(vs) != 1 || !strings.Contains(vs[0].Message, want) {
			t.Errorf("%s: want a message naming %s, got %v", file, want, vs)
		}
	}
}

func TestAnExternalSecretWithoutMetadataIsReportedNotPanicking(t *testing.T) {
	p := load(t)
	vs := p.Evaluate(map[string]any{"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret"})
	var ids []string
	for _, v := range vs {
		ids = append(ids, v.Rule)
	}
	sort.Strings(ids)
	if len(ids) != 1 || ids[0] != "WH001" {
		t.Fatalf("want WH001 only, got %v", ids)
	}
}

func TestRulesFileIsTheChartsFile(t *testing.T) {
	chart, err := os.ReadFile(filepath.Join("..", "..", "deploy", "charts", "wellhead", "files", "rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse(chart)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.RuleIDs(), ",") != strings.Join(load(t).RuleIDs(), ",") {
		t.Fatal("embedded rules differ from the chart's rules")
	}
	if p.SpecVersion != "v1alpha1" {
		t.Fatalf("spec version %q", p.SpecVersion)
	}
}
