package cli_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wellhead-dev/wellhead/internal/cli"
	"github.com/wellhead-dev/wellhead/internal/kube"
	"github.com/wellhead-dev/wellhead/internal/vault"
)

var now = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

type fakeCluster struct {
	es     map[string]map[string]any
	synced []string
}

func (f *fakeCluster) ListExternalSecrets(context.Context, string) ([]map[string]any, error) {
	var out []map[string]any
	for _, e := range f.es {
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeCluster) GetExternalSecret(_ context.Context, ns, name string) (map[string]any, error) {
	e, ok := f.es[ns+"/"+name]
	if !ok {
		return nil, kube.ErrNotFound
	}
	return e, nil
}

func (f *fakeCluster) GetStore(_ context.Context, kind, _, name string) (map[string]any, error) {
	switch {
	case kind == "ClusterSecretStore" && name == "vault":
		return map[string]any{"spec": map[string]any{"provider": map[string]any{"vault": map[string]any{"path": "kv", "version": "v2"}}}}, nil
	case name == "aws":
		return map[string]any{"spec": map[string]any{"provider": map[string]any{"aws": map[string]any{}}}}, nil
	}
	return nil, kube.ErrNotFound
}

func (f *fakeCluster) ForceSync(_ context.Context, ns, name string, _ time.Time) error {
	f.synced = append(f.synced, ns+"/"+name)
	return nil
}

func (f *fakeCluster) WaitReady(context.Context, string, string, time.Time, time.Duration) (kube.Condition, error) {
	return kube.Condition{Status: "True"}, nil
}

type fakeVault struct {
	paths  map[string]*vault.Secret
	meta   map[string]map[string]string
	writes int
}

func (f *fakeVault) Read(_ context.Context, mount, path string) (*vault.Secret, error) {
	s, ok := f.paths[mount+"/"+path]
	if !ok {
		return nil, vault.ErrNotFound
	}
	cp := &vault.Secret{Data: map[string]string{}, Version: s.Version}
	for k, v := range s.Data {
		cp.Data[k] = v
	}
	return cp, nil
}

func (f *fakeVault) Write(_ context.Context, mount, path string, data map[string]string, version int) (int, error) {
	cur := f.paths[mount+"/"+path]
	curVersion := 0
	if cur != nil {
		curVersion = cur.Version
	}
	if version >= 0 && version != curVersion {
		return 0, errors.New("check-and-set parameter did not match")
	}
	f.writes++
	f.paths[mount+"/"+path] = &vault.Secret{Data: data, Version: curVersion + 1}
	return curVersion + 1, nil
}

func (f *fakeVault) MergeMetadata(_ context.Context, mount, path string, custom map[string]string) error {
	if f.meta == nil {
		f.meta = map[string]map[string]string{}
	}
	f.meta[mount+"/"+path] = custom
	return nil
}

func (f *fakeVault) Self(context.Context) (string, error) { return "oidc-alice", nil }

type fakePrompt struct {
	answers []string
	secret  []string
	line    []string
	confirm bool
}

func (p *fakePrompt) next() (string, error) {
	if len(p.answers) == 0 {
		return "", errors.New("no more answers")
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return a, nil
}

func (p *fakePrompt) Secret(label string) (string, error) {
	p.secret = append(p.secret, label)
	return p.next()
}

func (p *fakePrompt) Line(label string) (string, error) {
	p.line = append(p.line, label)
	return p.next()
}

func (p *fakePrompt) Confirm(string) (bool, error) { return p.confirm, nil }

type harness struct {
	cluster *fakeCluster
	vault   *fakeVault
	prompt  *fakePrompt
	out     bytes.Buffer
	err     bytes.Buffer
}

func newHarness(es ...map[string]any) *harness {
	h := &harness{cluster: &fakeCluster{es: map[string]map[string]any{}}, vault: &fakeVault{paths: map[string]*vault.Secret{}}, prompt: &fakePrompt{}}
	for _, e := range es {
		meta := e["metadata"].(map[string]any)
		h.cluster.es[meta["namespace"].(string)+"/"+meta["name"].(string)] = e
	}
	return h
}

func (h *harness) run(args ...string) int {
	return cli.Run(context.Background(), args, cli.Deps{
		Version: "test",
		Stdout:  &h.out,
		Stderr:  &h.err,
		Prompt:  h.prompt,
		Now:     func() time.Time { return now },
		Cluster: func(cli.ClusterOptions) (cli.Cluster, error) { return h.cluster, nil },
		Vault:   func() (cli.Vault, error) { return h.vault, nil },
	})
}

func externalSecret(name string, ann map[string]string, spec map[string]any) map[string]any {
	a := map[string]any{}
	for k, v := range ann {
		a[k] = v
	}
	if spec == nil {
		spec = map[string]any{"dataFrom": []any{map[string]any{"extract": map[string]any{"key": "apps/" + name}}}}
	}
	if _, ok := spec["secretStoreRef"]; !ok {
		spec["secretStoreRef"] = map[string]any{"kind": "ClusterSecretStore", "name": "vault"}
	}
	return map[string]any{
		"apiVersion": "external-secrets.io/v1",
		"kind":       "ExternalSecret",
		"metadata":   map[string]any{"name": name, "namespace": "apps", "annotations": a},
		"spec":       spec,
	}
}

func registry(extra map[string]string) map[string]any {
	ann := map[string]string{
		"wellhead.dev/origin":                 "provided",
		"wellhead.dev/how":                    "Registry, robot accounts, create one with pull rights.",
		"wellhead.dev/fields":                 "username password",
		"wellhead.dev/plain":                  "username",
		"wellhead.dev/verify":                 "format",
		"wellhead.dev/verify.format.password": "[a-z0-9-]{8,}",
		"wellhead.dev/lifetime":               "30d",
	}
	for k, v := range extra {
		ann[k] = v
	}
	return externalSecret("registry", ann, nil)
}

func TestLintFixtures(t *testing.T) {
	h := newHarness()
	if code := h.run("lint", "../../testdata/policy/pass"); code != 0 {
		t.Fatalf("pass fixtures: exit %d\n%s%s", code, h.out.String(), h.err.String())
	}
	h = newHarness()
	if code := h.run("lint", "../../testdata/policy/fail"); code != 1 {
		t.Fatalf("fail fixtures: exit %d", code)
	}
	for _, id := range []string{"WH001", "WH007", "WH015"} {
		if !strings.Contains(h.out.String(), id+": ") {
			t.Errorf("lint output lacks %s", id)
		}
	}
	h = newHarness()
	if code := h.run("lint", "--store", "elsewhere", "../../testdata/policy/fail"); code != 0 {
		t.Fatalf("--store must leave out other stores: exit %d", code)
	}
}

func TestLintUnparsableFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.yaml"), []byte("a: [b"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness()
	if code := h.run("lint", dir); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestMissingReadsTheVaultNotTheStatus(t *testing.T) {
	minted := externalSecret("db", map[string]string{"wellhead.dev/origin": "minted"}, nil)
	other := externalSecret("cloud", map[string]string{"wellhead.dev/origin": "minted"}, map[string]any{"secretStoreRef": map[string]any{"kind": "SecretStore", "name": "aws"}})
	h := newHarness(registry(nil), minted, other)
	h.vault.paths["kv/apps/registry"] = &vault.Secret{Data: map[string]string{"username": "robot"}, Version: 1}
	if code := h.run("missing"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	out := h.out.String()
	for _, want := range []string{"apps/registry", "kv/apps/registry", "password", "wellhead seed apps/registry", "minted: waiting for the controller"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "robot") {
		t.Error("output shows a value")
	}
	if !strings.Contains(h.err.String(), "not a Vault or OpenBao store") {
		t.Errorf("a skipped store must be reported: %s", h.err.String())
	}
}

func TestMissingVerifyReportsRejectedValues(t *testing.T) {
	h := newHarness(registry(nil))
	h.vault.paths["kv/apps/registry"] = &vault.Secret{Data: map[string]string{"username": "robot", "password": "WRONG PASTE"}, Version: 1}
	if code := h.run("missing"); code != 0 {
		t.Fatalf("without --verify present fields are ok: exit %d", code)
	}
	h.out.Reset()
	if code := h.run("missing", "--verify"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.out.String(), "rejected") || strings.Contains(h.out.String(), "WRONG PASTE") {
		t.Fatalf("got:\n%s", h.out.String())
	}
}

func TestSeedAsksOnlyWhatIsMissingVerifiesWritesAndSyncs(t *testing.T) {
	h := newHarness(registry(nil))
	h.vault.paths["kv/apps/registry"] = &vault.Secret{Data: map[string]string{"username": "robot"}, Version: 4}
	h.prompt.answers = []string{"correct-horse-battery"}
	if code := h.run("seed", "apps/registry"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err.String())
	}
	if len(h.prompt.secret) != 1 || len(h.prompt.line) != 0 || !strings.HasPrefix(h.prompt.secret[0], "password") {
		t.Fatalf("asked secret %v, line %v", h.prompt.secret, h.prompt.line)
	}
	got := h.vault.paths["kv/apps/registry"]
	if got.Version != 5 || got.Data["username"] != "robot" || got.Data["password"] != "correct-horse-battery" {
		t.Fatalf("vault holds %+v", got)
	}
	meta := h.vault.meta["kv/apps/registry"]
	if meta["seeded-by"] != "oidc-alice" || meta["seeded-at"] != "2026-10-27T12:00:00Z" || meta["expires"] != "2026-11-26T12:00:00Z" {
		t.Fatalf("metadata %v", meta)
	}
	if len(h.cluster.synced) != 1 {
		t.Fatal("no force-sync")
	}
	if strings.Contains(h.err.String()+h.out.String(), "correct-horse-battery") {
		t.Fatal("a value was printed")
	}
}

func TestSeedShowsPlainFieldsWhileTyped(t *testing.T) {
	h := newHarness(registry(nil))
	h.prompt.answers = []string{"robot", "correct-horse-battery"}
	if code := h.run("seed", "--no-sync", "apps/registry"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err.String())
	}
	if len(h.prompt.line) != 1 || !strings.HasPrefix(h.prompt.line[0], "username") {
		t.Fatalf("username must be asked in the open: %v", h.prompt.line)
	}
}

func TestSeedWritesNothingWhenTheCheckRejects(t *testing.T) {
	h := newHarness(registry(nil))
	h.prompt.answers = []string{"robot", "NOT VALID"}
	if code := h.run("seed", "apps/registry"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if h.vault.writes != 0 || len(h.cluster.synced) != 0 {
		t.Fatal("something was written after a rejection")
	}
	if strings.Contains(h.err.String(), "NOT VALID") {
		t.Fatal("the rejected value was printed")
	}
}

func TestSeedGeneratesOrConfirmsAChosenValue(t *testing.T) {
	es := externalSecret("key", map[string]string{
		"wellhead.dev/origin":   "preserve",
		"wellhead.dev/how":      "Leave empty to generate.",
		"wellhead.dev/fields":   "encryption_key",
		"wellhead.dev/generate": "encryption_key",
		"wellhead.dev/verify":   "none",
	}, nil)
	h := newHarness(es)
	h.prompt.answers = []string{""}
	if code := h.run("seed", "apps/key"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err.String())
	}
	if v := h.vault.paths["kv/apps/key"].Data["encryption_key"]; len(v) != 43 {
		t.Fatalf("generated %d characters", len(v))
	}
	h = newHarness(es)
	h.prompt.answers = []string{"chosen-value-1", "chosen-value-2"}
	if code := h.run("seed", "apps/key"); code != 1 || h.vault.writes != 0 {
		t.Fatalf("two different entries must write nothing: exit %d, writes %d", code, h.vault.writes)
	}
}

func TestSeedNeverOverwritesPreserve(t *testing.T) {
	es := externalSecret("key", map[string]string{
		"wellhead.dev/origin": "preserve",
		"wellhead.dev/how":    "At-rest key.",
		"wellhead.dev/fields": "encryption_key",
		"wellhead.dev/verify": "none",
	}, nil)
	h := newHarness(es)
	h.vault.paths["kv/apps/key"] = &vault.Secret{Data: map[string]string{"encryption_key": "k"}, Version: 1}
	if code := h.run("seed", "--rotate", "apps/key"); code != 1 || h.vault.writes != 0 {
		t.Fatalf("exit %d, writes %d", code, h.vault.writes)
	}
}

func TestSeedRefusesMintedAndProjected(t *testing.T) {
	for _, origin := range []string{"minted", "projected"} {
		h := newHarness(externalSecret("x", map[string]string{"wellhead.dev/origin": origin}, nil))
		if code := h.run("seed", "apps/x"); code != 1 || !strings.Contains(h.err.String(), origin) {
			t.Fatalf("%s: exit %d: %s", origin, code, h.err.String())
		}
	}
}

func TestSeedRefusesAnExternalSecretThatBreaksTheSpec(t *testing.T) {
	h := newHarness(externalSecret("x", map[string]string{"wellhead.dev/origin": "provided"}, nil))
	if code := h.run("seed", "apps/x"); code != 1 || !strings.Contains(h.err.String(), "WH003") {
		t.Fatalf("exit %d: %s", code, h.err.String())
	}
}

func TestSeedRefusesValuesOnTheCommandLine(t *testing.T) {
	h := newHarness(registry(nil))
	if code := h.run("seed", "apps/registry", "password=hunter2"); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(h.err.String(), "hunter2") {
		t.Fatal("the value was echoed")
	}
}

func TestSeedReadsAFileField(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyFile, []byte("pem-contents-here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	es := externalSecret("app", map[string]string{
		"wellhead.dev/origin": "provided",
		"wellhead.dev/how":    "GitHub App settings.",
		"wellhead.dev/fields": "app_id private_key",
		"wellhead.dev/plain":  "app_id",
		"wellhead.dev/verify": "none",
	}, nil)
	h := newHarness(es)
	h.prompt.answers = []string{"4242"}
	if code := h.run("seed", "--no-sync", "apps/app", "private_key=@"+keyFile); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err.String())
	}
	if h.vault.paths["kv/apps/app"].Data["private_key"] != "pem-contents-here\n" {
		t.Fatal("file contents not written as is")
	}
	if len(h.prompt.secret) != 0 {
		t.Fatal("a file field was prompted for")
	}
}

func TestSeedNothingMissing(t *testing.T) {
	h := newHarness(registry(nil))
	h.vault.paths["kv/apps/registry"] = &vault.Secret{Data: map[string]string{"username": "robot", "password": "p"}, Version: 1}
	if code := h.run("seed", "apps/registry"); code != 0 || h.vault.writes != 0 {
		t.Fatalf("exit %d", code)
	}
}
