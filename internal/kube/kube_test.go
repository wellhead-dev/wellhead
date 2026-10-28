package kube_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wellhead-dev/wellhead/internal/kube"
)

func kubeconfig(t *testing.T, srv *httptest.Server, user string) string {
	t.Helper()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	cfg := `apiVersion: v1
kind: Config
current-context: test
clusters:
  - name: c
    cluster:
      server: ` + srv.URL + `
      certificate-authority-data: ` + base64.StdEncoding.EncodeToString(ca) + `
contexts:
  - name: test
    context: {cluster: c, user: u, namespace: apps}
users:
  - name: u
    user:
` + user
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type fakeAPI struct {
	t     *testing.T
	token string
	patch map[string]any
	ready string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /apis/external-secrets.io/v1":
		_, _ = w.Write([]byte(`{}`))
	case "GET /apis/external-secrets.io/v1/externalsecrets":
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"a","namespace":"apps"}}]}`))
	case "PATCH /apis/external-secrets.io/v1/namespaces/apps/externalsecrets/a":
		if r.Header.Get("Content-Type") != "application/merge-patch+json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &f.patch)
		f.ready = time.Now().UTC().Add(time.Second).Format(time.RFC3339)
		_, _ = w.Write([]byte(`{}`))
	case "GET /apis/external-secrets.io/v1/namespaces/apps/externalsecrets/a":
		status := map[string]any{}
		if f.ready != "" {
			status["conditions"] = []any{map[string]any{"type": "Ready", "status": "True", "lastTransitionTime": f.ready}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"name": "a"}, "status": status})
	case "GET /apis/external-secrets.io/v1/clustersecretstores/vault":
		_, _ = w.Write([]byte(`{"spec":{"provider":{"vault":{"server":"https://vault.example","path":"kv","version":"v2"}}}}`))
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestClientWithTokenKubeconfig(t *testing.T) {
	api := &fakeAPI{t: t, token: "static-token"}
	srv := httptest.NewTLSServer(api)
	defer srv.Close()
	cfg, err := kube.Load(kube.Options{Kubeconfig: kubeconfig(t, srv, "      token: static-token\n")})
	if err != nil {
		t.Fatal(err)
	}
	c := kube.New(cfg)
	if c.Namespace() != "apps" {
		t.Fatalf("namespace %q", c.Namespace())
	}
	ctx := context.Background()
	items, err := c.ListExternalSecrets(ctx, "")
	if err != nil || len(items) != 1 {
		t.Fatalf("got %v, %v", items, err)
	}
	store, err := c.GetStore(ctx, "ClusterSecretStore", "apps", "vault")
	if err != nil {
		t.Fatal(err)
	}
	vs, ok := kube.Vault(store)
	if !ok || vs.Mount != "kv" || vs.Version != "v2" {
		t.Fatalf("got %+v", vs)
	}
	since := time.Now()
	if err := c.ForceSync(ctx, "apps", "a", since); err != nil {
		t.Fatal(err)
	}
	ann := api.patch["metadata"].(map[string]any)["annotations"].(map[string]any)
	if ann["force-sync"] == "" {
		t.Fatal("no force-sync annotation")
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := c.WaitReady(wctx, "apps", "a", since, 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestClientWithExecPlugin(t *testing.T) {
	api := &fakeAPI{t: t, token: "from-plugin"}
	srv := httptest.NewTLSServer(api)
	defer srv.Close()
	plugin := filepath.Join(t.TempDir(), "plugin.sh")
	script := "#!/bin/sh\necho '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"from-plugin\"}}'\n"
	if err := os.WriteFile(plugin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	user := "      exec:\n        apiVersion: client.authentication.k8s.io/v1\n        command: " + plugin + "\n"
	cfg, err := kube.Load(kube.Options{Kubeconfig: kubeconfig(t, srv, user)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kube.New(cfg).ListExternalSecrets(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownContext(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := kube.Load(kube.Options{Kubeconfig: kubeconfig(t, srv, "      token: x\n"), Context: "other"}); err == nil {
		t.Fatal("want an error for an unknown context")
	}
}
