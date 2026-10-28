package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wellhead-dev/wellhead/internal/vault"
)

type kv struct {
	data     map[string]any
	version  int
	custom   map[string]string
	deleted  bool
	requests []string
}

func (k *kv) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.requests = append(k.requests, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Vault-Token") != "root" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/kv/data/apps/demo":
			if k.data == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			md := map[string]any{"version": k.version, "deletion_time": "", "destroyed": false}
			if k.deleted {
				md["deletion_time"] = "2026-10-01T00:00:00Z"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": k.data, "metadata": md}})
		case "POST /v1/kv/data/apps/demo":
			var body struct {
				Data    map[string]any `json:"data"`
				Options map[string]int `json:"options"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if cas, ok := body.Options["cas"]; ok && cas != k.version {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":["check-and-set parameter did not match the current version"]}`))
				return
			}
			k.data, k.version = body.Data, k.version+1
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": k.version}})
		case "GET /v1/kv/metadata/apps/demo":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"custom_metadata": k.custom}})
		case "POST /v1/kv/metadata/apps/demo":
			var body struct {
				Custom map[string]string `json:"custom_metadata"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			k.custom = body.Custom
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func client(srv *httptest.Server, token string) *vault.Client {
	return &vault.Client{Addr: srv.URL, Token: token, HTTP: srv.Client()}
}

func TestReadMissingPath(t *testing.T) {
	store := &kv{}
	srv := httptest.NewServer(store.handler(t))
	defer srv.Close()
	if _, err := client(srv, "root").Read(context.Background(), "kv", "apps/demo"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestReadDeletedVersionIsMissing(t *testing.T) {
	store := &kv{data: map[string]any{"token": "x"}, version: 3, deleted: true}
	srv := httptest.NewServer(store.handler(t))
	defer srv.Close()
	if _, err := client(srv, "root").Read(context.Background(), "kv", "apps/demo"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestWriteIsCheckAndSet(t *testing.T) {
	store := &kv{data: map[string]any{"username": "robot"}, version: 2}
	srv := httptest.NewServer(store.handler(t))
	defer srv.Close()
	c := client(srv, "root")
	if _, err := c.Write(context.Background(), "kv", "apps/demo", map[string]string{"username": "robot", "password": "p"}, 1); err == nil {
		t.Fatal("a stale version must be refused")
	}
	v, err := c.Write(context.Background(), "kv", "apps/demo", map[string]string{"username": "robot", "password": "p"}, 2)
	if err != nil || v != 3 {
		t.Fatalf("got %d, %v", v, err)
	}
	sec, err := c.Read(context.Background(), "kv", "apps/demo")
	if err != nil || sec.Data["password"] != "p" || sec.Data["username"] != "robot" {
		t.Fatalf("got %v, %v", sec, err)
	}
}

func TestMergeMetadataKeepsOtherKeys(t *testing.T) {
	store := &kv{custom: map[string]string{"owner": "team-a", "seeded-at": "old"}}
	srv := httptest.NewServer(store.handler(t))
	defer srv.Close()
	if err := client(srv, "root").MergeMetadata(context.Background(), "kv", "apps/demo", map[string]string{"seeded-at": "new", "seeded-by": "alice"}); err != nil {
		t.Fatal(err)
	}
	if store.custom["owner"] != "team-a" || store.custom["seeded-at"] != "new" || store.custom["seeded-by"] != "alice" {
		t.Fatalf("got %v", store.custom)
	}
}

func TestPermissionDenied(t *testing.T) {
	store := &kv{}
	srv := httptest.NewServer(store.handler(t))
	defer srv.Close()
	_, err := client(srv, "nope").Read(context.Background(), "kv", "apps/demo")
	if err == nil || errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("want a permission error, got %v", err)
	}
}
