package verify_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crypto"

	"github.com/wellhead-dev/wellhead/internal/verify"
)

var now = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func run(t *testing.T, srv *httptest.Server, kind string, params, values map[string]string) verify.Result {
	t.Helper()
	var hc *http.Client
	if srv != nil {
		hc = srv.Client()
		if params == nil {
			params = map[string]string{}
		}
		if _, ok := params["api"]; !ok && kind != "http" {
			params["api"] = srv.URL
		}
	}
	return verify.Default().Run(context.Background(), kind, verify.Request{Params: params, Values: values, HTTP: hc, Now: now})
}

func TestHTTPAcceptsTheExpectedStatusWithBasicAuth(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "robot" || p != "s3cret-value" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	params := map[string]string{"url": srv.URL + "/v2/", "auth": "basic:username:password"}
	if r := run(t, srv, "http", params, map[string]string{"username": "robot", "password": "s3cret-value"}); r.Outcome != verify.Accepted {
		t.Fatalf("want accepted, got %v: %s", r.Outcome, r.Detail)
	}
	r := run(t, srv, "http", params, map[string]string{"username": "robot", "password": "wrong-value"})
	if r.Outcome != verify.Rejected {
		t.Fatalf("want rejected, got %v: %s", r.Outcome, r.Detail)
	}
	if strings.Contains(r.Detail, "wrong-value") {
		t.Fatal("detail leaks the value")
	}
}

func TestHTTPTreatsRateLimitAsUnknown(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	r := run(t, srv, "http", map[string]string{"url": srv.URL, "auth": "bearer:token"}, map[string]string{"token": "abcd1234"})
	if r.Outcome != verify.Unknown {
		t.Fatalf("want unknown, got %v", r.Outcome)
	}
}

func TestHTTPRefusesPlainHTTP(t *testing.T) {
	r := run(t, nil, "http", map[string]string{"url": "http://example.com", "auth": "bearer:token"}, map[string]string{"token": "abcd1234"})
	if r.Outcome == verify.Accepted {
		t.Fatal("a check must never send a value over plain http")
	}
}

func TestFormat(t *testing.T) {
	params := map[string]string{"signing_secret": "[0-9a-f]{32}"}
	if r := run(t, nil, "format", params, map[string]string{"signing_secret": strings.Repeat("a1", 16)}); r.Outcome != verify.Accepted {
		t.Fatalf("want accepted: %s", r.Detail)
	}
	r := run(t, nil, "format", params, map[string]string{"signing_secret": "xoxb-pasted-the-wrong-thing"})
	if r.Outcome != verify.Rejected || strings.Contains(r.Detail, "xoxb") {
		t.Fatalf("want rejected without the value, got %v: %s", r.Outcome, r.Detail)
	}
	if r := run(t, nil, "format", params, map[string]string{"signing_secret": "prefix" + strings.Repeat("a1", 16)}); r.Outcome != verify.Rejected {
		t.Fatal("the pattern must be anchored")
	}
}

func TestUnimplementedKindIsUnknown(t *testing.T) {
	if r := run(t, nil, "x-vendor", nil, nil); r.Outcome != verify.Unknown {
		t.Fatalf("want unknown, got %v", r.Outcome)
	}
}

type fakeGitHub struct {
	key          *rsa.PublicKey
	appID        int64
	installation string
	suspended    bool
	selection    string
	repos        []string
	revoked      bool
}

func (f *fakeGitHub) verifyJWT(r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(f.key, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	_ = json.Unmarshal(raw, &c)
	return c.Iss == "4242" && c.Exp-c.Iat <= 600 && c.Iat < now.Unix()
}

func (f *fakeGitHub) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /app/installations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !f.verifyJWT(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.PathValue("id") != f.installation {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body := map[string]any{
			"app_id":               f.appID,
			"permissions":          map[string]string{"contents": "write", "pull_requests": "read"},
			"repository_selection": f.selection,
			"account":              map[string]string{"login": "example"},
			"suspended_at":         nil,
		}
		if f.suspended {
			body["suspended_at"] = "2026-10-01T00:00:00Z"
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		if !f.verifyJWT(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "ghs_installation"})
	})
	mux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghs_installation" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var list []map[string]string
		for _, n := range f.repos {
			list = append(list, map[string]string{"full_name": n})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"repositories": list})
	})
	mux.HandleFunc("DELETE /installation/token", func(w http.ResponseWriter, _ *http.Request) {
		f.revoked = true
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func appKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestGitHubApp(t *testing.T) {
	key, keyPEM := appKey(t)
	_, otherPEM := appKey(t)
	values := func(pem, inst string) map[string]string {
		return map[string]string{"app_id": "4242", "installation_id": inst, "private_key": pem}
	}
	cases := []struct {
		name   string
		fake   fakeGitHub
		params map[string]string
		values map[string]string
		want   verify.Outcome
	}{
		{"belongs together", fakeGitHub{appID: 4242, installation: "77", selection: "all"}, nil, values(keyPEM, "77"), verify.Accepted},
		{"key of another app", fakeGitHub{appID: 4242, installation: "77", selection: "all"}, nil, values(otherPEM, "77"), verify.Rejected},
		{"installation of another app", fakeGitHub{appID: 4242, installation: "77", selection: "all"}, nil, values(keyPEM, "78"), verify.Rejected},
		{"suspended", fakeGitHub{appID: 4242, installation: "77", selection: "all", suspended: true}, nil, values(keyPEM, "77"), verify.Rejected},
		{"permission missing", fakeGitHub{appID: 4242, installation: "77", selection: "all"}, map[string]string{"permissions": "issues:write"}, values(keyPEM, "77"), verify.Rejected},
		{"permission level too low", fakeGitHub{appID: 4242, installation: "77", selection: "all"}, map[string]string{"permissions": "pull_requests:write"}, values(keyPEM, "77"), verify.Rejected},
		{"permissions held", fakeGitHub{appID: 4242, installation: "77", selection: "all"}, map[string]string{"permissions": "contents:read pull_requests:read"}, values(keyPEM, "77"), verify.Accepted},
		{"selected repositories covered", fakeGitHub{appID: 4242, installation: "77", selection: "selected", repos: []string{"example/app", "example/infra"}}, map[string]string{"repositories": "example/app"}, values(keyPEM, "77"), verify.Accepted},
		{"selected repository missing", fakeGitHub{appID: 4242, installation: "77", selection: "selected", repos: []string{"example/app"}}, map[string]string{"repositories": "example/infra"}, values(keyPEM, "77"), verify.Rejected},
		{"not a key", fakeGitHub{appID: 4242, installation: "77", selection: "all"}, nil, values("ghp_not_a_key", "77"), verify.Rejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.fake.key = &key.PublicKey
			srv := httptest.NewTLSServer(tc.fake.handler())
			defer srv.Close()
			params := map[string]string{"api": srv.URL}
			for k, v := range tc.params {
				params[k] = v
			}
			r := run(t, srv, "github-app", params, tc.values)
			if r.Outcome != tc.want {
				t.Fatalf("want %v, got %v: %s", tc.want, r.Outcome, r.Detail)
			}
			if strings.Contains(r.Detail, "PRIVATE KEY") {
				t.Fatal("detail leaks the key")
			}
		})
	}
}

func TestGitHubAppRevokesTheTokenItMinted(t *testing.T) {
	key, keyPEM := appKey(t)
	fake := &fakeGitHub{key: &key.PublicKey, appID: 4242, installation: "77", selection: "selected", repos: []string{"example/app"}}
	srv := httptest.NewTLSServer(fake.handler())
	defer srv.Close()
	run(t, srv, "github-app", map[string]string{"api": srv.URL, "repositories": "example/app"}, map[string]string{"app_id": "4242", "installation_id": "77", "private_key": keyPEM})
	if !fake.revoked {
		t.Fatal("the installation token was not revoked")
	}
}

func TestGitHubTokenReadsTheExpiryHeader(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghp_good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("github-authentication-token-expiration", "2026-11-03 12:00:00 UTC")
		_, _ = w.Write([]byte(`{"login":"robot"}`))
	}))
	defer srv.Close()
	r := run(t, srv, "github-token", nil, map[string]string{"token": "ghp_good"})
	if r.Outcome != verify.Accepted || r.Expires.Format(time.DateOnly) != "2026-11-03" {
		t.Fatalf("got %v %v: %s", r.Outcome, r.Expires, r.Detail)
	}
	if r := run(t, srv, "github-token", nil, map[string]string{"token": "ghp_bad"}); r.Outcome != verify.Rejected {
		t.Fatalf("want rejected, got %v", r.Outcome)
	}
}

func TestGitLabToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v4/personal_access_tokens/self" || r.Header.Get("PRIVATE-TOKEN") != "glpat-good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"name":"ci","active":true,"revoked":false,"scopes":["read_api"],"expires_at":"2027-01-01"}`))
	}))
	defer srv.Close()
	if r := run(t, srv, "gitlab-token", map[string]string{"scopes": "read_api"}, map[string]string{"token": "glpat-good"}); r.Outcome != verify.Accepted || r.Expires.Year() != 2027 {
		t.Fatalf("got %v: %s", r.Outcome, r.Detail)
	}
	if r := run(t, srv, "gitlab-token", map[string]string{"scopes": "api"}, map[string]string{"token": "glpat-good"}); r.Outcome != verify.Rejected {
		t.Fatalf("a missing scope must reject, got %v", r.Outcome)
	}
	if r := run(t, srv, "gitlab-token", nil, map[string]string{"token": "glpat-bad"}); r.Outcome != verify.Rejected {
		t.Fatalf("want rejected, got %v", r.Outcome)
	}
}

func TestSlackBotTokenChecksScopes(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer xoxb-good" {
			_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
			return
		}
		w.Header().Set("x-oauth-scopes", "chat:write,channels:read")
		_, _ = w.Write([]byte(`{"ok":true,"team":"example","user":"bot"}`))
	}))
	defer srv.Close()
	if r := run(t, srv, "slack-bot-token", map[string]string{"scopes": "chat:write"}, map[string]string{"token": "xoxb-good"}); r.Outcome != verify.Accepted {
		t.Fatalf("got %v: %s", r.Outcome, r.Detail)
	}
	if r := run(t, srv, "slack-bot-token", map[string]string{"scopes": "users:read"}, map[string]string{"token": "xoxb-good"}); r.Outcome != verify.Rejected {
		t.Fatalf("a missing scope must reject, got %v", r.Outcome)
	}
	if r := run(t, srv, "slack-bot-token", nil, map[string]string{"token": "xoxb-bad"}); r.Outcome != verify.Rejected {
		t.Fatalf("want rejected, got %v", r.Outcome)
	}
}

func TestCloudflareToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cf-good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"result":{"status":"active","expires_on":"2026-11-01T00:00:00Z"}}`))
	}))
	defer srv.Close()
	r := run(t, srv, "cloudflare-token", nil, map[string]string{"token": "cf-good"})
	if r.Outcome != verify.Accepted || r.Expires.IsZero() {
		t.Fatalf("got %v: %s", r.Outcome, r.Detail)
	}
	if r := run(t, srv, "cloudflare-token", nil, map[string]string{"token": "cf-bad"}); r.Outcome != verify.Rejected {
		t.Fatalf("want rejected, got %v", r.Outcome)
	}
}
