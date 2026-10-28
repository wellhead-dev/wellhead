package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ErrNotFound means the API server has no such object.
var ErrNotFound = errors.New("not found")

const group = "external-secrets.io"

var versions = []string{"v1", "v1beta1"}

// Client calls the API server.
type Client struct {
	cfg     *Config
	version string
}

// New returns a client for a resolved config.
func New(cfg *Config) *Client {
	return &Client{cfg: cfg}
}

// Namespace is the namespace of the selected context.
func (c *Client) Namespace() string {
	return c.cfg.Namespace
}

func (c *Client) do(ctx context.Context, method, path, contentType string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.Server+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.cfg.token != nil {
		tok, err := c.cfg.token(ctx)
		if err != nil {
			return err
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 300 {
		var status struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &status)
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, status.Message)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *Client) apiVersion(ctx context.Context) (string, error) {
	if c.version != "" {
		return c.version, nil
	}
	for _, v := range versions {
		err := c.do(ctx, http.MethodGet, "/apis/"+group+"/"+v, "", nil, nil)
		if err == nil {
			c.version = v
			return v, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return "", err
		}
	}
	return "", errors.New("the cluster serves no external-secrets.io API; is External Secrets Operator installed?")
}

// ListExternalSecrets returns every ExternalSecret in every namespace, or in one namespace when ns is set.
func (c *Client) ListExternalSecrets(ctx context.Context, ns string) ([]map[string]any, error) {
	v, err := c.apiVersion(ctx)
	if err != nil {
		return nil, err
	}
	path := "/apis/" + group + "/" + v + "/externalsecrets"
	if ns != "" {
		path = "/apis/" + group + "/" + v + "/namespaces/" + url.PathEscape(ns) + "/externalsecrets"
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, path, "", nil, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// GetExternalSecret returns one ExternalSecret.
func (c *Client) GetExternalSecret(ctx context.Context, ns, name string) (map[string]any, error) {
	v, err := c.apiVersion(ctx)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	err = c.do(ctx, http.MethodGet, "/apis/"+group+"/"+v+"/namespaces/"+url.PathEscape(ns)+"/externalsecrets/"+url.PathEscape(name), "", nil, &obj)
	return obj, err
}

// GetStore returns a SecretStore in ns, or a ClusterSecretStore.
func (c *Client) GetStore(ctx context.Context, kind, ns, name string) (map[string]any, error) {
	v, err := c.apiVersion(ctx)
	if err != nil {
		return nil, err
	}
	path := "/apis/" + group + "/" + v + "/namespaces/" + url.PathEscape(ns) + "/secretstores/" + url.PathEscape(name)
	if kind == "ClusterSecretStore" {
		path = "/apis/" + group + "/" + v + "/clustersecretstores/" + url.PathEscape(name)
	}
	var obj map[string]any
	err = c.do(ctx, http.MethodGet, path, "", nil, &obj)
	return obj, err
}

// ForceSync sets the force-sync annotation External Secrets Operator watches, so an ExternalSecret with a
// long or zero refreshInterval reads the vault now.
func (c *Client) ForceSync(ctx context.Context, ns, name string, now time.Time) error {
	v, err := c.apiVersion(ctx)
	if err != nil {
		return err
	}
	patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]string{"force-sync": strconv.FormatInt(now.Unix(), 10)}}})
	return c.do(ctx, http.MethodPatch, "/apis/"+group+"/"+v+"/namespaces/"+url.PathEscape(ns)+"/externalsecrets/"+url.PathEscape(name), "application/merge-patch+json", patch, nil)
}

// WaitReady polls until the ExternalSecret reports Ready=True after since, or the context ends.
func (c *Client) WaitReady(ctx context.Context, ns, name string, since time.Time, every time.Duration) (Condition, error) {
	for {
		obj, err := c.GetExternalSecret(ctx, ns, name)
		if err != nil {
			return Condition{}, err
		}
		cond := Ready(obj)
		if cond.Status == "True" && !cond.Changed.Before(since.Truncate(time.Second)) {
			return cond, nil
		}
		select {
		case <-ctx.Done():
			return cond, ctx.Err()
		case <-time.After(every):
		}
	}
}

// Condition is an ExternalSecret's Ready condition.
type Condition struct {
	Status  string
	Reason  string
	Message string
	Changed time.Time
}

// Ready returns the Ready condition of an ExternalSecret.
func Ready(obj map[string]any) Condition {
	st, _ := obj["status"].(map[string]any)
	conds, _ := st["conditions"].([]any)
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if m["type"] != "Ready" {
			continue
		}
		out := Condition{}
		out.Status, _ = m["status"].(string)
		out.Reason, _ = m["reason"].(string)
		out.Message, _ = m["message"].(string)
		if ts, ok := m["lastTransitionTime"].(string); ok {
			out.Changed, _ = time.Parse(time.RFC3339, ts)
		}
		if rt, ok := st["refreshTime"].(string); ok {
			if t, err := time.Parse(time.RFC3339, rt); err == nil && t.After(out.Changed) {
				out.Changed = t
			}
		}
		return out
	}
	return Condition{Status: "Unknown"}
}

// VaultStore is the Vault or OpenBao provider settings of a store.
type VaultStore struct {
	Server  string
	Mount   string
	Version string
}

// Vault returns the vault provider of a SecretStore or ClusterSecretStore, or false for another provider.
// External Secrets Operator's Vault provider serves OpenBao too.
func Vault(store map[string]any) (VaultStore, bool) {
	sp, _ := store["spec"].(map[string]any)
	prov, _ := sp["provider"].(map[string]any)
	v, ok := prov["vault"].(map[string]any)
	if !ok {
		return VaultStore{}, false
	}
	out := VaultStore{Mount: "secret", Version: "v2"}
	if s, _ := v["server"].(string); s != "" {
		out.Server = s
	}
	if s, _ := v["path"].(string); s != "" {
		out.Mount = s
	}
	if s, _ := v["version"].(string); s != "" {
		out.Version = s
	}
	return out, true
}
