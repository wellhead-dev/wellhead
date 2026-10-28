// Package vault reads and writes Vault or OpenBao KV version 2 secrets over the HTTP API.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrNotFound means the path holds no live version.
var ErrNotFound = errors.New("not found")

// Client talks to one Vault or OpenBao server.
type Client struct {
	Addr      string
	Token     string
	Namespace string
	HTTP      *http.Client
}

// Secret is the current version of a KV v2 path.
type Secret struct {
	Data    map[string]string
	Version int
}

// Fields returns the field names at the path.
func (s *Secret) Fields() map[string]bool {
	out := map[string]bool{}
	for k := range s.Data {
		out[k] = true
	}
	return out
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	u := strings.TrimRight(c.Addr, "/") + "/v1/" + path
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.Token)
	req.Header.Set("X-Vault-Request", "true")
	if c.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, unwrapURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%s %s: permission denied; the token's policy does not allow it", method, path)
	case resp.StatusCode >= 300:
		return fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, apiErrors(raw))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func apiErrors(raw []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(raw, &e) == nil && len(e.Errors) > 0 {
		return strings.Join(e.Errors, "; ")
	}
	return "no error message"
}

func escape(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// Read returns the current version at mount/path, or ErrNotFound when it does not exist or its current
// version is deleted or destroyed.
func (c *Client) Read(ctx context.Context, mount, path string) (*Secret, error) {
	var resp struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version   int    `json:"version"`
				Destroyed bool   `json:"destroyed"`
				Deletion  string `json:"deletion_time"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, escape(mount)+"/data/"+escape(path), nil, &resp); err != nil {
		return nil, err
	}
	if resp.Data.Data == nil || resp.Data.Metadata.Destroyed || resp.Data.Metadata.Deletion != "" {
		return nil, ErrNotFound
	}
	s := &Secret{Data: map[string]string{}, Version: resp.Data.Metadata.Version}
	for k, v := range resp.Data.Data {
		switch t := v.(type) {
		case string:
			s.Data[k] = t
		default:
			b, _ := json.Marshal(t)
			s.Data[k] = string(b)
		}
	}
	return s, nil
}

// Write stores data as the next version, check-and-set against version: 0 creates the path, n requires
// the current version to still be n, so a concurrent write is refused rather than lost. A negative
// version writes without check-and-set, for a path whose current version is deleted.
func (c *Client) Write(ctx context.Context, mount, path string, data map[string]string, version int) (int, error) {
	body := map[string]any{"data": data}
	if version >= 0 {
		body["options"] = map[string]any{"cas": version}
	}
	var resp struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, escape(mount)+"/data/"+escape(path), body, &resp); err != nil {
		return 0, err
	}
	return resp.Data.Version, nil
}

// MergeMetadata merges custom metadata into the path's metadata, keeping keys it does not name.
func (c *Client) MergeMetadata(ctx context.Context, mount, path string, custom map[string]string) error {
	var resp struct {
		Data struct {
			Custom map[string]string `json:"custom_metadata"`
		} `json:"data"`
	}
	merged := map[string]string{}
	err := c.do(ctx, http.MethodGet, escape(mount)+"/metadata/"+escape(path), nil, &resp)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	for k, v := range resp.Data.Custom {
		merged[k] = v
	}
	for k, v := range custom {
		merged[k] = v
	}
	return c.do(ctx, http.MethodPost, escape(mount)+"/metadata/"+escape(path), map[string]any{"custom_metadata": merged}, nil)
}

// Self returns the display name of the token, for the seeded-by record.
func (c *Client) Self(ctx context.Context) (string, error) {
	var resp struct {
		Data struct {
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "auth/token/lookup-self", nil, &resp); err != nil {
		return "", err
	}
	return resp.Data.DisplayName, nil
}
