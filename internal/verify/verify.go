// Package verify checks a value against whoever issued it before it is written.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Outcome is what a check concluded.
type Outcome int

// Outcomes of a check.
const (
	Accepted Outcome = iota
	Rejected
	Unknown
)

func (o Outcome) String() string {
	return [...]string{"accepted", "rejected", "unknown"}[o]
}

// Result is the outcome of one check. Detail never contains a value.
type Result struct {
	Kind    string
	Outcome Outcome
	Detail  string
	Expires time.Time
}

// Request is the input of a check: its parameters from wellhead.dev/verify.<kind>.<param> and the values
// of the path, existing and new.
type Request struct {
	Params map[string]string
	Values map[string]string
	HTTP   *http.Client
	Now    time.Time
}

// Func runs one kind of check.
type Func func(context.Context, Request) Result

// Registry maps a verify kind to its check.
type Registry map[string]Func

// Default is every kind this release implements.
func Default() Registry {
	return Registry{
		"none":             none,
		"http":             HTTP,
		"format":           Format,
		"github-app":       GitHubApp,
		"github-token":     GitHubToken,
		"gitlab-token":     GitLabToken,
		"slack-bot-token":  SlackBotToken,
		"cloudflare-token": CloudflareToken,
	}
}

// Run runs one check. An unimplemented kind, such as an x- extension, is Unknown.
func (r Registry) Run(ctx context.Context, kind string, req Request) Result {
	if req.HTTP == nil {
		req.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if req.Now.IsZero() {
		req.Now = time.Now()
	}
	if req.Params == nil {
		req.Params = map[string]string{}
	}
	f, ok := r[kind]
	if !ok {
		return Result{Kind: kind, Outcome: Unknown, Detail: "this wellhead release does not implement " + kind}
	}
	res := f(ctx, req)
	res.Kind = kind
	return res
}

func none(context.Context, Request) Result {
	return Result{Outcome: Accepted, Detail: "not checked: verify is none, a reviewed exception"}
}

func accepted(format string, a ...any) Result {
	return Result{Outcome: Accepted, Detail: fmt.Sprintf(format, a...)}
}

func rejected(format string, a ...any) Result {
	return Result{Outcome: Rejected, Detail: fmt.Sprintf(format, a...)}
}

func unknown(format string, a ...any) Result {
	return Result{Outcome: Unknown, Detail: fmt.Sprintf(format, a...)}
}

func field(req Request, param, fallback string) (string, string, bool) {
	name := req.Params[param]
	if name == "" {
		name = fallback
	}
	v, ok := req.Values[name]
	return name, v, ok && v != ""
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func call(ctx context.Context, hc *http.Client, method, rawURL string, header http.Header, body io.Reader) (*response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("%s is not an https URL; a check never sends a value in the clear", u.Redacted())
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header = header
	req.Header.Set("User-Agent", "wellhead")
	resp, err := hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return nil, fmt.Errorf("%s %s: %w", method, u.Redacted(), ue.Err)
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: raw}, nil
}

func classify(status int, who string) (Result, bool) {
	switch {
	case status == http.StatusTooManyRequests || status >= 500:
		return unknown("%s answered HTTP %d; try again later", who, status), true
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return rejected("%s refuses it (HTTP %d)", who, status), true
	}
	return Result{}, false
}

func decode(r *response, out any) error {
	return json.Unmarshal(r.body, out)
}

func missingScopes(have []string, want string) []string {
	got := map[string]bool{}
	for _, s := range have {
		got[strings.TrimSpace(s)] = true
	}
	var miss []string
	for _, s := range strings.Fields(want) {
		if !got[s] {
			miss = append(miss, s)
		}
	}
	sort.Strings(miss)
	return miss
}

func expiryNote(exp, now time.Time) string {
	if exp.IsZero() {
		return "no expiry"
	}
	days := int(exp.Sub(now).Hours() / 24)
	return fmt.Sprintf("expires %s (%d days)", exp.Format(time.DateOnly), days)
}
