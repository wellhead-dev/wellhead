package verify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const githubAPI = "https://api.github.com"

func githubHeader(token string) http.Header {
	h := http.Header{}
	h.Set("Accept", "application/vnd.github+json")
	h.Set("X-GitHub-Api-Version", "2022-11-28")
	h.Set("Authorization", "Bearer "+token)
	return h
}

func base(req Request, fallback string) string {
	if v := req.Params["api"]; v != "" {
		return strings.TrimRight(v, "/")
	}
	return fallback
}

// GitHubApp proves that app_id, installation_id and private_key belong together: it signs an RS256 JWT
// with the key as the app, reads the installation, and checks it is the app's, not suspended, grants
// the expected permissions and covers the expected repositories.
//
// Parameters: api (default https://api.github.com); permissions, space-separated name:level pairs such
// as contents:write; repositories, space-separated owner/name. Field names are app_id, installation_id
// and private_key unless the app-id-field, installation-id-field or private-key-field parameters say
// otherwise. Checking repositories mints an installation token and revokes it straight after.
func GitHubApp(ctx context.Context, req Request) Result {
	appField, appID, ok := field(req, "app-id-field", "app_id")
	if !ok {
		return rejected("field %s is empty", appField)
	}
	instField, instID, ok := field(req, "installation-id-field", "installation_id")
	if !ok {
		return rejected("field %s is empty", instField)
	}
	keyField, keyPEM, ok := field(req, "private-key-field", "private_key")
	if !ok {
		return rejected("field %s is empty", keyField)
	}
	if _, err := strconv.ParseInt(appID, 10, 64); err != nil {
		return rejected("field %s is not a number", appField)
	}
	if _, err := strconv.ParseInt(instID, 10, 64); err != nil {
		return rejected("field %s is not a number", instField)
	}
	key, err := parseRSAKey(keyPEM)
	if err != nil {
		return rejected("field %s: %v", keyField, err)
	}
	jwt, err := appJWT(appID, key, req.Now)
	if err != nil {
		return rejected("cannot sign a JWT with %s: %v", keyField, err)
	}
	api := base(req, githubAPI)
	resp, err := call(ctx, req.HTTP, http.MethodGet, api+"/app/installations/"+instID, githubHeader(jwt), nil)
	if err != nil {
		return unknown("%v", err)
	}
	switch resp.status {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return rejected("GitHub refuses the JWT: %s does not belong to app %s", keyField, appID)
	case http.StatusNotFound:
		return rejected("installation %s does not belong to app %s", instID, appID)
	default:
		if r, ok := classify(resp.status, "GitHub"); ok {
			return r
		}
		return rejected("GitHub answered HTTP %d for installation %s", resp.status, instID)
	}
	var inst struct {
		AppID               int64             `json:"app_id"`
		SuspendedAt         *string           `json:"suspended_at"`
		Permissions         map[string]string `json:"permissions"`
		RepositorySelection string            `json:"repository_selection"`
		Account             struct {
			Login string `json:"login"`
		} `json:"account"`
	}
	if err := decode(resp, &inst); err != nil {
		return unknown("GitHub's answer is not JSON: %v", err)
	}
	if strconv.FormatInt(inst.AppID, 10) != appID {
		return rejected("installation %s belongs to app %d, not %s", instID, inst.AppID, appID)
	}
	if inst.SuspendedAt != nil && *inst.SuspendedAt != "" {
		return rejected("installation %s is suspended", instID)
	}
	if miss := missingPermissions(inst.Permissions, req.Params["permissions"]); len(miss) > 0 {
		return rejected("installation %s lacks permissions %s", instID, strings.Join(miss, ", "))
	}
	repos := strings.Fields(req.Params["repositories"])
	if len(repos) > 0 {
		if r := checkRepositories(ctx, req, api, jwt, instID, inst.RepositorySelection, inst.Account.Login, repos); r.Outcome != Accepted {
			return r
		}
	}
	return accepted("app %s, installation %s on %s, %d permissions", appID, instID, inst.Account.Login, len(inst.Permissions))
}

var levels = map[string]int{"read": 1, "write": 2, "admin": 3}

func missingPermissions(have map[string]string, want string) []string {
	var miss []string
	for _, pair := range strings.Fields(want) {
		name, level, _ := strings.Cut(pair, ":")
		if level == "" {
			level = "read"
		}
		if levels[have[name]] < levels[level] {
			miss = append(miss, pair)
		}
	}
	sort.Strings(miss)
	return miss
}

func checkRepositories(ctx context.Context, req Request, api, jwt, instID, selection, account string, repos []string) Result {
	if selection == "all" {
		for _, r := range repos {
			owner, _, _ := strings.Cut(r, "/")
			if !strings.EqualFold(owner, account) {
				return rejected("installation %s covers %s, not %s", instID, account, r)
			}
		}
		return accepted("installation %s covers every repository of %s", instID, account)
	}
	resp, err := call(ctx, req.HTTP, http.MethodPost, api+"/app/installations/"+instID+"/access_tokens", githubHeader(jwt), nil)
	if err != nil {
		return unknown("%v", err)
	}
	if resp.status != http.StatusCreated {
		if r, ok := classify(resp.status, "GitHub"); ok {
			return r
		}
		return rejected("GitHub would not mint an installation token (HTTP %d)", resp.status)
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := decode(resp, &tok); err != nil || tok.Token == "" {
		return unknown("GitHub's token answer is not usable")
	}
	defer func() {
		_, _ = call(context.WithoutCancel(ctx), req.HTTP, http.MethodDelete, api+"/installation/token", githubHeader(tok.Token), nil)
	}()
	covered := map[string]bool{}
	for page := 1; page <= 50; page++ {
		resp, err := call(ctx, req.HTTP, http.MethodGet, fmt.Sprintf("%s/installation/repositories?per_page=100&page=%d", api, page), githubHeader(tok.Token), nil)
		if err != nil {
			return unknown("%v", err)
		}
		if resp.status != http.StatusOK {
			if r, ok := classify(resp.status, "GitHub"); ok {
				return r
			}
			return rejected("GitHub answered HTTP %d listing the installation's repositories", resp.status)
		}
		var list struct {
			Repositories []struct {
				FullName string `json:"full_name"`
			} `json:"repositories"`
		}
		if err := decode(resp, &list); err != nil {
			return unknown("GitHub's answer is not JSON: %v", err)
		}
		for _, r := range list.Repositories {
			covered[strings.ToLower(r.FullName)] = true
		}
		if len(list.Repositories) < 100 {
			break
		}
	}
	var miss []string
	for _, r := range repos {
		if !covered[strings.ToLower(r)] {
			miss = append(miss, r)
		}
	}
	if len(miss) > 0 {
		return rejected("installation %s does not cover %s", instID, strings.Join(miss, ", "))
	}
	return accepted("installation %s covers %d expected repositories", instID, len(repos))
}

func parseRSAKey(p string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("not a PEM private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("not an RSA private key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rk, nil
}

func appJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": appID,
	})
	if err != nil {
		return "", err
	}
	signing := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// GitHubToken checks a personal access token with GET /user and reads its expiry from the
// github-authentication-token-expiration header. Parameters: api; field (default token).
func GitHubToken(ctx context.Context, req Request) Result {
	name, tok, ok := field(req, "field", "token")
	if !ok {
		return rejected("field %s is empty", name)
	}
	resp, err := call(ctx, req.HTTP, http.MethodGet, base(req, githubAPI)+"/user", githubHeader(tok), nil)
	if err != nil {
		return unknown("%v", err)
	}
	if r, ok := classify(resp.status, "GitHub"); ok {
		return r
	}
	if resp.status != http.StatusOK {
		return rejected("GitHub answered HTTP %d", resp.status)
	}
	var user struct {
		Login string `json:"login"`
	}
	_ = decode(resp, &user)
	var exp time.Time
	if h := resp.header.Get("github-authentication-token-expiration"); h != "" {
		for _, layout := range []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700", time.RFC3339} {
			if t, err := time.Parse(layout, h); err == nil {
				exp = t
				break
			}
		}
	}
	if miss := missingScopes(strings.Split(resp.header.Get("x-oauth-scopes"), ","), req.Params["scopes"]); len(miss) > 0 && resp.header.Get("x-oauth-scopes") != "" {
		return rejected("token for %s lacks scopes %s", user.Login, strings.Join(miss, ", "))
	}
	r := accepted("GitHub accepts it for %s, %s", user.Login, expiryNote(exp, req.Now))
	r.Expires = exp
	return r
}

// GitLabToken checks a personal, project or group access token with
// GET /api/v4/personal_access_tokens/self. Parameters: api (default https://gitlab.com); field
// (default token); scopes, space-separated scopes the token must have.
func GitLabToken(ctx context.Context, req Request) Result {
	name, tok, ok := field(req, "field", "token")
	if !ok {
		return rejected("field %s is empty", name)
	}
	h := http.Header{}
	h.Set("PRIVATE-TOKEN", tok)
	resp, err := call(ctx, req.HTTP, http.MethodGet, base(req, "https://gitlab.com")+"/api/v4/personal_access_tokens/self", h, nil)
	if err != nil {
		return unknown("%v", err)
	}
	if r, ok := classify(resp.status, "GitLab"); ok {
		return r
	}
	if resp.status != http.StatusOK {
		return rejected("GitLab answered HTTP %d", resp.status)
	}
	var self struct {
		Name      string   `json:"name"`
		Active    bool     `json:"active"`
		Revoked   bool     `json:"revoked"`
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expires_at"`
	}
	if err := decode(resp, &self); err != nil {
		return unknown("GitLab's answer is not JSON: %v", err)
	}
	if !self.Active || self.Revoked {
		return rejected("GitLab says token %s is not active", self.Name)
	}
	if miss := missingScopes(self.Scopes, req.Params["scopes"]); len(miss) > 0 {
		return rejected("token %s lacks scopes %s", self.Name, strings.Join(miss, ", "))
	}
	var exp time.Time
	if self.ExpiresAt != "" {
		exp, _ = time.Parse(time.DateOnly, self.ExpiresAt)
	}
	r := accepted("GitLab accepts %s, scopes %s, %s", self.Name, strings.Join(self.Scopes, ","), expiryNote(exp, req.Now))
	r.Expires = exp
	return r
}

// SlackBotToken checks a bot token with auth.test and its x-oauth-scopes header. Parameters: api
// (default https://slack.com/api); field (default token); scopes, space-separated required scopes.
func SlackBotToken(ctx context.Context, req Request) Result {
	name, tok, ok := field(req, "field", "token")
	if !ok {
		return rejected("field %s is empty", name)
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	resp, err := call(ctx, req.HTTP, http.MethodPost, base(req, "https://slack.com/api")+"/auth.test", h, nil)
	if err != nil {
		return unknown("%v", err)
	}
	if r, ok := classify(resp.status, "Slack"); ok {
		return r
	}
	var at struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Team  string `json:"team"`
		User  string `json:"user"`
	}
	if err := decode(resp, &at); err != nil {
		return unknown("Slack's answer is not JSON: %v", err)
	}
	if at.Error == "ratelimited" {
		return unknown("Slack is rate limiting; try again later")
	}
	if !at.OK {
		return rejected("Slack refuses it: %s", at.Error)
	}
	if miss := missingScopes(strings.Split(resp.header.Get("x-oauth-scopes"), ","), req.Params["scopes"]); len(miss) > 0 {
		return rejected("token for %s lacks scopes %s", at.User, strings.Join(miss, ", "))
	}
	return accepted("Slack accepts it as %s in %s", at.User, at.Team)
}

// CloudflareToken checks an API token with GET /user/tokens/verify. Parameters: api (default
// https://api.cloudflare.com/client/v4); field (default token).
func CloudflareToken(ctx context.Context, req Request) Result {
	name, tok, ok := field(req, "field", "token")
	if !ok {
		return rejected("field %s is empty", name)
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	resp, err := call(ctx, req.HTTP, http.MethodGet, base(req, "https://api.cloudflare.com/client/v4")+"/user/tokens/verify", h, nil)
	if err != nil {
		return unknown("%v", err)
	}
	if r, ok := classify(resp.status, "Cloudflare"); ok {
		return r
	}
	var v struct {
		Success bool `json:"success"`
		Result  struct {
			Status    string `json:"status"`
			ExpiresOn string `json:"expires_on"`
		} `json:"result"`
	}
	if err := decode(resp, &v); err != nil {
		return unknown("Cloudflare's answer is not JSON: %v", err)
	}
	if !v.Success || v.Result.Status != "active" {
		return rejected("Cloudflare says the token is %q", v.Result.Status)
	}
	var exp time.Time
	if v.Result.ExpiresOn != "" {
		exp, _ = time.Parse(time.RFC3339, v.Result.ExpiresOn)
	}
	r := accepted("Cloudflare accepts it, %s", expiryNote(exp, req.Now))
	r.Expires = exp
	return r
}
