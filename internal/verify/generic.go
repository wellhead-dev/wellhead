package verify

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// HTTP calls a URL with credentials from the fields and expects a status.
//
// Parameters: url (https, required); method (default GET); auth, one of bearer:<field>,
// basic:<user-field>:<password-field> or header:<Header-Name>:<field>; status, space-separated
// accepted codes (default 200). HTTP 429 and 5xx are unknown, not rejected.
func HTTP(ctx context.Context, req Request) Result {
	target := req.Params["url"]
	if target == "" {
		return rejected("verify.http.url is not set")
	}
	method := strings.ToUpper(req.Params["method"])
	if method == "" {
		method = http.MethodGet
	}
	header := http.Header{}
	if auth := req.Params["auth"]; auth != "" {
		parts := strings.Split(auth, ":")
		get := func(name string) (string, bool) {
			v, ok := req.Values[name]
			return v, ok && v != ""
		}
		switch {
		case parts[0] == "bearer" && len(parts) == 2:
			v, ok := get(parts[1])
			if !ok {
				return rejected("field %s is empty", parts[1])
			}
			header.Set("Authorization", "Bearer "+v)
		case parts[0] == "basic" && len(parts) == 3:
			u, _ := get(parts[1])
			p, ok := get(parts[2])
			if !ok {
				return rejected("field %s is empty", parts[2])
			}
			header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u+":"+p)))
		case parts[0] == "header" && len(parts) == 3:
			v, ok := get(parts[2])
			if !ok {
				return rejected("field %s is empty", parts[2])
			}
			header.Set(parts[1], v)
		default:
			return rejected("verify.http.auth %q is not bearer:<field>, basic:<user>:<password> or header:<name>:<field>", auth)
		}
	}
	want := map[int]bool{}
	for _, s := range strings.Fields(req.Params["status"]) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return rejected("verify.http.status %q is not a list of status codes", req.Params["status"])
		}
		want[n] = true
	}
	if len(want) == 0 {
		want[http.StatusOK] = true
	}
	resp, err := call(ctx, req.HTTP, method, target, header, nil)
	if err != nil {
		return unknown("%v", err)
	}
	if want[resp.status] {
		return accepted("%s %s answered HTTP %d", method, target, resp.status)
	}
	if r, ok := classify(resp.status, target); ok {
		return r
	}
	return rejected("%s %s answered HTTP %d", method, target, resp.status)
}

// Format matches each field named by a parameter against the parameter's regular expression, anchored
// at both ends. It catches the wrong paste where no API exists, such as a webhook signing secret.
func Format(_ context.Context, req Request) Result {
	if len(req.Params) == 0 {
		return rejected("no verify.format.<field> patterns are set")
	}
	names := make([]string, 0, len(req.Params))
	for name := range req.Params {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		re, err := regexp.Compile("^(?:" + req.Params[name] + ")$")
		if err != nil {
			return rejected("verify.format.%s is not a regular expression: %v", name, err)
		}
		v, ok := req.Values[name]
		if !ok {
			return rejected("field %s is empty", name)
		}
		if !re.MatchString(v) {
			return rejected("field %s does not have the expected format", name)
		}
	}
	return accepted("%s match the expected format", strings.Join(names, ", "))
}
