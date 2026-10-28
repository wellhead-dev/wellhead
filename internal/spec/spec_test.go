package spec_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/wellhead-dev/wellhead/internal/spec"
)

func TestParse(t *testing.T) {
	s, err := spec.Parse(map[string]string{
		"wellhead.dev/origin":                         "provided",
		"wellhead.dev/how":                            "Vendor console,\n  API tokens.",
		"wellhead.dev/fields":                         "app_id installation_id private_key",
		"wellhead.dev/plain":                          "app_id installation_id",
		"wellhead.dev/verify":                         "github-app format",
		"wellhead.dev/verify.github-app.repositories": "example/app",
		"wellhead.dev/verify.format.app_id":           "[0-9]+",
		"wellhead.dev/lifetime":                       "2w",
		"wellhead.dev/rotate-on-compromise":           "false",
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Origin != spec.Provided || !s.Origin.ByPerson() || s.How != "Vendor console, API tokens." {
		t.Fatalf("got %+v", s)
	}
	if !s.Plain["app_id"] || s.Plain["private_key"] || len(s.Fields) != 3 {
		t.Fatalf("got %+v", s)
	}
	if len(s.Checks) != 2 || s.Checks[0].Params["repositories"] != "example/app" || s.Checks[1].Params["app_id"] != "[0-9]+" {
		t.Fatalf("got %+v", s.Checks)
	}
	if s.Lifetime != 14*24*time.Hour || s.RotateOnCompromise == nil || *s.RotateOnCompromise {
		t.Fatalf("got %+v", s)
	}
}

func TestPaths(t *testing.T) {
	es := map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{"wellhead.dev/fields": "username password"}},
		"spec": map[string]any{
			"dataFrom": []any{map[string]any{"extract": map[string]any{"key": "apps/registry"}}, map[string]any{"find": map[string]any{"name": map[string]any{"regexp": ".*"}}}},
			"data": []any{
				map[string]any{"secretKey": "a", "remoteRef": map[string]any{"key": "apps/one", "property": "token"}},
				map[string]any{"secretKey": "b", "remoteRef": map[string]any{"key": "apps/one", "property": "token"}},
				map[string]any{"secretKey": "c", "remoteRef": map[string]any{"key": "apps/whole"}},
			},
		},
	}
	got := spec.Paths(es)
	want := []spec.Path{
		{Key: "apps/registry", Fields: []string{"username", "password"}},
		{Key: "apps/one", Fields: []string{"token"}},
		{Key: "apps/whole", Whole: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}
