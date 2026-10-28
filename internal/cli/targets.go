package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wellhead-dev/wellhead/internal/kube"
	"github.com/wellhead-dev/wellhead/internal/spec"
)

type target struct {
	mount  string
	key    string
	fields []string
	whole  bool
}

type stores struct {
	cluster Cluster
	cache   map[string]storeResult
}

type storeResult struct {
	vs     kube.VaultStore
	reason string
}

func (s *stores) vault(ctx context.Context, obj map[string]any) (kube.VaultStore, string, error) {
	ref := spec.Store(obj)
	meta, _ := obj["metadata"].(map[string]any)
	ns, _ := meta["namespace"].(string)
	if ref.Name == "" {
		return kube.VaultStore{}, "no secretStoreRef", nil
	}
	cacheKey := ref.Kind + "/" + ref.Name
	if ref.Kind != "ClusterSecretStore" {
		cacheKey = ns + "/" + cacheKey
	}
	if r, ok := s.cache[cacheKey]; ok {
		return r.vs, r.reason, nil
	}
	store, err := s.cluster.GetStore(ctx, ref.Kind, ns, ref.Name)
	r := storeResult{}
	switch {
	case errors.Is(err, kube.ErrNotFound):
		r.reason = fmt.Sprintf("%s %s does not exist", ref.Kind, ref.Name)
	case err != nil:
		return kube.VaultStore{}, "", err
	default:
		vs, ok := kube.Vault(store)
		switch {
		case !ok:
			r.reason = fmt.Sprintf("%s %s is not a Vault or OpenBao store", ref.Kind, ref.Name)
		case vs.Version != "v2":
			r.reason = fmt.Sprintf("%s %s uses KV %s; wellhead reads KV v2 only", ref.Kind, ref.Name, vs.Version)
		default:
			r.vs = vs
		}
	}
	s.cache[cacheKey] = r
	return r.vs, r.reason, nil
}

func targets(vs kube.VaultStore, obj map[string]any) []target {
	var out []target
	for _, p := range spec.Paths(obj) {
		out = append(out, target{mount: vs.Mount, key: normalise(vs.Mount, p.Key), fields: p.Fields, whole: p.Whole})
	}
	return out
}

func normalise(mount, key string) string {
	key = strings.TrimPrefix(key, "/")
	m := strings.Trim(mount, "/") + "/"
	key = strings.TrimPrefix(key, m+"data/")
	return strings.TrimPrefix(key, m)
}

func splitRef(ref string) (string, string, error) {
	ns, name, ok := strings.Cut(ref, "/")
	if !ok || ns == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("%q is not NAMESPACE/NAME", ref)
	}
	return ns, name, nil
}

func present(have map[string]string, f string) bool {
	if _, ok := have[f]; ok {
		return true
	}
	head, _, found := strings.Cut(f, ".")
	if !found {
		return false
	}
	_, ok := have[head]
	return ok
}
