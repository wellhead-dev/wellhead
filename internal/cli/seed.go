package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wellhead-dev/wellhead/internal/policy"
	"github.com/wellhead-dev/wellhead/internal/prompt"
	"github.com/wellhead-dev/wellhead/internal/redact"
	"github.com/wellhead-dev/wellhead/internal/spec"
	"github.com/wellhead-dev/wellhead/internal/vault"
	"github.com/wellhead-dev/wellhead/internal/verify"
)

const maxFile = 1 << 20

type pathPlan struct {
	target
	existing *vault.Secret
	ask      []string
}

func seed(ctx context.Context, args []string, d Deps, secrets *redact.Set) (int, error) {
	fs := flags("seed", d)
	rotate := fs.Bool("rotate", false, "ask for every field again, not only the missing ones (refused for preserve and rolled)")
	noSync := fs.Bool("no-sync", false, "do not force External Secrets Operator to sync afterwards")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long to wait for the ExternalSecret to become Ready")
	var co ClusterOptions
	fs.StringVar(&co.Kubeconfig, "kubeconfig", "", "kubeconfig file")
	fs.StringVar(&co.Context, "context", "", "kubeconfig context")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	if fs.NArg() < 1 {
		return 2, errors.New("seed needs NAMESPACE/NAME")
	}
	ns, name, err := splitRef(fs.Arg(0))
	if err != nil {
		return 2, err
	}
	files, err := fileArgs(fs.Args()[1:])
	if err != nil {
		return 2, err
	}
	cluster, err := d.Cluster(co)
	if err != nil {
		return 2, err
	}
	vc, err := d.Vault()
	if err != nil {
		return 2, err
	}
	es, err := cluster.GetExternalSecret(ctx, ns, name)
	if err != nil {
		return 2, fmt.Errorf("ExternalSecret %s/%s: %w", ns, name, err)
	}
	ref := ns + "/" + name
	pol, err := policy.Load()
	if err != nil {
		return 2, err
	}
	if vs := pol.Evaluate(es); len(vs) > 0 {
		for _, v := range vs {
			_, _ = fmt.Fprintln(d.Stderr, v.Message)
		}
		return 1, fmt.Errorf("%s does not meet spec %s; fix its annotations first", ref, pol.SpecVersion)
	}
	s, err := spec.Parse(spec.Annotations(es))
	if err != nil {
		return 1, err
	}
	switch s.Origin {
	case spec.Minted:
		return 1, fmt.Errorf("%s is minted: a controller in the cluster writes it, not a person", ref)
	case spec.Projected:
		return 1, fmt.Errorf("%s is projected: seed the ExternalSecret that owns its path", ref)
	}
	if *rotate && (s.Origin == spec.Preserve || s.Origin == spec.Rolled) {
		return 1, fmt.Errorf("%s is %s; wellhead never overwrites it", ref, s.Origin)
	}
	st := &stores{cluster: cluster, cache: map[string]storeResult{}}
	vs, reason, err := st.vault(ctx, es)
	if err != nil {
		return 2, err
	}
	if reason != "" {
		return 1, fmt.Errorf("%s: %s", ref, reason)
	}
	var plans []*pathPlan
	asked := 0
	for _, t := range targets(vs, es) {
		p := &pathPlan{target: t}
		sec, err := vc.Read(ctx, t.mount, t.key)
		switch {
		case errors.Is(err, vault.ErrNotFound):
		case err != nil:
			return 2, err
		default:
			p.existing = sec
			for _, v := range sec.Data {
				secrets.Add(v)
			}
		}
		if len(t.fields) == 0 {
			return 1, fmt.Errorf("%s reads all of %s/%s; list its fields in wellhead.dev/fields", ref, t.mount, t.key)
		}
		for _, f := range t.fields {
			if *rotate || p.existing == nil || !present(p.existing.Data, f) {
				p.ask = append(p.ask, f)
			}
		}
		asked += len(p.ask)
		plans = append(plans, p)
	}
	if asked == 0 {
		_, _ = fmt.Fprintf(d.Stderr, "%s: the vault already holds every field it reads\n", ref)
		return 0, nil
	}
	for f := range files {
		if !wanted(plans, f) {
			return 2, fmt.Errorf("%s=@... names a field %s does not need", f, ref)
		}
	}
	_, _ = fmt.Fprintf(d.Stderr, "%s (%s)\n", ref, s.Origin)
	if s.How != "" {
		_, _ = fmt.Fprintf(d.Stderr, "  %s\n", s.How)
	}
	if s.Docs != "" {
		_, _ = fmt.Fprintf(d.Stderr, "  %s\n", s.Docs)
	}
	newValues := map[string]map[string]string{}
	for _, p := range plans {
		newValues[p.key] = map[string]string{}
		for _, f := range p.ask {
			v, err := ask(d, s, p, f, files)
			if err != nil {
				return 1, err
			}
			secrets.Add(v)
			newValues[p.key][f] = v
		}
	}
	all := map[string]string{}
	for _, p := range plans {
		if p.existing != nil {
			for k, v := range p.existing.Data {
				all[k] = v
			}
		}
		for k, v := range newValues[p.key] {
			all[k] = v
		}
	}
	expires, err := runChecks(ctx, d, s, all, secrets)
	if err != nil {
		return 1, err
	}
	who := d.SeededBy
	if who == "" {
		if n, err := vc.Self(ctx); err == nil && n != "" {
			who = n
		} else {
			who = os.Getenv("USER")
		}
	}
	now := d.Now().UTC()
	for _, p := range plans {
		if len(newValues[p.key]) == 0 {
			continue
		}
		data := map[string]string{}
		version := -1
		if p.existing != nil {
			for k, v := range p.existing.Data {
				data[k] = v
			}
			version = p.existing.Version
		}
		for k, v := range newValues[p.key] {
			data[k] = v
		}
		ver, err := vc.Write(ctx, p.mount, p.key, data, version)
		if err != nil {
			return 1, fmt.Errorf("write %s/%s: %w; nothing more written", p.mount, p.key, err)
		}
		meta := map[string]string{"seeded-by": who, "seeded-at": now.Format(time.RFC3339)}
		if !expires.IsZero() {
			meta["expires"] = expires.UTC().Format(time.RFC3339)
		}
		if err := vc.MergeMetadata(ctx, p.mount, p.key, meta); err != nil {
			_, _ = fmt.Fprintf(d.Stderr, "  warning: wrote %s/%s but not its custom metadata: %v\n", p.mount, p.key, secrets.Error(err))
		}
		_, _ = fmt.Fprintf(d.Stderr, "  wrote %s to %s/%s (version %d)\n", strings.Join(sortedKeys(newValues[p.key]), ", "), p.mount, p.key, ver)
	}
	offerDelete(d, files)
	if *noSync {
		return 0, nil
	}
	return sync(ctx, d, cluster, ns, name, *timeout)
}

func fileArgs(args []string) (map[string]string, error) {
	out := map[string]string{}
	for _, a := range args {
		f, path, ok := strings.Cut(a, "=@")
		if !ok || f == "" || path == "" {
			return nil, errors.New("values never go on the command line: pass FIELD=@FILE, or type the value when asked")
		}
		out[f] = path
	}
	return out, nil
}

func wanted(plans []*pathPlan, f string) bool {
	for _, p := range plans {
		for _, a := range p.ask {
			if a == f {
				return true
			}
		}
	}
	return false
}

func ask(d Deps, s spec.Spec, p *pathPlan, f string, files map[string]string) (string, error) {
	label := fmt.Sprintf("%s for %s/%s", f, p.mount, p.key)
	if path, ok := files[f]; ok {
		return readFile(path)
	}
	var v string
	var err error
	if s.Plain[f] {
		v, err = d.Prompt.Line(label)
	} else {
		v, err = d.Prompt.Secret(label)
	}
	if err != nil {
		return "", err
	}
	if s.Generate[f] {
		if v == "" {
			return generate()
		}
		again, err := d.Prompt.Secret(label + ", again")
		if err != nil {
			return "", err
		}
		if again != v {
			return "", fmt.Errorf("the two entries for %s differ; nothing written", f)
		}
		return v, nil
	}
	if v == "" {
		return "", fmt.Errorf("%s is empty; nothing written (for a multi-line value pass %s=@FILE)", f, f)
	}
	return v, nil
}

func readFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxFile {
		return "", fmt.Errorf("%s is larger than 1 MiB", path)
	}
	f, err := os.Open(path) //nolint:gosec // the person names the file on purpose
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxFile))
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", fmt.Errorf("%s is empty; nothing written", path)
	}
	return string(b), nil
}

func generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func runChecks(ctx context.Context, d Deps, s spec.Spec, values map[string]string, secrets *redact.Set) (time.Time, error) {
	var expires time.Time
	for _, c := range s.Checks {
		res := d.Verifiers.Run(ctx, c.Kind, verify.Request{Params: c.Params, Values: values, Now: d.Now()})
		_, _ = fmt.Fprintf(d.Stderr, "  %s: %s: %s\n", c.Kind, res.Outcome, secrets.String(res.Detail))
		switch res.Outcome {
		case verify.Rejected:
			return expires, errors.New("rejected; nothing written")
		case verify.Unknown:
			if !d.Interactive {
				return expires, errors.New("the check could not decide; nothing written")
			}
			ok, err := d.Prompt.Confirm("The check could not decide. Write anyway?")
			if err != nil {
				return expires, err
			}
			if !ok {
				return expires, prompt.ErrCancelled
			}
		}
		if !res.Expires.IsZero() && (expires.IsZero() || res.Expires.Before(expires)) {
			expires = res.Expires
		}
	}
	if expires.IsZero() && !s.Expires.IsZero() {
		expires = s.Expires
	}
	if expires.IsZero() && s.Lifetime > 0 {
		expires = d.Now().Add(s.Lifetime)
	}
	if !expires.IsZero() && expires.Sub(d.Now()) < expiryWarning {
		_, _ = fmt.Fprintf(d.Stderr, "  warning: this value expires %s\n", expires.Format(time.DateOnly))
	}
	return expires, nil
}

func offerDelete(d Deps, files map[string]string) {
	if !d.Interactive {
		return
	}
	for _, f := range sortedKeys(files) {
		path := files[f]
		ok, err := d.Prompt.Confirm(fmt.Sprintf("Delete %s now that the vault holds it?", path))
		if err != nil || !ok {
			continue
		}
		if err := os.Remove(path); err != nil {
			_, _ = fmt.Fprintf(d.Stderr, "  could not delete %s: %v\n", path, err)
		}
	}
}

func sync(ctx context.Context, d Deps, cluster Cluster, ns, name string, timeout time.Duration) (int, error) {
	since := d.Now()
	if err := cluster.ForceSync(ctx, ns, name, since); err != nil {
		return 1, fmt.Errorf("force-sync %s/%s: %w", ns, name, err)
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cond, err := cluster.WaitReady(wctx, ns, name, since, d.PollEvery)
	if err != nil {
		return 1, fmt.Errorf("%s/%s is not Ready after %s (%s: %s)", ns, name, timeout, cond.Reason, cond.Message)
	}
	_, _ = fmt.Fprintf(d.Stderr, "  %s/%s is Ready\n", ns, name)
	return 0, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
