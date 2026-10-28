package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/wellhead-dev/wellhead/internal/manifest"
	"github.com/wellhead-dev/wellhead/internal/redact"
	"github.com/wellhead-dev/wellhead/internal/spec"
	"github.com/wellhead-dev/wellhead/internal/vault"
	"github.com/wellhead-dev/wellhead/internal/verify"
)

const expiryWarning = 14 * 24 * time.Hour

type row struct {
	ref, origin, path, field, state, detail string
}

func missing(ctx context.Context, args []string, d Deps, secrets *redact.Set) (int, error) {
	fs := flags("missing", d)
	ns := fs.String("namespace", "", "only this namespace")
	runVerify := fs.Bool("verify", false, "also run each ExternalSecret's checks on the values that exist and report rejected ones")
	all := fs.Bool("all", false, "list fields that are ok too")
	var co ClusterOptions
	fs.StringVar(&co.Kubeconfig, "kubeconfig", "", "kubeconfig file")
	fs.StringVar(&co.Context, "context", "", "kubeconfig context")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return 2, nil
	}
	cluster, err := d.Cluster(co)
	if err != nil {
		return 2, err
	}
	vc, err := d.Vault()
	if err != nil {
		return 2, err
	}
	items, err := cluster.ListExternalSecrets(ctx, *ns)
	if err != nil {
		return 2, err
	}
	sort.Slice(items, func(i, j int) bool { return manifest.Ref(items[i]) < manifest.Ref(items[j]) })
	st := &stores{cluster: cluster, cache: map[string]storeResult{}}
	var rows []row
	skipped := map[string]int{}
	for _, es := range items {
		vs, reason, err := st.vault(ctx, es)
		if err != nil {
			return 2, err
		}
		if reason != "" {
			skipped[reason]++
			continue
		}
		r, err := check(ctx, d, vc, es, targets(vs, es), *runVerify, secrets)
		if err != nil {
			return 2, err
		}
		rows = append(rows, r...)
	}
	for reason, n := range skipped {
		_, _ = fmt.Fprintf(d.Stderr, "skipped %d ExternalSecrets: %s\n", n, reason)
	}
	counts := map[string]int{}
	tw := tabwriter.NewWriter(d.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "EXTERNALSECRET\tORIGIN\tPATH\tFIELD\tSTATE\tDETAIL")
	for _, r := range rows {
		counts[r.state]++
		if r.state == "ok" && !*all {
			continue
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ref, r.origin, r.path, r.field, r.state, r.detail)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintf(d.Stderr, "%d fields: %d missing, %d rejected, %d ok\n", len(rows), counts["missing"], counts["rejected"], counts["ok"])
	if counts["missing"]+counts["rejected"] > 0 {
		return 1, nil
	}
	return 0, nil
}

func hint(s spec.Spec, ref string) string {
	switch s.Origin {
	case "":
		return "no wellhead.dev/origin; nobody knows who writes it"
	case spec.Minted:
		return "minted: waiting for the controller that writes it"
	case spec.Projected:
		return "projected: seed the ExternalSecret that owns this path"
	default:
		return "wellhead seed " + ref
	}
}

func check(ctx context.Context, d Deps, vc Vault, es map[string]any, ts []target, runVerify bool, secrets *redact.Set) ([]row, error) {
	ref := manifest.Ref(es)
	s, _ := spec.Parse(spec.Annotations(es))
	origin := string(s.Origin)
	if origin == "" {
		origin = "-"
	}
	var rows []row
	values := map[string]string{}
	complete := true
	for _, t := range ts {
		path := t.mount + "/" + t.key
		sec, err := vc.Read(ctx, t.mount, t.key)
		if errors.Is(err, vault.ErrNotFound) {
			complete = false
			fields := t.fields
			if len(fields) == 0 {
				fields = []string{"*"}
			}
			for _, f := range fields {
				rows = append(rows, row{ref, origin, path, f, "missing", hint(s, ref)})
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ref, err)
		}
		for _, v := range sec.Data {
			secrets.Add(v)
		}
		for k, v := range sec.Data {
			values[k] = v
		}
		if len(t.fields) == 0 {
			rows = append(rows, row{ref, origin, path, "*", "ok", fmt.Sprintf("version %d", sec.Version)})
		}
		for _, f := range t.fields {
			if present(sec.Data, f) {
				rows = append(rows, row{ref, origin, path, f, "ok", fmt.Sprintf("version %d", sec.Version)})
				continue
			}
			complete = false
			rows = append(rows, row{ref, origin, path, f, "missing", hint(s, ref)})
		}
	}
	if !runVerify || !complete || len(s.Checks) == 0 || s.Exception() {
		return rows, nil
	}
	for _, c := range s.Checks {
		res := d.Verifiers.Run(ctx, c.Kind, verify.Request{Params: c.Params, Values: values, Now: d.Now()})
		detail := secrets.String(c.Kind + ": " + res.Detail)
		switch {
		case res.Outcome == verify.Rejected:
			for i := range rows {
				if rows[i].state == "ok" {
					rows[i].state, rows[i].detail = "rejected", detail
				}
			}
		case !res.Expires.IsZero() && res.Expires.Sub(d.Now()) < expiryWarning:
			for i := range rows {
				if rows[i].state == "ok" {
					rows[i].detail = secrets.String(c.Kind + ": expires " + res.Expires.Format(time.DateOnly))
				}
			}
		case res.Outcome == verify.Unknown:
			for i := range rows {
				if rows[i].state == "ok" {
					rows[i].detail = strings.TrimSpace(rows[i].detail + "; " + detail)
				}
			}
		}
	}
	return rows, nil
}
