package cli

import (
	"fmt"

	"github.com/wellhead-dev/wellhead/internal/manifest"
	"github.com/wellhead-dev/wellhead/internal/policy"
	"github.com/wellhead-dev/wellhead/internal/spec"
)

func lint(args []string, d Deps) (int, error) {
	fs := flags("lint", d)
	var stores, excludes multi
	fs.Var(&stores, "store", "check only ExternalSecrets on this store name, as the chart's storeNames value does (repeatable)")
	fs.Var(&excludes, "exclude", "leave out paths matching this glob (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	paths := fs.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}
	pol, err := policy.Load()
	if err != nil {
		return 2, err
	}
	docs, scanErr := manifest.Scan(paths, excludes)
	only := map[string]bool{}
	for _, s := range stores {
		only[s] = true
	}
	checked, violations := 0, 0
	for _, doc := range docs {
		if len(only) > 0 && !only[spec.Store(doc.Object).Name] {
			continue
		}
		checked++
		for _, v := range pol.Evaluate(doc.Object) {
			violations++
			_, _ = fmt.Fprintf(d.Stdout, "%s:%d: %s: %s\n", doc.Path, doc.Line, doc.Ref(), v.Message)
		}
	}
	_, _ = fmt.Fprintf(d.Stderr, "%d ExternalSecrets checked against spec %s, %d violations\n", checked, pol.SpecVersion, violations)
	if scanErr != nil {
		return 2, scanErr
	}
	if violations > 0 {
		return 1, nil
	}
	return 0, nil
}
