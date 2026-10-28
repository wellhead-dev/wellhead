// Package spec reads the wellhead.dev/ annotations (spec v1alpha1) and the vault paths an ExternalSecret reads.
package spec

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Prefix starts every annotation key of the spec.
const Prefix = "wellhead.dev/"

// Version is the spec version this module implements.
const Version = "v1alpha1"

// Origin says who writes a value.
type Origin string

// Origins of the spec.
const (
	Provided  Origin = "provided"
	Preserve  Origin = "preserve"
	Rolled    Origin = "rolled"
	Minted    Origin = "minted"
	Projected Origin = "projected"
)

// ByPerson reports whether a person enters the value.
func (o Origin) ByPerson() bool {
	return o == Provided || o == Preserve || o == Rolled
}

// Check is one verify kind with its parameters.
type Check struct {
	Kind   string
	Params map[string]string
}

// Spec is what the annotations of one ExternalSecret declare.
type Spec struct {
	Origin             Origin
	How                string
	Docs               string
	Fields             []string
	Plain              map[string]bool
	Generate           map[string]bool
	Checks             []Check
	Expires            time.Time
	Lifetime           time.Duration
	RotateOnCompromise *bool
}

// Exception reports whether verify is the reviewed exception none.
func (s Spec) Exception() bool {
	return len(s.Checks) == 1 && s.Checks[0].Kind == "none"
}

var lifetimeRE = regexp.MustCompile(`^([1-9][0-9]*)([hdw])$`)

// Parse reads the annotations. It does not enforce the rules; the policy package does.
func Parse(ann map[string]string) (Spec, error) {
	s := Spec{
		Origin:   Origin(ann[Prefix+"origin"]),
		How:      strings.Join(strings.Fields(ann[Prefix+"how"]), " "),
		Docs:     ann[Prefix+"docs"],
		Fields:   List(ann[Prefix+"fields"]),
		Plain:    set(List(ann[Prefix+"plain"])),
		Generate: set(List(ann[Prefix+"generate"])),
	}
	for _, kind := range List(ann[Prefix+"verify"]) {
		c := Check{Kind: kind, Params: map[string]string{}}
		param := Prefix + "verify." + kind + "."
		for k, v := range ann {
			if name, ok := strings.CutPrefix(k, param); ok {
				c.Params[name] = v
			}
		}
		s.Checks = append(s.Checks, c)
	}
	if v := ann[Prefix+"expires"]; v != "" {
		t, err := time.Parse(time.DateOnly, v)
		if err != nil {
			return s, fmt.Errorf("wellhead.dev/expires: %w", err)
		}
		s.Expires = t
	}
	if v := ann[Prefix+"lifetime"]; v != "" {
		d, err := ParseLifetime(v)
		if err != nil {
			return s, err
		}
		s.Lifetime = d
	}
	if v, ok := ann[Prefix+"rotate-on-compromise"]; ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return s, fmt.Errorf("wellhead.dev/rotate-on-compromise: %w", err)
		}
		s.RotateOnCompromise = &b
	}
	return s, nil
}

// ParseLifetime reads a lifetime such as 90d, 12w or 36h.
func ParseLifetime(v string) (time.Duration, error) {
	m := lifetimeRE.FindStringSubmatch(v)
	if m == nil {
		return 0, fmt.Errorf("wellhead.dev/lifetime %q is not a number of hours, days or weeks", v)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, err
	}
	unit := map[string]time.Duration{"h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]]
	return time.Duration(n) * unit, nil
}

// List splits a list annotation on single spaces.
func List(v string) []string {
	var out []string
	for _, f := range strings.Split(v, " ") {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func set(items []string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

// Annotations returns an object's annotations as strings.
func Annotations(obj map[string]any) map[string]string {
	meta, _ := obj["metadata"].(map[string]any)
	raw, _ := meta["annotations"].(map[string]any)
	out := map[string]string{}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// StoreRef is the store an ExternalSecret reads from.
type StoreRef struct {
	Kind string
	Name string
}

// Store returns spec.secretStoreRef, defaulting the kind to SecretStore as ESO does.
func Store(obj map[string]any) StoreRef {
	sp, _ := obj["spec"].(map[string]any)
	ref, _ := sp["secretStoreRef"].(map[string]any)
	r := StoreRef{}
	r.Kind, _ = ref["kind"].(string)
	r.Name, _ = ref["name"].(string)
	if r.Kind == "" {
		r.Kind = "SecretStore"
	}
	return r
}

// Path is one vault path an ExternalSecret reads, with the fields it needs there.
type Path struct {
	Key    string
	Fields []string
	Whole  bool
}

// Paths lists the vault paths an ExternalSecret reads through remoteRef and dataFrom.extract, with the
// fields named by remoteRef.property and, for extract, by wellhead.dev/fields. A data entry without a
// property reads the whole path. dataFrom.find and generator sources are left out: they name no path.
func Paths(obj map[string]any) []Path {
	sp, _ := obj["spec"].(map[string]any)
	declared := List(Annotations(obj)[Prefix+"fields"])
	byKey := map[string]*Path{}
	var order []string
	get := func(key string) *Path {
		if p, ok := byKey[key]; ok {
			return p
		}
		p := &Path{Key: key}
		byKey[key] = p
		order = append(order, key)
		return p
	}
	for _, d := range items(sp["dataFrom"]) {
		ex, _ := d["extract"].(map[string]any)
		key, _ := ex["key"].(string)
		if key == "" {
			continue
		}
		p := get(key)
		for _, f := range declared {
			p.Fields = appendOnce(p.Fields, f)
		}
		if len(declared) == 0 {
			p.Whole = true
		}
	}
	for _, d := range items(sp["data"]) {
		rr, _ := d["remoteRef"].(map[string]any)
		key, _ := rr["key"].(string)
		if key == "" {
			continue
		}
		p := get(key)
		if prop, _ := rr["property"].(string); prop != "" {
			p.Fields = appendOnce(p.Fields, prop)
		} else {
			p.Whole = true
		}
	}
	out := make([]Path, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

// FieldsOf lists every field name an ExternalSecret reads, declared or named by a property, sorted.
func FieldsOf(obj map[string]any) []string {
	seen := map[string]bool{}
	for _, p := range Paths(obj) {
		for _, f := range p.Fields {
			seen[f] = true
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func items(v any) []map[string]any {
	list, _ := v.([]any)
	var out []map[string]any
	for _, i := range list {
		if m, ok := i.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func appendOnce(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
