// Package manifest finds ExternalSecrets in plain, multi-document YAML files.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Document is one ExternalSecret found in a file.
type Document struct {
	Path   string
	Line   int
	Object map[string]any
}

// Ref names the document as namespace/name.
func (d Document) Ref() string {
	return Ref(d.Object)
}

// Ref names an object as namespace/name, or name alone without a namespace.
func Ref(obj map[string]any) string {
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	ns, _ := meta["namespace"].(string)
	if ns == "" {
		return name
	}
	return ns + "/" + name
}

// IsExternalSecret reports whether an object is an External Secrets Operator ExternalSecret.
func IsExternalSecret(obj map[string]any) bool {
	kind, _ := obj["kind"].(string)
	api, _ := obj["apiVersion"].(string)
	return kind == "ExternalSecret" && strings.HasPrefix(api, "external-secrets.io/")
}

// Scan walks files and directories and returns every ExternalSecret in them. A file that is not valid
// YAML is an error, never skipped: a check that quietly skips is how a missing value goes unnoticed.
// Paths matching an exclude glob (matched against the slash-separated path and its base name) are left out.
func Scan(paths, excludes []string) ([]Document, error) {
	var docs []Document
	var errs []error
	for _, root := range paths {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if excluded(path, excludes) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if path != root && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !isYAML(path) {
				return nil
			}
			found, err := ScanFile(path)
			if err != nil {
				errs = append(errs, err)
				return nil
			}
			docs = append(docs, found...)
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	return docs, errors.Join(errs...)
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

func excluded(path string, excludes []string) bool {
	slash := filepath.ToSlash(path)
	for _, pattern := range excludes {
		if ok, _ := filepath.Match(pattern, slash); ok {
			return true
		}
		if ok, _ := filepath.Match(pattern, filepath.Base(path)); ok {
			return true
		}
	}
	return false
}

// ScanFile returns the ExternalSecrets in one file.
func ScanFile(path string) ([]Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, data)
}

// Parse returns the ExternalSecrets in YAML data, including those inside a v1 List.
func Parse(path string, data []byte) ([]Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []Document
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		strTimestamps(&node)
		var obj map[string]any
		if err := node.Decode(&obj); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, node.Line, err)
		}
		for _, o := range expand(obj) {
			if IsExternalSecret(o) {
				docs = append(docs, Document{Path: path, Line: line(&node), Object: o})
			}
		}
	}
}

func expand(obj map[string]any) []map[string]any {
	if obj == nil {
		return nil
	}
	if kind, _ := obj["kind"].(string); kind == "List" {
		items, _ := obj["items"].([]any)
		var out []map[string]any
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return []map[string]any{obj}
}

func strTimestamps(n *yaml.Node) {
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!timestamp" {
		n.Tag = "!!str"
	}
	for _, c := range n.Content {
		strTimestamps(c)
	}
}

func line(n *yaml.Node) int {
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		return n.Content[0].Line
	}
	return n.Line
}
