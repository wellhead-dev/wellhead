package manifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wellhead-dev/wellhead/internal/manifest"
)

const multi = `---
# a comment-only document
---
apiVersion: v1
kind: ConfigMap
metadata: {name: c}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: first
  namespace: apps
  annotations:
    wellhead.dev/expires: 2027-01-31
---
apiVersion: v1
kind: List
items:
  - apiVersion: external-secrets.io/v1beta1
    kind: ExternalSecret
    metadata: {name: second}
`

func TestParseFindsExternalSecretsInMultiDocumentFilesAndLists(t *testing.T) {
	docs, err := manifest.Parse("x.yaml", []byte(multi))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 || docs[0].Ref() != "apps/first" || docs[1].Ref() != "second" {
		t.Fatalf("got %+v", docs)
	}
	if docs[0].Line != 8 {
		t.Fatalf("line %d", docs[0].Line)
	}
	ann := docs[0].Object["metadata"].(map[string]any)["annotations"].(map[string]any)
	if ann["wellhead.dev/expires"] != "2027-01-31" {
		t.Fatalf("an unquoted date must stay the string it was written as, got %#v", ann["wellhead.dev/expires"])
	}
}

func TestScanFailsLoudlyOnInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("kind: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Scan([]string{dir}, nil); err == nil {
		t.Fatal("an unparsable file must be an error, not skipped")
	}
	if _, err := manifest.Scan([]string{dir}, []string{"bad.yaml"}); err != nil {
		t.Fatalf("an excluded file must be left out: %v", err)
	}
}
