// Package deploy embeds the policy rules the Helm chart renders, so the CLI evaluates the same CEL as admission.
package deploy

import _ "embed"

// Rules is deploy/charts/wellhead/files/rules.yaml.
//
//go:embed charts/wellhead/files/rules.yaml
var Rules []byte
