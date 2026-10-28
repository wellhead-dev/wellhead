{{- define "wellhead.name" -}}
{{- default .Release.Name .Values.nameOverride | trunc 50 | trimSuffix "-" -}}
{{- end -}}

{{- define "wellhead.labels" -}}
app.kubernetes.io/name: wellhead
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "wellhead.rules" -}}
{{- .Files.Get "files/rules.yaml" | fromYaml | toJson -}}
{{- end -}}

{{- define "wellhead.matchConstraints" -}}
resourceRules:
  - apiGroups: ["external-secrets.io"]
    apiVersions: ["*"]
    operations: ["CREATE", "UPDATE"]
    resources: ["externalsecrets"]
{{- end -}}

{{- define "wellhead.matchConditions" -}}
{{- if .Values.storeNames -}}
matchConditions:
  - name: store
    expression: {{ printf "object.?spec.?secretStoreRef.?name.orValue('') in %s" (.Values.storeNames | toJson | replace "\"" "'") | quote }}
{{- end }}
{{- end -}}

{{- define "wellhead.body" -}}
{{- $rules := include "wellhead.rules" . | fromJson -}}
variables:
{{- range $rules.variables }}
  - name: {{ .name }}
    expression: {{ .expression | quote }}
{{- end }}
validations:
{{- range $rules.validations }}
  - expression: {{ .expression | quote }}
    messageExpression: {{ .messageExpression | quote }}
    reason: Invalid
{{- end }}
{{- end -}}
