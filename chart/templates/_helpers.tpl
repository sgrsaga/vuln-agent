{{/*
Expand the name of the chart.
*/}}
{{- define "vuln-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "vuln-agent.fullname" -}}
{{- if .Values.fullnameOverride }}
  {{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
  {{- $name := default .Chart.Name .Values.nameOverride }}
  {{- if contains $name .Release.Name }}
    {{- .Release.Name | trunc 63 | trimSuffix "-" }}
  {{- else }}
    {{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
  {{- end }}
{{- end }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "vuln-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
  {{- default (include "vuln-agent.fullname" .) .Values.serviceAccount.name }}
{{- else }}
  {{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "vuln-agent.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/name: {{ include "vuln-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "vuln-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vuln-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the Opaque secret holding API keys.
*/}}
{{- define "vuln-agent.secretName" -}}
{{- printf "%s-secrets" (include "vuln-agent.fullname" .) }}
{{- end }}

{{/*
Name of the docker-registry secret for image push.
*/}}
{{- define "vuln-agent.registrySecretName" -}}
{{- if .Values.registry.existingSecret }}
  {{- .Values.registry.existingSecret }}
{{- else }}
  {{- printf "%s-registry" (include "vuln-agent.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Excluded namespaces as a comma-separated string.
Always includes the release namespace so the agent never scans itself.
*/}}
{{- define "vuln-agent.excludedNamespaces" -}}
{{- $ns := .Values.discovery.excludedNamespaces | default list }}
{{- $ns = append $ns .Release.Namespace }}
{{- $ns | uniq | join "," }}
{{- end }}
