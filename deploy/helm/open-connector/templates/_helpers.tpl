{{/*
Expand the name of the chart.
*/}}
{{- define "open-connector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to
this (by the DNS naming spec).
*/}}
{{- define "open-connector.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "open-connector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels - applied to every resource the chart creates.
Follows the Kubernetes recommended labels:
https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
*/}}
{{- define "open-connector.labels" -}}
helm.sh/chart: {{ include "open-connector.chart" . }}
{{ include "open-connector.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: open-connector
{{- end -}}

{{/*
Selector labels - stable across upgrades. MUST NOT include version or
release-specific values. Used by the Deployment selector.
*/}}
{{- define "open-connector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "open-connector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Image reference. A reviewed immutable digest is required; there is no global/tag fallback.
*/}}
{{- define "open-connector.image" -}}
{{- $repo := required "image.repository must name the reviewed scoped image" .Values.image.repository -}}
{{- $digest := required "imageDigest is required" .Values.imageDigest -}}
{{- printf "%s@%s" $repo $digest -}}
{{- end -}}

{{/*
ServiceAccount name.
*/}}
{{- define "open-connector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "open-connector.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
