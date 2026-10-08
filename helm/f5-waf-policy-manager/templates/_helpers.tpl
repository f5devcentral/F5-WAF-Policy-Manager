{{/*
Expand the name of the chart.
*/}}
{{- define "f5-waf-policy-manager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "f5-waf-policy-manager.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "f5-waf-policy-manager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "f5-waf-policy-manager.labels" -}}
helm.sh/chart: {{ include "f5-waf-policy-manager.chart" . }}
{{ include "f5-waf-policy-manager.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "f5-waf-policy-manager.selectorLabels" -}}
app.kubernetes.io/name: {{ include "f5-waf-policy-manager.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "f5-waf-policy-manager.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "f5-waf-policy-manager.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Redis fullname
*/}}
{{- define "f5-waf-policy-manager.redisFullname" -}}
{{- printf "%s-redis" (include "f5-waf-policy-manager.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Redis selector labels
*/}}
{{- define "f5-waf-policy-manager.redisSelectorLabels" -}}
app.kubernetes.io/name: {{ include "f5-waf-policy-manager.name" . }}-redis
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Redis labels
*/}}
{{- define "f5-waf-policy-manager.redisLabels" -}}
helm.sh/chart: {{ include "f5-waf-policy-manager.chart" . }}
{{ include "f5-waf-policy-manager.redisSelectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Resolve Redis host
*/}}
{{- define "f5-waf-policy-manager.redisHost" -}}
{{- if .Values.redis.enabled }}
{{- include "f5-waf-policy-manager.redisFullname" . }}
{{- else if .Values.redis.external.enabled }}
{{- .Values.redis.external.host }}
{{- else }}
{{- "localhost" }}
{{- end }}
{{- end }}

{{/*
Resolve Redis port
*/}}
{{- define "f5-waf-policy-manager.redisPort" -}}
{{- if .Values.redis.enabled }}
{{- .Values.redis.service.port }}
{{- else if .Values.redis.external.enabled }}
{{- .Values.redis.external.port }}
{{- else }}
{{- 6379 }}
{{- end }}
{{- end }}

{{/*
Resolve Secret name for Redis password
*/}}
{{- define "f5-waf-policy-manager.secretName" -}}
{{- if and (not .Values.redis.enabled) .Values.redis.external.existingSecret }}
{{- .Values.redis.external.existingSecret }}
{{- else }}
{{- include "f5-waf-policy-manager.fullname" . }}
{{- end }}
{{- end }}

{{/*
apcompile fullname
*/}}
{{- define "f5-waf-policy-manager.apcompileFullname" -}}
{{- printf "%s-apcompile" (include "f5-waf-policy-manager.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
apcompile selector labels
*/}}
{{- define "f5-waf-policy-manager.apcompileSelectorLabels" -}}
app.kubernetes.io/name: {{ include "f5-waf-policy-manager.name" . }}-apcompile
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
apcompile labels
*/}}
{{- define "f5-waf-policy-manager.apcompileLabels" -}}
helm.sh/chart: {{ include "f5-waf-policy-manager.chart" . }}
{{ include "f5-waf-policy-manager.apcompileSelectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
apcompile compiler service URL
*/}}
{{- define "f5-waf-policy-manager.compilerServiceUrl" -}}
{{- if .Values.apcompile.enabled -}}
http://{{ include "f5-waf-policy-manager.apcompileFullname" . }}:{{ .Values.apcompile.service.port }}
{{- else -}}
{{ .Values.config.compilerServiceUrl | default "" }}
{{- end -}}
{{- end }}
