variable "detection_id" {
  description = "Kebab-case detection ID, e.g. s3-public. Used in every resource name."
  type        = string
}

variable "package" {
  description = "Python package name inside the deployment artifact, e.g. s3_public."
  type        = string
}

variable "description" {
  description = "One line describing what this detection remediates."
  type        = string
}

variable "event_pattern" {
  description = "EventBridge event pattern, as JSON."
  type        = string
}

variable "detection_policy" {
  description = "Detection-specific IAM policy document, rendered from remediations/*/policy.json."
  type        = string
}

variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
}

variable "dry_run" {
  description = "When true the function plans, snapshots, and alerts but changes nothing."
  type        = bool
}

variable "region" {
  type = string
}

variable "account_id" {
  type = string
}

variable "partition" {
  type = string
}

variable "lambda_zip_path" {
  type = string
}

variable "lambda_source_hash" {
  type = string
}

variable "timeout_seconds" {
  type = number
}

variable "memory_mb" {
  type = number
}

variable "reserved_concurrency" {
  type = number
}

variable "audit_table_name" {
  type = string
}

variable "audit_table_arn" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "slack_secret_arn" {
  type = string
}

variable "circuit_breaker_max_actions" {
  type = number
}

variable "circuit_breaker_window_seconds" {
  type = number
}

variable "dedup_window_seconds" {
  type = number
}

variable "log_retention_days" {
  type = number
}

variable "alarm_topic_arn" {
  description = "Optional SNS topic for alarm actions. Empty creates alarms with no action."
  type        = string
  default     = ""
}
