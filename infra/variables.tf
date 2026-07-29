variable "project" {
  description = "Resource name prefix. SCPs in AwLZ protect resources named pac-*."
  type        = string
  default     = "pac"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,12}$", var.project))
    error_message = "project must be lowercase alphanumeric with hyphens, 2-13 characters."
  }
}

variable "region" {
  description = "Region to deploy into. Must be the region the org trail delivers from."
  type        = string
  default     = "sa-east-1"
}

variable "profile" {
  description = "AWS CLI profile. Empty uses the ambient credentials."
  type        = string
  default     = ""
}

variable "account_id" {
  description = "Account this stack is deployed into. Guards against a stale SSO session."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "environment" {
  description = "Environment name. Appears in every alert so nobody has to guess which account fired it."
  type        = string

  validation {
    condition     = contains(["lab", "dev", "prod"], var.environment)
    error_message = "environment must be one of: lab, dev, prod."
  }
}

variable "dry_run" {
  description = <<-EOT
    When true, detections plan, snapshot, and alert but change nothing.

    Defaults to true. Turning this off is the single most consequential setting
    in the repository — it is what makes the system able to modify production
    resources — so it is an explicit, per-environment decision rather than
    something you inherit by forgetting to set it.
  EOT
  type        = bool
  default     = true
}

variable "detections_enabled" {
  description = "Detection IDs to deploy. Removing one destroys its rule, function, and role."
  type        = set(string)
  default     = ["s3-public", "iam-key-leak", "sg-open"]

  validation {
    condition = alltrue([
      for id in var.detections_enabled : contains(["s3-public", "iam-key-leak", "sg-open"], id)
    ])
    error_message = "Unknown detection ID. Known: s3-public, iam-key-leak, sg-open."
  }
}

variable "circuit_breaker_max_actions" {
  description = <<-EOT
    Remediations one detection may perform inside a window before it refuses.

    This is the control for threat R2 — auto-remediation weaponised as a denial
    of service. Set it just above the number of resources you would expect one
    legitimate incident to touch.
  EOT
  type        = number
  default     = 5

  validation {
    condition     = var.circuit_breaker_max_actions >= 1 && var.circuit_breaker_max_actions <= 100
    error_message = "circuit_breaker_max_actions must be between 1 and 100."
  }
}

variable "circuit_breaker_window_seconds" {
  description = "Rolling window for the circuit breaker, in seconds."
  type        = number
  default     = 300
}

variable "dedup_window_seconds" {
  description = "How long an identical alert is suppressed for. Threat R7, alert fatigue."
  type        = number
  default     = 900
}

variable "log_retention_days" {
  description = <<-EOT
    CloudWatch log retention for the remediation functions.

    365 days, not the default of 'never expire': these logs are the record of
    what an automation did to production resources, and one year is the shortest
    window that outlives a typical audit cycle. Longer costs more than the whole
    budget for this repository.
  EOT
  type        = number
  default     = 365
}

variable "lambda_timeout_seconds" {
  description = "Function timeout. Remediations are a handful of API calls."
  type        = number
  default     = 30
}

variable "lambda_memory_mb" {
  description = "Function memory. CPU scales with this; 256 MB keeps cold starts reasonable."
  type        = number
  default     = 256
}

variable "reserved_concurrency" {
  description = <<-EOT
    Per-function concurrency cap.

    The infrastructure half of the circuit breaker: this bounds how fast we can
    be invoked, the DynamoDB breaker bounds how much damage an invocation storm
    is allowed to do. Also stops one detection under attack from consuming the
    account's whole concurrency pool.
  EOT
  type        = number
  default     = 5
}

variable "slack_webhook_secret_name" {
  description = <<-EOT
    Secrets Manager secret holding the Slack webhook.

    Terraform creates the secret but never its value — writing the webhook here
    would put it in the state file, which is the leak this indirection exists to
    prevent. Populate it with `aws secretsmanager put-secret-value` after apply.
  EOT
  type        = string
  default     = "pac/slack-webhook"
}

variable "lambda_build_dir" {
  description = "Staging directory produced by `make build`. Zipped into the deployment package."
  type        = string
  default     = "../build/lambda"
}

variable "alarm_topic_arn" {
  description = <<-EOT
    Optional SNS topic for the operational alarms (function errors, dead-letter
    depth, dead-man's-switch). Leave empty to create the alarms without an
    action — they still show as ALARM in the console, they just do not page.
  EOT
  type        = string
  default     = ""
}

variable "tags" {
  description = "Extra tags merged into every resource."
  type        = map(string)
  default     = {}
}
