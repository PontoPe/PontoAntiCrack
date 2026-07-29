# Copy to terraform.tfvars (gitignored) and fill in.
#
# Account IDs come from AwLZ:  cd ../../AwLZ/live/org-root && terraform output account_ids

project = "pac"
region  = "sa-east-1"
profile = "mgmt"

# The account this stack is deployed into. Terraform refuses to apply if the
# credentials in scope belong to a different one.
account_id = "000000000000"

# lab | dev | prod. Shows up in every alert.
environment = "lab"

# LEAVE THIS TRUE until the fixtures have been confirmed against real events and
# you have watched a full dry-run cycle. Setting it to false is what allows this
# system to modify live AWS resources.
dry_run = true

detections_enabled = ["s3-public", "iam-key-leak", "sg-open"]

# Threat R2: how many remediations one detection may perform in a five-minute
# window before it refuses and escalates instead.
circuit_breaker_max_actions    = 5
circuit_breaker_window_seconds = 300

# Threat R7: how long an identical alert stays suppressed.
dedup_window_seconds = 900

log_retention_days   = 365
reserved_concurrency = 5

# Created empty by Terraform. Populate with:
#   aws secretsmanager put-secret-value --secret-id pac/slack-webhook \
#     --secret-string '{"webhook_url":"https://hooks.slack.com/services/..."}'
slack_webhook_secret_name = "pac/slack-webhook"

# Optional: SNS topic the operational alarms publish to.
# alarm_topic_arn = "arn:aws:sns:sa-east-1:000000000000:pac-alarms"

tags = {
  Owner = "pedro"
}
