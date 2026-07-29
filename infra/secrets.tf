# The Slack webhook lives here and nowhere else.
#
# Terraform creates the container and never the value. A webhook passed through
# a variable ends up in the state file, and a state file is a much easier thing
# to accidentally share than a Secrets Manager secret. After apply:
#
#   aws secretsmanager put-secret-value \
#     --secret-id pac/slack-webhook \
#     --secret-string '{"webhook_url":"https://hooks.slack.com/services/..."}' \
#     --profile <profile>
#
# Functions receive the secret ARN in an environment variable, never the
# webhook. Threat R5.

resource "aws_secretsmanager_secret" "slack_webhook" {
  # checkov:skip=CKV2_AWS_57: Slack incoming webhooks have no rotation API. There is nothing for a rotation Lambda to call — rotating means creating a new webhook in the Slack app configuration by hand and putting the new value here. Automating a rotation that cannot be automated would mean a rotation Lambda with write access to this secret, which is more attack surface for no gain. Tracked as accepted residual risk under R5 in docs/threat-model.md.
  name        = var.slack_webhook_secret_name
  description = "PontoAntiCrack alert webhook. Value is set out of band, never by Terraform."
  kms_key_id  = aws_kms_key.pac.arn

  # 7 days rather than the 30-day default: if this is deleted by mistake, it is
  # replaced by pasting a new webhook, and a week of recovery window is plenty.
  recovery_window_in_days = 7
}
