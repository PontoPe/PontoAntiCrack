# One deployment package for all three functions.
#
# The alternative — a zip per detection — means vendoring remediations/common
# and notifier/ into each one and keeping three copies in step. Sharing one
# artifact and varying only the handler entrypoint means the code that runs is
# provably the code that was tested, for every detection at once.
#
# Isolation between detections is enforced by the IAM role, not by the artifact
# boundary. A shared zip does not share permissions.

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = var.lambda_build_dir
  output_path = "${path.module}/.terraform/${local.name_prefix}-lambda.zip"
  excludes    = ["__pycache__", "*.pyc", "*.pyo"]
}

module "detection" {
  source   = "./modules/detection"
  for_each = local.enabled_detections

  detection_id  = each.key
  package       = each.value.package
  description   = each.value.description
  event_pattern = file("${path.module}/../detections/${each.key}/pattern.json")

  # The detection-specific half of the execution role. The runtime half — logs,
  # the audit table, the webhook secret, the key — is added by the module, so
  # this file is exactly "the extra power this detection needs" and is
  # reviewable on its own.
  detection_policy = templatefile(
    "${path.module}/../remediations/${each.value.package}/policy.json",
    {
      partition  = local.partition
      account_id = var.account_id
      region     = var.region
    },
  )

  name_prefix = local.name_prefix
  environment = var.environment
  dry_run     = var.dry_run
  region      = var.region
  account_id  = var.account_id
  partition   = local.partition

  lambda_zip_path      = data.archive_file.lambda.output_path
  lambda_source_hash   = data.archive_file.lambda.output_base64sha256
  timeout_seconds      = var.lambda_timeout_seconds
  memory_mb            = var.lambda_memory_mb
  reserved_concurrency = var.reserved_concurrency

  audit_table_name = aws_dynamodb_table.audit.name
  audit_table_arn  = aws_dynamodb_table.audit.arn
  kms_key_arn      = aws_kms_key.pac.arn
  slack_secret_arn = aws_secretsmanager_secret.slack_webhook.arn

  circuit_breaker_max_actions    = var.circuit_breaker_max_actions
  circuit_breaker_window_seconds = var.circuit_breaker_window_seconds
  dedup_window_seconds           = var.dedup_window_seconds

  log_retention_days = var.log_retention_days
  alarm_topic_arn    = var.alarm_topic_arn
}
