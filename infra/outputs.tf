output "audit_table_name" {
  description = "DynamoDB table holding snapshots, circuit breaker counters, and dedup claims."
  value       = aws_dynamodb_table.audit.name
}

output "kms_key_arn" {
  description = "Key encrypting the audit table, the webhook secret, the queues, and the log groups."
  value       = aws_kms_key.pac.arn
}

output "slack_webhook_secret_arn" {
  description = "Populate this with put-secret-value. Terraform never writes the value."
  value       = aws_secretsmanager_secret.slack_webhook.arn
}

output "detection_function_names" {
  description = "Lambda function per detection."
  value       = { for id, detection in module.detection : id => detection.function_name }
}

output "detection_role_arns" {
  description = "Execution role per detection. One role each, scoped to that detection's actions."
  value       = { for id, detection in module.detection : id => detection.role_arn }
}

output "dry_run" {
  description = "Whether remediations will actually modify resources."
  value       = var.dry_run
}

output "post_apply_checklist" {
  description = "What to do after this applies. See docs/session-report.md for the full version."
  value = [
    "1. aws secretsmanager put-secret-value --secret-id ${var.slack_webhook_secret_name} --secret-string '{\"webhook_url\":\"https://hooks.slack.com/services/...\"}'",
    "2. Confirm each pattern against the real service: aws events test-event-pattern --event-pattern file://detections/<id>/pattern.json --event file://tests/fixtures/...",
    "3. Trigger one benign event per detection and read the delivered event out of the function's log group.",
    "4. Replace the documentation-derived fixtures with the captured events and flip the _pac_fixture markers.",
    "5. Only then consider dry_run = false. Currently ${var.dry_run ? "true — nothing will be modified" : "FALSE — remediations will modify live resources"}.",
  ]
}
