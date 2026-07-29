output "function_name" {
  description = "Remediation function for this detection."
  value       = aws_lambda_function.detection.function_name
}

output "function_arn" {
  value = aws_lambda_function.detection.arn
}

output "role_arn" {
  description = "Execution role. One per detection, scoped to that detection's actions only."
  value       = aws_iam_role.detection.arn
}

output "rule_arn" {
  value = aws_cloudwatch_event_rule.detection.arn
}

output "dead_letter_queue_url" {
  description = "Events the function could not process. A non-empty queue means a blind detection."
  value       = aws_sqs_queue.dead_letter.url
}
