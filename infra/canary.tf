# Opt-in sandbox canary. Never creates a VPC, trail, backend or instance.
variable "canary_enabled" {
  type        = bool
  description = "Enable real EC2 mutations on a dedicated unattached lab SG. Review plan first."
  default     = false
}
variable "canary_round" {
  type        = string
  description = "Unique round ID; exact tag value authorizing the dedicated SG."
  default     = ""
  validation {
    condition     = var.canary_round == "" || can(regex("^[a-z0-9][a-z0-9-]{0,31}$", var.canary_round))
    error_message = "Use a lowercase round ID, at most 32 characters."
  }
}
variable "canary_vpc_id" {
  type        = string
  description = "Existing isolated lab VPC, confirmed by inventory; never inferred."
  default     = ""
}
variable "sg_scope_group_id" {
  type        = string
  description = "Exact existing unattached SG for manual testing when automatic canary is disabled."
  default     = ""
  validation {
    condition     = var.sg_scope_group_id == "" || can(regex("^sg-[a-f0-9]+$", var.sg_scope_group_id))
    error_message = "Supply an exact SG ID, not a wildcard."
  }
}
locals {
  sg_scope_group = var.canary_enabled ? aws_security_group.canary[0].id : var.sg_scope_group_id
  canary_functions = var.canary_enabled ? {
    producer = { handler = "canary.handler.lambda_handler", schedule = "cron(0/5 * * * ? *)" }
    observer = { handler = "canary.observer.lambda_handler", schedule = "cron(4/5 * * * ? *)" }
  } : {}
  canary_env = {
    PAC_SCOPE_ACCOUNT = var.account_id
    PAC_SCOPE_REGION  = var.region
    PAC_SCOPE_GROUP   = local.sg_scope_group
    PAC_SCOPE_ROUND   = var.canary_round
    PAC_TABLE_NAME    = aws_dynamodb_table.audit.name
  }
}
resource "aws_security_group" "canary" {
  # checkov:skip=CKV2_AWS_5:Unattached by design: this SG is a real-event canary, never a workload firewall. Attaching it would expose a workload during the experiment; Scope.inspect refuses ENIs. Revisit only if the canary design changes; threat model register.
  count       = var.canary_enabled ? 1 : 0
  name_prefix = "pac-canary-${var.canary_round}-"
  description = "Unattached disposable SG for PAC response effect verification"
  vpc_id      = var.canary_vpc_id
  # No standing ingress or egress. Producer opens only SSH to trigger the
  # genuine CloudTrail path. Do not attach this SG to anything.
  tags = { "pac:canary" = var.canary_round }
  lifecycle {
    # EC2 ingress is the experimental state, not Terraform-managed desired
    # state. Never use an apply to undo a detonation or erase its evidence.
    ignore_changes = [ingress]
    precondition {
      condition = (var.environment == "lab" && var.region == "sa-east-1" &&
        var.canary_round != "" && var.canary_vpc_id != "" &&
      var.alarm_topic_arn != "" && contains(var.detections_enabled, "sg-open"))
      error_message = "Canary requires explicit lab scope, existing VPC, sg-open and an independently tested SNS topic."
    }
  }
}
resource "aws_iam_role" "canary" {
  for_each = local.canary_functions
  # Deliberately NOT pac-*: the remediation's loop guard must inspect these
  # real API calls instead of classifying them as its own remediation calls.
  name = "labcanary-${var.canary_round}-${each.key}"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
}
resource "aws_cloudwatch_log_group" "canary" {
  for_each          = local.canary_functions
  name              = "/aws/lambda/${local.name_prefix}-canary-${var.canary_round}-${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.pac.arn
}
resource "aws_sqs_queue" "canary" {
  for_each                  = local.canary_functions
  name                      = "${local.name_prefix}-canary-${var.canary_round}-${each.key}-dlq"
  kms_master_key_id         = aws_kms_key.pac.arn
  message_retention_seconds = 1209600
}
resource "aws_sqs_queue_policy" "canary" {
  for_each  = local.canary_functions
  queue_url = aws_sqs_queue.canary[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "sqs:*",
    Resource  = aws_sqs_queue.canary[each.key].arn,
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] })
}
resource "aws_iam_role_policy" "canary" {
  for_each = local.canary_functions
  role     = aws_iam_role.canary[each.key].id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat([
    { Effect = "Allow", Action = ["ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces"], Resource = "*" },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.canary[each.key].arn}:*" },
    { Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.pac.arn },
    { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.canary[each.key].arn },
    {
      Effect    = "Allow", Action = each.key == "producer" ? ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"] : ["dynamodb:GetItem", "dynamodb:Query"],
      Resource  = aws_dynamodb_table.audit.arn,
      Condition = { "ForAllValues:StringLike" = { "dynamodb:LeadingKeys" = each.key == "producer" ? ["CANARY#${var.canary_round}"] : ["CANARY#${var.canary_round}", "AUDIT#sg-open#${local.sg_scope_group}"] } }
    }
    ], each.key == "producer" ? [{
      Effect    = "Allow", Action = ["ec2:AuthorizeSecurityGroupIngress"],
      Resource  = "arn:${local.partition}:ec2:${var.region}:${var.account_id}:security-group/${local.sg_scope_group}",
      Condition = { StringEquals = { "ec2:ResourceTag/pac:canary" = var.canary_round }, Null = { "ec2:ResourceTag/pac:exclude" = "true" } }
      }] : [{
      Effect    = "Allow", Action = ["cloudwatch:PutMetricData"], Resource = "*",
      Condition = { StringEquals = { "cloudwatch:namespace" = "PAC/Canary" } }
  }]) })
}
resource "aws_lambda_function" "canary" {
  for_each = local.canary_functions
  # checkov:skip=CKV_AWS_117:Public AWS APIs only, no VPC data plane. NAT costs exceed the whole lab budget; same accepted risk as detection functions, threat model register.
  # checkov:skip=CKV_AWS_272:Same local pinned-commit artifact as detections; no CI deployment identity or signing profile. Revisit when CI receives deploy capability; threat model register.
  function_name                  = "${local.name_prefix}-canary-${var.canary_round}-${each.key}"
  description                    = "Independent ${each.key} for dedicated PAC lab canary"
  role                           = aws_iam_role.canary[each.key].arn
  handler                        = each.value.handler
  runtime                        = "python3.13"
  architectures                  = ["arm64"]
  filename                       = data.archive_file.lambda.output_path
  source_code_hash               = data.archive_file.lambda.output_base64sha256
  timeout                        = 30
  memory_size                    = 256
  reserved_concurrent_executions = 1
  kms_key_arn                    = aws_kms_key.pac.arn
  environment { variables = local.canary_env }
  tracing_config { mode = "Active" }
  dead_letter_config { target_arn = aws_sqs_queue.canary[each.key].arn }
  depends_on = [aws_iam_role_policy.canary]
}
resource "aws_lambda_function_event_invoke_config" "canary" {
  for_each                     = local.canary_functions
  function_name                = aws_lambda_function.canary[each.key].function_name
  maximum_event_age_in_seconds = 60
  maximum_retry_attempts       = 0
}
resource "aws_cloudwatch_event_rule" "canary" {
  for_each            = local.canary_functions
  name                = "${local.name_prefix}-canary-${var.canary_round}-${each.key}"
  description         = "Independent ${each.key} schedule; never uses the sg-open rule"
  schedule_expression = each.value.schedule
  # Begin disabled. Read state and test notification delivery, then explicitly
  # enable only the exact round's schedules after deployment review.
  state = "DISABLED"
}
resource "aws_cloudwatch_event_target" "canary" {
  for_each = local.canary_functions
  rule     = aws_cloudwatch_event_rule.canary[each.key].name
  arn      = aws_lambda_function.canary[each.key].arn
  retry_policy {
    maximum_event_age_in_seconds = 60
    maximum_retry_attempts       = 0
  }
}
resource "aws_lambda_permission" "canary" {
  for_each       = local.canary_functions
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.canary[each.key].function_name
  principal      = "events.amazonaws.com"
  source_arn     = aws_cloudwatch_event_rule.canary[each.key].arn
  source_account = var.account_id
}
resource "aws_cloudwatch_metric_alarm" "canary" {
  count               = var.canary_enabled ? 1 : 0
  alarm_name          = "${local.name_prefix}-canary-${var.canary_round}-effect"
  alarm_description   = "No independently correlated successful SG remediation, or observer unavailable"
  namespace           = "PAC/Canary"
  metric_name         = "EffectVerified"
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  dimensions          = { Round = var.canary_round }
  alarm_actions       = [var.alarm_topic_arn]
  ok_actions          = [var.alarm_topic_arn]
}
