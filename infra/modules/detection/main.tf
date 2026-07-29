# One detection: EventBridge rule, Lambda, its own execution role, its own log
# group, its own dead-letter queue, its own alarms.
#
# The unit of isolation is this module. Three instances of it share a table, a
# key, and a deployment artifact, and share no permissions at all — a compromise
# of the sg-open function yields the ability to revoke security group ingress
# and nothing else. That is threat R1's control, and it is why this is a module
# rather than three functions on one role.

locals {
  name = "${var.name_prefix}-${var.detection_id}"
}

# ---------------------------------------------------------------------------
# Execution role
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    # Without these the role can be assumed by the Lambda service on behalf of
    # any account that can talk it into doing so — the confused deputy.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${var.partition}:lambda:${var.region}:${var.account_id}:function:${local.name}"]
    }
  }
}

resource "aws_iam_role" "detection" {
  name                 = "${local.name}-remediation"
  description          = "Execution role for the ${var.detection_id} remediation. Scoped to that detection only."
  assume_role_policy   = data.aws_iam_policy_document.assume_role.json
  max_session_duration = 3600
}

# The detection-specific permissions, straight from
# remediations/<package>/policy.json. Kept as a separate inline policy so a
# diff on the review of a remediation shows exactly the capability being added.
resource "aws_iam_role_policy" "detection" {
  name   = "${var.detection_id}-remediation"
  role   = aws_iam_role.detection.id
  policy = var.detection_policy
}

# The runtime permissions every detection needs and none needs more of.
data "aws_iam_policy_document" "runtime" {
  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    # Scoped to this function's own log group. A remediation role that can write
    # to any log group can also forge the record of what it did.
    resources = ["${aws_cloudwatch_log_group.detection.arn}:*"]
  }

  statement {
    sid    = "WriteAuditTrail"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:GetItem",
    ]
    resources = [var.audit_table_arn]
  }

  # No dynamodb:DeleteItem and no dynamodb:BatchWriteItem. The remediation path
  # never removes an audit record, so the role that walks that path must not be
  # able to. Threat R6.

  statement {
    sid       = "ReadAlertWebhook"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.slack_secret_arn]
  }

  statement {
    sid       = "EncryptThroughTheServicesThisFunctionWritesTo"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey"]
    resources = [var.kms_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "dynamodb.${var.region}.amazonaws.com",
        "secretsmanager.${var.region}.amazonaws.com",
        "sqs.${var.region}.amazonaws.com",
      ]
    }
  }

  statement {
    sid       = "DecryptWithTheStackKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]

    # No kms:ViaService condition here, unlike the statement above. Lambda
    # decrypts the function's own environment variables using this role
    # directly, not through another service, so a ViaService condition would
    # make the function fail to start. The grant is still bound to this one key.
  }

  statement {
    sid       = "SendUnprocessableEventsToItsOwnDeadLetterQueue"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dead_letter.arn]
  }
}

resource "aws_iam_role_policy" "runtime" {
  name   = "${var.detection_id}-runtime"
  role   = aws_iam_role.detection.id
  policy = data.aws_iam_policy_document.runtime.json
}

# ---------------------------------------------------------------------------
# Logs and dead letters
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "detection" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

# An event that reaches this queue is an event the detection did not act on.
# The alarm on its depth is the difference between a detection that broke and a
# detection that broke silently — threat R4.
resource "aws_sqs_queue" "dead_letter" {
  name                              = "${local.name}-dlq"
  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = 1209600 # 14 days, the maximum
  sqs_managed_sse_enabled           = false
}

data "aws_iam_policy_document" "dead_letter" {
  statement {
    sid    = "OnlyThisDetectionsFunctionMayWriteHere"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dead_letter.arn]

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${var.partition}:lambda:${var.region}:${var.account_id}:function:${local.name}"]
    }
  }

  statement {
    sid    = "DenyPlaintextTransport"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["sqs:*"]
    resources = [aws_sqs_queue.dead_letter.arn]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sqs_queue_policy" "dead_letter" {
  queue_url = aws_sqs_queue.dead_letter.id
  policy    = data.aws_iam_policy_document.dead_letter.json
}

# ---------------------------------------------------------------------------
# Function
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "detection" {
  # checkov:skip=CKV_AWS_117:Not in a VPC, deliberately. The function calls only public AWS service endpoints (S3, EC2, IAM, DynamoDB, Secrets Manager) plus the Slack webhook, and reaches no private resource. Placing it in a VPC would require either a NAT gateway (~USD 32/month, more than this repository's entire USD 20/month budget) or five interface endpoints (~USD 36/month), to protect against nothing: there is no lateral movement path into a VPC it does not touch. Revisit if a remediation ever needs to reach a private resource.
  # checkov:skip=CKV_AWS_272:Code signing is not configured. The signing profile is free, but signed artifacts require the build to hold a Signer identity, which puts a new credential into a CI pipeline that currently holds none — a worse trade than the risk it removes while this repository is single-author and the artifact is built from a pinned commit. Revisit when CI gains deploy credentials.
  function_name = local.name
  description   = var.description
  role          = aws_iam_role.detection.arn

  filename         = var.lambda_zip_path
  source_code_hash = var.lambda_source_hash
  handler          = "remediations.${var.package}.handler.lambda_handler"
  runtime          = "python3.13"
  architectures    = ["arm64"]

  timeout     = var.timeout_seconds
  memory_size = var.memory_mb

  # Environment variables at rest under the stack key rather than the
  # AWS-managed default. Nothing secret is in them by design — the webhook is
  # referenced by ARN — but this puts their readability under a key policy we
  # control rather than one we do not.
  kms_key_arn = var.kms_key_arn

  # Bounds how fast an invocation storm can arrive. The DynamoDB circuit breaker
  # bounds how much damage it can do once it does. Both, because they fail
  # differently.
  reserved_concurrent_executions = var.reserved_concurrency

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dead_letter.arn
  }

  environment {
    variables = {
      PAC_DETECTION_ID                   = var.detection_id
      PAC_TABLE_NAME                     = var.audit_table_name
      PAC_ENVIRONMENT                    = var.environment
      PAC_DRY_RUN                        = var.dry_run ? "true" : "false"
      PAC_EXCLUSION_TAG                  = "pac:exclude"
      PAC_CIRCUIT_BREAKER_MAX_ACTIONS    = tostring(var.circuit_breaker_max_actions)
      PAC_CIRCUIT_BREAKER_WINDOW_SECONDS = tostring(var.circuit_breaker_window_seconds)
      PAC_DEDUP_WINDOW_SECONDS           = tostring(var.dedup_window_seconds)
      # An ARN, not a webhook. The value is fetched at runtime so it never
      # appears in GetFunctionConfiguration, in CloudTrail, or in the state file.
      PAC_SLACK_SECRET_ARN = var.slack_secret_arn
      PAC_LOG_LEVEL        = "INFO"
    }
  }

  # The role's policies must exist before the function, or the first invocation
  # races them and fails with AccessDenied for reasons that look like a bug.
  depends_on = [
    aws_iam_role_policy.detection,
    aws_iam_role_policy.runtime,
    aws_cloudwatch_log_group.detection,
  ]
}

# ---------------------------------------------------------------------------
# Trigger
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "detection" {
  name          = local.name
  description   = var.description
  event_pattern = var.event_pattern
  state         = "ENABLED"
}

resource "aws_cloudwatch_event_target" "detection" {
  rule = aws_cloudwatch_event_rule.detection.name
  arn  = aws_lambda_function.detection.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }

  dead_letter_config {
    arn = aws_sqs_queue.dead_letter.arn
  }
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowExecutionFrom${replace(title(replace(var.detection_id, "-", " ")), " ", "")}Rule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detection.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection.arn
}

# ---------------------------------------------------------------------------
# Alarms
# ---------------------------------------------------------------------------

# A detection that throws is a detection that is not detecting.
resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${local.name}-errors"
  alarm_description   = "The ${var.detection_id} remediation is failing. Events are matching and nothing is being remediated."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.detection.function_name
  }

  alarm_actions = var.alarm_topic_arn == "" ? [] : [var.alarm_topic_arn]
  ok_actions    = var.alarm_topic_arn == "" ? [] : [var.alarm_topic_arn]
}

# Threat R4, the silent failure: events arriving and being dropped is worse than
# the function erroring, because nothing else about the system looks wrong.
resource "aws_cloudwatch_metric_alarm" "dead_letters" {
  alarm_name          = "${local.name}-dead-letters"
  alarm_description   = "Events for ${var.detection_id} are being dead-lettered. This detection is blind until the queue is drained and the cause fixed."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.dead_letter.name
  }

  alarm_actions = var.alarm_topic_arn == "" ? [] : [var.alarm_topic_arn]
}

# Throttling means the concurrency cap is being hit, which means either a real
# storm or a limit set too low. Both need a human.
resource "aws_cloudwatch_metric_alarm" "throttles" {
  alarm_name          = "${local.name}-throttles"
  alarm_description   = "The ${var.detection_id} remediation is being throttled by its own concurrency cap. Either an event storm is in progress or reserved_concurrency is too low."
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.detection.function_name
  }

  alarm_actions = var.alarm_topic_arn == "" ? [] : [var.alarm_topic_arn]
}
