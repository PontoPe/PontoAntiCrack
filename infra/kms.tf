# One customer-managed key for everything this stack encrypts: the audit table,
# the Slack webhook secret, the dead-letter queues, and the function log groups.
#
# One key rather than four because a CMK is USD 1/month and this repository's
# entire budget is USD 20/month shared with AwLZ. The blast radius of sharing is
# acceptable — all four are components of the same system, with the same
# operators and the same lifecycle. Splitting them would buy separation between
# things that are already compromised together.

resource "aws_kms_key" "pac" {
  description             = "PontoAntiCrack: audit table, webhook secret, dead-letter queues, function logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "pac" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.pac.key_id
}

data "aws_iam_policy_document" "kms" {
  # checkov:skip=CKV_AWS_109:This is a KMS key policy, not an identity policy, and checkov evaluates the two with the same rules. In a key policy `Resource: "*"` means "the key this policy is attached to" — it is the only form AWS accepts, and scoping it to the key ARN is rejected at CreateKey. The `kms:*` grant to the account root is likewise mandatory: AWS refuses a key policy that leaves no principal able to administer the key, and without it the key becomes unmanageable and unrecoverable. Neither is a real permissions-management exposure.
  # checkov:skip=CKV_AWS_111:Same reason. The write actions flagged here are the root administration grant that AWS requires on every CMK. Actual use of the key is granted by the per-detection IAM policies in modules/detection, which are scoped to this key ARN, to specific actions, and by kms:ViaService.
  # checkov:skip=CKV_AWS_356:Same reason. `Resource: "*"` inside a key policy is self-referential, not account-wide.

  # Without this the key is unmanageable: AWS refuses a key policy that leaves
  # no principal able to administer it.
  statement {
    sid    = "AccountRootManagesTheKey"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${var.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchLogsEncryptsLogGroups"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]

    # Scoped so the log service can only use this key for log groups in this
    # account, not for anything else it happens to be asked to encrypt.
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${var.region}:${var.account_id}:log-group:*"]
    }
  }
}
