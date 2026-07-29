# One provider, one account. Detections are deployed per account rather than
# from a central account assuming into members: a remediation role that can be
# assumed cross-account is a far more attractive target than three roles that
# cannot leave their own account (threat R1).
#
# allowed_account_ids is the guard that stops a stale SSO session from applying
# this to the wrong account.

provider "aws" {
  region              = var.region
  profile             = var.profile != "" ? var.profile : null
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = local.tags
  }
}
