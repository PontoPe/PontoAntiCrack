# The audit table.
#
# Holds three item families under one pair of keys:
#
#   AUDIT#<detection>#<resource>  the pre-change snapshot and the outcome
#   CB#<detection>                circuit breaker counters (TTL'd)
#   DEDUP#<fingerprint>           alert suppression claims (TTL'd)
#
# One table because all three are written on the same code path by the same
# roles, and because a second on-demand table would double the operational
# surface to save nothing. Audit items carry no TTL — they are the rollback
# source and the evidence trail, and deleting evidence on a timer is exactly
# what threat R6 is about.

resource "aws_dynamodb_table" "audit" {
  name         = "${local.name_prefix}-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.pac.arn
  }

  point_in_time_recovery {
    enabled = true
  }

  # Threat R3: an attacker who can delete this table destroys both the rollback
  # source and the record of what they did. Deletion protection is the cheap
  # half of the control; the SCP on pac-* resources in AwLZ is the other half.
  deletion_protection_enabled = true

  lifecycle {
    prevent_destroy = true
  }
}
