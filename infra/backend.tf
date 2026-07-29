# Partial backend configuration, matching the AwLZ convention: the bucket and
# key are supplied at init time so the same code can be pointed at a different
# state without editing a tracked file.
#
#   terraform init -backend-config=backend.hcl
#
terraform {
  backend "s3" {}
}
