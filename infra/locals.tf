locals {
  name_prefix = var.project

  tags = merge(
    {
      Project   = "PontoAntiCrack"
      ManagedBy = "terraform"
      Repo      = "github.com/PontoPe/PontoAntiCrack"
      Env       = var.environment
    },
    var.tags,
  )

  partition = data.aws_partition.current.partition

  # Every detection in one place. `handler` is the module path inside the
  # deployment package; `package` is the Python package name, which is the
  # detection ID with hyphens swapped for underscores.
  detections = {
    "s3-public" = {
      package     = "s3_public"
      description = "Remove public exposure from an S3 bucket"
    }
    "iam-key-leak" = {
      package     = "iam_key_leak"
      description = "Deactivate an IAM access key GuardDuty flagged as abused"
    }
    "sg-open" = {
      package     = "sg_open"
      description = "Revoke security group ingress open to the internet"
    }
  }

  enabled_detections = {
    for id, detection in local.detections : id => detection
    if contains(var.detections_enabled, id)
  }
}

data "aws_partition" "current" {}
