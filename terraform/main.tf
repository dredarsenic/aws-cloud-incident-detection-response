data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  project_name = "aws-cloud-ir"

  trail_name = "${local.project_name}-${var.environment}"

  account_id = data.aws_caller_identity.current.account_id
}
