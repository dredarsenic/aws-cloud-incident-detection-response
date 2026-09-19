resource "aws_dynamodb_table" "incidents" {
  name         = "${local.project_name}-incidents"
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }
}
