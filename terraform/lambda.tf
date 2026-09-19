data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/lambda.zip"
}

resource "aws_lambda_function" "detector" {
  function_name = "${local.project_name}-detection-engine"

  role    = aws_iam_role.lambda.arn
  handler = "incident_handler.lambda_handler"
  runtime = "python3.12"

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  timeout = 30

  environment {
    variables = {
      INCIDENT_TABLE  = aws_dynamodb_table.incidents.name
      EVIDENCE_BUCKET = aws_s3_bucket.incident_evidence.bucket
      SNS_TOPIC_ARN   = aws_sns_topic.security_alerts.arn
      RESPONSE_MODE   = var.response_mode
    }
  }
}
