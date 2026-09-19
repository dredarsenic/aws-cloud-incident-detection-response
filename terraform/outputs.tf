output "cloudtrail_name" {
  description = "Name of the CloudTrail trail."
  value       = aws_cloudtrail.security.name
}

output "cloudtrail_bucket" {
  description = "S3 bucket storing CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail_logs.bucket
}

output "incident_evidence_bucket" {
  description = "S3 bucket storing preserved incident evidence."
  value       = aws_s3_bucket.incident_evidence.bucket
}

output "incident_table" {
  description = "DynamoDB table storing security incidents."
  value       = aws_dynamodb_table.incidents.name
}

output "security_alert_topic" {
  description = "SNS topic used for security notifications."
  value       = aws_sns_topic.security_alerts.arn
}

output "lambda_function_name" {
  description = "Security detection Lambda function."
  value       = aws_lambda_function.detector.function_name
}
