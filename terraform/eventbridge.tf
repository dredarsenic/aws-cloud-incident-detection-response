resource "aws_cloudwatch_event_rule" "cloudtrail_tampering" {
  name        = "${local.project_name}-cloudtrail-tampering"
  description = "Detect attempts to disable or modify CloudTrail logging."

  event_pattern = jsonencode({
    source = ["aws.cloudtrail"]

    detail-type = [
      "AWS API Call via CloudTrail"
    ]

    detail = {
      eventSource = [
        "cloudtrail.amazonaws.com"
      ]

      eventName = [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "cloudtrail_tampering" {
  rule = aws_cloudwatch_event_rule.cloudtrail_tampering.name
  arn  = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudtrail_tampering.arn
}
