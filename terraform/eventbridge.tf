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

resource "aws_cloudwatch_event_rule" "root_activity" {
  name        = "${local.project_name}-root-activity"
  description = "Detect AWS API activity performed using the root account."

  event_pattern = jsonencode({
    source = ["aws.cloudtrail"]

    detail-type = [
      "AWS API Call via CloudTrail"
    ]

    detail = {
      userIdentity = {
        type = [
          "Root"
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "root_activity" {
  rule = aws_cloudwatch_event_rule.root_activity.name
  arn  = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "root_activity_eventbridge" {
  statement_id  = "AllowRootActivityFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.root_activity.arn
}
