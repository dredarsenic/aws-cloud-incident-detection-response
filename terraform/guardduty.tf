resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${local.project_name}-guardduty-findings"
  description = "Route GuardDuty findings to the cloud incident detection engine."

  event_pattern = jsonencode({
    source = [
      "aws.guardduty"
    ]

    detail-type = [
      "GuardDuty Finding"
    ]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_findings" {
  rule = aws_cloudwatch_event_rule.guardduty_findings.name
  arn  = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "guardduty_eventbridge" {
  statement_id  = "AllowGuardDutyFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}
