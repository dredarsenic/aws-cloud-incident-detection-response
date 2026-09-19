# Deployment and Detection Evidence

This directory contains sanitized evidence demonstrating that the AWS Cloud Incident Detection & Automated Response platform was successfully deployed and tested.

## Validation Date

19 September 2026

## Test 1 - Synthetic CloudTrail StopLogging Event

A synthetic CloudTrail event representing a `StopLogging` API call was submitted directly to the detection Lambda.

Expected detection:

- Event: `StopLogging`
- Severity: `CRITICAL`
- Detection: CloudTrail logging disabled
- MITRE ATT&CK: `T1562.008`
- Response mode: `alert`

Observed incident:

- Incident ID: `IR-20260919-142902-7a645bc0`
- Status: `OPEN`
- Evidence successfully written to Amazon S3
- Incident successfully written to DynamoDB
- CRITICAL SNS email alert successfully delivered

This validated:

Lambda -> S3 Evidence -> DynamoDB Incident -> SNS Alert

## Test 2 - Real AWS UpdateTrail Event

A real AWS CLI `UpdateTrail` operation was performed against the deployed CloudTrail trail without disabling logging or weakening its configuration.

The actual AWS API call was recorded by CloudTrail and matched by the EventBridge detection rule.

Expected detection:

- Event: `UpdateTrail`
- Severity: `HIGH`
- Detection: CloudTrail configuration modified
- MITRE ATT&CK: `T1562.008`
- Response mode: `alert`

Observed incident:

- Incident ID: `IR-20260919-143204-246e74f5`
- Status: `OPEN`
- Event automatically routed from CloudTrail through EventBridge
- Evidence successfully preserved in Amazon S3
- Incident successfully recorded in DynamoDB
- HIGH SNS email alert successfully delivered

This validated the complete detection path:

AWS API Activity
-> CloudTrail
-> EventBridge
-> Lambda Detection Engine
-> S3 Evidence
-> DynamoDB Incident Record
-> SNS Security Alert

## Evidence Files

### cloudtrail-status.json

Confirms that the deployed CloudTrail trail is actively logging.

### eventbridge-rule.json

Shows the deployed EventBridge detection rule and monitored CloudTrail API operations.

### lambda-config.json

Confirms the deployed detection Lambda configuration and runtime.

### dynamodb-incidents.json

Contains sanitized incident records generated during testing.

### s3-evidence-list.txt

Shows the forensic event objects preserved by the detection Lambda.

## Security Note

Evidence committed to this repository is intentionally sanitized. AWS credentials, secrets, Terraform state, local configuration, personal email information, and unnecessary source-IP information are not included.

Raw incident evidence remains stored in the dedicated encrypted and versioned S3 evidence bucket.

## Test 3 - AWS Root Account Activity Detection

A synthetic CloudTrail event representing AWS API activity performed using the root identity was submitted to the deployed detection Lambda.

The EventBridge event pattern was also independently tested using the AWS Events `test-event-pattern` API and returned a successful match.

Expected detection:

- Identity type: `Root`
- Event: `ListUsers`
- Severity: `CRITICAL`
- Detection: AWS root account activity detected
- MITRE ATT&CK: `T1078.004`
- Response mode: `alert`

Observed incident:

- Incident ID: `IR-20260919-145000-76e699ee`
- Status: `OPEN`
- EventBridge pattern match: `true`
- Evidence successfully preserved in Amazon S3
- Incident successfully recorded in DynamoDB
- CRITICAL SNS email alert successfully delivered

This test validated identity-based detection in addition to event-name-based detection.

No real AWS root account activity was performed during testing.

### root-activity-eventbridge-rule.json

Shows the deployed EventBridge rule used to identify AWS API activity where the CloudTrail `userIdentity.type` is `Root`.
