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

## Test 4 - AdministratorAccess Privilege Escalation Detection

A synthetic CloudTrail event representing an IAM `AttachRolePolicy` operation was submitted to the deployed detection Lambda.

The event simulated attachment of the AWS managed `AdministratorAccess` policy to an IAM role.

The deployed EventBridge rule was independently tested using the AWS Events `test-event-pattern` API and successfully matched the event.

Expected detection:

- Event: `AttachRolePolicy`
- Policy: `AdministratorAccess`
- Severity: `CRITICAL`
- Detection: AdministratorAccess policy attached
- MITRE ATT&CK: `T1098`
- Response mode: `alert`

Observed incident:

- Incident ID: `IR-20260919-145823-3988da73`
- Status: `OPEN`
- EventBridge pattern match: `true`
- Evidence successfully preserved in Amazon S3
- Incident successfully recorded in DynamoDB
- CRITICAL SNS alert successfully generated

This test validated detection of a high-risk IAM privilege escalation attempt without modifying a real IAM role.

### administrator-access-eventbridge-rule.json

Shows the deployed EventBridge rule used to detect attachment of the AWS managed `AdministratorAccess` policy to IAM users, roles, or groups.

## Test 5 - Public SSH Exposure Detection

A synthetic CloudTrail `AuthorizeSecurityGroupIngress` event was submitted representing TCP port 22 being exposed to `0.0.0.0/0`.

Expected detection:

- Event: `AuthorizeSecurityGroupIngress`
- Port: `22`
- CIDR: `0.0.0.0/0`
- Severity: `HIGH`
- Detection: Security group exposes SSH or RDP to the internet
- MITRE ATT&CK: `T1133`

Observed result:

- Detection successfully triggered
- HIGH security incident created
- Incident recorded in DynamoDB
- Raw event preserved in Amazon S3
- SNS email alert successfully delivered

Observed incident:

- Incident ID: `IR-20260919-150503-016b052a`

## Test 6 - Private SSH Negative Test

A second synthetic `AuthorizeSecurityGroupIngress` event was submitted for TCP port 22 restricted to the private CIDR `10.0.0.0/8`.

Expected behavior:

- EventBridge forwards the security-group change
- Lambda inspects port and CIDR context
- No security incident is created
- No evidence object is written
- No SNS notification is sent

Observed result:

- Lambda returned `No matching security detection.`
- DynamoDB incident count remained unchanged at 5
- S3 evidence count remained unchanged at 5

This negative test demonstrates false-positive control by distinguishing publicly exposed remote-management ports from restricted private-network access.

### public-remote-access-eventbridge-rule.json

Shows the deployed EventBridge rule forwarding EC2 `AuthorizeSecurityGroupIngress` API activity to the detection Lambda.

### private-ssh-negative-test.json

Documents the successful negative test confirming that restricted SSH access does not generate a security incident.

## Test 7 - Amazon GuardDuty Managed Threat Detection

Amazon GuardDuty was integrated with the custom incident-response pipeline using Amazon EventBridge.

An official AWS GuardDuty sample finding was generated using the GuardDuty `create-sample-findings` API. No malicious activity was performed.

Finding tested:

- Type: `UnauthorizedAccess:EC2/TorClient`
- Severity: `HIGH`
- Resource: Sample EC2 instance
- Source: Amazon GuardDuty managed detection
- Response mode: `alert`

Observed incident:

- Incident ID: `IR-20260919-160705-fd9815ad`
- Status: `OPEN`
- GuardDuty finding successfully delivered to EventBridge
- Lambda successfully normalized the GuardDuty finding
- Affected EC2 resource successfully extracted
- Raw GuardDuty evidence preserved in Amazon S3
- Incident successfully recorded in DynamoDB
- HIGH SNS email alert successfully delivered

This test validated integration between an AWS-managed threat detection service and the custom incident-response platform:

GuardDuty
-> EventBridge
-> Lambda Detection Engine
-> S3 Evidence Preservation
-> DynamoDB Incident Record
-> SNS Security Alert

### guardduty-eventbridge-rule.json

Shows the deployed EventBridge rule used to route GuardDuty findings into the incident detection Lambda.

### guardduty-sample-finding.json

Contains a sanitized representation of the official AWS sample GuardDuty finding used to validate the integration.

## Test 8 - Automated Public SSH Containment

A temporary isolated security group was created for a controlled automated-response test. The security group was not attached to any EC2 instance or network interface.

A real AWS `AuthorizeSecurityGroupIngress` API call opened TCP port 22 to `0.0.0.0/0`.

The platform detected the CloudTrail event and classified it as a HIGH-severity public remote-access exposure.

For this controlled test only, `response_mode` was changed from `alert` to `contain`.

Observed response:

- CloudTrail captured the real AWS API operation.
- EventBridge routed the event to Lambda.
- Lambda identified public SSH exposure.
- The incident was created and evidence preserved.
- Lambda invoked `RevokeSecurityGroupIngress`.
- The public SSH rule was automatically removed.
- SNS delivered the containment result.
- The security group contained no ingress permissions after remediation.

The test security group was isolated and not attached to a workload.

After validation, the platform was returned to its default `alert` response mode and the temporary security group was deleted.

### automated-containment-test.json

Contains a sanitized record of the successful automated containment test.
