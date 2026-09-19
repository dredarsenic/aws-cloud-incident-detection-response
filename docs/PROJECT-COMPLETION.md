# AWS Cloud Incident Detection & Automated Response
## Project Completion Summary

**Status:** Completed  
**Version:** v1.0  
**Completion Date:** 19 September 2026

## Objective

Build an AWS-native cloud security platform capable of detecting suspicious activity and dangerous configuration changes, preserving forensic evidence, creating auditable incidents, notifying responders, and optionally performing controlled automated containment.

## Architecture

AWS Activity / GuardDuty
-> CloudTrail / EventBridge
-> Lambda Detection Engine
-> DynamoDB Incident Store
-> S3 Evidence Store
-> SNS Security Alerts
-> Optional Automated Containment

## Implemented Capabilities

### CloudTrail Defense-Evasion Detection

Detects:

- StopLogging
- DeleteTrail
- UpdateTrail
- PutEventSelectors

MITRE ATT&CK:

- T1562.008 - Disable or Modify Cloud Logs

### AWS Root Account Activity

Detects API activity performed using the AWS root identity.

MITRE ATT&CK:

- T1078.004 - Cloud Accounts

### IAM Privilege Escalation

Detects attachment of the AWS managed AdministratorAccess policy to IAM:

- Users
- Roles
- Groups

MITRE ATT&CK:

- T1098 - Account Manipulation

### IAM Access Key Creation

Detects creation of new long-lived IAM credentials.

MITRE ATT&CK:

- T1098.001 - Additional Cloud Credentials

### Public SSH/RDP Exposure

Detects security group ingress exposing:

- SSH TCP/22
- RDP TCP/3389

to:

- 0.0.0.0/0
- ::/0

MITRE ATT&CK:

- T1133 - External Remote Services

The detector performs contextual inspection instead of alerting on every security group modification.

### False-Positive Control

A negative test verified that SSH restricted to the private network 10.0.0.0/8 does not create an incident.

### Amazon GuardDuty Integration

Amazon GuardDuty findings are routed through EventBridge into the custom incident-response pipeline.

Validated using an official AWS GuardDuty sample finding:

- UnauthorizedAccess:EC2/TorClient

The finding was normalized into the common incident model and generated:

- S3 forensic evidence
- DynamoDB incident record
- SNS security alert

### Automated Containment

The platform supports two operating modes:

- alert
- contain

Alert mode is the default.

A controlled containment test demonstrated automatic remediation of public SSH exposure.

During the test:

1. An isolated security group was created.
2. The security group was not attached to any workload.
3. TCP/22 was opened to 0.0.0.0/0.
4. CloudTrail recorded the API operation.
5. EventBridge routed the event to Lambda.
6. Lambda classified the event as HIGH severity.
7. Lambda invoked RevokeSecurityGroupIngress.
8. The dangerous rule was removed automatically.
9. Evidence and incident records were preserved.
10. SNS delivered the containment result.

After testing, response mode was returned to alert.

## Incident Data

Normalized incidents contain information including:

- Incident ID
- Severity
- Status
- Detection
- Event type
- AWS account
- Region
- Principal
- Source IP
- Event time
- Resource
- MITRE ATT&CK mapping
- Response mode
- Containment result
- Recommended response
- Evidence location

## Security Controls

The platform implements:

- Infrastructure as Code with Terraform
- Least-privilege Lambda IAM permissions
- S3 encryption
- S3 versioning
- S3 public-access blocking
- CloudTrail log-file validation
- Multi-region CloudTrail
- DynamoDB encryption
- DynamoDB point-in-time recovery
- Evidence preservation
- Event-driven security automation
- Safe alert-first response model

## Validation

The project was tested using:

- Synthetic CloudTrail events
- Real AWS API activity
- EventBridge event-pattern validation
- Official GuardDuty sample findings
- Positive detection tests
- Negative false-positive tests
- Real controlled automated containment

Testing demonstrated the complete workflow:

Detection
-> Investigation Context
-> Evidence Preservation
-> Incident Recording
-> Alerting
-> Optional Containment

## Evidence

Sanitized deployment and test evidence is available under:

`evidence/`

Raw security-event evidence remains in the project's dedicated AWS S3 evidence bucket.

## Safety

Automated containment is disabled by default.

The default configuration is:

`response_mode = "alert"`

Containment should only be enabled after detection logic has been validated against the target environment.

## Future Version

A future v2 may expand the platform with:

- Multi-account AWS Organizations support
- Security Hub integration
- Step Functions response workflows
- SQS dead-letter queues
- KMS customer-managed encryption keys
- Immutable S3 Object Lock evidence storage
- Incident deduplication and correlation
- Risk scoring
- Automated IAM credential quarantine
- EC2 network isolation
- Slack / Microsoft Teams / ticketing integrations
- CloudWatch dashboards
- Cross-region incident aggregation
- CI/CD security testing
- Unit and integration test suites
- Additional GuardDuty finding-specific playbooks

Version 1.0 is intentionally considered complete rather than continuously expanding scope.
