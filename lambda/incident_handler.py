import json
import os
import uuid
from datetime import datetime, timezone

import boto3

from detections import detect


dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
sns = boto3.client("sns")

INCIDENT_TABLE = os.environ["INCIDENT_TABLE"]
EVIDENCE_BUCKET = os.environ["EVIDENCE_BUCKET"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
RESPONSE_MODE = os.environ.get("RESPONSE_MODE", "alert")


def get_principal(detail):
    identity = detail.get("userIdentity", {})

    return (
        identity.get("arn")
        or identity.get("principalId")
        or identity.get("type")
        or "unknown"
    )


def generate_incident_id():
    now = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:8]

    return f"IR-{now}-{suffix}"


def preserve_evidence(incident_id, event):
    timestamp = datetime.now(timezone.utc)

    key = (
        f"incidents/"
        f"{timestamp.year}/"
        f"{timestamp.month:02d}/"
        f"{incident_id}.json"
    )

    s3.put_object(
        Bucket=EVIDENCE_BUCKET,
        Key=key,
        Body=json.dumps(event, indent=2).encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )

    return key


def store_incident(incident):
    table = dynamodb.Table(INCIDENT_TABLE)

    table.put_item(
        Item=incident
    )


def send_alert(incident):
    subject = (
        f"[{incident['severity']}] "
        f"AWS Security Incident - "
        f"{incident['event_name']}"
    )

    message = f"""
AWS CLOUD SECURITY INCIDENT

Incident ID: {incident['incident_id']}
Severity: {incident['severity']}
Status: {incident['status']}

Detection:
{incident['detection']}

AWS Account:
{incident['aws_account']}

Region:
{incident['region']}

Principal:
{incident['principal']}

Source IP:
{incident['source_ip']}

Event:
{incident['event_name']}

Event Time:
{incident['event_time']}

MITRE ATT&CK:
{incident['mitre_attack']}

Response Mode:
{incident['response_mode']}

Recommended Action:
{incident['recommended_action']}

Evidence:
s3://{EVIDENCE_BUCKET}/{incident['evidence_key']}
"""

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject[:100],
        Message=message,
    )


def lambda_handler(event, context):
    detail = event.get("detail", {})
    event_name = detail.get("eventName")

    detection = detect(event_name)

    if not detection:
        return {
            "statusCode": 200,
            "message": "No matching security detection.",
        }

    incident_id = generate_incident_id()

    evidence_key = preserve_evidence(
        incident_id,
        event,
    )

    incident = {
        "incident_id": incident_id,
        "status": "OPEN",
        "severity": detection["severity"],
        "detection": detection["title"],
        "event_name": event_name,
        "aws_account": event.get("account", "unknown"),
        "region": event.get("region", "unknown"),
        "principal": get_principal(detail),
        "source_ip": detail.get("sourceIPAddress", "unknown"),
        "event_time": detail.get(
            "eventTime",
            event.get("time", "unknown"),
        ),
        "mitre_attack": detection["mitre_attack"],
        "recommended_action": detection["recommended_action"],
        "response_mode": RESPONSE_MODE,
        "evidence_key": evidence_key,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    store_incident(incident)
    send_alert(incident)

    print(
        json.dumps(
            incident,
            indent=2,
        )
    )

    return incident
