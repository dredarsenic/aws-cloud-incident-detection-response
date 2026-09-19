EVENT_DETECTIONS = {
    "StopLogging": {
        "severity": "CRITICAL",
        "title": "CloudTrail logging disabled",
        "mitre_attack": "T1562.008",
        "recommended_action": (
            "Immediately restore CloudTrail logging and investigate "
            "the identity responsible for the action."
        ),
    },
    "DeleteTrail": {
        "severity": "CRITICAL",
        "title": "CloudTrail trail deleted",
        "mitre_attack": "T1562.008",
        "recommended_action": (
            "Investigate the actor, restore audit logging, and determine "
            "whether additional defense-evasion activity occurred."
        ),
    },
    "UpdateTrail": {
        "severity": "HIGH",
        "title": "CloudTrail configuration modified",
        "mitre_attack": "T1562.008",
        "recommended_action": (
            "Review the CloudTrail configuration change and validate "
            "whether it was authorized."
        ),
    },
    "PutEventSelectors": {
        "severity": "HIGH",
        "title": "CloudTrail event selectors modified",
        "mitre_attack": "T1562.008",
        "recommended_action": (
            "Review the event-selector change to ensure security-relevant "
            "events have not been excluded from logging."
        ),
    },
}


ROOT_ACTIVITY_DETECTION = {
    "severity": "CRITICAL",
    "title": "AWS root account activity detected",
    "mitre_attack": "T1078.004",
    "recommended_action": (
        "Validate whether root account usage was authorized, review MFA "
        "protection and source context, and investigate surrounding activity."
    ),
}


ADMINISTRATOR_ACCESS_DETECTION = {
    "severity": "CRITICAL",
    "title": "AdministratorAccess policy attached",
    "mitre_attack": "T1098",
    "recommended_action": (
        "Validate whether the privilege escalation was authorized, identify "
        "the affected IAM principal, and remove AdministratorAccess if the "
        "change was unexpected or malicious."
    ),
}


ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

ADMIN_ATTACHMENT_EVENTS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
}


def detect(detail):
    event_name = detail.get("eventName")
    identity = detail.get("userIdentity", {})
    request_parameters = detail.get("requestParameters", {})

    event_detection = EVENT_DETECTIONS.get(event_name)

    if event_detection:
        return event_detection

    if (
        event_name in ADMIN_ATTACHMENT_EVENTS
        and request_parameters.get("policyArn") == ADMIN_POLICY_ARN
    ):
        return ADMINISTRATOR_ACCESS_DETECTION

    if identity.get("type") == "Root":
        return ROOT_ACTIVITY_DETECTION

    return None
