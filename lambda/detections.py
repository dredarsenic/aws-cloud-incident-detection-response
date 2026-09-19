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


PUBLIC_REMOTE_ACCESS_DETECTION = {
    "severity": "HIGH",
    "title": "Security group exposes SSH or RDP to the internet",
    "mitre_attack": "T1133",
    "recommended_action": (
        "Review the security group change and restrict SSH or RDP access "
        "to trusted administrative networks, VPN ranges, or approved "
        "management infrastructure."
    ),
}


ACCESS_KEY_CREATION_DETECTION = {
    "severity": "MEDIUM",
    "title": "IAM access key created",
    "mitre_attack": "T1098.001",
    "recommended_action": (
        "Verify that creation of the IAM access key was authorized and "
        "necessary. If unexpected, deactivate and delete the credential "
        "and investigate the identity responsible for creating it."
    ),
}


ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

ADMIN_ATTACHMENT_EVENTS = {
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
}

REMOTE_ADMIN_PORTS = {
    22,
    3389,
}

PUBLIC_CIDRS = {
    "0.0.0.0/0",
    "::/0",
}


def exposes_public_remote_access(request_parameters):
    permissions = (
        request_parameters
        .get("ipPermissions", {})
        .get("items", [])
    )

    for permission in permissions:
        from_port = permission.get("fromPort")
        to_port = permission.get("toPort")

        if from_port is None or to_port is None:
            continue

        exposed_port = any(
            from_port <= port <= to_port
            for port in REMOTE_ADMIN_PORTS
        )

        if not exposed_port:
            continue

        ipv4_ranges = (
            permission
            .get("ipRanges", {})
            .get("items", [])
        )

        ipv6_ranges = (
            permission
            .get("ipv6Ranges", {})
            .get("items", [])
        )

        for ip_range in ipv4_ranges:
            if ip_range.get("cidrIp") in PUBLIC_CIDRS:
                return True

        for ip_range in ipv6_ranges:
            if ip_range.get("cidrIpv6") in PUBLIC_CIDRS:
                return True

    return False


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

    if (
        event_name == "AuthorizeSecurityGroupIngress"
        and exposes_public_remote_access(request_parameters)
    ):
        return PUBLIC_REMOTE_ACCESS_DETECTION

    if event_name == "CreateAccessKey":
        return ACCESS_KEY_CREATION_DETECTION

    if identity.get("type") == "Root":
        return ROOT_ACTIVITY_DETECTION

    return None
