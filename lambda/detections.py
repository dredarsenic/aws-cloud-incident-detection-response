DETECTIONS = {
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


def detect(event_name):
    return DETECTIONS.get(event_name)
