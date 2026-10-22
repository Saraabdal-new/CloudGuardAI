
"""Generate human-readable explanations for IAM policy findings."""
from __future__ import annotations

from typing import Any


REMEDIATION = {
    "IAM-001": {
        "risk": (
            "The policy allows every action on every resource. "
            "If attached to an identity, it can grant extremely broad access."
        ),
        "recommendation": (
            "Replace Action '*' with only the actions required for the task. "
            "Restrict Resource to the specific resources needed."
        ),
    },
    "IAM-002": {
        "risk": (
            "The policy uses a wildcard action, which may grant more permissions "
            "than intended depending on the resource and service."
        ),
        "recommendation": (
            "Replace wildcard actions with the smallest set of required API actions."
        ),
    },
    "IAM-003": {
        "risk": (
            "The policy applies to all resources rather than limiting access "
            "to specific resource ARNs where supported."
        ),
        "recommendation": (
            "Scope Resource to the required ARN patterns. Some AWS actions "
            "require Resource '*', so verify the service's authorization guidance."
        ),
    },
    "IAM-004": {
        "risk": (
            "A wildcard principal may allow unintended principals to access "
            "a resource if the policy is attached to a resource that supports "
            "principal-based access."
        ),
        "recommendation": (
            "Restrict Principal to explicitly trusted AWS accounts, roles, "
            "or services. Review any required conditions."
        ),
    },
    "IAM-005": {
        "risk": (
            "Sensitive IAM, KMS, or STS actions are allowed against all resources, "
            "which can create a high-impact permission exposure."
        ),
        "recommendation": (
            "Limit sensitive actions and scope resources wherever supported. "
            "Review trust relationships and key or role access separately."
        ),
    },
    "IAM-006": {
        "risk": (
            "The policy contains actions associated with privilege escalation. "
            "Depending on the permissions and environment, these may let a user "
            "obtain permissions beyond those intended."
        ),
        "recommendation": (
            "Remove unnecessary privilege-management actions and apply least "
            "privilege. Review the affected roles, policies, and permissions."
        ),
    },
    "IAM-007": {
        "risk": (
            "NotAction or NotResource can create complex permission boundaries "
            "that are easy to misinterpret."
        ),
        "recommendation": (
            "Review the statement's Effect, action/resource scope, and conditions. "
            "Prefer explicit, narrowly scoped permissions when practical."
        ),
    },
    "IAM-009": {
        "risk": (
            "The policy appears to reference an AWS account principal without "
            "a detected condition. The scanner cannot confirm whether that "
            "account is trusted."
        ),
        "recommendation": (
            "Verify the account and principal are trusted. Add suitable conditions "
            "and restrict access to the intended roles or resources."
        ),
    },
}


def explain_finding(finding: dict[str, Any]) -> dict[str, str]:
    """Explain one scanner finding and suggest a remediation."""
    rule_id = finding.get("rule_id", "")
    guidance = REMEDIATION.get(
        rule_id,
        {
            "risk": finding.get(
                "description",
                "Review this IAM policy finding to determine its impact.",
            ),
            "recommendation": (
                "Review the policy statement and apply least-privilege permissions."
            ),
        },
    )

    return {
        "rule_id": rule_id,
        "title": str(finding.get("title", rule_id or "IAM finding")),
        "severity": str(finding.get("severity", "UNKNOWN")),
        "risk": guidance["risk"],
        "recommendation": guidance["recommendation"],
        "evidence": str(finding.get("evidence", "See the original finding.")),
    }


def explain_prediction(result: dict[str, Any]) -> dict[str, Any]:
    """Produce an offline explanation report from a prediction result."""
    findings = [
        explain_finding(finding)
        for finding in result.get("findings", [])
    ]

    prediction_label = result.get("prediction_label", "unknown")
    risk_probability = float(result.get("risk_probability", 0.0))

    if findings:
        summary = (
            f"The scanner identified {len(findings)} finding(s). "
            f"The highest reported severity is "
            f"{result.get('highest_severity', 'UNKNOWN')}."
        )
    elif prediction_label == "misconfigured":
        summary = (
            "The ML model predicts a misconfiguration, but the rule-based "
            "scanner did not identify a finding. Manual review is recommended."
        )
    else:
        summary = (
            "The rule-based scanner found no issues covered by its current rules. "
            "This does not guarantee that the policy is secure."
        )

    return {
        "summary": summary,
        "prediction": prediction_label,
        "risk_probability": risk_probability,
        "highest_severity": result.get("highest_severity", "NONE"),
        "findings": findings,
        "limitations": (
            "This is an offline decision-support tool, not an official AWS "
            "validator. Findings cover only implemented detection rules, and "
            "the model's probability is not a calibrated real-world risk score."
        ),
    }
