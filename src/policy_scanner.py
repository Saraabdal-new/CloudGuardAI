"""Rule-based scanner for AWS IAM policy misconfigurations.

Findings come in two categories:
  - "misconfiguration": rules R1-R7 from src/labeling.py (they define the ML label).
  - "advisory": softer least-privilege hints that do NOT change the label.

Every finding carries evidence copied from the real statement, so explanations
never describe something that is not in the policy.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

from .data_loader import PolicyValidationError, as_list, parse_policy
from .labeling import evaluate_statement

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# label rule -> finding template
RULE_CATALOG: dict[str, dict[str, str]] = {
    "R1": {
        "rule_id": "IAM-001", "severity": "CRITICAL",
        "title": "Broad administrative permissions",
        "description": "The statement allows all actions on all resources without any condition.",
        "recommendation": "Apply least privilege: list only the required actions and the specific "
                          "resource ARNs, and add conditions such as MFA or source IP where relevant.",
    },
    "R2": {
        "rule_id": "IAM-004", "severity": "CRITICAL",
        "title": "Public access through a wildcard principal",
        "description": "The statement allows any principal ('*') without a condition.",
        "recommendation": "Replace '*' with the exact principals, or restrict access with conditions "
                          "such as aws:PrincipalOrgID or aws:SourceVpce.",
    },
    "R3": {
        "rule_id": "IAM-005", "severity": "HIGH",
        "title": "Wildcard on a sensitive service",
        "description": "A service wildcard (for example iam:* or kms:*) applies to all resources "
                       "without a condition.",
        "recommendation": "Grant only the specific IAM/KMS/STS actions needed, on named resources.",
    },
    "R4": {
        "rule_id": "IAM-006", "severity": "HIGH",
        "title": "Privilege-escalation action on all resources",
        "description": "The statement allows an action that can be used to gain more privileges "
                       "(such as iam:PassRole or iam:CreateAccessKey) on all resources.",
        "recommendation": "Restrict the action to specific role/user ARNs and add conditions "
                          "(for example iam:PassedToService).",
    },
    "R5": {
        "rule_id": "IAM-007", "severity": "HIGH",
        "title": "Allow combined with NotAction or NotResource",
        "description": "An Allow statement using NotAction/NotResource grants everything except "
                       "the listed items, which is an implicit broad permission.",
        "recommendation": "Rewrite the statement with an explicit list of allowed actions and resources.",
    },
    "R6": {
        "rule_id": "IAM-008", "severity": "MEDIUM",
        "title": "Service wildcard on all resources",
        "description": "A service wildcard (for example s3:* or ec2:*) applies to all resources "
                       "without a condition.",
        "recommendation": "Replace the wildcard with the specific actions needed and limit Resource "
                          "to the required ARNs.",
    },
    "R7": {
        "rule_id": "IAM-009", "severity": "HIGH",
        "title": "External account without condition",
        "description": "The statement trusts another AWS account without a condition such as "
                       "sts:ExternalId or aws:PrincipalOrgID.",
        "recommendation": "Add an ExternalId or organization condition, or remove the external principal "
                          "if it is not needed.",
    },
}

ADVISORY_WILDCARD_ACTION = {
    "rule_id": "IAM-002", "severity": "HIGH",
    "title": "Wildcard action permissions",
    "description": "The statement grants all actions ('*') on specific resources without a condition.",
    "recommendation": "Replace the wildcard action with the specific actions that are required.",
}
ADVISORY_WILDCARD_RESOURCE = {
    "rule_id": "IAM-003", "severity": "MEDIUM",
    "title": "Wildcard resource permissions",
    "description": "The statement applies to all resources without a condition.",
    "recommendation": "Limit Resource to the specific ARNs that are required.",
}


def _invalid(title: str, description: str, index: int | None = None) -> dict[str, Any]:
    return {
        "rule_id": "IAM-INVALID-STATEMENT", "label_rule": "", "severity": "HIGH",
        "category": "invalid", "title": title, "description": description,
        "recommendation": "Correct the policy structure and validate it before scanning.",
        "statement_index": index, "sid": "", "evidence": "",
    }


def _statement_problem(stmt: Any) -> str | None:
    if not isinstance(stmt, dict):
        return "The statement is not a JSON object."
    if stmt.get("Effect") not in ("Allow", "Deny"):
        return "'Effect' must be 'Allow' or 'Deny'."
    if "Action" not in stmt and "NotAction" not in stmt:
        return "The statement needs 'Action' or 'NotAction'."
    for key in ("Action", "NotAction", "Resource", "NotResource"):
        if key in stmt and not all(isinstance(v, str) for v in as_list(stmt[key])):
            return f"'{key}' must contain only strings."
    return None


def _evidence(stmt: dict) -> str:
    keys = ("Effect", "Principal", "Action", "NotAction", "Resource", "NotResource")
    return json.dumps({k: stmt[k] for k in keys if k in stmt})


def _finding(template: dict, label_rule: str, category: str, index: int, stmt: dict) -> dict[str, Any]:
    return {
        "rule_id": template["rule_id"], "label_rule": label_rule,
        "severity": template["severity"], "category": category,
        "title": template["title"], "description": template["description"],
        "recommendation": template["recommendation"],
        "statement_index": index, "sid": str(stmt.get("Sid", "")),
        "evidence": _evidence(stmt),
    }


def scan_iam_policy(policy: Any) -> list[dict[str, Any]]:
    """Return findings for an IAM policy dict. Never raises on malformed input."""
    if not isinstance(policy, dict):
        return [_invalid("Invalid policy", "The policy must be a JSON object.")]
    if "Statement" not in policy:
        return [_invalid("Missing Statement", "The policy has no 'Statement' field.")]

    statements = as_list(policy["Statement"])
    if not statements:
        return [_invalid("Empty Statement", "The policy 'Statement' is empty.")]

    findings: list[dict[str, Any]] = []
    for index, stmt in enumerate(statements):
        problem = _statement_problem(stmt)
        if problem:
            findings.append(_invalid(f"Invalid statement at index {index}", problem, index))
            continue
        if stmt["Effect"] != "Allow":
            continue

        rules = evaluate_statement(stmt)  # R1-R7, condition-aware
        for rule in rules:
            findings.append(_finding(RULE_CATALOG[rule], rule, "misconfiguration", index, stmt))

        if stmt.get("Condition"):
            continue  # advisories only apply to unconditioned statements

        actions = as_list(stmt.get("Action"))
        all_resources = "*" in as_list(stmt.get("Resource"))
        if "*" in actions and not all_resources:
            findings.append(_finding(ADVISORY_WILDCARD_ACTION, "", "advisory", index, stmt))
        elif all_resources and not rules:
            findings.append(_finding(ADVISORY_WILDCARD_RESOURCE, "", "advisory", index, stmt))

    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), f["statement_index"] or 0))
    return findings


def scan_policy_source(source: Union[str, bytes, dict, Path]) -> list[dict[str, Any]]:
    """Scan a JSON string, file path or dict. Invalid input becomes a finding, not an exception."""
    try:
        policy = parse_policy(source)
    except PolicyValidationError as exc:
        return [_invalid("Invalid policy", str(exc))]
    except (OSError, ValueError) as exc:
        return [_invalid("Unreadable policy", str(exc))]
    return scan_iam_policy(policy)


def is_misconfigured(findings: list[dict[str, Any]]) -> bool:
    """True if any finding belongs to the misconfiguration rules (same definition as the ML label)."""
    return any(f["category"] == "misconfiguration" for f in findings)


def highest_severity(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "NONE"

    return max(
        (f["severity"] for f in findings),
        key=lambda s: SEVERITY_ORDER.get(s, 0),
    )