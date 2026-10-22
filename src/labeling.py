
"""Rule-based IAM policy labels used by the scanner and ML dataset."""
from __future__ import annotations

from typing import Any

from .data_loader import as_list


PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
}


def _has_condition(statement: dict[str, Any]) -> bool:
    condition = statement.get("Condition")
    return isinstance(condition, dict) and bool(condition)


def _principal_values(principal: Any) -> list[str]:
    """Extract principal values from common IAM Principal structures."""
    if principal == "*":
        return ["*"]

    values: list[str] = []
    if isinstance(principal, str):
        return [principal]

    if isinstance(principal, dict):
        for value in principal.values():
            values.extend(str(item) for item in as_list(value))

    return values


def evaluate_statement(statement: dict[str, Any]) -> list[str]:
    """Return matching misconfiguration rules R1-R7 for one statement."""
    if statement.get("Effect") != "Allow":
        return []

    # This project's simplified policy assumes a non-empty Condition
    # neutralizes these broad-access rules. This is a demo heuristic,
    # not a general AWS IAM security guarantee.
    if _has_condition(statement):
        return []

    action_values = [str(x) for x in as_list(statement.get("Action", []))]
    not_action_values = [
        str(x) for x in as_list(statement.get("NotAction", []))
    ]
    resource_values = [
        str(x) for x in as_list(statement.get("Resource", []))
    ]
    not_resource_values = [
        str(x) for x in as_list(statement.get("NotResource", []))
    ]

    rules: list[str] = []
    wildcard_resource = "*" in resource_values

    # R1: all actions on all resources.
    if "*" in action_values and wildcard_resource:
        rules.append("R1")

    # R2: public wildcard principal.
    if "*" in _principal_values(statement.get("Principal")):
        rules.append("R2")

    # R3: sensitive-service wildcard on all resources.
    sensitive_services = ("iam:", "kms:", "sts:")
    if wildcard_resource and any(
        action.endswith("*") and action.startswith(sensitive_services)
        for action in action_values
    ):
        rules.append("R3")

    # R4: known privilege-escalation action on all resources.
    if wildcard_resource and any(
        action.lower() in {x.lower() for x in PRIVILEGE_ESCALATION_ACTIONS}
        for action in action_values
    ):
        rules.append("R4")

    # R5: broad inverse matching.
    if not_action_values or not_resource_values:
        rules.append("R5")

    # R6: other service wildcards on all resources.
    if wildcard_resource and any(
        action.endswith(":*")
        and not action.startswith(sensitive_services)
        for action in action_values
    ):
        rules.append("R6")

    # R7: external AWS account principal without a condition.
    principals = _principal_values(statement.get("Principal"))
    if any(
        "arn:aws:iam::" in principal
        and not principal.startswith("arn:aws:iam::" + "000000000000")
        for principal in principals
    ):
        rules.append("R7")

    return rules


def label_policy(policy: dict[str, Any]) -> int:
    """Return 1 if any statement matches R1-R7, otherwise 0."""
    statements = as_list(policy.get("Statement", []))
    return int(
        any(
            isinstance(statement, dict)
            and evaluate_statement(statement)
            for statement in statements
        )
    )


def evaluate_policy(policy: dict[str, Any]) -> list[str]:
    """Return unique matching rule IDs across all policy statements."""
    results: list[str] = []
    for statement in as_list(policy.get("Statement", [])):
        if isinstance(statement, dict):
            for rule in evaluate_statement(statement):
                if rule not in results:
                    results.append(rule)
    return results
