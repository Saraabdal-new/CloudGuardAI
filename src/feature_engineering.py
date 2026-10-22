
"""Extract numerical features from AWS IAM policies."""
from __future__ import annotations

from typing import Any

from .data_loader import as_list
from .labeling import PRIVILEGE_ESCALATION_ACTIONS


SENSITIVE_SERVICES = ("iam:", "kms:", "sts:")


def extract_features(policy: dict[str, Any]) -> dict[str, int]:
    """Convert an IAM policy into a numerical feature dictionary."""
    statements = as_list(policy.get("Statement", []))
    statements = [s for s in statements if isinstance(s, dict)]

    actions: list[str] = []
    allow_statements = []
    deny_statements = []
    num_wildcard_actions = 0
    num_wildcard_resources = 0
    has_external_principal = 0
    has_conditions = 0
    has_not_action_or_resource = 0
    share_statements_with_condition = 0
    allows_all_actions = 0
    allows_all_resources = 0
    has_sensitive_service_action = 0
    has_privilege_escalation_action = 0

    for statement in statements:
        effect = statement.get("Effect")
        statement_actions = [
            str(a) for a in as_list(
                statement.get("Action", statement.get("NotAction", []))
            )
        ]
        resources = [
            str(r) for r in as_list(
                statement.get("Resource", statement.get("NotResource", []))
            )
        ]

        actions.extend(statement_actions)

        if effect == "Allow":
            allow_statements.append(statement)
        elif effect == "Deny":
            deny_statements.append(statement)

        if effect == "Allow" and "*" in statement_actions:
            allows_all_actions = 1

        if effect == "Allow" and "*" in resources:
            allows_all_resources = 1

        num_wildcard_actions += sum(
            "*" in action or "?" in action for action in statement_actions
        )
        num_wildcard_resources += sum(
            "*" in resource or "?" in resource for resource in resources
        )

        if any(
            action.startswith(SENSITIVE_SERVICES)
            and ("*" in action or action.endswith(":*"))
            for action in statement_actions
        ):
            has_sensitive_service_action = 1

        if any(
            action.lower() in {x.lower() for x in PRIVILEGE_ESCALATION_ACTIONS}
            for action in statement_actions
        ):
            has_privilege_escalation_action = 1

        if statement.get("Condition"):
            has_conditions = 1
            if effect == "Allow":
                share_statements_with_condition += 1

        if "NotAction" in statement or "NotResource" in statement:
            has_not_action_or_resource = 1

        principal = statement.get("Principal")
        if isinstance(principal, str) and principal == "*":
            has_external_principal = 1
        elif isinstance(principal, dict):
            principal_values = [
                str(v)
                for value in principal.values()
                for v in as_list(value)
            ]
            if any(
                value == "*" or "arn:aws:iam::" in value
                for value in principal_values
            ):
                has_external_principal = 1

    return {
        "allows_all_actions": allows_all_actions,
        "allows_all_resources": allows_all_resources,
        "has_external_principal": has_external_principal,
        "has_conditions": has_conditions,
        "has_deny_statement": int(bool(deny_statements)),
        "number_of_statements": len(statements),
        "number_of_actions": len(actions),
        "num_wildcard_actions": num_wildcard_actions,
        "num_wildcard_resources": num_wildcard_resources,
        "has_sensitive_service_action": has_sensitive_service_action,
        "has_not_action_or_resource": has_not_action_or_resource,
        "share_statements_with_condition": share_statements_with_condition,
        "num_allow_statements": len(allow_statements),
        "has_privilege_escalation_action": has_privilege_escalation_action,
    }
