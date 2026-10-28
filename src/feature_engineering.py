
"""Extract numerical features from AWS IAM policies."""
from __future__ import annotations

from typing import Any

from .data_loader import as_list
from .labeling import (
    DEFAULT_OWN_ACCOUNT_ID,
    PRIVILEGE_ESCALATION_ACTIONS,
)


SENSITIVE_SERVICES = ("iam:", "kms:", "sts:")

WRITE_VERBS = (
    "put", "create", "update", "delete", "remove", "attach",
    "detach", "modify", "authorize", "revoke", "set", "run",
    "start", "stop", "terminate", "passrole", "send", "publish",
)

READ_VERBS = (
    "get", "list", "describe", "head", "lookup", "read",
    "search", "query", "view",
)

DELETE_VERBS = ("delete", "remove", "terminate", "detach", "revoke")

# Mirrors the demo account used by rule R7 in labeling.py.

def _strings(value: Any) -> list[str]:
    """Convert IAM scalar/list values to normalized strings."""
    return [str(item).strip() for item in as_list(value) if item is not None]


def _condition_text(condition: Any) -> str:
    """Flatten condition content for simple indicator features."""
    if isinstance(condition, dict):
        return " ".join(
            [str(key) for key in condition]
            + [_condition_text(value) for value in condition.values()]
        ).lower()
    if isinstance(condition, list):
        return " ".join(_condition_text(value) for value in condition)
    return str(condition).lower()

def _statement_context_features(statements: list[dict[str, Any]]) -> dict[str, int]:
    """Features computed per statement, then combined across the policy.

    Aggregate features cannot tell whether a Condition and a wildcard sit in
    the same statement. These indicators only look at Allow statements that
    have no Condition.
    """
    unconditioned = [
        s for s in statements
        if str(s.get("Effect", "")).lower() == "allow"
        and not (isinstance(s.get("Condition"), dict) and s.get("Condition"))
    ]

    all_resources = False
    wildcard_action = False
    wildcard_on_all = False
    inverse_match = False

    for statement in unconditioned:
        actions = _strings(statement.get("Action", []))
        resources = _strings(statement.get("Resource", []))
        statement_wildcard = any("*" in action for action in actions)
        statement_all = "*" in resources

        all_resources = all_resources or statement_all
        wildcard_action = wildcard_action or statement_wildcard
        wildcard_on_all = wildcard_on_all or (statement_wildcard and statement_all)
        inverse_match = inverse_match or bool(
            statement.get("NotAction") or statement.get("NotResource")
        )

    return {
        "num_unconditioned_allow_statements": len(unconditioned),
        "has_unconditioned_allow_all_resources": int(all_resources),
        "has_unconditioned_wildcard_action": int(wildcard_action),
        "has_unconditioned_wildcard_on_all_resources": int(wildcard_on_all),
        "has_unconditioned_not_action_or_resource": int(inverse_match),
    }

def extract_features(
    policy: dict[str, Any],
    own_account_id: str = DEFAULT_OWN_ACCOUNT_ID,
) -> dict[str, int]:
    """Convert an IAM policy into numerical features for ML."""
    statements = as_list(policy.get("Statement", []))
    statements = [s for s in statements if isinstance(s, dict)]

    actions: list[str] = []
    resources: list[str] = []
    allow_statements = []
    deny_statements = []
    principals: list[str] = []
    conditions: list[str] = []

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
    has_write_action = 0
    has_read_action = 0
    has_delete_action = 0
    has_service_principal = 0
    has_federated_principal = 0
    has_account_root_principal = 0
    has_mfa_condition = 0
    has_ip_condition = 0
    has_secure_transport_condition = 0
    has_not_principal = 0

    for statement in statements:
        effect = str(statement.get("Effect", "")).lower()

        statement_actions = _strings(
            statement.get("Action", statement.get("NotAction", []))
        )
        statement_resources = _strings(
            statement.get("Resource", statement.get("NotResource", []))
        )

        actions.extend(statement_actions)
        resources.extend(statement_resources)

        if effect == "allow":
            allow_statements.append(statement)
        elif effect == "deny":
            deny_statements.append(statement)

        if effect == "allow" and "*" in statement_actions:
            allows_all_actions = 1

        if effect == "allow" and "*" in statement_resources:
            allows_all_resources = 1

        num_wildcard_actions += sum(
            "*" in action or "?" in action
            for action in statement_actions
        )
        num_wildcard_resources += sum(
            "*" in resource or "?" in resource
            for resource in statement_resources
        )

        if any(
            action.lower().startswith(SENSITIVE_SERVICES)
            and "*" in action
            for action in statement_actions
        ):
            has_sensitive_service_action = 1

        normalized_actions = [action.lower() for action in statement_actions]
        escalation_actions = {
            action.lower() for action in PRIVILEGE_ESCALATION_ACTIONS
        }

        if any(action in escalation_actions for action in normalized_actions):
            has_privilege_escalation_action = 1

        for action in normalized_actions:
            if action == "*" or ":" not in action:
                continue

            operation = action.split(":", 1)[1]
            operation_parts = operation.replace("*", "").split("/")

            if any(
                operation_part.startswith(verb)
                for operation_part in operation_parts
                for verb in WRITE_VERBS
            ):
                has_write_action = 1

            if any(
                operation_part.startswith(verb)
                for operation_part in operation_parts
                for verb in READ_VERBS
            ):
                has_read_action = 1

            if any(
                operation_part.startswith(verb)
                for operation_part in operation_parts
                for verb in DELETE_VERBS
            ):
                has_delete_action = 1

        if "NotAction" in statement or "NotResource" in statement:
            has_not_action_or_resource = 1

        if "NotPrincipal" in statement:
            has_not_principal = 1

        condition = statement.get("Condition")
        if condition:
            has_conditions = 1
            condition_text = _condition_text(condition)
            conditions.append(condition_text)

            if effect == "allow":
                share_statements_with_condition += 1

            if "aws:multifactorauthpresent" in condition_text:
                has_mfa_condition = 1

            if any(
                marker in condition_text
                for marker in ("aws:sourceip", "aws:sourcevpc", "aws:sourcevpce")
            ):
                has_ip_condition = 1

            if "aws:securetransport" in condition_text:
                has_secure_transport_condition = 1

        principal = statement.get("Principal")
        if principal is not None:
            if isinstance(principal, str):
                principals.append(principal)
            elif isinstance(principal, dict):
                for principal_type, value in principal.items():
                    values = _strings(value)
                    principals.extend(values)

                    if principal_type.lower() == "service" and values:
                        has_service_principal = 1

                    if principal_type.lower() == "federated" and values:
                        has_federated_principal = 1

            if isinstance(principal, str) and principal == "*":
                has_external_principal = 1
            elif isinstance(principal, dict):
                principal_values = [
                    item
                    for value in principal.values()
                    for item in _strings(value)
                ]
                if any(value == "*" for value in principal_values):
                    has_external_principal = 1

    normalized_actions = [action.lower() for action in actions]
    service_names = {
        action.split(":", 1)[0]
        for action in normalized_actions
        if ":" in action
    }

    principal_text = " ".join(principals).lower()
    if ":root" in principal_text and "arn:aws:iam::" in principal_text:
        has_account_root_principal = 1

    # Without the policy owner's account ID, an IAM ARN cannot reliably
    # be classified as external. This legacy feature is only a signal.
    has_iam_arn_principal = int("arn:aws:iam::" in principal_text)

    return {
        # Existing features: retained for compatibility.
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

        # Additional permission and principal features.
        "has_write_action": has_write_action,
        "has_read_action": has_read_action,
        "has_delete_action": has_delete_action,
        "has_iam_action": int("iam" in service_names),
        "has_s3_action": int("s3" in service_names),
        "has_kms_action": int("kms" in service_names),
        "has_sts_action": int("sts" in service_names),
        "has_ec2_action": int("ec2" in service_names),
        "num_distinct_services": len(service_names),
        "has_service_principal": has_service_principal,
        "has_federated_principal": has_federated_principal,
        "has_account_root_principal": has_account_root_principal,
        "has_iam_arn_principal": has_iam_arn_principal,
        "has_external_account_principal": int(any(
            "arn:aws:iam::" in principal
            and not principal.startswith(
                f"arn:aws:iam::{own_account_id}:"
            )
            for principal in principals
        )),
        "has_not_principal": has_not_principal,

        # Additional condition indicators.
        "has_mfa_condition": has_mfa_condition,
        "has_ip_condition": has_ip_condition,
        "has_secure_transport_condition": has_secure_transport_condition,
        **_statement_context_features(statements),
    }
