
"""Load and validate AWS IAM policy documents."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PolicyValidationError(ValueError):
    """Raised when a policy cannot be parsed or has an invalid structure."""


def as_list(value: Any) -> list:
    """Normalize a scalar or list value into a list."""
    if isinstance(value, list):
        return value
    return [value]


def parse_policy(source: str | bytes | dict | Path) -> dict:
    """Parse a policy dictionary, JSON string, bytes, or JSON file path."""
    if isinstance(source, dict):
        policy = source
    elif isinstance(source, bytes):
        try:
            policy = json.loads(source.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PolicyValidationError(f"Invalid JSON: {exc}") from exc
    elif isinstance(source, Path):
        try:
            policy = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyValidationError(f"Cannot read policy file: {exc}") from exc
    elif isinstance(source, str):
        stripped = source.strip()

        if stripped.startswith("{"):
            try:
                policy = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise PolicyValidationError(f"Invalid JSON: {exc}") from exc
        else:
            try:
                policy = json.loads(Path(stripped).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise PolicyValidationError(
                    f"Cannot parse policy JSON or read file: {exc}"
                ) from exc
    else:
        raise PolicyValidationError("Unsupported policy input type.")

    if not isinstance(policy, dict):
        raise PolicyValidationError("The policy must be a JSON object.")

    if "Statement" not in policy:
        raise PolicyValidationError("The policy has no 'Statement' field.")

    return policy
