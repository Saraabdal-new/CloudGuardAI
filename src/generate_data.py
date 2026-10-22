"""Generate a reproducible, diverse synthetic AWS IAM policy dataset.

Policies are assembled from statement generators. Labels always come from
label_policy(), so the dataset stays consistent with the scanner. Generators
are built to exercise features that were constant in the previous dataset
(Condition, NotPrincipal, Service/Federated principals, delete actions) and to
include "hard negatives": policies that look risky but are safe by the rules.
"""
from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path
from typing import Callable

import pandas as pd

from .labeling import PRIVILEGE_ESCALATION_ACTIONS, evaluate_policy, label_policy


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "raw" / "iam_policies.csv"

SEED = 42
SAMPLES_PER_CLASS = 120
MAX_ATTEMPTS_PER_CLASS = SAMPLES_PER_CLASS * 200

ACCOUNT = "123456789012"
# label_policy() treats this account as internal (rule R7 does not fire).
OWN_ACCOUNT = "000000000000"
EXTERNAL_ACCOUNTS = ["999988887777", "111122223333", "444455556666", "777788889999"]

# sorted() keeps generation deterministic (set order varies between runs).
ESCALATION_ACTIONS = sorted(PRIVILEGE_ESCALATION_ACTIONS)

SERVICES = {
    "s3": {
        "read": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
        "write": ["s3:PutObject", "s3:PutObjectTagging"],
        "delete": ["s3:DeleteObject"],
        "resources": [
            "arn:aws:s3:::app-data/*", "arn:aws:s3:::app-data",
            "arn:aws:s3:::reports-prod/*", "arn:aws:s3:::logs-archive/*",
        ],
    },
    "dynamodb": {
        "read": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"],
        "write": ["dynamodb:PutItem", "dynamodb:UpdateItem"],
        "delete": ["dynamodb:DeleteItem"],
        "resources": [
            f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/orders",
            f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/users",
        ],
    },
    "sqs": {
        "read": ["sqs:ReceiveMessage", "sqs:GetQueueAttributes"],
        "write": ["sqs:SendMessage"],
        "delete": ["sqs:DeleteMessage"],
        "resources": [
            f"arn:aws:sqs:us-east-1:{ACCOUNT}:jobs",
            f"arn:aws:sqs:us-east-1:{ACCOUNT}:events",
        ],
    },
    "sns": {
        "read": ["sns:GetTopicAttributes", "sns:ListSubscriptionsByTopic"],
        "write": ["sns:Publish"],
        "delete": ["sns:Unsubscribe"],
        "resources": [f"arn:aws:sns:us-east-1:{ACCOUNT}:alerts"],
    },
    "logs": {
        "read": ["logs:GetLogEvents", "logs:FilterLogEvents"],
        "write": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "delete": ["logs:DeleteLogStream"],
        "resources": [
            f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:app:*",
            f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:batch:*",
        ],
    },
    "ec2": {
        "read": ["ec2:DescribeInstances", "ec2:DescribeVolumes"],
        "write": ["ec2:StartInstances", "ec2:StopInstances"],
        "delete": ["ec2:TerminateInstances"],
        "resources": [
            f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc123def456",
            f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0fed654cba321",
        ],
    },
    "kms": {
        "read": ["kms:Decrypt", "kms:DescribeKey"],
        "write": ["kms:Encrypt", "kms:GenerateDataKey"],
        "delete": [],
        "resources": [
            f"arn:aws:kms:us-east-1:{ACCOUNT}:key/app-key",
            f"arn:aws:kms:us-east-1:{ACCOUNT}:key/backup-key",
        ],
    },
    "iam": {
        "read": ["iam:GetRole", "iam:ListRolePolicies", "iam:GetPolicy"],
        "write": [],
        "delete": [],
        "resources": [
            f"arn:aws:iam::{ACCOUNT}:role/app-role",
            f"arn:aws:iam::{ACCOUNT}:role/batch-role",
        ],
    },
    "lambda": {
        "read": ["lambda:GetFunction", "lambda:ListVersionsByFunction"],
        "write": ["lambda:InvokeFunction", "lambda:UpdateFunctionCode"],
        "delete": ["lambda:DeleteFunction"],
        "resources": [
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:processor",
            f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:notifier",
        ],
    },
}

DISCOVERY_ACTIONS = [
    "ec2:DescribeInstances", "cloudwatch:GetMetricData",
    "logs:DescribeLogGroups", "s3:ListAllMyBuckets", "sts:GetCallerIdentity",
]

CONDITIONS = [
    {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
    {"Bool": {"aws:SecureTransport": "true"}},
    {"StringEquals": {"aws:SourceVpc": "vpc-0abc123"}},
]

SERVICE_PRINCIPALS = [
    "lambda.amazonaws.com", "ec2.amazonaws.com", "ecs-tasks.amazonaws.com",
]

Statement = dict
Generator = Callable[[random.Random], Statement]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _action_value(actions: list[str]):
    """Return a scalar for one action and a list otherwise (both are valid IAM)."""
    return actions[0] if len(actions) == 1 else actions


def _pick_actions(rng: random.Random, service: str, kind: str) -> list[str]:
    pool = SERVICES[service][kind] or SERVICES[service]["read"]
    count = rng.randint(1, min(3, len(pool)))
    return rng.sample(pool, count)


def _scoped_resource(rng: random.Random, service: str):
    pool = SERVICES[service]["resources"]
    if len(pool) > 1 and rng.random() < 0.25:
        return rng.sample(pool, 2)
    return rng.choice(pool)


# --------------------------------------------------------------------------
# Safe statement generators (label_policy must return no rule for these)
# --------------------------------------------------------------------------
def safe_scoped(rng: random.Random) -> Statement:
    service = rng.choice(list(SERVICES))
    kind = rng.choice(["read", "read", "write", "delete"])
    return {
        "Effect": "Allow",
        "Action": _action_value(_pick_actions(rng, service, kind)),
        "Resource": _scoped_resource(rng, service),
    }


def safe_discovery(rng: random.Random) -> Statement:
    actions = rng.sample(DISCOVERY_ACTIONS, rng.randint(1, 2))
    return {"Effect": "Allow", "Action": _action_value(actions), "Resource": "*"}


def safe_scoped_wildcard(rng: random.Random) -> Statement:
    """Wildcard action on a specific resource: advisory only, not a rule hit."""
    service = rng.choice(list(SERVICES))
    action = rng.choice(
        [f"{service}:*", f"{service}:Get*", f"{service}:List*", f"{service}:Describe*"]
    )
    return {
        "Effect": "Allow",
        "Action": action,
        "Resource": _scoped_resource(rng, service),
    }


def safe_escalation_scoped(rng: random.Random) -> Statement:
    """Escalation-capable action limited to one role: hard negative."""
    return {
        "Effect": "Allow",
        "Action": rng.choice(ESCALATION_ACTIONS),
        "Resource": rng.choice(SERVICES["iam"]["resources"]),
    }

def safe_deny(rng: random.Random) -> Statement:
    variant = rng.randrange(4)
    if variant == 0:
        return {"Effect": "Deny", "Action": "*", "Resource": "*"}
    if variant == 1:
        return {
            "Effect": "Deny",
            "Action": rng.choice(SERVICES["s3"]["delete"] + SERVICES["ec2"]["delete"]),
            "Resource": "*",
        }
    if variant == 2:
        return {
            "Effect": "Deny",
            "NotPrincipal": {"AWS": f"arn:aws:iam::{OWN_ACCOUNT}:root"},
            "Action": "s3:*",
            "Resource": rng.choice(SERVICES["s3"]["resources"]),
        }
    # Classic "deny everything except IAM self-service without MFA" pattern.
    return {
        "Effect": "Deny",
        "NotAction": ["iam:ListUsers", "iam:GetUser"],
        "Resource": "*",
        "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
    }

def safe_conditional(rng: random.Random) -> Statement:
    """Broad Allow neutralised by a Condition.

    This follows the project's simplified heuristic (a non-empty Condition
    makes the statement safe). It is not a general AWS security guarantee.
    """
    action = rng.choice(["*", "iam:*", "s3:*", "kms:*", "ec2:*", "iam:PassRole"])
    return {
        "Effect": "Allow",
        "Action": action,
        "Resource": "*",
        "Condition": rng.choice(CONDITIONS),
    }


def safe_principal(rng: random.Random) -> Statement:
    variant = rng.randrange(4)
    if variant == 0:  # service trust policy
        return {
            "Effect": "Allow",
            "Principal": {"Service": rng.choice(SERVICE_PRINCIPALS)},
            "Action": "sts:AssumeRole",
        }
    if variant == 1:  # AWS service writing to a bucket
        return {
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": rng.choice(SERVICES["s3"]["resources"]),
        }
    if variant == 2:  # own-account root principal
        return {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{OWN_ACCOUNT}:root"},
            "Action": _action_value(_pick_actions(rng, "s3", "read")),
            "Resource": rng.choice(SERVICES["s3"]["resources"]),
        }
    return {  # federated identity with a condition
        "Effect": "Allow",
        "Principal": {"Federated": "cognito-identity.amazonaws.com"},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {"cognito-identity.amazonaws.com:aud": "eu-west-1:demo-pool"}
        },
    }


# --------------------------------------------------------------------------
# Risky statement generators (each triggers at least one of R1-R7)
# --------------------------------------------------------------------------
def risky_r1(rng: random.Random) -> Statement:
    return {"Effect": "Allow", "Action": "*", "Resource": "*"}


def risky_r3(rng: random.Random) -> Statement:
    action = rng.choice(["iam:*", "kms:*", "sts:*", "iam:Create*", "iam:Put*"])
    actions = [action]
    if rng.random() < 0.4:
        actions.append(rng.choice(SERVICES["s3"]["read"]))
    return {"Effect": "Allow", "Action": _action_value(actions), "Resource": "*"}


def risky_r4(rng: random.Random) -> Statement:
    actions = [rng.choice(ESCALATION_ACTIONS)]
    if rng.random() < 0.4:
        actions.append(rng.choice(SERVICES["s3"]["read"] + ESCALATION_ACTIONS))
    return {
        "Effect": "Allow",
        "Action": _action_value(sorted(set(actions))),
        "Resource": "*",
    }


def risky_r6(rng: random.Random) -> Statement:
    service = rng.choice(["s3", "ec2", "lambda", "dynamodb", "sns", "sqs", "logs"])
    return {"Effect": "Allow", "Action": f"{service}:*", "Resource": "*"}


def risky_r2(rng: random.Random) -> Statement:
    service = rng.choice(["s3", "sqs", "sns", "lambda"])
    return {
        "Effect": "Allow",
        "Principal": rng.choice(["*", {"AWS": "*"}]),
        "Action": _action_value(_pick_actions(rng, service, rng.choice(["read", "write"]))),
        "Resource": _scoped_resource(rng, service),
    }


def risky_r5(rng: random.Random) -> Statement:
    variant = rng.randrange(3)
    if variant == 0:
        return {
            "Effect": "Allow",
            "NotAction": rng.choice(["iam:*", ["iam:*", "sts:*"]]),
            "Resource": "*",
        }
    if variant == 1:
        return {
            "Effect": "Allow",
            "NotAction": "s3:DeleteObject",
            "Resource": rng.choice(SERVICES["s3"]["resources"]),
        }
    return {
        "Effect": "Allow",
        "Action": _action_value(_pick_actions(rng, "s3", "read")),
        "NotResource": "arn:aws:s3:::approved/*",
    }


def risky_r7(rng: random.Random) -> Statement:
    account = rng.choice(EXTERNAL_ACCOUNTS)
    arn = rng.choice(
        [
            f"arn:aws:iam::{account}:root",
            f"arn:aws:iam::{account}:role/partner",
            f"arn:aws:iam::{account}:user/contractor",
        ]
    )
    principal_value = arn
    if rng.random() < 0.3:
        principal_value = [arn, f"arn:aws:iam::{OWN_ACCOUNT}:root"]
    service = rng.choice(["s3", "sqs", "lambda"])
    return {
        "Effect": "Allow",
        "Principal": {"AWS": principal_value},
        "Action": _action_value(_pick_actions(rng, service, "read")),
        "Resource": _scoped_resource(rng, service),
    }


SAFE_GENERATORS: list[tuple[Generator, int]] = [
    (safe_scoped, 6),
    (safe_discovery, 2),
    (safe_scoped_wildcard, 2),
    (safe_escalation_scoped, 1),
    (safe_deny, 2),
    (safe_conditional, 3),
    (safe_principal, 3),
]

RISKY_GENERATORS: list[tuple[Generator, int]] = [
    (risky_r1, 1),
    (risky_r3, 2),
    (risky_r4, 2),
    (risky_r6, 2),
    (risky_r2, 2),
    (risky_r5, 2),
    (risky_r7, 2),
]


def _draw(rng: random.Random, generators: list[tuple[Generator, int]]) -> Statement:
    functions = [function for function, _ in generators]
    weights = [weight for _, weight in generators]
    return rng.choices(functions, weights=weights, k=1)[0](rng)


def make_policy(rng: random.Random, label: int) -> dict:
    """Build a 1-3 statement policy; label 1 contains at least one risky statement."""
    count = rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
    risky_position = rng.randrange(count) if label == 1 else -1

    statements = []
    for position in range(count):
        if position == risky_position:
            statements.append(_draw(rng, RISKY_GENERATORS))
        elif label == 1 and rng.random() < 0.4:
            statements.append(_draw(rng, RISKY_GENERATORS))
        else:
            statements.append(_draw(rng, SAFE_GENERATORS))

    return {"Version": "2012-10-17", "Statement": statements}


def main() -> None:
    rng = random.Random(SEED)
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    rule_counts: Counter[str] = Counter()
    rejected = 0

    for expected_label in (0, 1):
        created = 0
        attempts = 0
        while created < SAMPLES_PER_CLASS and attempts < MAX_ATTEMPTS_PER_CLASS:
            attempts += 1
            policy = make_policy(rng, expected_label)

            # label_policy() stays the single source of truth for labels.
            if int(label_policy(policy)) != expected_label:
                rejected += 1
                continue

            serialized = json.dumps(policy, sort_keys=True, separators=(",", ":"))
            if serialized in seen:
                continue

            seen.add(serialized)
            rows.append({"policy_json": serialized, "label": expected_label})
            rule_counts.update(evaluate_policy(policy))
            created += 1

        if created < SAMPLES_PER_CLASS:
            raise RuntimeError(
                f"Generated only {created}/{SAMPLES_PER_CLASS} samples "
                f"for label {expected_label}. Review generators and labels."
            )

    rng.shuffle(rows)
    df = pd.DataFrame(rows)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT, index=False)

    print(f"Generated {len(df)} policies: {OUTPUT}")
    print(f"Unique JSON policies: {df['policy_json'].nunique()}")
    print(f"Candidates rejected (label mismatch): {rejected}")
    print("Label counts:")
    print(df["label"].value_counts().sort_index().to_string())
    print("Rule coverage (risky class):", dict(sorted(rule_counts.items())))


if __name__ == "__main__":
    main()