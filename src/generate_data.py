
"""Generate a reproducible synthetic AWS IAM policy dataset."""
from __future__ import annotations

import json
import random
from pathlib import Path

import pandas as pd

from .data_loader import as_list
from .labeling import label_policy


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "raw" / "iam_policies.csv"

random.seed(42)

SAFE_POLICIES = [
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::demo-bucket/*",
        }],
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:demo:*",
        }],
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "ec2:DescribeInstances",
            "Resource": "*",
        }],
    },
]

RISKY_POLICIES = [
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "*", "Resource": "*",
        }],
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "iam:*", "Resource": "*",
        }],
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "s3:*", "Resource": "*",
        }],
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*",
        }],
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "*",
        }],
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "NotAction": "iam:*",
            "Resource": "*",
        }],
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::demo-bucket/*",
        }],
    },
]


def main() -> None:
    """Write a reproducible CSV with policy JSON and binary labels."""
    rows = []

    for policy in SAFE_POLICIES:
        rows.append({
            "policy_json": json.dumps(policy),
            "label": label_policy(policy),
        })

    for policy in RISKY_POLICIES:
        rows.append({
            "policy_json": json.dumps(policy),
            "label": label_policy(policy),
        })

    # Add reproducible variations to provide more examples.
    for _ in range(100):
        policy = random.choice(SAFE_POLICIES + RISKY_POLICIES)
        rows.append({
            "policy_json": json.dumps(policy),
            "label": label_policy(policy),
        })

    random.shuffle(rows)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT, index=False)

    print(f"Generated {len(df)} policies: {OUTPUT}")
    print("Label counts:")
    print(df["label"].value_counts().sort_index().to_string())


if __name__ == "__main__":
    main()
