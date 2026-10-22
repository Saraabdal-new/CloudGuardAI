import pandas as pd

from src.policy_scanner import (
    highest_severity, is_misconfigured, scan_iam_policy, scan_policy_source,
)


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def ids(findings):
    return {f["rule_id"] for f in findings}


def test_admin_is_critical():
    findings = scan_iam_policy(policy({"Effect": "Allow", "Action": "*", "Resource": "*"}))
    assert "IAM-001" in ids(findings)
    assert highest_severity(findings) == "CRITICAL"
    assert findings[0]["statement_index"] == 0
    assert '"Action": "*"' in findings[0]["evidence"]


def test_condition_neutralises_admin():
    findings = scan_iam_policy(policy({
        "Effect": "Allow", "Action": "*", "Resource": "*",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}))
    assert findings == []


def test_wildcard_action_on_specific_resource_is_advisory():
    findings = scan_iam_policy(policy({"Effect": "Allow", "Action": "*",
                                       "Resource": "arn:aws:s3:::b/*"}))
    assert ids(findings) == {"IAM-002"}
    assert not is_misconfigured(findings)


def test_wildcard_resource_is_advisory():
    findings = scan_iam_policy(policy({"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}))
    assert ids(findings) == {"IAM-003"}


def test_multiple_findings_per_statement():
    findings = scan_iam_policy(policy({"Effect": "Allow", "Principal": "*",
                                       "Action": "iam:*", "Resource": "*"}))
    assert {"IAM-004", "IAM-005"} <= ids(findings)


def test_privilege_escalation():
    findings = scan_iam_policy(policy({"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}))
    assert "IAM-006" in ids(findings)


def test_not_action():
    findings = scan_iam_policy(policy({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
    assert "IAM-007" in ids(findings)


def test_external_account_without_condition():
    findings = scan_iam_policy(policy({
        "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
        "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}))
    assert "IAM-009" in ids(findings)


def test_deny_statement_has_no_findings():
    assert scan_iam_policy(policy({"Effect": "Deny", "Action": "*", "Resource": "*"})) == []


def test_clean_policy():
    assert scan_iam_policy(policy({"Effect": "Allow", "Action": "s3:GetObject",
                                   "Resource": "arn:aws:s3:::b/*"})) == []


def test_invalid_inputs_never_raise():
    assert ids(scan_iam_policy("not a dict")) == {"IAM-INVALID-STATEMENT"}
    assert ids(scan_iam_policy({"Version": "x"})) == {"IAM-INVALID-STATEMENT"}
    assert ids(scan_iam_policy(policy("oops"))) == {"IAM-INVALID-STATEMENT"}
    assert ids(scan_policy_source("{broken json")) == {"IAM-INVALID-STATEMENT"}


def test_scanner_matches_dataset_labels():
    df = pd.read_csv("data/raw/iam_policies.csv")
    predicted = [int(is_misconfigured(scan_policy_source(p))) for p in df["policy_json"]]
    assert predicted == df["label"].tolist()