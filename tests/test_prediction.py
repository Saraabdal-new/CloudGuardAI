
"""Tests for CloudGuard AI ML predictions."""
from src.predict import predict_policy


ADMIN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    ],
}

SAFE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::example-bucket/*",
        }
    ],
}


def test_admin_policy_is_detected():
    result = predict_policy(ADMIN_POLICY)

    assert result["prediction"] == 1
    assert result["prediction_label"] == "misconfigured"
    assert result["risk_probability"] >= 0.0
    assert result["highest_severity"] == "CRITICAL"
    assert any(
        finding["rule_id"] == "IAM-001"
        for finding in result["findings"]
    )


def test_prediction_contains_required_fields():
    result = predict_policy(ADMIN_POLICY)

    assert "prediction" in result
    assert "prediction_label" in result
    assert "risk_probability" in result
    assert "features" in result
    assert "findings" in result
    assert "rule_based_misconfigured" in result
    assert "highest_severity" in result


def test_safe_policy_is_not_flagged_by_rules():
    result = predict_policy(SAFE_POLICY)

    assert result["rule_based_misconfigured"] is False
    assert result["findings"] == []
    assert result["highest_severity"] == "NONE"
