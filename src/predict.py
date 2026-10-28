
"""Run ML predictions and rule-based scans on IAM policies."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from .data_loader import parse_policy
from .feature_engineering import extract_features
from .labeling import DEFAULT_OWN_ACCOUNT_ID
from .policy_scanner import scan_iam_policy


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "iam_risk_model.joblib"
FEATURES_PATH = ROOT / "models" / "feature_names.json"


def load_model():
    """Load the saved classifier."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}. Run python -m src.train first."
        )
    return joblib.load(MODEL_PATH)


def predict_policy(
    source: str | bytes | dict | Path,
    model: Any | None = None,
    own_account_id: str = DEFAULT_OWN_ACCOUNT_ID,
) -> dict[str, Any]:
    """Return ML prediction and rule-based findings for one policy."""
    policy = parse_policy(source)
    classifier = model if model is not None else load_model()

    features = extract_features(
    policy,
    own_account_id=own_account_id,
    )

    if FEATURES_PATH.exists():
        import json
        feature_names = json.loads(FEATURES_PATH.read_text(encoding="utf-8"))
    else:
        feature_names = list(features)

    X = pd.DataFrame(
        [[features.get(name, 0) for name in feature_names]],
        columns=feature_names,
    )

    prediction = int(classifier.predict(X)[0])

    probabilities = classifier.predict_proba(X)[0]
    classes = list(classifier.classes_)
    positive_index = classes.index(1) if 1 in classes else None
    risk_probability = (
        float(probabilities[positive_index])
        if positive_index is not None
        else 0.0
    )

    findings = scan_iam_policy(
    policy,
    own_account_id=own_account_id,
    )

    return {
        "prediction": prediction,
        "prediction_label": (
            "misconfigured" if prediction == 1 else "safe"
        ),
        "risk_probability": risk_probability,
        "features": features,
        "findings": findings,
        "rule_based_misconfigured": any(
            finding["category"] == "misconfiguration"
            for finding in findings
        ),
        "highest_severity": (
            max(
                findings,
                key=lambda finding: {
                    "CRITICAL": 4,
                    "HIGH": 3,
                    "MEDIUM": 2,
                    "LOW": 1,
                }.get(finding["severity"], 0),
            )["severity"]
            if findings
            else "NONE"
        ),
    }


if __name__ == "__main__":
    example = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}
        ],
    }

    result = predict_policy(example)
    print("Prediction:", result["prediction_label"])
    print("Risk probability:", f"{result['risk_probability']:.1%}")
    print("Highest severity:", result["highest_severity"])
    print("Findings:")
    for finding in result["findings"]:
        print(
            f"- [{finding['severity']}] {finding['rule_id']}: "
            f"{finding['title']}"
        )
