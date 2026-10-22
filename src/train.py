
"""Train and evaluate a baseline IAM policy misconfiguration classifier."""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .data_loader import parse_policy
from .feature_engineering import extract_features


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "raw" / "iam_policies.csv"
MODEL_PATH = ROOT / "models" / "iam_risk_model.joblib"
FEATURES_PATH = ROOT / "models" / "feature_names.json"


def main() -> None:
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}. Run python -m src.generate_data first."
        )

    df = pd.read_csv(DATA_PATH)

    required = {"policy_json", "label"}
    if not required.issubset(df.columns):
        raise ValueError(f"Dataset must contain columns: {sorted(required)}")

    X_rows = []
    for raw_policy in df["policy_json"]:
        policy = parse_policy(str(raw_policy))
        X_rows.append(extract_features(policy))

    X = pd.DataFrame(X_rows).fillna(0)
    y = df["label"].astype(int)

    if y.nunique() < 2:
        raise ValueError("Training requires examples from both label classes.")

    # Synthetic examples are duplicates, so use a stratified split for this
    # baseline only. This is not a reliable estimate of real-world performance.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced",
        )),
    ])

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    FEATURES_PATH.write_text(
        json.dumps(list(X.columns), indent=2),
        encoding="utf-8",
    )

    print(f"Dataset rows: {len(df)}")
    print(f"Training rows: {len(X_train)}")
    print(f"Test rows: {len(X_test)}")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.3f}")
    print("\nConfusion matrix:")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))
    print("\nClassification report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["safe", "misconfigured"],
        zero_division=0,
    ))
    print(f"Saved model: {MODEL_PATH}")
    print(f"Saved feature names: {FEATURES_PATH}")


if __name__ == "__main__":
    main()
