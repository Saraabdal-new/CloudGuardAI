"""List the policies the random forest misclassifies under grouped CV.

Usage: python -m src.error_analysis
Uses the same folds and model settings as src/train.py.
"""
from __future__ import annotations

import json

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.model_selection import StratifiedGroupKFold

from .data_loader import parse_policy
from .feature_engineering import extract_features
from .labeling import evaluate_policy
from .train import DATA_PATH, N_SPLITS, SEED, build_random_forest


def main() -> None:
    df = pd.read_csv(DATA_PATH)
    policies = [parse_policy(str(p)) for p in df["policy_json"]]
    X = pd.DataFrame([extract_features(p) for p in policies]).fillna(0)
    y = df["label"].astype(int)

    groups = X.astype(str).agg("|".join, axis=1).factorize()[0]
    cv = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=SEED)

    predictions = np.zeros(len(y), dtype=int)
    risk = np.zeros(len(y))
    for train_idx, test_idx in cv.split(X, y, groups):
        model = clone(build_random_forest())
        model.fit(X.iloc[train_idx], y.iloc[train_idx])
        predictions[test_idx] = model.predict(X.iloc[test_idx])
        risk[test_idx] = model.predict_proba(X.iloc[test_idx])[:, 1]

    df["prediction"] = predictions
    df["risk"] = risk
    df["n_statements"] = [len(p.get("Statement", [])) for p in policies]
    df["rules"] = [",".join(evaluate_policy(p)) or "-" for p in policies]
    df["error"] = df["label"] != df["prediction"]

    print("Error rate by number of statements:")
    summary = df.groupby("n_statements")["error"].agg(["count", "sum", "mean"])
    summary.columns = ["policies", "errors", "error_rate"]
    print(summary.round(3).to_string())

    print("\nError rate by rules triggered (label 1 only):")
    risky = df[df["label"] == 1]
    by_rule = risky.groupby("rules")["error"].agg(["count", "sum"])
    by_rule.columns = ["policies", "missed"]
    print(by_rule.to_string())

    print(f"\nMisclassified policies: {int(df['error'].sum())}")
    for row in df[df["error"]].itertuples():
        kind = "MISSED (false negative)" if row.label == 1 else "FALSE ALARM"
        print(f"\n[{kind}] label={row.label} predicted={row.prediction} "
              f"risk={row.risk:.2f} statements={row.n_statements} rules={row.rules}")
        print(json.dumps(json.loads(row.policy_json), separators=(",", ":")))


if __name__ == "__main__":
    main()