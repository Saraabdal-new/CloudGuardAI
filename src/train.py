"""Train and evaluate IAM policy misconfiguration classifiers.

Evaluation uses grouped cross-validation: policies whose feature vectors are
identical share a group, so the same profile never appears in both the
training and the test fold. Several models are compared, including simple
baselines, to show how much of the task the rules alone already solve.

The saved model is a Random Forest pipeline trained on all rows, in the same
format that src/predict.py already expects.
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from .data_loader import parse_policy
from .feature_engineering import extract_features


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "raw" / "iam_policies.csv"
MODEL_PATH = ROOT / "models" / "iam_risk_model.joblib"
FEATURES_PATH = ROOT / "models" / "feature_names.json"
METRICS_PATH = ROOT / "models" / "metrics.json"

SEED = 42
N_SPLITS = 5


def build_models() -> dict[str, object]:
    return {
        "Majority-class baseline": DummyClassifier(strategy="most_frequent"),
        "Decision tree (depth 3)": DecisionTreeClassifier(
            max_depth=3, random_state=SEED, class_weight="balanced"
        ),
        "Logistic regression": Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(
                max_iter=1000, class_weight="balanced", random_state=SEED
            )),
        ]),
        "Random forest": build_random_forest(),
    }


def build_random_forest() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=200,
            random_state=SEED,
            class_weight="balanced",
        )),
    ])


def evaluate(model, X: pd.DataFrame, y: pd.Series, splits) -> dict:
    """Run cross-validation over precomputed splits."""
    fold_scores: dict[str, list[float]] = {
        "accuracy": [], "precision": [], "recall": [], "f1": [],
    }
    out_of_fold = np.zeros(len(y), dtype=int)

    for train_idx, test_idx in splits:
        fitted = clone(model)
        fitted.fit(X.iloc[train_idx], y.iloc[train_idx])
        predictions = fitted.predict(X.iloc[test_idx])
        truth = y.iloc[test_idx]

        fold_scores["accuracy"].append(accuracy_score(truth, predictions))
        fold_scores["precision"].append(
            precision_score(truth, predictions, zero_division=0))
        fold_scores["recall"].append(
            recall_score(truth, predictions, zero_division=0))
        fold_scores["f1"].append(f1_score(truth, predictions, zero_division=0))
        out_of_fold[test_idx] = predictions

    return {
        "mean": {k: float(np.mean(v)) for k, v in fold_scores.items()},
        "std": {k: float(np.std(v)) for k, v in fold_scores.items()},
        "confusion_matrix": confusion_matrix(
            y, out_of_fold, labels=[0, 1]).tolist(),
    }


def main() -> None:
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}. Run python -m src.generate_data first."
        )

    df = pd.read_csv(DATA_PATH)

    required = {"policy_json", "label"}
    if not required.issubset(df.columns):
        raise ValueError(f"Dataset must contain columns: {sorted(required)}")

    X = pd.DataFrame(
        [extract_features(parse_policy(str(p))) for p in df["policy_json"]]
    ).fillna(0)
    y = df["label"].astype(int)

    if y.nunique() < 2:
        raise ValueError("Training requires examples from both label classes.")

    # Identical feature vectors form one group, so they stay in the same fold.
    groups = X.astype(str).agg("|".join, axis=1).factorize()[0]
    n_groups = len(set(groups))

    grouped_cv = StratifiedGroupKFold(
        n_splits=N_SPLITS, shuffle=True, random_state=SEED)
    grouped_splits = list(grouped_cv.split(X, y, groups))

    print(f"Dataset rows: {len(df)}")
    print(f"Features: {X.shape[1]}")
    print(f"Unique feature vectors (groups): {n_groups}")
    print(f"Evaluation: {N_SPLITS}-fold stratified group cross-validation\n")

    results: dict[str, dict] = {}
    for name, model in build_models().items():
        results[name] = evaluate(model, X, y, grouped_splits)

    header = f"{'Model':<26}{'Accuracy':>16}{'Precision':>16}{'Recall':>16}{'F1':>16}"
    print(header)
    print("-" * len(header))
    for name, res in results.items():
        cells = "".join(
            f"{res['mean'][m]:>9.3f} ±{res['std'][m]:.3f}"
            for m in ("accuracy", "precision", "recall", "f1")
        )
        print(f"{name:<26}{cells}")

    print("\nOut-of-fold confusion matrices (rows = truth, columns = prediction;"
          " order: safe, misconfigured):")
    for name, res in results.items():
        print(f"- {name}: {res['confusion_matrix']}")

    # Leakage illustration: ungrouped CV lets identical vectors cross folds.
    naive_cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=SEED)
    naive = evaluate(build_random_forest(), X, y, list(naive_cv.split(X, y)))
    print(
        "\nRandom forest, ungrouped CV (optimistic, shown for comparison): "
        f"accuracy {naive['mean']['accuracy']:.3f}, "
        f"F1 {naive['mean']['f1']:.3f}"
    )

    # Final model: trained on all rows, saved in the format predict.py expects.
    final_model = build_random_forest()
    final_model.fit(X, y)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, MODEL_PATH)
    FEATURES_PATH.write_text(
        json.dumps(list(X.columns), indent=2), encoding="utf-8")
    METRICS_PATH.write_text(
        json.dumps(
            {
                "evaluation": f"{N_SPLITS}-fold stratified group CV",
                "rows": len(df),
                "unique_feature_vectors": n_groups,
                "models": results,
                "random_forest_ungrouped_cv": naive["mean"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    importances = final_model.named_steps["classifier"].feature_importances_
    ranking = sorted(zip(X.columns, importances), key=lambda item: -item[1])[:8]
    print("\nTop features (final random forest):")
    for name, value in ranking:
        print(f"- {name}: {value:.3f}")

    print(f"\nSaved model: {MODEL_PATH}")
    print(f"Saved feature names: {FEATURES_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")
    print(
        "\nNote: data is synthetic and labels come from the same rules the "
        "features mirror. These scores do not measure real-world performance."
    )


if __name__ == "__main__":
    main()