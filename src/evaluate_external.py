"""Compare the ML model and the rule-based scanner on independent policies.

The policies in data/external/realistic_policies.json were written by hand and
are NOT produced by src/generate_data.py. Each one carries an "expert_label"
(1 = misconfigured, 0 = acceptable) based on common IAM security practice.
That label is a human judgement, not an AWS ground truth, so "debatable"
cases are reported separately.

Usage: python -m src.evaluate_external
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from .labeling import DEFAULT_OWN_ACCOUNT_ID
from .predict import load_model, predict_policy


ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_PATH = ROOT / "data" / "external" / "realistic_policies.json"
REPORT_PATH = ROOT / "reports" / "external_eval.csv"


def summarize(truth: pd.Series, prediction: pd.Series) -> dict:
    tn, fp, fn, tp = confusion_matrix(truth, prediction, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(truth, prediction),
        "precision": precision_score(truth, prediction, zero_division=0),
        "recall": recall_score(truth, prediction, zero_division=0),
        "f1": f1_score(truth, prediction, zero_division=0),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def print_summary(title: str, frame: pd.DataFrame) -> None:
    print(f"\n{title} ({len(frame)} policies)")
    header = (f"{'System':<10}{'Acc':>7}{'Prec':>7}{'Recall':>8}{'F1':>7}"
              f"{'  TN':>5}{'FP':>4}{'FN':>4}{'TP':>4}")
    print(header)
    print("-" * len(header))
    for name, column in (("Scanner", "scanner"), ("ML model", "ml")):
        s = summarize(frame["expert"], frame[column])
        print(f"{name:<10}{s['accuracy']:>7.3f}{s['precision']:>7.3f}"
              f"{s['recall']:>8.3f}{s['f1']:>7.3f}"
              f"{s['tn']:>5}{s['fp']:>4}{s['fn']:>4}{s['tp']:>4}")


def main() -> None:
    items = json.loads(EXTERNAL_PATH.read_text(encoding="utf-8"))
    model = load_model()

    rows = []
    for item in items:

        own_account_id = item.get(
    "own_account_id",
    DEFAULT_OWN_ACCOUNT_ID,
    )
        result = predict_policy(
    item["policy"],
    model,
    own_account_id=own_account_id,
    )
        rows.append({
            "id": item["id"],
            "description": item["description"],
            "difficulty": item["difficulty"],
            "expert": int(item["expert_label"]),
            "scanner": int(result["rule_based_misconfigured"]),
            "ml": int(result["prediction"]),
            "ml_risk": round(result["risk_probability"], 2),
            "rationale": item["rationale"],
        })
    df = pd.DataFrame(rows)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(REPORT_PATH, index=False, encoding="utf-8")

    print("Per-policy results (1 = misconfigured). '*' marks a disagreement "
          "with the expert label.")
    shown = df[["id", "difficulty", "expert", "scanner", "ml", "ml_risk",
                "description"]].copy()
    shown["flag"] = [
        ("S" if row.scanner != row.expert else "-")
        + ("M" if row.ml != row.expert else "-")
        for row in df.itertuples()
    ]
    print(shown.to_string(index=False))
    print("flag: S = scanner differs from expert, M = ML differs from expert")

    print_summary("All policies", df)
    print_summary("Clear cases only", df[df["difficulty"] == "clear"])

    agreement = (df["scanner"] == df["ml"]).mean()
    print(f"\nScanner and ML agree on {agreement:.0%} of policies.")

    wrong = df[(df["scanner"] != df["expert"]) | (df["ml"] != df["expert"])]
    print(f"\nDisagreements with the expert label: {len(wrong)}")
    for row in wrong.itertuples():
        who = []
        if row.scanner != row.expert:
            who.append("scanner")
        if row.ml != row.expert:
            who.append("ML")
        kind = "missed risk" if row.expert == 1 else "false alarm"
        print(f"\n[{row.id}] {row.description}")
        print(f"  expert={row.expert} scanner={row.scanner} ml={row.ml} "
              f"(risk {row.ml_risk:.2f}); {kind} by {' and '.join(who)}")
        print(f"  why: {row.rationale}")

    print(f"\nSaved: {REPORT_PATH}")
    print("Note: only a few dozen policies and a human-written label, so read "
          "these numbers as a qualitative check, not a benchmark.")


if __name__ == "__main__":
    main()