"""
Production-Predictor Benchmark Regression
=========================================
Runs the frozen 210-URL benchmark through the PRODUCTION ml_predictor
(backend/services/ml_predictor.py) to prove the integration reproduces the
verified SivakumarP evaluation numbers.

    cd backend && python benchmark/evaluate_production.py

Reference (verified SivakumarP adapter results):
    Accuracy 85.71% | Precision 93.42% | Recall 73.96% | F1 0.8256
    ROC-AUC 0.9471 | FPR 4.39% | FNR 26.04%
"""

import json
import os
import sys

import numpy as np

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from services.ml_predictor import predict_url  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def metrics(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    n = tp + fp + tn + fn
    return {
        "accuracy": (tp + tn) / n, "precision": tp / (tp + fp) if (tp + fp) else 0,
        "recall": tp / (tp + fn) if (tp + fn) else 0,
        "f1": 2 * tp / (2 * tp + fp + fn) if (tp + fp + fn) else 0,
        "fpr": fp / (fp + tn) if (fp + tn) else 0,
        "fnr": fn / (fn + tp) if (fn + tp) else 0,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def roc_auc(y_true, scores):
    order = np.argsort(np.asarray(scores, dtype=float), kind="stable")
    y = np.asarray(y_true, dtype=float)
    s = np.asarray(scores, dtype=float)[order]
    y = y[order]
    pos, neg = np.sum(y == 1), np.sum(y == 0)
    if pos == 0 or neg == 0:
        return float("nan")
    ranks = np.zeros(len(y))
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and s[j + 1] == s[i]:
            j += 1
        ranks[i:j + 1] = (i + j) / 2 + 1
        i = j + 1
    return float((np.sum(ranks[y == 1]) - pos * (pos + 1) / 2) / (pos * neg))


def main():
    with open(os.path.join(HERE, "dataset.json"), encoding="utf-8") as f:
        dataset = json.load(f)
    records = dataset["records"]

    y_true, y_pred, scores = [], [], []
    mismatched_backend = 0
    for rec in records:
        r = predict_url(rec["url"])
        if not r.get("available"):
            print("FATAL: production predictor unavailable:", r.get("error"))
            return 1
        if r.get("model_name") != "SivakumarP/PhishingURLDetection":
            mismatched_backend += 1
        y_true.append(rec["label"])
        y_pred.append(1 if r["prediction"] == "PHISHING" else 0)
        scores.append(r["phishing_probability"])

    m = metrics(y_true, y_pred)
    auc = roc_auc(y_true, scores)
    n = len(records)
    legit = sum(1 for t in y_true if t == 0)

    def p(x):
        return f"{x * 100:.2f}%"

    print(f"URLs evaluated (production predictor): {n}")
    print(f"Unexpected backend used: {mismatched_backend}")
    print()
    print(f"{'Metric':<12} {'Production':<12} {'Verified SivakumarP':<20} {'Match':<6}")
    expected = {
        "accuracy": 0.8571, "precision": 0.9342, "recall": 0.7396, "f1": 0.8256,
        "fpr": 0.0439, "fnr": 0.2604,
    }
    ok = True
    for key, label in [("accuracy", "Accuracy"), ("precision", "Precision"),
                       ("recall", "Recall"), ("f1", "F1"),
                       ("fpr", "FPR"), ("fnr", "FNR")]:
        got, want = m[key], expected[key]
        match = abs(got - want) < 0.01
        ok = ok and match
        print(f"{label:<12} {p(got):<12} {p(want):<20} {'OK' if match else 'DRIFT'}")
    auc_match = abs(auc - 0.9471) < 0.01
    ok = ok and auc_match
    print(f"{'ROC-AUC':<12} {auc:<12.4f} {'0.9471':<20} {'OK' if auc_match else 'DRIFT'}")
    print()
    print(f"Confusion matrix: TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")
    print(f"(legit n={legit}, phishing n={n - legit})")
    print()
    print("PRODUCTION BENCHMARK REGRESSION:", "PASS" if ok else "FAIL")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
