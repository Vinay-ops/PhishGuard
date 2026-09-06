"""
Model Evaluation Pipeline
=========================
Evaluates pirocheto/phishing-url-detection (ml/model.onnx) against the
frozen benchmark dataset (benchmark/dataset.json).

The evaluation passes only URL *strings* to the model — nothing is fetched
from the network during inference. Metrics are computed with numpy only.

Outputs
-------
- benchmark/results.csv          per-record predictions
- benchmark/report.md            full metrics report
"""

import csv
import json
import os

import numpy as np
import onnxruntime as ort

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(HERE, "dataset.json")
MODEL = os.path.join(os.path.dirname(HERE), "ml", "model.onnx")
RESULTS_CSV = os.path.join(HERE, "results.csv")
REPORT_MD = os.path.join(HERE, "report.md")


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

class OnnxModel:
    """Minimal ONNX wrapper matching the model's verified I/O contract."""

    def __init__(self, path: str):
        self.session = ort.InferenceSession(path, providers=["CPUExecutionProvider"])
        self.input_name = self.session.get_inputs()[0].name
        self.output_names = [o.name for o in self.session.get_outputs()]

    def predict(self, url: str) -> dict:
        inputs = np.array([url.strip()], dtype=np.str_)
        raw = self.session.run(None, {self.input_name: inputs})
        results = dict(zip(self.output_names, raw))
        labels = np.asarray(results["label"])
        probs = np.asarray(results["probabilities"], dtype=float)
        label = int(labels.reshape(-1)[0])
        safe_prob = float(probs[0, 0])
        phish_prob = float(probs[0, 1])
        return {
            "predicted_label": 1 if label == 1 else 0,
            "safe_prob": safe_prob,
            "phishing_prob": phish_prob,
        }


# ---------------------------------------------------------------------------
# Metrics (numpy only)
# ---------------------------------------------------------------------------

def confusion_counts(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    return tp, fp, tn, fn


def metrics(y_true, y_pred):
    tp, fp, tn, fn = confusion_counts(y_true, y_pred)
    n = tp + fp + tn + fn
    accuracy = (tp + tn) / n if n else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": accuracy, "precision": precision, "recall": recall,
        "f1": f1, "fpr": fpr, "fnr": fnr,
    }


def roc_auc(y_true, scores):
    """Area under the ROC curve (Mann–Whitney U, tie-safe).

    Ranks are assigned in ascending score order (rank 1 = lowest score),
    which is the convention the U-statistic formula expects.
    """
    order = np.argsort(np.asarray(scores, dtype=float), kind="stable")
    y = np.asarray(y_true, dtype=float)
    s = np.asarray(scores, dtype=float)[order]
    y = y[order]
    pos = np.sum(y == 1)
    neg = np.sum(y == 0)
    if pos == 0 or neg == 0:
        return float("nan")
    ranks = np.zeros(len(y))
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and s[j + 1] == s[i]:
            j += 1
        avg_rank = (i + j) / 2 + 1  # 1-based average rank, lowest score = 1
        ranks[i:j + 1] = avg_rank
        i = j + 1
    sum_pos_ranks = np.sum(ranks[y == 1])
    auc = (sum_pos_ranks - pos * (pos + 1) / 2) / (pos * neg)
    return float(auc)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    with open(DATASET, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    meta = dataset["meta"]
    records = dataset["records"]
    print(f"Model: {meta['model']}")
    print(f"Records: {meta['counts']['legit']} legit / {meta['counts']['phishing']} phishing")

    model = OnnxModel(MODEL)

    rows = []
    for rec in records:
        out = model.predict(rec["url"])
        rows.append({
            "url": rec["url"],
            "ground_truth": rec["label"],
            "predicted": out["predicted_label"],
            "safe_prob": round(out["safe_prob"], 6),
            "phishing_prob": round(out["phishing_prob"], 6),
            "category": rec.get("category", ""),
            "source": rec.get("source", ""),
        })

    # Per-record CSV
    with open(RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "ground_truth", "predicted",
                                               "safe_prob", "phishing_prob",
                                               "category", "source"])
        writer.writeheader()
        writer.writerows(rows)

    y_true = [r["ground_truth"] for r in rows]
    y_pred = [r["predicted"] for r in rows]
    scores = [r["phishing_prob"] for r in rows]

    overall = metrics(y_true, y_pred)
    auc = roc_auc(y_true, scores)

    # Sub-metrics by category
    by_category = {}
    for rec in records:
        cat = rec.get("category", "other")
        by_category.setdefault(cat, {"y_true": [], "y_pred": [], "scores": []})
    for row in rows:
        cat = row["category"] or "other"
        by_category[cat]["y_true"].append(row["ground_truth"])
        by_category[cat]["y_pred"].append(row["predicted"])
        by_category[cat]["scores"].append(row["phishing_prob"])

    # Deployment host breakdown (Vercel / Netlify / GitHub Pages)
    def host_kind(url):
        if "vercel.app" in url or "vercel.com" in url or "nextjs.org" in url or "astro.build" in url:
            return "Vercel"
        if "netlify" in url:
            return "Netlify"
        if "github.io" in url or "github.com" in url:
            return "GitHub"
        return None

    deploy_stats = {}
    for row in rows:
        kind = host_kind(row["url"])
        if kind:
            deploy_stats.setdefault(kind, {"n": 0, "fp": 0, "flagged": []})
            deploy_stats[kind]["n"] += 1
            if row["predicted"] == 1 and row["ground_truth"] == 0:
                deploy_stats[kind]["fp"] += 1
                deploy_stats[kind]["flagged"].append((row["url"], row["phishing_prob"]))

    # Notable false positives (legit URLs predicted as phishing), by prob desc
    false_positives = sorted(
        [r for r in rows if r["ground_truth"] == 0 and r["predicted"] == 1],
        key=lambda r: -r["phishing_prob"],
    )
    # False negatives (phishing predicted safe), by prob asc (most missed first)
    false_negatives = sorted(
        [r for r in rows if r["ground_truth"] == 1 and r["predicted"] == 0],
        key=lambda r: r["phishing_prob"],
    )

    # Learnova entry
    learnova = next(r for r in rows if "learnova" in r["url"])

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    def pct(x):
        return f"{x * 100:.2f}%"

    cm = f"""```
                 Predicted
              Phishing   Safe
Actual Phishing   {overall['tp']:>3}        {overall['fn']:>3}
Actual Legit      {overall['fp']:>3}        {overall['tn']:>3}
```"""

    lines = []
    lines.append("# Model Benchmark Report")
    lines.append("")
    lines.append(f"**MODEL:** {meta['model']}")
    lines.append(f"**Model file:** `{meta['model_file']}`")
    lines.append(f"**Dataset built:** {meta['built_at']} (seed {meta['seed']})")
    lines.append("")
    lines.append("## Dataset")
    lines.append("")
    lines.append(f"- Number of legitimate URLs: **{meta['counts']['legit']}**")
    lines.append(f"- Number of phishing URLs: **{meta['counts']['phishing']}**")
    lines.append(f"- Total: **{meta['counts']['total']}**")
    lines.append("")
    lines.append("### Sources")
    lines.append("")
    for s in meta["sources"]:
        lines.append(f"- {s}")
    lines.append("")
    lines.append("> " + meta["notes"])
    lines.append("")
    lines.append("## Overall Metrics")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Accuracy | {pct(overall['accuracy'])} |")
    lines.append(f"| Precision (phishing-positive) | {pct(overall['precision'])} |")
    lines.append(f"| Recall (phishing-positive) | {pct(overall['recall'])} |")
    lines.append(f"| F1-score | {overall['f1']:.4f} |")
    lines.append(f"| ROC-AUC | {auc:.4f} |")
    lines.append(f"| False Positive Rate | {pct(overall['fpr'])} |")
    lines.append(f"| False Negative Rate | {pct(overall['fnr'])} |")
    lines.append("")
    lines.append("## Confusion Matrix")
    lines.append("")
    lines.append(cm)
    lines.append("")
    lines.append(f"- TP = {overall['tp']}, FP = {overall['fp']}, TN = {overall['tn']}, FN = {overall['fn']}")
    lines.append("")

    lines.append("## Metrics by URL Category")
    lines.append("")
    lines.append("| Category | n | Accuracy | Precision | Recall | F1 | FPR | FNR |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for cat in sorted(by_category):
        m = metrics(by_category[cat]["y_true"], by_category[cat]["y_pred"])
        lines.append(
            f"| {cat} | {len(by_category[cat]['y_true'])} | {pct(m['accuracy'])} | "
            f"{pct(m['precision'])} | {pct(m['recall'])} | {m['f1']:.4f} | "
            f"{pct(m['fpr'])} | {pct(m['fnr'])} |"
        )
    lines.append("")

    lines.append("## Deployment Host Breakdown (legit Vercel/Netlify/GitHub)")
    lines.append("")
    lines.append("| Host | n | False Positives |")
    lines.append("|---|---|---|")
    for kind in sorted(deploy_stats):
        d = deploy_stats[kind]
        lines.append(f"| {kind} | {d['n']} | {d['fp']} |")
    lines.append("")
    for kind in sorted(deploy_stats):
        d = deploy_stats[kind]
        if d["flagged"]:
            lines.append(f"### {kind} — flagged legit deployments")
            lines.append("")
            for url, prob in sorted(d["flagged"], key=lambda x: -x[1]):
                lines.append(f"- `{url}` — phishing prob {prob * 100:.1f}%")
            lines.append("")

    lines.append("## Notable False Positives (legit predicted as phishing)")
    lines.append("")
    if false_positives:
        lines.append("| URL | Ground Truth | Predicted | Phishing Prob | Category |")
        lines.append("|---|---|---|---|---|")
        for fp in false_positives:
            lines.append(
                f"| `{fp['url']}` | legit | phishing | {fp['phishing_prob'] * 100:.2f}% | {fp['category']} |"
            )
    else:
        lines.append("_None._")
    lines.append("")

    lines.append("## False Negatives (phishing predicted as legit)")
    lines.append("")
    if false_negatives:
        lines.append("| URL | Ground Truth | Predicted | Phishing Prob | Category |")
        lines.append("|---|---|---|---|---|")
        for fn in false_negatives:
            lines.append(
                f"| `{fn['url'][:90]}` | phishing | legit | {fn['phishing_prob'] * 100:.2f}% | {fn['category']} |"
            )
    else:
        lines.append("_None._")
    lines.append("")

    lines.append("## Learnova Deployment (documented case)")
    lines.append("")
    lines.append(
        f"- URL: `{learnova['url']}`"
    )
    lines.append(f"- Ground truth (benchmark): **legitimate** (user's own Vercel deployment)")
    lines.append(f"- Predicted label: **{'phishing' if learnova['predicted'] == 1 else 'safe'}**")
    lines.append(f"- Phishing probability: **{learnova['phishing_prob'] * 100:.1f}%**")
    lines.append(f"- Safe probability: **{learnova['safe_prob'] * 100:.1f}%**")
    lines.append("")
    lines.append(
        "This is a model prediction, not independent evidence. The model assigns a high "
        "phishing probability to this deployment host pattern; the production risk engine "
        "reports it as MODEL-RULE DISAGREEMENT because no URL rules trigger."
    )
    lines.append("")

    lines.append("## Reproducibility")
    lines.append("")
    lines.append("```bash")
    lines.append("# 1. Rebuild the frozen dataset (requires network for Phishing.Database)")
    lines.append("python benchmark/build_dataset.py")
    lines.append("# 2. Re-run evaluation against dataset.json (no network needed)")
    lines.append("python benchmark/evaluate.py")
    lines.append("```")
    lines.append("")
    lines.append("Full per-record predictions: `benchmark/results.csv`")

    with open(REPORT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    # Console summary
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Accuracy:            {pct(overall['accuracy'])}")
    print(f"Precision:           {pct(overall['precision'])}")
    print(f"Recall:              {pct(overall['recall'])}")
    print(f"F1:                  {overall['f1']:.4f}")
    print(f"ROC-AUC:             {auc:.4f}")
    print(f"False Positive Rate: {pct(overall['fpr'])}")
    print(f"False Negative Rate: {pct(overall['fnr'])}")
    print()
    print("Confusion matrix: TP=%d FP=%d TN=%d FN=%d" % (overall['tp'], overall['fp'], overall['tn'], overall['fn']))
    print()
    print("False positives (legit->phishing):", len(false_positives))
    for fp in false_positives[:10]:
        print(f"  {fp['url'][:80]:80s} prob={fp['phishing_prob'] * 100:6.2f}%  [{fp['category']}]")
    print()
    print("False negatives (phishing->legit):", len(false_negatives))
    for fn in false_negatives[:10]:
        print(f"  {fn['url'][:80]:80s} prob={fn['phishing_prob'] * 100:6.2f}%  [{fn['category']}]")
    print()
    print(f"Learnova: phishing_prob={learnova['phishing_prob'] * 100:.1f}%  predicted={'phishing' if learnova['predicted'] == 1 else 'safe'}")
    print()
    print("Report written to", REPORT_MD)
    print("Results written to", RESULTS_CSV)


if __name__ == "__main__":
    main()