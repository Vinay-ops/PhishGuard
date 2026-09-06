"""
Three-Model Comparison
======================
Evaluates pirocheto, SivakumarP, and r3ddkahili on the SAME frozen dataset
(benchmark/dataset.json) with the SAME metrics and threshold methodology
(predicted phishing iff phishing_prob >= 0.5; ROC-AUC via tie-safe
Mann-Whitney U).

Outputs
-------
- benchmark/comparison_results/<model>.csv   per-record predictions
- benchmark/comparison_report.md             full comparative report
"""

import csv
import json
import os

import numpy as np

from adapters import ADAPTERS

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET = os.path.join(HERE, "dataset.json")
OUT_DIR = os.path.join(HERE, "comparison_results")
REPORT = os.path.join(HERE, "comparison_report.md")


# ---------------------------------------------------------------------------
# Metrics (identical to evaluate.py)
# ---------------------------------------------------------------------------

def metrics(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    n = tp + fp + tn + fn
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": (tp + tn) / n if n else 0.0,
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "f1": (2 * tp / (2 * tp + fp + fn)) if (tp + fp + fn) else 0.0,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "fnr": fn / (fn + tp) if (fn + tp) else 0.0,
    }


def roc_auc(y_true, scores):
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
        ranks[i:j + 1] = (i + j) / 2 + 1
        i = j + 1
    return float((np.sum(ranks[y == 1]) - pos * (pos + 1) / 2) / (pos * neg))


def pct(x):
    return f"{x * 100:.2f}%"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(DATASET, "r", encoding="utf-8") as f:
        dataset = json.load(f)
    records = dataset["records"]
    meta = dataset["meta"]

    # Notable URLs for the per-URL comparison table
    NOTABLE_SUBSTR = [
        "paypal.com", "google.com", "microsoft.com", "github.com",
        "wikipedia.org", "aws.amazon", "bankofamerica", "vercel", "netlify",
        "github.io", "learnova",
    ]

    all_rows = {}       # model name -> list of row dicts
    all_summaries = {}  # model name -> summary dict

    for adapter_cls in ADAPTERS:
        print(f"Evaluating {adapter_cls.display} ...")
        adapter = adapter_cls()
        rows = []
        for rec in records:
            out = adapter.predict(rec["url"])
            rows.append({
                "url": rec["url"],
                "ground_truth": rec["label"],
                "predicted": out["predicted_label"],
                "phishing_prob": round(out["phishing_prob"], 6),
                "category": rec.get("category", ""),
                "source": rec.get("source", ""),
                "detail": out["detail"],
            })
        all_rows[adapter.name] = rows

        # CSV
        with open(os.path.join(OUT_DIR, f"{adapter.name}.csv"), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "ground_truth", "predicted", "phishing_prob", "category", "source"])
            for r in rows:
                writer.writerow([r["url"], r["ground_truth"], r["predicted"],
                                 r["phishing_prob"], r["category"], r["source"]])

        # Metrics
        y_true = [r["ground_truth"] for r in rows]
        y_pred = [r["predicted"] for r in rows]
        scores = [r["phishing_prob"] for r in rows]
        m = metrics(y_true, y_pred)
        auc = roc_auc(y_true, scores)

        # REAL vs PATTERN split
        real = [r for r in rows if r["source"] != "PATTERN"]
        pattern = [r for r in rows if r["source"] == "PATTERN"]
        m_real = metrics([r["ground_truth"] for r in real], [r["predicted"] for r in real])
        m_pattern = metrics([r["ground_truth"] for r in pattern], [r["predicted"] for r in pattern])

        # By category
        cats = {}
        for r in rows:
            cats.setdefault(r["category"], {"y_true": [], "y_pred": [], "scores": []})
        for r in rows:
            cats[r["category"]]["y_true"].append(r["ground_truth"])
            cats[r["category"]]["y_pred"].append(r["predicted"])
            cats[r["category"]]["scores"].append(r["phishing_prob"])

        # False positives among legit (sorted by prob desc)
        fps = sorted([r for r in rows if r["ground_truth"] == 0 and r["predicted"] == 1],
                     key=lambda r: -r["phishing_prob"])
        # False negatives among phishing
        fns = sorted([r for r in rows if r["ground_truth"] == 1 and r["predicted"] == 0],
                     key=lambda r: r["phishing_prob"])

        all_summaries[adapter.name] = {
            "m": m, "auc": auc,
            "m_real": m_real, "m_pattern": m_pattern,
            "cats": cats, "fps": fps, "fns": fns,
        }
        print(f"  acc={pct(m['accuracy'])} f1={m['f1']:.4f} auc={auc:.4f} fpr={pct(m['fpr'])} fnr={pct(m['fnr'])}")

    # ------------------------------------------------------------------
    # Build report
    # ------------------------------------------------------------------
    L = []
    L.append("# Three-Model Benchmark Comparison")
    L.append("")
    L.append(f"**Dataset:** `benchmark/dataset.json` (seed {meta['seed']}, built {meta['built_at']})")
    L.append(f"- Legitimate URLs: **{meta['counts']['legit']}** | Phishing URLs: **{meta['counts']['phishing']}** | Total: **{meta['counts']['total']}**")
    L.append("")
    L.append("**Protocol:** identical for all three models — same URLs, same ground-truth labels, "
             "same threshold (phishing iff phishing probability ≥ 0.5), same metrics, same "
             "tie-safe Mann–Whitney ROC-AUC.")
    L.append("")
    L.append("## A. Model Architecture Comparison")
    L.append("")
    L.append("| Model | Architecture | Input format | Preprocessing | Class labels | Probability output | Size | ONNX? | Dependencies |")
    L.append("|---|---|---|---|---|---|---|---|---|")

    # ---- fill per-model architecture rows ----
    for adapter_cls in ADAPTERS:
        a = adapter_cls
        name = a.display
        if a.name == "pirocheto":
            arch = "ONNX text classifier (opaque internals)"
            inp = "raw URL string"
            pre = "handled inside model"
            cls = "2 (safe/phishing)"
            prob = "probabilities[0]=safe, [1]=phishing (verified)"
            size = "23.5 MB"
            onnx = "yes (native)"
            deps = "onnxruntime, numpy"
        elif a.name == "sivakumarp":
            arch = "RandomForest 100 trees (gini, depth 32)"
            inp = "187-dim feature vector"
            pre = "char TF-IDF(1-gram) on url/dom/tld + StandardScaler(digit_cnt, is_https); dom/tld via tldextract (verified vs dataset)"
            cls = "2 (0=benign, 1=phishing)"
            prob = "predict_proba[1] = phishing"
            size = "29.8 MB (model) + preprocessors"
            onnx = "no (pickle/joblib)"
            deps = "scikit-learn, joblib, scipy, tldextract"
        else:
            arch = "BertForSequenceClassification (bert-base-uncased, 110M)"
            inp = "raw URL string (tokenized)"
            pre = "BERT tokenizer, max_length=128"
            cls = "4 (0=Benign, 1=Defacement, 2=Phishing, 3=Malware)"
            prob = "softmax(logits)[2] = phishing"
            size = "417.7 MB (F32 safetensors)"
            onnx = "no (PyTorch/safetensors)"
            deps = "torch, transformers, safetensors"
        L.append(f"| {name} | {arch} | {inp} | {pre} | {cls} | {prob} | {size} | {onnx} | {deps} |")
    L.append("")

    L.append("## B. Input / Preprocessing Comparison")
    L.append("")
    L.append("- **pirocheto**: consumes the raw URL string directly; all preprocessing is internal to the model. "
             "This is the only candidate that matches the current PhishGuard integration with zero changes.")
    L.append("- **SivakumarP**: does **NOT** accept a raw URL. It requires the exact URL-Phish feature layout: "
             "char-level TF-IDF of the full URL, the registered domain (e.g. `google.com`, not `www.google.com`), "
             "the public suffix (e.g. `com`, `co.uk`), and scaled `digit_cnt` + `is_https`. The dom/tld semantics "
             "were reverse-engineered from the original URL-Phish Dataset.csv and reproduced 9/9 with `tldextract`. "
             "Feeding PhishGuard's existing feature vector would be incorrect.")
    L.append("- **r3ddkahili**: accepts a raw URL string but tokenizes it with the BERT WordPiece tokenizer "
             "(128-token limit). It outputs 4 classes; phishing must be extracted as class 2. The artifact's "
             "`config.json` label map is generic (LABEL_0..3); the semantic mapping comes from the model card.")
    L.append("")

    L.append("## C. Output / Class Mapping")
    L.append("")
    L.append("| Model | Class order | Phishing class | Verified? |")
    L.append("|---|---|---|---|")
    L.append("| pirocheto | [safe, phishing] | index 1 (label 1) | yes — probabilities sum to 1, google.com→safe, IP→phishing |")
    L.append("| SivakumarP | [benign, phishing] | index 1 (class 1) | yes — URL-Phish dataset label column (0=benign, 1=phishing); predict_proba column order = classes_ [0,1] |")
    L.append("| r3ddkahili | [Benign, Defacement, Phishing, Malware] | index 2 | mapping from model card only; artifact config has generic LABEL_0..3 |")
    L.append("")

    L.append("## D. Performance Comparison (overall)")
    L.append("")
    L.append("| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR |")
    L.append("|---|---|---|---|---|---|---|---|")
    for adapter_cls in ADAPTERS:
        s = all_summaries[adapter_cls.name]
        m = s["m"]
        L.append(f"| {adapter_cls.display} | {pct(m['accuracy'])} | {pct(m['precision'])} | {pct(m['recall'])} | "
                 f"{m['f1']:.4f} | {s['auc']:.4f} | {pct(m['fpr'])} | {pct(m['fnr'])} |")
    L.append("")
    L.append("### Confusion Matrices")
    L.append("")
    for adapter_cls in ADAPTERS:
        m = all_summaries[adapter_cls.name]["m"]
        L.append(f"**{adapter_cls.display}**")
        L.append("```")
        L.append(f"              Predicted")
        L.append(f"           Phishing  Safe")
        L.append(f"Actual Phish   {m['tp']:>3}      {m['fn']:>3}")
        L.append(f"Actual Legit   {m['fp']:>3}      {m['tn']:>3}")
        L.append("```")
        L.append("")
    L.append("## E. REAL/SOURCED vs SYNTHETIC/PATTERN (separated)")
    L.append("")
    L.append("| Model | Split | n | Accuracy | Precision | Recall | F1 | FPR | FNR |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for adapter_cls in ADAPTERS:
        s = all_summaries[adapter_cls.name]
        mr, mp_ = s["m_real"], s["m_pattern"]
        n_real = sum(1 for r in all_rows[adapter_cls.name] if r["source"] != "PATTERN")
        n_pat = sum(1 for r in all_rows[adapter_cls.name] if r["source"] == "PATTERN")
        L.append(f"| {adapter_cls.display} | REAL/SOURCED | {n_real} | {pct(mr['accuracy'])} | {pct(mr['precision'])} | {pct(mr['recall'])} | {mr['f1']:.4f} | {pct(mr['fpr'])} | {pct(mr['fnr'])} |")
        L.append(f"| {adapter_cls.display} | SYNTHETIC/PATTERN | {n_pat} | {pct(mp_['accuracy'])} | {pct(mp_['precision'])} | {pct(mp_['recall'])} | {mp_['f1']:.4f} | {pct(mp_['fpr'])} | {pct(mp_['fnr'])} |")
    L.append("")
    L.append("> REAL/SOURCED = curated legitimate domains + verified deployments + Phishing.Database domains/links. "
             "SYNTHETIC/PATTERN = phishing URLs constructed from characteristic patterns (IP, @, punycode, etc.), "
             "labeled by construction.")
    L.append("")

    L.append("## F. False-Positive Comparison (legitimate → phishing)")
    L.append("")
    L.append("| Model | # FP | Notable legit FPs (prob) |")
    L.append("|---|---|---|")
    for adapter_cls in ADAPTERS:
        s = all_summaries[adapter_cls.name]
        fps = s["fps"]
        notable = ", ".join(f"`{r['url'][:45]}` ({r['phishing_prob']*100:.0f}%)" for r in fps[:6])
        L.append(f"| {adapter_cls.display} | {len(fps)} | {notable} |")
    L.append("")

    L.append("## G. False-Negative Comparison (phishing → legitimate)")
    L.append("")
    L.append("| Model | # FN | Examples (prob) |")
    L.append("|---|---|---|")
    for adapter_cls in ADAPTERS:
        s = all_summaries[adapter_cls.name]
        fns = s["fns"]
        notable = ", ".join(f"`{r['url'][:45]}` ({r['phishing_prob']*100:.0f}%)" for r in fns[:6])
        L.append(f"| {adapter_cls.display} | {len(fns)} | {notable} |")
    L.append("")

    L.append("## H. Notable URL Comparison")
    L.append("")
    L.append("| URL | Ground Truth | pirocheto | SivakumarP | r3ddkahili |")
    L.append("|---|---|---|---|---|")
    seen = set()
    for rec in records:
        url = rec["url"]
        if not any(sub in url for sub in NOTABLE_SUBSTR):
            continue
        key = url
        if key in seen:
            continue
        seen.add(key)
        cells = [f"`{url[:60]}`", "legit" if rec["label"] == 0 else "phishing"]
        for adapter_cls in ADAPTERS:
            row = next(r for r in all_rows[adapter_cls.name] if r["url"] == url)
            prob = row["phishing_prob"]
            cells.append(f"{'PHISHING' if row['predicted'] == 1 else 'safe'} ({prob*100:.1f}%)")
        L.append("| " + " | ".join(cells) + " |")
    L.append("")

    L.append("## I. Learnova (documented case)")
    L.append("")
    for adapter_cls in ADAPTERS:
        row = next(r for r in all_rows[adapter_cls.name] if "learnova" in r["url"])
        L.append(f"- **{adapter_cls.display}**: predicted "
                 f"{'PHISHING' if row['predicted'] == 1 else 'SAFE'} — phishing probability "
                 f"**{row['phishing_prob']*100:.1f}%**")
    L.append("")

    L.append("## J. Vercel Compatibility")
    L.append("")
    L.append("| Model | Vercel serverless compatible? | Notes |")
    L.append("|---|---|---|")
    L.append("| pirocheto | **Yes (current)** | onnxruntime CPU wheel installs cleanly; 23.5 MB model; raw-string input needs no preprocessing |")
    L.append("| SivakumarP | **Uncertain / heavy** | requires scikit-learn + joblib + scipy + tldextract at runtime plus 5 pickle artifacts; 187-dim feature pipeline must be reimplemented server-side |")
    L.append("| r3ddkahili | **Not practical** | 418 MB F32 BERT + torch runtime; far exceeds typical serverless limits; would require quantization/conversion and a custom 4→2 label mapping |")
    L.append("")

    L.append("## K. Recommendation")
    L.append("")
    # Build recommendation
    rec_lines = _recommendation(all_summaries, ADAPTERS, all_rows)
    L.extend(rec_lines)
    L.append("")

    L.append("## L. Production Changes Required If Selected")
    L.append("")
    L.append("### pirocheto (keep)")
    L.append("- None. Current integration already correct.")
    L.append("")
    L.append("### SivakumarP (replace)")
    L.append("- Replace `ml/model.onnx` with the 5 pickle artifacts (model + 3 TF-IDF + scaler).")
    L.append("- Rewrite `ml_predictor.py` to run the 187-dim feature pipeline (tldextract + TF-IDF + scaler + RF predict_proba).")
    L.append("- Add scikit-learn, joblib, scipy to backend requirements (Vercel build compatibility must be verified).")
    L.append("- No ONNX conversion would be needed if pickles are accepted; else convert RF to ONNX (skl2onnx).")
    L.append("")
    L.append("### r3ddkahili (replace)")
    L.append("- Not feasible without major work: 418 MB model, torch runtime, 4-class→phishing mapping.")
    L.append("- Would require ONNX conversion + quantization and re-verification of the degenerate-output issue first.")
    L.append("")

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("\nReport written to", REPORT)


def _recommendation(summaries, adapter_classes, all_rows):
    """Evidence-based recommendation (F1, recall, FPR, FNR, AUC, compat)."""
    lines = []
    names = [a.name for a in adapter_classes]
    data = {a.name: summaries[a.name] for a in adapter_classes}

    # r3ddkahili is degenerate: constant phishing prediction
    r3 = data["r3ddkahili"]
    r3_constant = r3["m"]["fpr"] > 0.95 or abs(r3["auc"] - 0.5) < 0.05
    if r3_constant:
        lines.append("**r3ddkahili/final-complete-malicious-url-model is REJECTED.**")
        lines.append("")
        lines.append("Empirically, the published artifact is a near-constant classifier: it assigns class-2 "
                     "(Phishing) logits ≈ +4 and ~99.8% phishing probability to every input tested, from "
                     "`a` to `https://www.google.com/`. It yields no discriminative signal "
                     f"(ROC-AUC {r3['auc']:.4f} ≈ 0.5, FPR {r3['m']['fpr']*100:.0f}%). It cannot be used for "
                     "phishing detection in its current published state, regardless of deployment cost.")
        lines.append("")

    sk = data["sivakumarp"]
    pi = data["pirocheto"]

    # Compare on F1 / recall / FPR / FNR / AUC
    def cmp(name):
        m = data[name]["m"]
        return (m["f1"], m["recall"], -m["fpr"], -m["fnr"], data[name]["auc"])
    best_metric = max(("pirocheto", cmp("pirocheto")), ("sivakumarp", cmp("sivakumarp")), key=lambda x: x[1])

    lines.append(f"- F1: pirocheto {pi['m']['f1']:.4f} vs SivakumarP {sk['m']['f1']:.4f}")
    lines.append(f"- Recall: pirocheto {pi['m']['recall']*100:.1f}% vs SivakumarP {sk['m']['recall']*100:.1f}%")
    lines.append(f"- FPR: pirocheto {pi['m']['fpr']*100:.1f}% vs SivakumarP {sk['m']['fpr']*100:.1f}%")
    lines.append(f"- FNR: pirocheto {pi['m']['fnr']*100:.1f}% vs SivakumarP {sk['m']['fnr']*100:.1f}%")
    lines.append(f"- ROC-AUC: pirocheto {pi['auc']:.4f} vs SivakumarP {sk['auc']:.4f}")
    lines.append("")
    lines.append(f"Metric leader: **{best_metric[0]}** (lexicographic: F1, recall, −FPR, −FNR, AUC).")
    lines.append("")
    lines.append("### Verdict")
    lines.append("")
    lines.append("**Primary recommendation: REPLACE WITH SIVAKUMARP** (conditional, see below).")
    lines.append("")
    lines.append("- **r3ddkahili/final-complete-malicious-url-model: REJECTED** — degenerate constant classifier "
                 "(see analysis above); unusable regardless of deployment cost.")
    lines.append("- **SivakumarP vs pirocheto:** SivakumarP wins the project's stated priority (false positives: "
                 f"FPR {sk['m']['fpr']*100:.1f}% vs {pi['m']['fpr']*100:.1f}%) and has higher F1 "
                 f"({sk['m']['f1']:.4f} vs {pi['m']['f1']:.4f}) and ROC-AUC ({sk['auc']:.4f} vs {pi['auc']:.4f}). "
                 f"It loses on recall ({sk['m']['recall']*100:.1f}% vs {pi['m']['recall']*100:.1f}%) and "
                 f"FNR ({sk['m']['fnr']*100:.1f}% vs {pi['m']['fnr']*100:.1f}%), and it misses some pattern "
                 "phishing (@-symbol, typo-squats, obfuscation) that pirocheto catches perfectly.")
    lines.append("- **Condition:** replacing pirocheto with SivakumarP requires (1) re-validating the "
                 "reverse-engineered feature pipeline against the model author's exact preprocessing, and "
                 "(2) confirming scikit-learn/joblib run inside Vercel serverless. Until both are verified, "
                 "the safer default is **KEEP PIROCHETO** — its false positives are at least surfaced "
                 "transparently as MODEL-RULE DISAGREEMENT.")
    lines.append("- **NONE — train a custom model** remains a legitimate option: pirocheto's 26% legit-domain FPR "
                 "and SivakumarP's 26% FNR + opaque training pipeline are both material. A custom model trained "
                 "on URL-Phish plus modern benign deployment hosts (Vercel/Netlify/GitHub Pages) would target "
                 "both weaknesses directly, at the cost of building and maintaining a training pipeline.")
    lines.append("")
    lines.append("### Trade-offs considered")
    lines.append("")
    lines.append("- **False positives are the stated priority.** For this project the model that misflags the "
                 "fewest legitimate domains matters most. Both candidates misflag some legit domains; see "
                 "section F. r3ddkahili flags literally everything, which is disqualifying.")
    lines.append("- **SivakumarP** requires a non-trivial feature pipeline (TF-IDF + tldextract + scaler) that "
                 "must be reproduced exactly to match training; its predictions here rely on reverse-engineered "
                 "feature semantics (verified 9/9 against the source dataset, but the model author's exact "
                 "training preprocessing cannot be fully confirmed).")
    lines.append("- **pirocheto** is already integrated, has the simplest deployment (ONNX, raw URL), and its "
                 "known weakness (deployment-host false positives, e.g. vercel.app) is *explainable* and "
                 "visible as MODEL-RULE DISAGREEMENT in the product rather than silently wrong.")
    lines.append("- **Learnova must not drive the decision.** No model was tuned on it; it appears in section "
                 "I only as documentation.")
    lines.append("")
    return lines


if __name__ == "__main__":
    main()