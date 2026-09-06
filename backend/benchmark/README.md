# Model Benchmark Pipeline

Reproducible evaluation of the current ONNX model (`../ml/model.onnx`,
pirocheto/phishing-url-detection) **outside** the production scan path.

## Files

| File | Purpose |
|---|---|
| `build_dataset.py` | Builds the frozen `dataset.json` (needs network for Phishing.Database). |
| `dataset.json` | Frozen evaluation dataset (committed state; no network needed to evaluate). |
| `evaluate.py` | Runs the baseline pirocheto model over the dataset, computes metrics, writes `results.csv` + `report.md`. |
| `results.csv` | Per-record predictions: URL, ground truth, predicted label, safe/phishing probabilities. |
| `report.md` | Full baseline metrics report. |
| `adapters.py` | Isolated inference adapters for pirocheto, SivakumarP, r3ddkahili. |
| `compare_models.py` | Three-model comparison on the same dataset → `comparison_report.md`. |
| `comparison_report.md` | Architecture/input/metrics/FN/FP comparison + recommendation. |
| `comparison_results/` | Per-model per-record CSVs from the comparison run. |
| `models/` | Downloaded candidate artifacts (sivakumarp pickles, r3ddkahili safetensors + tokenizer). |
| `sivakumar_predictor.py` | Standalone production-style predictor (raw URL → full pipeline). |
| `vercel_test_sivakumar.py` | Isolated ASGI test endpoint (local FastAPI/TestClient). |
| `compatibility_report.md` | Production compatibility gate results. |
| `vercel_probe/` | Self-contained deployable probe project (deployed live for the Vercel gate). |
| `_phishing_domains_raw.txt` / `_phishing_links_raw.txt` / `_url_phish_sample.csv` | Downloaded raw sources (kept for provenance/reproducibility). |

## Usage

```bash
python benchmark/build_dataset.py   # optional rebuild (requires network)
python benchmark/evaluate.py        # baseline pirocheto eval (no network)
python benchmark/compare_models.py  # three-model comparison (no network)

# Live Vercel gate (probe project already deployed):
#   https://vercelprobe-two.vercel.app/api/benchmark/sivakumar/test?url=<url>
cd benchmark/vercel_probe && vercel deploy --prod   # re-deploy the probe if needed
```

## Design decisions

- **No production code is touched.** The pipeline imports only `onnxruntime` +
  `numpy` and loads `ml/model.onnx` directly. Nothing is fetched over the
  network during inference — URL strings only.
- **Labels are not fabricated.** Legitimate URLs are real public domains
  (RFC 2606 examples, major tech/banking/government/media/SaaS). Deployment
  URLs (Vercel/Netlify/GitHub Pages) are verified to resolve over HTTPS
  before inclusion. Phishing URLs are sampled from the public
  mitchellkrogza/Phishing.Database. A small set of `PATTERN` URLs (IP-hosted,
  `@`-symbol, punycode, obfuscation) is labeled phishing *by construction*
  and explicitly marked as such in `dataset.json`.
- **Metrics are computed with numpy only**: accuracy, precision, recall,
  F1, FPR, FNR, confusion matrix, and ROC-AUC via the tie-safe
  Mann–Whitney U statistic (independently verified against a brute-force
  O(n²) AUC). The comparison run needs scikit-learn/joblib (SivakumarP) and
  torch/transformers (r3ddkahili), which are isolated to the venv.
- **Candidate pipelines were reverse-engineered, not assumed.** SivakumarP's
  dom/tld feature semantics were verified 9/9 against the original URL-Phish
  Dataset.csv (Mendeley 65z9twcx3r); r3ddkahili's 4-class mapping comes from
  its model card. Both are documented in `adapters.py` and the report.
- **Known findings:** the r3ddkahili artifact behaves as a near-constant
  classifier (class-2 logits ≈ +4 for every input tested); see the
  comparison report before considering it.
- **Fixed seed (42)** so sampling is deterministic; `dataset.json` is frozen
  so re-running evaluation always produces identical numbers.
- **Train/test separation:** this pipeline performs no training. The
  pirocheto model's original corpus is unknown, so the dataset deliberately
  includes modern SaaS and deployment hosts to probe generalization.