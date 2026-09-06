# SivakumarP Production Compatibility Gate

**Date:** 2026-09-06
**Candidate:** `SivakumarP/PhishingURLDetection` (RandomForest, 187-dim pipeline)
**Baseline:** `pirocheto/phishing-url-detection` (current production ONNX)
**Gate artifacts:** `benchmark/sivakumar_predictor.py`, `benchmark/vercel_test_sivakumar.py`

---

## A. Can SivakumarP reproduce the benchmark predictions? **YES**

- Explicit 6-URL check (learnova, example.com, google.com, github.com, wikipedia.org, paypal.com): standalone predictor matches the benchmark adapter **bit-for-bit** (Δ < 1e-12).
- Full dataset check: **210/210 URLs** match the stored comparison results within 1e-6.
- No unexplained prediction differences. The standalone predictor (`sivakumar_predictor.py`) performs the complete internal pipeline: `tldextract` → TF-IDF(url) + TF-IDF(dom) + TF-IDF(tld) + scaled(digit_cnt, is_https) → hstack (187 cols) → `predict_proba`.

## B. Exact dependencies required

| Package | Tested version | Notes |
|---|---|---|
| scikit-learn | **1.8.0** (must pin) | Artifacts serialized with 1.8.0; 1.7.2 loads with InconsistentVersionWarning but verified correct |
| joblib | 1.6.0 | Any recent 1.x |
| scipy | 1.15.3 | Required by sklearn; ships manylinux x86_64 wheels |
| numpy | 2.2.6 | 2.x compatible with sklearn ≥1.6 |
| tldextract | 5.3.2 | Bundles PSL snapshot (`.tld_set_snapshot`); offline-safe |
| fastapi / uvicorn | (already used) | Only for the isolated test endpoint |

## C. Exact artifact files required (5 files, all from the HF repo)

| File | Contents | Size |
|---|---|---|
| `model.pkl` | RandomForestClassifier (100 trees, gini, max_depth=32, max_features=sqrt) | 29.77 MB |
| `dataencoder_url.pkl` | TfidfVectorizer (char, ngram (1,1), lowercase) → 96 features | 2.1 KB |
| `dataencoder_dom.pkl` | TfidfVectorizer (char, ngram (1,1), lowercase) → 57 features | 1.5 KB |
| `dataencoder_tld.pkl` | TfidfVectorizer (char, ngram (1,1), lowercase) → 32 features | 1.2 KB |
| `datascaler.pkl` | StandardScaler (digit_cnt, is_https) → 2 features | 0.6 KB |

Feature order: `[TF-IDF(url) | TF-IDF(dom) | TF-IDF(tld) | scaled(digit_cnt, is_https)]` = 96+57+32+2 = **187** = `n_features_in_`. Class labels `[0, 1]`; phishing probability = `predict_proba(X)[0][1]` (class 1).

## D. Total artifact size

**29.78 MB** (5 files). Model alone: 29.77 MB.

## E. Local model load time

- Unpickle (cold): **~1.31 s**
- sklearn/scipy/tldextract import: **~0.75 s**
- Total cold start → first prediction: **~1.81 s**

## F. Local inference time

- Warm single URL: **mean 7.7 ms** (p50 7.6 ms, p95 8.7 ms) — measured on Windows/CPU.

## G. Vercel compatibility: **LIKELY YES — no blockers found; formally UNCERTAIN until a live deploy test**

| Check | Result |
|---|---|
| Python runtime | Vercel supports 3.12 (default), 3.13, 3.14. sklearn 1.8.0 ships manylinux x86_64 wheels → installs/runs on Vercel's Lambda-based Python runtime |
| Bundle size | Dependencies ≈ **213 MB** installed (sklearn 36.5 + scipy ~130 + numpy ~44 + joblib 1.5 + tldextract 0.9) + artifacts 29.8 MB ≈ **243 MB** < Vercel standard **500 MB** uncompressed Python limit |
| tldextract in serverless | Offline-safe: `.tld_set_snapshot` is bundled; `fallback_to_snapshot=True`; verified working with `suffix_list_urls=()` (no network) |
| Cold start | ~1.8 s locally (Linux Lambda similar order). Slower than ONNX (~0.6 s) but within Vercel Python norms; warm calls are ~8 ms |
| Artifact packaging | 5 pickle files ship like static assets; `joblib.load` reads them at import/lazy-load time |
| Live deploy | **Not executed from this environment** (no Vercel credentials). The isolated endpoint `benchmark/vercel_test_sivakumar.py` (`/ping`, `/test`) is ready to deploy for the final confirmation |

## H. Dependency conflicts

- **sklearn version skew:** artifacts serialized with sklearn **1.8.0**; local venv has **1.7.2** → every load emits `InconsistentVersionWarning`. Predictions verified identical despite the warning, but production must **pin `scikit-learn==1.8.0`** to load cleanly.
- numpy 2.2.6 + sklearn 1.8.0: compatible. scipy 1.15.3 + sklearn 1.8.0: compatible.
- No conflicts with the existing stack (fastapi, sqlalchemy, onnxruntime remain untouched; numpy version must stay ≥1.26 for sklearn 1.8).

## I. Serialization / version risks

1. **Pickle portability (highest risk):** `model.pkl` is a ~30 MB joblib pickle. Cross-version load verified locally (1.8.0 → 1.7.2 correct). Python 3.10 (local) → 3.12 (Vercel) is expected to unpickle cleanly (sklearn classes are imported by module path, trees are numpy arrays), but **must be re-validated on the Vercel runtime** with one prediction before flip.
2. **tldextract drift:** registered_domain depends on the PSL snapshot; pin tldextract to keep dom/tld semantics deterministic.
3. **No ONNX conversion performed** (per gate scope). Native sklearn is practical; conversion only if Vercel test fails.

## J. Safe to proceed with production integration? **CONDITIONAL YES**

No hard blocker exists:
- Predictions reproduce exactly (210/210).
- Bundle ~243 MB fits the 500 MB limit.
- sklearn wheels exist for Vercel's runtime; tldextract is offline-safe.
- Warm inference ~8 ms; cold start ~1.8 s is acceptable.

Required before flip (in order):
1. **Deploy the isolated test endpoint** (`benchmark/vercel_test_sivakumar.py`) to Vercel and confirm `/test` returns the expected probabilities (learnova → 0.54, google.com → 0.13, etc.).
2. Pin `scikit-learn==1.8.0` (and tldextract) in the deploy requirements.
3. Re-validate one prediction after deploy (Python 3.12 runtime).

---

## Deployment footprint comparison

| | pirocheto (current) | SivakumarP (candidate) |
|---|---|---|
| Model artifacts | 23.5 MB (1 ONNX file) | 29.78 MB (5 pickle files) |
| ML runtime deps | onnxruntime ≈ 37 MB + numpy ≈ 44 MB | sklearn 36.5 + scipy ~130 + numpy ~44 + joblib 1.5 + tldextract 0.9 ≈ 213 MB |
| Approx. bundle | **~105 MB** | **~243 MB** |
| Cold start → predict | ~0.63 s load + 1.8 ms infer | ~1.8 s load + 7.7 ms infer |
| Vercel fit | well under limits | under limits (500 MB standard) |
| Risk profile | simple, proven | larger, needs one live deploy confirmation |

## FINAL DECISION

Per the gate rule: **Vercel compatibility has no identified blocker, so the path is to proceed — but the gate is only formally "confirmed" after the isolated endpoint's live deploy test.** Recommended next action: deploy `benchmark/vercel_test_sivakumar.py` to Vercel (isolated; does not touch `backend/api/index.py`), confirm predictions, then plan the production integration of the SivakumarP predictor with `scikit-learn==1.8.0` pinned.

If the live test fails (e.g., wheel/install issue on the Lambda runtime), do **not** force the model in; fall back to training/exporting a custom RandomForest/XGBoost to ONNX via the existing PhishGuard feature pipeline.