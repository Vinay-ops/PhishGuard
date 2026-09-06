# SivakumarP — LIVE Vercel Compatibility Test Report

**Date:** 2026-09-06
**Probe URL:** https://vercelprobe-two.vercel.app
**Probe project:** `vercel_probe` (new, isolated Vercel project — production PhishGuard app untouched)
**Deploy:** Python 3.12 (default), uv installer, bundle **246.77 MB** (auto-optimized), ready in 32–43 s

Endpoints (live):
- `GET /api/benchmark/sivakumar/ping`
- `GET /api/benchmark/sivakumar/test?url=<url>`

---

## VERCEL COMPATIBILITY: **PASS**

| Check | Result |
|---|---|
| Model loading | **PASS** — `model_load_status: OK`, all 5 artifacts loaded |
| sklearn InconsistentVersionWarning | **None possible** — live runtime reports `sklearn_version: 1.8.0`, exactly matching the serializer version (pinned in requirements.txt) |
| Missing artifact errors | **None** — model + 3 TF-IDF + scaler all load |
| scipy/numpy import errors | **None** — live ping reports scipy 1.15.3, numpy 2.2.6 |
| tldextract network dependency | **None** — registered_domain/public_suffix extracted on live with bundled PSL snapshot (offline-safe) |
| Filesystem write requirement | **None** — read-only model load |
| Timeout | **None** — every request returned HTTP 200; worst (cold) 1.82 s |
| Memory error | **None** |
| Serverless bundle-size error | **None** — 246.77 MB < 500 MB standard Python limit; Vercel optimized deps automatically |
| Inference | **PASS** — warm ~11 ms per request in-handler |

## Prediction Comparison (local benchmark vs live)

| URL | Local | Live | Match |
|---|---|---|---|
| https://learnova-ai-8.vercel.app/ | 54.0000% | 54.0000% | **exact** |
| https://www.google.com/ | 13.0000% | 13.0000% | **exact** |
| https://example.com/ | 30.0191% | 30.0191% | **exact** |
| https://github.com/ | 32.0378% | 32.0378% | **exact** |
| https://paypal.com/ | 45.0026% | 45.0026% | **exact** |

All five predictions are bit-identical between the live Vercel function (sklearn 1.8.0, Python 3.12) and the local venv (sklearn 1.7.2, Python 3.10). No meaningful difference to investigate.

## Timing

| Metric | Value |
|---|---|
| **Cold start** (true, fresh instance after re-deploy, first request) | **1.82 s end-to-end** (TTFB 1.817 s); handler model load **1148 ms** + first inference ~100 ms |
| **Warm inference** (in-handler, after load) | **~11 ms** |
| **Warm request total** (curl end-to-end) | ~0.27–0.49 s (Vercel platform + network overhead) |
| **Response status** | HTTP 200 on every request |

Note: warm in-handler `model_load_ms` = 0.02 ms — the module-level predictor singleton persists per Lambda instance, so the ~1.15 s unpickle cost is paid once per cold instance only.

## Bundle / Dependency Status

Pinned in `benchmark/vercel_probe/requirements.txt` (verified live via /ping):
- `scikit-learn==1.8.0` (matches pickled serializer — no warning)
- `joblib==1.6.0`, `scipy==1.15.3`, `numpy==2.2.6`
- `tldextract==5.3.2` (bundled PSL snapshot)
- `fastapi==0.141.1`, `uvicorn==0.52.4`

Bundle ≈ 246.77 MB (deps ~213 MB + artifacts ~30 MB) — fits the 500 MB standard Python limit with ~250 MB headroom.

## Any warnings
None. The single residual operational note (not a failure): cold instances pay ~1.15 s model-unpickle + sklearn import; on Vercel this is absorbed into the ~1.8 s cold request and does not affect warm traffic. If it ever matters, Vercel Large/Fluid compute or keeping an instance warm would remove it.

---

## FINAL: **SAFE TO INTEGRATE**

The live Vercel test passed every check: model loads, predictions reproduce bit-for-bit, no version/serialization/network/filesystem issues, bundle fits comfortably, no timeouts or memory errors, and warm inference is ~11 ms.

Per instruction, the production model (`backend/ml/model.onnx`) was **NOT** replaced and no production behavior was modified. The isolated probe project (`vercel_probe`, aliased `vercelprobe-two.vercel.app`) remains deployed for independent verification and can be removed with `vercel remove vercel_probe --yes`.

Next step (out of scope for this gate, awaiting your go): production integration of the SivakumarP predictor with `scikit-learn==1.8.0` pinned, following `compatibility_report.md` section J.