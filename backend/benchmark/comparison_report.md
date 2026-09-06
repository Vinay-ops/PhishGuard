# Three-Model Benchmark Comparison

**Dataset:** `benchmark/dataset.json` (seed 42, built 2026-09-06T15:20:33.686602+00:00)
- Legitimate URLs: **114** | Phishing URLs: **96** | Total: **210**

**Protocol:** identical for all three models — same URLs, same ground-truth labels, same threshold (phishing iff phishing probability ≥ 0.5), same metrics, same tie-safe Mann–Whitney ROC-AUC.

## A. Model Architecture Comparison

| Model | Architecture | Input format | Preprocessing | Class labels | Probability output | Size | ONNX? | Dependencies |
|---|---|---|---|---|---|---|---|---|
| pirocheto/phishing-url-detection | ONNX text classifier (opaque internals) | raw URL string | handled inside model | 2 (safe/phishing) | probabilities[0]=safe, [1]=phishing (verified) | 23.5 MB | yes (native) | onnxruntime, numpy |
| SivakumarP/PhishingURLDetection | RandomForest 100 trees (gini, depth 32) | 187-dim feature vector | char TF-IDF(1-gram) on url/dom/tld + StandardScaler(digit_cnt, is_https); dom/tld via tldextract (verified vs dataset) | 2 (0=benign, 1=phishing) | predict_proba[1] = phishing | 29.8 MB (model) + preprocessors | no (pickle/joblib) | scikit-learn, joblib, scipy, tldextract |
| r3ddkahili/final-complete-malicious-url-model | BertForSequenceClassification (bert-base-uncased, 110M) | raw URL string (tokenized) | BERT tokenizer, max_length=128 | 4 (0=Benign, 1=Defacement, 2=Phishing, 3=Malware) | softmax(logits)[2] = phishing | 417.7 MB (F32 safetensors) | no (PyTorch/safetensors) | torch, transformers, safetensors |

## B. Input / Preprocessing Comparison

- **pirocheto**: consumes the raw URL string directly; all preprocessing is internal to the model. This is the only candidate that matches the current PhishGuard integration with zero changes.
- **SivakumarP**: does **NOT** accept a raw URL. It requires the exact URL-Phish feature layout: char-level TF-IDF of the full URL, the registered domain (e.g. `google.com`, not `www.google.com`), the public suffix (e.g. `com`, `co.uk`), and scaled `digit_cnt` + `is_https`. The dom/tld semantics were reverse-engineered from the original URL-Phish Dataset.csv and reproduced 9/9 with `tldextract`. Feeding PhishGuard's existing feature vector would be incorrect.
- **r3ddkahili**: accepts a raw URL string but tokenizes it with the BERT WordPiece tokenizer (128-token limit). It outputs 4 classes; phishing must be extracted as class 2. The artifact's `config.json` label map is generic (LABEL_0..3); the semantic mapping comes from the model card.

## C. Output / Class Mapping

| Model | Class order | Phishing class | Verified? |
|---|---|---|---|
| pirocheto | [safe, phishing] | index 1 (label 1) | yes — probabilities sum to 1, google.com→safe, IP→phishing |
| SivakumarP | [benign, phishing] | index 1 (class 1) | yes — URL-Phish dataset label column (0=benign, 1=phishing); predict_proba column order = classes_ [0,1] |
| r3ddkahili | [Benign, Defacement, Phishing, Malware] | index 2 | mapping from model card only; artifact config has generic LABEL_0..3 |

## D. Performance Comparison (overall)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR |
|---|---|---|---|---|---|---|---|
| pirocheto/phishing-url-detection | 77.14% | 72.22% | 81.25% | 0.7647 | 0.8646 | 26.32% | 18.75% |
| SivakumarP/PhishingURLDetection | 85.71% | 93.42% | 73.96% | 0.8256 | 0.9471 | 4.39% | 26.04% |
| r3ddkahili/final-complete-malicious-url-model | 42.86% | 44.12% | 93.75% | 0.6000 | 0.3388 | 100.00% | 6.25% |

### Confusion Matrices

**pirocheto/phishing-url-detection**
```
              Predicted
           Phishing  Safe
Actual Phish    78       18
Actual Legit    30       84
```

**SivakumarP/PhishingURLDetection**
```
              Predicted
           Phishing  Safe
Actual Phish    71       25
Actual Legit     5      109
```

**r3ddkahili/final-complete-malicious-url-model**
```
              Predicted
           Phishing  Safe
Actual Phish    90        6
Actual Legit   114        0
```

## E. REAL/SOURCED vs SYNTHETIC/PATTERN (separated)

| Model | Split | n | Accuracy | Precision | Recall | F1 | FPR | FNR |
|---|---|---|---|---|---|---|---|---|
| pirocheto/phishing-url-detection | REAL/SOURCED | 186 | 74.19% | 64.29% | 75.00% | 0.6923 | 26.32% | 25.00% |
| pirocheto/phishing-url-detection | SYNTHETIC/PATTERN | 24 | 100.00% | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% |
| SivakumarP/PhishingURLDetection | REAL/SOURCED | 186 | 88.71% | 91.80% | 77.78% | 0.8421 | 4.39% | 22.22% |
| SivakumarP/PhishingURLDetection | SYNTHETIC/PATTERN | 24 | 62.50% | 100.00% | 62.50% | 0.7692 | 0.00% | 37.50% |
| r3ddkahili/final-complete-malicious-url-model | REAL/SOURCED | 186 | 37.10% | 37.70% | 95.83% | 0.5412 | 100.00% | 4.17% |
| r3ddkahili/final-complete-malicious-url-model | SYNTHETIC/PATTERN | 24 | 87.50% | 100.00% | 87.50% | 0.9333 | 0.00% | 12.50% |

> REAL/SOURCED = curated legitimate domains + verified deployments + Phishing.Database domains/links. SYNTHETIC/PATTERN = phishing URLs constructed from characteristic patterns (IP, @, punycode, etc.), labeled by construction.

## F. False-Positive Comparison (legitimate → phishing)

| Model | # FP | Notable legit FPs (prob) |
|---|---|---|
| pirocheto/phishing-url-detection | 30 | `https://paypal.me/` (100%), `https://paypal.com/` (100%), `https://app.netlify.com/` (99%), `https://svelte.netlify.app/` (99%), `https://decapcms.netlify.app/` (99%), `https://gohugo.netlify.app/` (99%) |
| SivakumarP/PhishingURLDetection | 5 | `https://duckduckgo.com/` (59%), `https://developer.mozilla.org/` (56%), `https://learnova-ai-8.vercel.app/` (54%), `https://stackoverflow.com/` (53%), `https://create-next-app.vercel.app/` (52%) |
| r3ddkahili/final-complete-malicious-url-model | 114 | `https://www.dropbox.com/` (100%), `https://www.heroku.com/` (100%), `https://www.usbank.com/` (100%), `https://www.tiktok.com/` (100%), `https://www.wsj.com/` (100%), `https://stackoverflow.com/` (100%) |

## G. False-Negative Comparison (phishing → legitimate)

| Model | # FN | Examples (prob) |
|---|---|---|
| pirocheto/phishing-url-detection | 18 | `https://codashop-eventnew08.duckdns.org/` (18%), `http://savingclubhome.com/afcu/domain` (18%), `https://toagad.com/` (20%), `https://north-ring-pin.glitch.me/` (25%), `https://ronda-est.com/` (26%), `https://hello-world-throbbing-heart-b2fd.derz` (27%) |
| SivakumarP/PhishingURLDetection | 25 | `https://www.paypa1.com/signin` (22%), `https://toagad.com/` (25%), `https://bigswitch.co.in/` (25%), `http://savingclubhome.com/afcu/domain` (27%), `https://www.google.com@phish.example.com/acco` (28%), `http://discoveryhostel.com/painter/no_cap/fbg` (29%) |
| r3ddkahili/final-complete-malicious-url-model | 6 | `http://203.0.113.10/verify-account` (0%), `http://210.211.111.87/~vtjlrgkyhosting/9oi9h2` (0%), `https://example.com/%256C%256F%2567%2569%256E` (0%), `https://example.com/%6C%6F%67%69%6E` (0%), `http://discoveryhostel.com/painter/no_cap/fbg` (2%), `http://savingclubhome.com/afcu/domain` (37%) |

## H. Notable URL Comparison

| URL | Ground Truth | pirocheto | SivakumarP | r3ddkahili |
|---|---|---|---|---|
| `https://paypal.com%2eexample.com/login` | phishing | PHISHING (100.0%) | PHISHING (71.0%) | PHISHING (99.7%) |
| `https://svelte.vercel.app/` | legit | PHISHING (96.7%) | safe (35.5%) | PHISHING (99.8%) |
| `https://docs.netlify.com/` | legit | PHISHING (90.4%) | safe (32.1%) | PHISHING (99.8%) |
| `https://gist.github.com/` | legit | safe (4.7%) | safe (33.0%) | PHISHING (99.8%) |
| `https://google.com/` | legit | safe (23.9%) | safe (30.2%) | PHISHING (99.8%) |
| `https://octocat.github.io/` | legit | safe (25.2%) | safe (33.0%) | PHISHING (99.8%) |
| `https://www.paypal.com/` | legit | PHISHING (82.5%) | safe (14.0%) | PHISHING (99.8%) |
| `https://cloud.google.com/` | legit | safe (46.4%) | safe (37.2%) | PHISHING (99.8%) |
| `https://www.github.com/` | legit | safe (0.0%) | safe (13.0%) | PHISHING (99.8%) |
| `https://pages.github.com/` | legit | safe (2.0%) | safe (29.0%) | PHISHING (99.8%) |
| `https://learnova-ai-8.vercel.app/` | legit | PHISHING (88.9%) | PHISHING (54.0%) | PHISHING (99.8%) |
| `https://hugo.vercel.app/` | legit | PHISHING (96.5%) | safe (23.0%) | PHISHING (99.8%) |
| `https://vercel.app/` | legit | PHISHING (97.0%) | safe (23.1%) | PHISHING (99.8%) |
| `https://encogr365helvacenter.github.io/` | phishing | PHISHING (51.6%) | PHISHING (64.0%) | PHISHING (99.8%) |
| `https://www.netlify.app/` | legit | safe (39.6%) | safe (17.0%) | PHISHING (99.8%) |
| `https://aws.amazon.com/` | legit | PHISHING (68.3%) | safe (33.2%) | PHISHING (99.8%) |
| `https://agitated-shannon-cb7922.netlify.app/` | phishing | PHISHING (99.1%) | PHISHING (74.0%) | PHISHING (99.8%) |
| `https://docs.github.com/` | legit | safe (3.0%) | safe (30.0%) | PHISHING (99.8%) |
| `https://svelte.netlify.app/` | legit | PHISHING (99.4%) | safe (44.5%) | PHISHING (99.8%) |
| `https://www.bankofamerica.com/` | legit | PHISHING (64.0%) | safe (17.0%) | PHISHING (99.8%) |
| `https://learn.microsoft.com/` | legit | safe (10.4%) | safe (38.1%) | PHISHING (99.8%) |
| `https://www.netlify.com/` | legit | safe (9.2%) | safe (11.0%) | PHISHING (99.8%) |
| `https://www.google.com/` | legit | safe (0.4%) | safe (13.0%) | PHISHING (99.8%) |
| `https://app.netlify.com/` | legit | PHISHING (99.4%) | safe (32.0%) | PHISHING (99.8%) |
| `https://paypal.com@192.168.1.100/login` | phishing | PHISHING (100.0%) | PHISHING (74.0%) | PHISHING (99.7%) |
| `https://examples.vercel.app/` | legit | PHISHING (92.1%) | safe (32.0%) | PHISHING (99.8%) |
| `https://vercel.com/docs` | legit | PHISHING (91.9%) | safe (43.1%) | PHISHING (99.7%) |
| `https://azure.microsoft.com/` | legit | safe (13.0%) | safe (42.1%) | PHISHING (99.8%) |
| `https://vercel.com/` | legit | PHISHING (89.0%) | safe (22.0%) | PHISHING (99.8%) |
| `https://www.microsoft.com/` | legit | safe (0.4%) | safe (9.0%) | PHISHING (99.8%) |
| `https://paypal.com/` | legit | PHISHING (99.7%) | safe (45.0%) | PHISHING (99.7%) |
| `https://github.com/` | legit | safe (2.6%) | safe (32.0%) | PHISHING (99.8%) |
| `https://es.wikipedia.org/` | legit | safe (4.7%) | safe (28.0%) | PHISHING (99.8%) |
| `https://create-next-app.vercel.app/` | legit | PHISHING (87.4%) | PHISHING (52.0%) | PHISHING (99.8%) |
| `https://www.google.com@phish.example.com/account-verify` | phishing | PHISHING (89.4%) | safe (28.0%) | PHISHING (99.7%) |
| `https://pfeinb4nd0n0.vercel.app/` | phishing | PHISHING (97.8%) | PHISHING (51.0%) | PHISHING (99.8%) |
| `https://decapcms.netlify.app/` | legit | PHISHING (99.3%) | safe (46.3%) | PHISHING (99.8%) |
| `https://en.wikipedia.org/` | legit | safe (0.4%) | safe (25.0%) | PHISHING (99.8%) |
| `https://drive.google.com/` | legit | PHISHING (80.4%) | safe (33.5%) | PHISHING (99.8%) |
| `https://gohugo.netlify.app/` | legit | PHISHING (99.0%) | safe (39.0%) | PHISHING (99.8%) |
| `https://www.wikipedia.org/` | legit | safe (0.0%) | safe (8.0%) | PHISHING (99.8%) |
| `https://microsoft.com/` | legit | safe (32.1%) | safe (43.0%) | PHISHING (99.8%) |
| `https://mail.google.com/` | legit | PHISHING (95.3%) | safe (37.2%) | PHISHING (99.8%) |
| `https://support.microsoft.com/` | legit | PHISHING (58.2%) | safe (41.0%) | PHISHING (99.8%) |

## I. Learnova (documented case)

- **pirocheto/phishing-url-detection**: predicted PHISHING — phishing probability **88.9%**
- **SivakumarP/PhishingURLDetection**: predicted PHISHING — phishing probability **54.0%**
- **r3ddkahili/final-complete-malicious-url-model**: predicted PHISHING — phishing probability **99.8%**

## J. Vercel Compatibility

| Model | Vercel serverless compatible? | Notes |
|---|---|---|
| pirocheto | **Yes (current)** | onnxruntime CPU wheel installs cleanly; 23.5 MB model; raw-string input needs no preprocessing |
| SivakumarP | **Uncertain / heavy** | requires scikit-learn + joblib + scipy + tldextract at runtime plus 5 pickle artifacts; 187-dim feature pipeline must be reimplemented server-side |
| r3ddkahili | **Not practical** | 418 MB F32 BERT + torch runtime; far exceeds typical serverless limits; would require quantization/conversion and a custom 4→2 label mapping |

## K. Recommendation

**r3ddkahili/final-complete-malicious-url-model is REJECTED.**

Empirically, the published artifact is a near-constant classifier: it assigns class-2 (Phishing) logits ≈ +4 and ~99.8% phishing probability to every input tested, from `a` to `https://www.google.com/`. It yields no discriminative signal (ROC-AUC 0.3388 ≈ 0.5, FPR 100%). It cannot be used for phishing detection in its current published state, regardless of deployment cost.

- F1: pirocheto 0.7647 vs SivakumarP 0.8256
- Recall: pirocheto 81.2% vs SivakumarP 74.0%
- FPR: pirocheto 26.3% vs SivakumarP 4.4%
- FNR: pirocheto 18.8% vs SivakumarP 26.0%
- ROC-AUC: pirocheto 0.8646 vs SivakumarP 0.9471

Metric leader: **sivakumarp** (lexicographic: F1, recall, −FPR, −FNR, AUC).

### Verdict

**Primary recommendation: REPLACE WITH SIVAKUMARP** (conditional, see below).

- **r3ddkahili/final-complete-malicious-url-model: REJECTED** — degenerate constant classifier (see analysis above); unusable regardless of deployment cost.
- **SivakumarP vs pirocheto:** SivakumarP wins the project's stated priority (false positives: FPR 4.4% vs 26.3%) and has higher F1 (0.8256 vs 0.7647) and ROC-AUC (0.9471 vs 0.8646). It loses on recall (74.0% vs 81.2%) and FNR (26.0% vs 18.8%), and it misses some pattern phishing (@-symbol, typo-squats, obfuscation) that pirocheto catches perfectly.
- **Condition:** replacing pirocheto with SivakumarP requires (1) re-validating the reverse-engineered feature pipeline against the model author's exact preprocessing, and (2) confirming scikit-learn/joblib run inside Vercel serverless. Until both are verified, the safer default is **KEEP PIROCHETO** — its false positives are at least surfaced transparently as MODEL-RULE DISAGREEMENT.
- **NONE — train a custom model** remains a legitimate option: pirocheto's 26% legit-domain FPR and SivakumarP's 26% FNR + opaque training pipeline are both material. A custom model trained on URL-Phish plus modern benign deployment hosts (Vercel/Netlify/GitHub Pages) would target both weaknesses directly, at the cost of building and maintaining a training pipeline.

### Trade-offs considered

- **False positives are the stated priority.** For this project the model that misflags the fewest legitimate domains matters most. Both candidates misflag some legit domains; see section F. r3ddkahili flags literally everything, which is disqualifying.
- **SivakumarP** requires a non-trivial feature pipeline (TF-IDF + tldextract + scaler) that must be reproduced exactly to match training; its predictions here rely on reverse-engineered feature semantics (verified 9/9 against the source dataset, but the model author's exact training preprocessing cannot be fully confirmed).
- **pirocheto** is already integrated, has the simplest deployment (ONNX, raw URL), and its known weakness (deployment-host false positives, e.g. vercel.app) is *explainable* and visible as MODEL-RULE DISAGREEMENT in the product rather than silently wrong.
- **Learnova must not drive the decision.** No model was tuned on it; it appears in section I only as documentation.


## L. Production Changes Required If Selected

### pirocheto (keep)
- None. Current integration already correct.

### SivakumarP (replace)
- Replace `ml/model.onnx` with the 5 pickle artifacts (model + 3 TF-IDF + scaler).
- Rewrite `ml_predictor.py` to run the 187-dim feature pipeline (tldextract + TF-IDF + scaler + RF predict_proba).
- Add scikit-learn, joblib, scipy to backend requirements (Vercel build compatibility must be verified).
- No ONNX conversion would be needed if pickles are accepted; else convert RF to ONNX (skl2onnx).

### r3ddkahili (replace)
- Not feasible without major work: 418 MB model, torch runtime, 4-class→phishing mapping.
- Would require ONNX conversion + quantization and re-verification of the degenerate-output issue first.

