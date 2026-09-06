# Model Benchmark Report

**MODEL:** pirocheto/phishing-url-detection
**Model file:** `ml/model.onnx`
**Dataset built:** 2026-09-06T15:20:33.686602+00:00 (seed 42)

## Dataset

- Number of legitimate URLs: **114**
- Number of phishing URLs: **96**
- Total: **210**

### Sources

- Phishing.Database (mitchellkrogza) - phishing-domains-ACTIVE.txt
- Phishing.Database (mitchellkrogza) - phishing-links-ACTIVE.txt
- Curated legitimate domains (RFC 2606 + major public sites)
- PATTERN phishing URLs (labeled by construction)

> The pirocheto model's original training corpus is unknown; the dataset intentionally includes modern SaaS and deployment hosts to probe generalization. PATTERN URLs are synthetic phishing samples labeled by construction, never contacted by the evaluation.

## Overall Metrics

| Metric | Value |
|---|---|
| Accuracy | 77.14% |
| Precision (phishing-positive) | 72.22% |
| Recall (phishing-positive) | 81.25% |
| F1-score | 0.7647 |
| ROC-AUC | 0.8646 |
| False Positive Rate | 26.32% |
| False Negative Rate | 18.75% |

## Confusion Matrix

```
                 Predicted
              Phishing   Safe
Actual Phishing    78         18
Actual Legit       30         84
```

- TP = 78, FP = 30, TN = 84, FN = 18

## Metrics by URL Category

| Category | n | Accuracy | Precision | Recall | F1 | FPR | FNR |
|---|---|---|---|---|---|---|---|
| at | 3 | 100.00% | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% |
| impersonation | 2 | 100.00% | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% |
| ip | 4 | 100.00% | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% |
| keyword | 3 | 100.00% | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% |
| legit | 114 | 73.68% | 0.00% | 0.00% | 0.0000 | 26.32% | 0.00% |
| long | 2 | 100.00% | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% |
| obfuscation | 3 | 100.00% | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% |
| phishing | 72 | 75.00% | 100.00% | 75.00% | 0.8571 | 0.00% | 25.00% |
| port | 2 | 100.00% | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% |
| punycode | 3 | 100.00% | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% |
| subdomain | 2 | 100.00% | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% |

## Deployment Host Breakdown (legit Vercel/Netlify/GitHub)

| Host | n | False Positives |
|---|---|---|
| GitHub | 7 | 0 |
| Netlify | 8 | 5 |
| Vercel | 11 | 8 |

### Netlify — flagged legit deployments

- `https://app.netlify.com/` — phishing prob 99.4%
- `https://svelte.netlify.app/` — phishing prob 99.4%
- `https://decapcms.netlify.app/` — phishing prob 99.3%
- `https://gohugo.netlify.app/` — phishing prob 99.0%
- `https://docs.netlify.com/` — phishing prob 90.4%

### Vercel — flagged legit deployments

- `https://vercel.app/` — phishing prob 97.0%
- `https://svelte.vercel.app/` — phishing prob 96.7%
- `https://hugo.vercel.app/` — phishing prob 96.5%
- `https://examples.vercel.app/` — phishing prob 92.1%
- `https://vercel.com/docs` — phishing prob 91.9%
- `https://vercel.com/` — phishing prob 89.0%
- `https://learnova-ai-8.vercel.app/` — phishing prob 88.9%
- `https://create-next-app.vercel.app/` — phishing prob 87.4%

## Notable False Positives (legit predicted as phishing)

| URL | Ground Truth | Predicted | Phishing Prob | Category |
|---|---|---|---|---|
| `https://paypal.me/` | legit | phishing | 99.70% | legit |
| `https://paypal.com/` | legit | phishing | 99.68% | legit |
| `https://app.netlify.com/` | legit | phishing | 99.41% | legit |
| `https://svelte.netlify.app/` | legit | phishing | 99.38% | legit |
| `https://decapcms.netlify.app/` | legit | phishing | 99.28% | legit |
| `https://gohugo.netlify.app/` | legit | phishing | 98.97% | legit |
| `https://outlook.live.com/` | legit | phishing | 98.48% | legit |
| `https://vercel.app/` | legit | phishing | 96.99% | legit |
| `https://svelte.vercel.app/` | legit | phishing | 96.74% | legit |
| `https://hugo.vercel.app/` | legit | phishing | 96.51% | legit |
| `https://mail.google.com/` | legit | phishing | 95.25% | legit |
| `https://examples.vercel.app/` | legit | phishing | 92.08% | legit |
| `https://vercel.com/docs` | legit | phishing | 91.87% | legit |
| `https://docs.netlify.com/` | legit | phishing | 90.35% | legit |
| `https://vercel.com/` | legit | phishing | 88.96% | legit |
| `https://learnova-ai-8.vercel.app/` | legit | phishing | 88.92% | legit |
| `https://create-next-app.vercel.app/` | legit | phishing | 87.43% | legit |
| `https://www.paypal.com/` | legit | phishing | 82.47% | legit |
| `https://kubernetes.io/` | legit | phishing | 81.46% | legit |
| `https://drive.google.com/` | legit | phishing | 80.35% | legit |
| `https://raw.githubusercontent.com/` | legit | phishing | 78.82% | legit |
| `https://aws.amazon.com/` | legit | phishing | 68.26% | legit |
| `https://search.yahoo.com/` | legit | phishing | 65.59% | legit |
| `https://www.bankofamerica.com/` | legit | phishing | 64.04% | legit |
| `https://crates.io/` | legit | phishing | 61.45% | legit |
| `https://support.microsoft.com/` | legit | phishing | 58.16% | legit |
| `https://medium.com/` | legit | phishing | 57.54% | legit |
| `https://x.com/` | legit | phishing | 56.50% | legit |
| `https://duckduckgo.com/` | legit | phishing | 56.34% | legit |
| `https://example.net/` | legit | phishing | 54.72% | legit |

## False Negatives (phishing predicted as legit)

| URL | Ground Truth | Predicted | Phishing Prob | Category |
|---|---|---|---|---|
| `https://codashop-eventnew08.duckdns.org/` | phishing | legit | 17.51% | phishing |
| `http://savingclubhome.com/afcu/domain` | phishing | legit | 18.47% | phishing |
| `https://toagad.com/` | phishing | legit | 19.77% | phishing |
| `https://north-ring-pin.glitch.me/` | phishing | legit | 24.94% | phishing |
| `https://ronda-est.com/` | phishing | legit | 25.57% | phishing |
| `https://hello-world-throbbing-heart-b2fd.derzuteydo.workers.dev/` | phishing | legit | 26.66% | phishing |
| `https://legal-associate.com/` | phishing | legit | 26.78% | phishing |
| `https://intro-trezorbridgedownload.pages.dev/` | phishing | legit | 26.87% | phishing |
| `https://imtoken-etc.pro/` | phishing | legit | 27.59% | phishing |
| `https://hasszda.duckdns.org/` | phishing | legit | 29.30% | phishing |
| `https://wefrgbtre.blogspot.com/` | phishing | legit | 30.12% | phishing |
| `https://freefireeventy7.duckdns.org/` | phishing | legit | 32.77% | phishing |
| `https://meta-law-kyc.buzz/` | phishing | legit | 35.26% | phishing |
| `https://help-center424.crabdance.com/` | phishing | legit | 36.37% | phishing |
| `https://mediafire-firal-234.duckdns.org/` | phishing | legit | 39.54% | phishing |
| `https://business-poste.life` | phishing | legit | 41.47% | phishing |
| `https://boatsandshores.com/` | phishing | legit | 43.11% | phishing |
| `https://event-codashop70.duckdns.org/` | phishing | legit | 46.42% | phishing |

## Learnova Deployment (documented case)

- URL: `https://learnova-ai-8.vercel.app/`
- Ground truth (benchmark): **legitimate** (user's own Vercel deployment)
- Predicted label: **phishing**
- Phishing probability: **88.9%**
- Safe probability: **11.1%**

This is a model prediction, not independent evidence. The model assigns a high phishing probability to this deployment host pattern; the production risk engine reports it as MODEL-RULE DISAGREEMENT because no URL rules trigger.

## Reproducibility

```bash
# 1. Rebuild the frozen dataset (requires network for Phishing.Database)
python benchmark/build_dataset.py
# 2. Re-run evaluation against dataset.json (no network needed)
python benchmark/evaluate.py
```

Full per-record predictions: `benchmark/results.csv`
