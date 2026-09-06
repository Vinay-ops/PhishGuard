"""
Isolated Benchmark Adapters
===========================
Thin wrappers that let the comparison script run each candidate model over
the frozen dataset. Each adapter exposes:

    predict(url: str) -> dict
        {"predicted_label": int (1=phishing, 0=legit),
         "phishing_prob": float (0-1),
         "detail": dict with model-specific extra info}

Adapters load models lazily and are completely independent of the production
scan path (services/, app/, database/).

Models
------
1. PirochetoOnnxAdapter  — pirocheto/phishing-url-detection (ONNX, raw URL)
2. SivakumarPRFAdapter   — SivakumarP/PhishingURLDetection (RandomForest on
                           TF-IDF(url, dom, tld) + scaled(digit_cnt, is_https))
3. R3ddkahiliBertAdapter — r3ddkahili/final-complete-malicious-url-model
                           (BERT 4-class; phishing = class 2 per model card)
"""

import os

import joblib
import numpy as np
import tldextract
from scipy import sparse

HERE = os.path.dirname(os.path.abspath(__file__))
ONNX_PATH = os.path.join(os.path.dirname(HERE), "ml", "model.onnx")
SIVAKUMARP_DIR = os.path.join(HERE, "models", "sivakumarp")
R3DDKAHILI_DIR = os.path.join(HERE, "models", "r3ddkahili")


# ---------------------------------------------------------------------------
# 1. pirocheto/phishing-url-detection (ONNX, raw URL string)
# ---------------------------------------------------------------------------

class PirochetoOnnxAdapter:
    """Current production baseline. Input: raw URL string."""

    name = "pirocheto"
    display = "pirocheto/phishing-url-detection"
    input_format = "raw URL string"
    architecture = "ONNX text classifier (char/word model, internals opaque)"
    classes = {0: "safe", 1: "phishing"}

    def __init__(self):
        import onnxruntime as ort
        self.session = ort.InferenceSession(ONNX_PATH, providers=["CPUExecutionProvider"])
        self.input_name = self.session.get_inputs()[0].name

    def predict(self, url: str) -> dict:
        inputs = np.array([url.strip()], dtype=np.str_)
        raw = self.session.run(None, {self.input_name: inputs})
        results = dict(zip([o.name for o in self.session.get_outputs()], raw))
        probs = np.asarray(results["probabilities"], dtype=float)
        label = int(np.asarray(results["label"]).reshape(-1)[0])
        return {
            "predicted_label": 1 if label == 1 else 0,
            "phishing_prob": float(probs[0, 1]),
            "detail": {"raw_label": label},
        }


# ---------------------------------------------------------------------------
# 2. SivakumarP/PhishingURLDetection (RandomForest on engineered features)
# ---------------------------------------------------------------------------

class SivakumarPRFAdapter:
    """
    RandomForest classifier trained on the URL-Phish dataset.

    Feature pipeline (verified against the URL-Phish dataset columns):
        - TF-IDF (char, ngram 1-1, lowercase) of the full URL string
        - TF-IDF (char, ngram 1-1, lowercase) of the *registered domain*
        - TF-IDF (char, ngram 1-1, lowercase) of the *public suffix* (TLD)
        - StandardScaler([digit_cnt, is_https])
      concatenated into a single 187-dim vector.

    dom/tld semantics verified against the original URL-Phish Dataset.csv:
        https://sites.google.com/...  -> dom="google.com"   tld="com"
        https://www.google.co.uk/     -> dom="google.co.uk" tld="co.uk"
        http://202.194.232.100:8005/  -> dom="202.194.232.100" tld=""
      which is exactly tldextract(registered_domain, suffix).

    Class mapping: classes_ = [0, 1], 0 = benign, 1 = phishing
    (URL-Phish label column: 0 = benign, 1 = phishing).
    """

    name = "sivakumarp"
    display = "SivakumarP/PhishingURLDetection"
    input_format = "feature vector: TF-IDF(url, dom, tld) + scaled(digit_cnt, is_https)"
    architecture = "RandomForest (100 trees, gini, max_depth=32) + TF-IDF + StandardScaler"
    classes = {0: "benign", 1: "phishing"}

    def __init__(self):
        self.model = joblib.load(os.path.join(SIVAKUMARP_DIR, "model.pkl"))
        self.enc_url = joblib.load(os.path.join(SIVAKUMARP_DIR, "dataencoder_url.pkl"))
        self.enc_dom = joblib.load(os.path.join(SIVAKUMARP_DIR, "dataencoder_dom.pkl"))
        self.enc_tld = joblib.load(os.path.join(SIVAKUMARP_DIR, "dataencoder_tld.pkl"))
        self.scaler = joblib.load(os.path.join(SIVAKUMARP_DIR, "datascaler.pkl"))

    @staticmethod
    def _extract(url: str):
        ext = tldextract.extract(url)
        dom = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        tld = ext.suffix
        digit_cnt = sum(c.isdigit() for c in url)
        is_https = 1 if url.startswith("https") else 0
        return url, dom, tld, digit_cnt, is_https

    def predict(self, url: str) -> dict:
        url_s, dom, tld, digit_cnt, is_https = self._extract(url)
        u = self.enc_url.transform([url_s])
        d = self.enc_dom.transform([dom])
        t = self.enc_tld.transform([tld])
        n = self.scaler.transform([[digit_cnt, is_https]])
        X = sparse.hstack([u, d, t, sparse.csr_matrix(n)]).tocsr()
        proba = self.model.predict_proba(X)[0]
        phish = float(proba[1])
        return {
            "predicted_label": 1 if phish >= 0.5 else 0,
            "phishing_prob": phish,
            "detail": {
                "dom": dom, "tld": tld,
                "digit_cnt": digit_cnt, "is_https": is_https,
                "p_benign": float(proba[0]),
            },
        }


# ---------------------------------------------------------------------------
# 3. r3ddkahili/final-complete-malicious-url-model (BERT, 4 classes)
# ---------------------------------------------------------------------------

class R3ddkahiliBertAdapter:
    """
    Fine-tuned BERT-LoRA classifier (4 classes). Per the model card:
        {0: Benign, 1: Defacement, 2: Phishing, 3: Malware}
    Phishing probability = softmax(logits)[2].

    NOTE: empirical inspection (Sep 2026) shows this artifact behaves as a
    near-constant classifier — class 2 logits ≈ +4 for every input tested,
    including 'a' and 'google.com'. It is benchmarked as-is to document this.
    """

    name = "r3ddkahili"
    display = "r3ddkahili/final-complete-malicious-url-model"
    input_format = "raw URL string (BERT tokenizer, max_length=128)"
    architecture = "BertForSequenceClassification (bert-base-uncased, 110M), 4 classes"
    label_map = {0: "Benign", 1: "Defacement", 2: "Phishing", 3: "Malware"}

    def __init__(self):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self.torch = torch
        self.tokenizer = AutoTokenizer.from_pretrained(R3DDKAHILI_DIR)
        self.model = AutoModelForSequenceClassification.from_pretrained(R3DDKAHILI_DIR)
        self.model.eval()

    def predict(self, url: str) -> dict:
        torch = self.torch
        inputs = self.tokenizer(
            url, return_tensors="pt", truncation=True, padding=True, max_length=128
        )
        with torch.no_grad():
            logits = self.model(**inputs).logits
        probs = torch.softmax(logits, dim=-1)[0]
        pred = int(logits.argmax().item())
        phish_prob = float(probs[2])
        any_malicious = 1.0 - float(probs[0])
        return {
            "predicted_label": 1 if pred == 2 else 0,
            "phishing_prob": phish_prob,
            "detail": {
                "argmax_class": pred,
                "class_name": self.label_map.get(pred, "?"),
                "probs": [round(float(p), 6) for p in probs.tolist()],
                "any_malicious_prob": any_malicious,
            },
        }


ADAPTERS = [PirochetoOnnxAdapter, SivakumarPRFAdapter, R3ddkahiliBertAdapter]