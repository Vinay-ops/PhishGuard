"""
ML Predictor
============
ONNX-based phishing URL detection using the pirocheto/phishing-url-detection model.

Model information:
    - Model: pirocheto/phishing-url-detection
    - Source: https://huggingface.co/pirocheto/phishing-url-detection
    - Type: LinearSVM (exported to ONNX)
    - Input: URL strings directly (model handles preprocessing internally)
    - Output labels: 0 = SAFE, 1 = PHISHING
    - Output probabilities: [safe_probability, phishing_probability]

The model accepts raw URL strings and handles all preprocessing internally.
No manual feature engineering is required for ML inference.

Security: Never loads pickle files, never fetches URLs from the network.
"""

import os
from typing import Optional

import numpy as np

# Path to the ONNX model relative to this file's directory.
_MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "ml")
_MODEL_PATH = os.path.join(_MODEL_DIR, "model.onnx")

# Module-level model reference (loaded once, reused across requests).
_session = None
_model_loaded = False
_model_load_error: Optional[str] = None


def _load_model():
    """Load the ONNX model once and cache the inference session."""
    global _session, _model_loaded, _model_load_error

    if _model_loaded:
        return

    if not os.path.isfile(_MODEL_PATH):
        _model_load_error = "ML model file not found at ml/model.onnx"
        _model_loaded = True  # Mark as attempted so we don't retry
        return

    try:
        import onnxruntime as ort
        _session = ort.InferenceSession(
            _MODEL_PATH,
            providers=["CPUExecutionProvider"],
        )
        _model_loaded = True
    except ImportError:
        _model_load_error = (
            "ONNX Runtime is not installed. "
            "Install with: pip install onnxruntime"
        )
        _model_loaded = True
    except Exception as exc:
        _model_load_error = f"Failed to load ML model: {exc}"
        _model_loaded = True


def predict_url(url: str) -> dict:
    """
    Run ML inference on a URL string.

    The ONNX model accepts raw URL strings and handles all preprocessing
    internally (it was trained on URL character sequences).

    Parameters:
        url: The URL string to classify.

    Returns:
        If model is available:
            {
                "available": True,
                "prediction": "SAFE" | "PHISHING",
                "phishing_probability": float,   # 0.0 to 1.0
                "safe_probability": float,       # 0.0 to 1.0
                "model_name": "pirocheto/phishing-url-detection",
            }
        If model is unavailable:
            {
                "available": False,
                "prediction": None,
                "phishing_probability": None,
                "safe_probability": None,
                "error": "<reason>",
            }
    """
    _load_model()

    # Model is not available.
    if _model_load_error or not _model_loaded or _session is None:
        return {
            "available": False,
            "prediction": None,
            "phishing_probability": None,
            "safe_probability": None,
            "error": _model_load_error or "ML model not loaded",
        }

    try:
        # Prepare input: model expects a numpy array of URL strings.
        inputs = np.array([url.strip()], dtype="str")

        # Run inference.
        # Model I/O (verified by inspection):
        #   Input:  "inputs"     -> tensor(string), shape [None]
        #   Output: "label"      -> tensor(int64),  shape [None]        (0=safe, 1=phishing)
        #   Output: "probabilities" -> tensor(float), shape [None, 2]   ([safe_prob, phishing_prob])
        results = _session.run(None, {"inputs": inputs})

        # Extract probabilities.
        probabilities = results[1][0]  # First (only) URL, shape [2]
        safe_prob = float(probabilities[0])
        phishing_prob = float(probabilities[1])

        # Determine prediction label.
        # Label 0 = SAFE, Label 1 = PHISHING (verified from model output).
        prediction = "PHISHING" if phishing_prob >= 0.5 else "SAFE"

        return {
            "available": True,
            "prediction": prediction,
            "phishing_probability": round(phishing_prob, 4),
            "safe_probability": round(safe_prob, 4),
            "model_name": "pirocheto/phishing-url-detection",
        }

    except Exception as exc:
        return {
            "available": False,
            "prediction": None,
            "phishing_probability": None,
            "safe_probability": None,
            "error": f"ML inference failed: {exc}",
        }


def get_model_info() -> dict:
    """Return basic information about the loaded ML model."""
    _load_model()
    return {
        "model_name": "pirocheto/phishing-url-detection",
        "model_type": "LinearSVM (ONNX)",
        "available": _model_loaded and _session is not None and _model_load_error is None,
        "error": _model_load_error,
    }
