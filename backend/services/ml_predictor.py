"""
ML Predictor
============
ONNX-based phishing URL detection using the pirocheto/phishing-url-detection model.

Model information:
    - Model: pirocheto/phishing-url-detection
    - Source: https://huggingface.co/pirocheto/phishing-url-detection
    - Type: ONNX classifier (the artifact does not expose model metadata)
    - Input: URL strings directly (model handles preprocessing internally)
        - Output labels: 0 = SAFE, 1 = PHISHING (artifact contract verified by
            output shape and repository model documentation)
        - Output probabilities: [safe_probability, phishing_probability]

The model accepts raw URL strings and handles all preprocessing internally.
No manual feature engineering is required for ML inference.

Security: Never loads pickle files, never fetches URLs from the network.
"""

import os
from typing import Optional

import numpy as np

from app.core.config import MODEL_PATH

# Path to the ONNX model relative to this file's directory.
_MODEL_PATH = os.path.abspath(MODEL_PATH)

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
        _model_load_error = f"ML model file not found at {_MODEL_PATH}"
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
            "predicted_label": None,
            "phishing_probability": None,
            "safe_probability": None,
            "model_status": "UNAVAILABLE",
            "error": _model_load_error or "ML model not loaded",
        }

    try:
        if not isinstance(url, str) or not url.strip():
            raise ValueError("URL must be a non-empty string.")

        input_name = _session.get_inputs()[0].name
        output_names = [output.name for output in _session.get_outputs()]
        if len(output_names) < 2:
            raise ValueError("ML model must expose label and probability outputs.")

        # The verified artifact accepts a one-dimensional string tensor.
        inputs = np.array([url.strip()], dtype=np.str_)

        # Run inference.
        # Model I/O (verified by inspection):
        #   Input:  "inputs"     -> tensor(string), shape [None]
        #   Output: "label"      -> tensor(int64),  shape [None]        (0=safe, 1=phishing)
        #   Output: "probabilities" -> tensor(float), shape [None, 2]   ([safe_prob, phishing_prob])
        raw_results = _session.run(None, {input_name: inputs})
        results = dict(zip(output_names, raw_results))

        labels = np.asarray(results.get("label"))
        probability_values = np.asarray(results.get("probabilities"), dtype=float)
        if labels.size < 1 or probability_values.shape != (1, 2):
            raise ValueError("ML model returned an unexpected output shape.")

        label = int(labels.reshape(-1)[0])
        safe_prob = float(probability_values[0, 0])
        phishing_prob = float(probability_values[0, 1])
        if not all(np.isfinite(value) for value in (safe_prob, phishing_prob)):
            raise ValueError("ML model returned non-finite probabilities.")
        if min(safe_prob, phishing_prob) < 0 or max(safe_prob, phishing_prob) > 1:
            raise ValueError("ML model returned probabilities outside 0-1.")

        # The artifact's output contract is class 0 = safe and class 1 =
        # phishing. Use the predicted label, while returning the actual
        # probability columns rather than treating a decision score as one.
        if label not in (0, 1):
            raise ValueError(f"ML model returned unknown class label: {label}")
        prediction = "PHISHING" if label == 1 else "SAFE"

        return {
            "available": True,
            "prediction": prediction,
            "predicted_label": prediction,
            "phishing_probability": round(phishing_prob, 4),
            "safe_probability": round(safe_prob, 4),
            "model_name": "pirocheto/phishing-url-detection",
            "model_status": "AVAILABLE",
        }

    except Exception as exc:
        return {
            "available": False,
            "prediction": None,
            "predicted_label": None,
            "phishing_probability": None,
            "safe_probability": None,
            "model_status": "UNAVAILABLE",
            "error": f"ML inference failed: {exc}",
        }


def get_model_info() -> dict:
    """Return basic information about the loaded ML model."""
    _load_model()
    return {
        "model_name": "pirocheto/phishing-url-detection",
            "model_type": "ONNX classifier",
            "input": "Raw URL string",
            "output": "Class label and safe/phishing probabilities",
        "available": _model_loaded and _session is not None and _model_load_error is None,
        "error": _model_load_error,
    }
