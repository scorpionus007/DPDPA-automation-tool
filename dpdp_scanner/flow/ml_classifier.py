"""
ML-based flow validity classifier.

Uses a feature vector from multiple evidence signals (symbol tracking, taint,
consent proximity, path heuristics) to classify flows as valid/invalid.

Ships with a calibrated rule-based model by default; can optionally train
a scikit-learn model if labeled data is available.
"""

from __future__ import annotations

import json
import math
import os
from typing import Any, Dict, List, Optional, Tuple

try:
    import numpy as np
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.calibration import CalibratedClassifierCV
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

MODEL_PATH = os.path.join(os.path.dirname(__file__), "flow_model.json")


def build_feature_vector(evidence: Dict[str, Any]) -> List[float]:
    """
    Build a fixed-length feature vector from flow evidence signals.

    Features (14-dimensional):
    0: symbol_continuity_score (0-1)
    1: taint_reached_sink (0/1)
    2: taint_confidence (0-1)
    3: taint_total_events (0+, clipped to 10)
    4: consent_found_at_sink (0/1)
    5: consent_purpose_specific (0/1)
    6: consent_proximity_score (0-1)
    7: hop_count (0+, clipped to 8)
    8: sink_type_is_analytics (0/1)
    9: sink_type_is_marketing (0/1)
    10: sink_type_is_logging (0/1)
    11: pii_field_count (0+, clipped to 10)
    12: path_length (0+, clipped to 8)
    13: sink_call_arg_pii_count (0+, clipped to 5)
    """
    def _g(key: str, default: float = 0.0) -> float:
        v = evidence.get(key, default)
        if isinstance(v, bool):
            return 1.0 if v else 0.0
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

    sink_type = str(evidence.get("sink_type", "")).lower()

    return [
        _g("symbol_continuity_score"),
        1.0 if evidence.get("taint_reached_sink") else 0.0,
        _g("taint_confidence"),
        min(_g("taint_total_events"), 10.0) / 10.0,
        1.0 if evidence.get("consent_found_at_sink") else 0.0,
        1.0 if evidence.get("consent_purpose_specific") else 0.0,
        _g("consent_proximity_score"),
        min(_g("hop_count"), 8.0) / 8.0,
        1.0 if "analytics" in sink_type else 0.0,
        1.0 if "marketing" in sink_type else 0.0,
        1.0 if "log" in sink_type else 0.0,
        min(_g("pii_field_count"), 10.0) / 10.0,
        min(_g("path_length"), 8.0) / 8.0,
        min(_g("sink_call_arg_pii_count"), 5.0) / 5.0,
    ]


class RuleBasedFlowClassifier:
    """
    Calibrated rule-based classifier using weighted feature combination.
    Weights are hand-tuned from analysis of flow evidence patterns.
    """

    WEIGHTS = [
        0.20,   # symbol_continuity
        0.15,   # taint_reached_sink
        0.12,   # taint_confidence
        0.08,   # taint_events
        -0.10,  # consent_found (reduces violation probability)
        -0.05,  # consent_purpose_specific
        -0.08,  # consent_proximity_score
        0.03,   # hop_count (more hops = slightly more suspicious)
        0.05,   # is_analytics
        0.05,   # is_marketing
        0.02,   # is_logging
        0.08,   # pii_field_count
        0.02,   # path_length
        0.12,   # sink_call_arg_pii
    ]

    BIAS = 0.25

    def predict_proba(self, features: List[float]) -> float:
        """Return probability that this flow is a real compliance violation."""
        score = self.BIAS
        for w, f in zip(self.WEIGHTS, features):
            score += w * f
        return 1.0 / (1.0 + math.exp(-5.0 * (score - 0.5)))

    def classify(self, features: List[float], threshold: float = 0.5) -> Tuple[bool, float]:
        """Return (is_violation, probability)."""
        prob = self.predict_proba(features)
        return prob >= threshold, round(prob, 3)


class TrainedFlowClassifier:
    """Scikit-learn based classifier, trainable from labeled data."""

    def __init__(self):
        if not HAS_SKLEARN:
            raise RuntimeError("scikit-learn is required for TrainedFlowClassifier")
        self.model = CalibratedClassifierCV(
            GradientBoostingClassifier(
                n_estimators=100,
                max_depth=4,
                learning_rate=0.1,
                random_state=42,
            ),
            cv=3,
        )
        self._fitted = False

    def train(self, X: List[List[float]], y: List[int]) -> Dict:
        """Train the classifier. X = feature vectors, y = 0/1 labels."""
        X_np = np.array(X)
        y_np = np.array(y)
        self.model.fit(X_np, y_np)
        self._fitted = True
        preds = self.model.predict(X_np)
        accuracy = float(np.mean(preds == y_np))
        return {"accuracy": round(accuracy, 3), "samples": len(y)}

    def predict_proba(self, features: List[float]) -> float:
        if not self._fitted:
            raise RuntimeError("Model not trained yet")
        proba = self.model.predict_proba(np.array([features]))[0]
        return float(proba[1])

    def classify(self, features: List[float], threshold: float = 0.5) -> Tuple[bool, float]:
        prob = self.predict_proba(features)
        return prob >= threshold, round(prob, 3)

    def save(self, path: str | None = None):
        """Save model weights to JSON (simplified serialization)."""
        if not self._fitted:
            raise RuntimeError("Model not trained yet")
        import pickle
        import base64
        data = {
            "type": "sklearn_gbm",
            "model_b64": base64.b64encode(pickle.dumps(self.model)).decode(),
        }
        with open(path or MODEL_PATH, "w") as f:
            json.dump(data, f)

    def load(self, path: str | None = None):
        """Load model from JSON."""
        import pickle
        import base64
        with open(path or MODEL_PATH) as f:
            data = json.load(f)
        self.model = pickle.loads(base64.b64decode(data["model_b64"]))
        self._fitted = True


def get_classifier() -> RuleBasedFlowClassifier | TrainedFlowClassifier:
    """
    Return the best available classifier.
    Uses trained model if available, falls back to rule-based.
    """
    if HAS_SKLEARN and os.path.exists(MODEL_PATH):
        try:
            clf = TrainedFlowClassifier()
            clf.load()
            return clf
        except Exception:
            pass
    return RuleBasedFlowClassifier()


def classify_flow(evidence: Dict[str, Any], threshold: float = 0.5) -> Dict[str, Any]:
    """
    End-to-end flow classification.
    Returns {is_violation, probability, features, classifier_type}.
    """
    features = build_feature_vector(evidence)
    clf = get_classifier()
    is_violation, prob = clf.classify(features, threshold)
    return {
        "is_violation": is_violation,
        "ml_confidence": prob,
        "features": features,
        "classifier_type": type(clf).__name__,
    }
