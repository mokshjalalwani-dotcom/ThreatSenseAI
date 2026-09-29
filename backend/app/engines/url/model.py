"""
URL Model — loads the trained XGBoost classifier from disk and runs inference.

Model lifecycle:
  1. ``load_model()`` is called lazily on first inference.
  2. If ``ml/artifacts/url_model/model.joblib`` is absent, the loader returns
     ``None`` and the URLEngine falls back to a transparent rule-based scorer.
  3. The rule-based scorer uses the same feature weights as the model's
     expected top SHAP features, so explanations remain meaningful.

This module NEVER trains — training lives in ``ml/training/train_url_model.py``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Path to the pre-trained model artifact (relative to repo root)
_MODEL_PATH = (
    Path(__file__).resolve().parents[5]  # repo root
    / "ml" / "artifacts" / "url_model" / "model.joblib"
)

_model: Any | None = None          # Lazy-loaded XGBoost / pipeline
_model_loaded: bool = False        # True after first load attempt
_model_version: str = "unknown"


def load_model() -> Any | None:
    """Load and cache the trained URL classifier.

    Returns:
        A sklearn-compatible object with ``.predict_proba()`` or None when
        no model is available (falls back to rule-based scoring).
    """
    global _model, _model_loaded, _model_version

    if _model_loaded:
        return _model

    _model_loaded = True

    if not _MODEL_PATH.exists():
        logger.info(
            "URL model not found at %s — using rule-based fallback. "
            "Run `make train-url-model` to build the real model.",
            _MODEL_PATH,
        )
        return None

    try:
        import joblib

        pipeline = joblib.load(_MODEL_PATH)
        _model = pipeline

        # Try to read model version from companion metadata file
        meta_path = _MODEL_PATH.with_suffix(".meta.json")
        if meta_path.exists():
            import json

            meta = json.loads(meta_path.read_text())
            _model_version = meta.get("version", "unknown")

        logger.info("URL model loaded from %s (version=%s)", _MODEL_PATH, _model_version)
    except Exception as exc:
        logger.error("Failed to load URL model: %s — using rule fallback", exc)
        _model = None

    return _model


def predict_proba(feature_vector: list[float]) -> tuple[float, list[dict]]:
    """Run inference and return (risk_score, shap_features).

    Args:
        feature_vector: Output of ``URLFeatures.to_vector()``.

    Returns:
        Tuple of:
          - risk_score: float in [0, 1] (probability of malicious class)
          - shap_features: list of {name, value, importance} for top-5 features
    """
    from app.engines.url.features import URLFeatures

    feature_names = URLFeatures.feature_names()
    model = load_model()

    if model is not None:
        return _predict_with_model(model, feature_vector, feature_names)
    return _predict_rule_based(feature_vector, feature_names)


def _predict_with_model(
    model: Any,
    vector: list[float],
    feature_names: list[str],
) -> tuple[float, list[dict]]:
    """XGBoost / sklearn pipeline inference with SHAP explanations."""
    import numpy as np

    X = np.array([vector], dtype=float)  # noqa: N806
    try:
        prob = float(model.predict_proba(X)[0, 1])
    except Exception as exc:
        logger.warning("Model predict_proba failed: %s — using rule fallback", exc)
        return _predict_rule_based(vector, feature_names)

    # SHAP explanations
    shap_features: list[dict] = []
    try:
        import shap

        # Get the base estimator if wrapped in CalibratedClassifierCV
        base = model
        if hasattr(model, "calibrated_classifiers_"):
            base = model.calibrated_classifiers_[0].estimator
        elif hasattr(model, "named_steps"):
            last_step = list(model.named_steps.values())[-1]
            if hasattr(last_step, "calibrated_classifiers_"):
                base = last_step.calibrated_classifiers_[0].estimator
            else:
                base = last_step

        explainer = shap.TreeExplainer(base)

        # Pre-process X through any non-final pipeline steps
        X_transformed = X  # noqa: N806
        if hasattr(model, "named_steps") and len(model.named_steps) > 1:
            steps = list(model.named_steps.items())
            for _, step in steps[:-1]:
                X_transformed = step.transform(X_transformed)  # noqa: N806

        shap_vals = explainer.shap_values(X_transformed)
        if isinstance(shap_vals, list):
            shap_vals = shap_vals[1]  # Positive class

        vals = shap_vals[0]
        top_k = sorted(
            enumerate(vals), key=lambda t: abs(t[1]), reverse=True
        )[:5]
        shap_features = [
            {
                "name": feature_names[i] if i < len(feature_names) else f"f{i}",
                "value": round(float(vector[i]), 4),
                "importance": round(float(v), 4),
            }
            for i, v in top_k
        ]
    except Exception:
        pass  # SHAP is best-effort; inference result is still returned

    return prob, shap_features


# ── Rule-based fallback scorer ────────────────────────────────────────────────
# Weights calibrated to approximate model decision boundaries.
# Values > 0 → phishing signal; < 0 → benign signal.

_RULE_WEIGHTS: list[float] = [
    0.004,   # url_length
    0.008,   # domain_length (longer domains more suspicious)
    0.05,    # subdomain_count
    0.002,   # digit_count
    0.005,   # special_char_count
    0.04,    # entropy
    0.03,    # param_count
    0.02,    # path_depth
    -0.15,   # is_https (https = safer, negative weight)
    0.30,    # is_ip_host (big signal)
    0.20,    # has_punycode
    0.06,    # suspicious_token_count
    0.25,    # tld_risk
    0.25,    # has_at_sign
    0.10,    # double_slash_in_path
    0.10,    # has_hex_encoding
    0.15,    # is_shortener
    0.12,    # path_has_exe
    0.05,    # fragment_present
    0.03,    # dash_count
    0.002,   # token_length_max
    0.003,   # dot_count
    0.10,    # has_redirect_param
    0.0,     # domain_age_days (network, often -1 → ignored)
    0.0,     # dns_a_count
    0.0,     # dns_mx_present
    0.0,     # dns_ns_count
    0.0,     # dns_ttl
]

_RULE_BIAS = -0.5  # Logistic offset so score starts near 0.1 for neutral URLs


def _predict_rule_based(
    vector: list[float],
    feature_names: list[str],
) -> tuple[float, list[dict]]:
    """Transparent linear rule-based scorer (used when no model is loaded)."""
    import math

    # Linear combination (skip network features with sentinel -1)
    score = _RULE_BIAS
    contributions: list[tuple[int, float]] = []

    for i, (feat, weight) in enumerate(zip(vector, _RULE_WEIGHTS, strict=False)):
        if feat < 0 and i >= 23:  # Network feature with sentinel
            contrib = 0.0
        else:
            contrib = feat * weight
        contributions.append((i, contrib))
        score += contrib

    # Sigmoid to [0, 1]
    risk = 1.0 / (1.0 + math.exp(-score))
    risk = max(0.0, min(1.0, risk))

    # Top-5 contributing features as "pseudo-SHAP"
    top_k = sorted(contributions, key=lambda t: abs(t[1]), reverse=True)[:5]
    shap_features = [
        {
            "name": feature_names[i] if i < len(feature_names) else f"f{i}",
            "value": round(float(vector[i]), 4),
            "importance": round(float(v), 4),
        }
        for i, v in top_k
    ]

    return risk, shap_features
