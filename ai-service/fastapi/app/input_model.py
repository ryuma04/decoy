"""Input-risk model serving (10 §IR): risk 0-1 + attack label for one attacker-typed value."""
import os
import threading

import joblib
import numpy as np

from app.preprocess import decode, extract_payload, is_plain

MODEL_PATH = os.environ.get("INPUT_MODEL_PATH") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "input.joblib")
LABELS = ["normal", "cmd_injection", "sqli", "xss", "path_traversal"]


class InputModel:
    def __init__(self, bundle: dict):
        self.pipe = bundle["pipeline"]
        self.version = bundle["version"]
        self.classes = list(self.pipe.classes_)
        self._feats = self.pipe.named_steps["feats"]
        self._clf = self.pipe.named_steps["clf"]
        self._names = np.array([n.split("__", 1)[1] for n in self._feats.get_feature_names_out()])

    @classmethod
    def load(cls, path: str = MODEL_PATH) -> "InputModel":
        return cls(joblib.load(path))

    def classify(self, value: str) -> dict:
        decoded, was_encoded = decode(value)
        if is_plain(value):
            return {"label": "normal", "risk": 0.0, "scores": {l: (1.0 if l == "normal" else 0.0) for l in LABELS},
                    "top_features": [], "payload": None, "was_encoded": False}
        x = self._feats.transform([value])
        proba = self._clf.predict_proba(x)[0]
        scores = {c: round(float(p), 4) for c, p in zip(self.classes, proba)}
        k = int(proba.argmax())
        label = self.classes[k]
        risk = round(1.0 - scores["normal"], 2)
        return {
            "label": label,
            "risk": risk,
            "scores": {l: scores.get(l, 0.0) for l in LABELS},
            "top_features": self._top_features(x, k) if label != "normal" else [],
            "payload": extract_payload(value) if label == "cmd_injection" else None,
            "was_encoded": was_encoded,
        }

    def _top_features(self, x, k: int, n: int = 5) -> list[str]:
        row = x.tocsr()
        idx, vals = row.indices, row.data
        contrib = vals * self._clf.coef_[k][idx]
        order = np.argsort(-contrib)
        out = []
        for i in order:
            if contrib[i] <= 0 or len(out) == n:
                break
            name = self._names[idx[i]].strip()
            if len(name) >= 2 and name not in out:
                out.append(name)
        return out


_model: InputModel | None = None
_lock = threading.Lock()


def get_model() -> InputModel | None:
    """Lazy singleton; None if the model file is missing (service still serves narration)."""
    global _model
    if _model is None:
        with _lock:
            if _model is None and os.path.exists(MODEL_PATH):
                _model = InputModel.load()
    return _model
