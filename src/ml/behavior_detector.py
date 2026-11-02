"""Security Behavior Analytics: Machine Learning (Isolation Forest) & Rule-Based Baseline.

Detects anomalous issuer activity (burst issuance, brute-force takeover, privilege escalation)
without replacing cryptographic verification or automatically deleting documents.
"""
import os
import pickle
import logging
from pathlib import Path
from typing import Any
from .feature_extractor import FEATURE_NAMES, explain_features

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "models"
DEFAULT_MODEL_PATH = MODEL_DIR / "isolation_forest.pkl"


class RuleBasedBaseline:
    """
    Deterministic rule-based anomaly detector serving as the academic baseline.
    Flags sessions exceeding hard threshold rules.
    """

    @staticmethod
    def evaluate(feature_vector: list[float]) -> dict[str, Any]:
        """
        Evaluate a feature vector against static security rules.
        Returns:
            {
                "is_anomalous": bool,
                "risk_score": float (0-100),
                "risk_level": str ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
                "reasons": list[str],
                "method": "RULE_BASED_BASELINE"
            }
        """
        if len(feature_vector) < 6:
            return {
                "is_anomalous": False,
                "risk_score": 0.0,
                "risk_level": "LOW",
                "reasons": ["Thiếu đặc trưng"],
                "method": "RULE_BASED_BASELINE"
            }

        login_fails, issue_burst, revoke_burst, access_denied, off_hours, velocity = feature_vector[:6]
        reasons = []
        score = 10.0  # Base normal score

        if login_fails >= 5:
            reasons.append(f"Quy tắc RB-01: Đăng nhập thất bại vượt ngưỡng ({int(login_fails)} >= 5)")
            score += 40.0
        elif login_fails >= 3:
            score += 20.0

        if issue_burst >= 10:
            reasons.append(f"Quy tắc RB-02: Tần suất phát hành tài liệu tăng đột biến ({int(issue_burst)} >= 10)")
            score += 45.0
        elif issue_burst >= 6:
            score += 20.0

        if revoke_burst >= 4:
            reasons.append(f"Quy tắc RB-03: Thu hồi tài liệu hàng loạt ({int(revoke_burst)} >= 4)")
            score += 40.0

        if access_denied >= 3:
            reasons.append(f"Quy tắc RB-04: Cố gắng truy cập trái phép vượt ngưỡng ({int(access_denied)} >= 3)")
            score += 35.0

        if off_hours >= 0.7 and (issue_burst > 2 or login_fails > 1):
            reasons.append("Quy tắc RB-05: Thao tác nhạy cảm tập trung ngoài giờ làm việc")
            score += 25.0

        risk_score = min(100.0, score)
        is_anomalous = len(reasons) > 0 or risk_score >= 65.0

        if risk_score >= 85.0:
            risk_level = "CRITICAL"
        elif risk_score >= 70.0:
            risk_level = "HIGH"
        elif risk_score >= 40.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "is_anomalous": is_anomalous,
            "risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "reasons": reasons if reasons else ["Hoạt động trong giới hạn an toàn"],
            "method": "RULE_BASED_BASELINE"
        }


class IsolationForestDetector:
    """
    Unsupervised Anomaly Detection using Isolation Forest.
    Learns normal multi-dimensional behavioral boundaries and scores unseen outliers.
    """

    def __init__(self, model_path: Path | str = DEFAULT_MODEL_PATH):
        self.model_path = Path(model_path)
        self.model = None
        self.baseline = RuleBasedBaseline()
        self.load_model()

    def load_model(self) -> bool:
        """Load trained Isolation Forest model from disk if available."""
        if not SKLEARN_AVAILABLE:
            logging.warning("⚠️  [ML] scikit-learn không khả dụng. Sử dụng Rule-Based Baseline làm fallback.")
            return False

        if self.model_path.exists():
            try:
                with open(self.model_path, "rb") as f:
                    data = pickle.load(f)
                    if isinstance(data, dict) and "model" in data:
                        self.model = data["model"]
                    else:
                        self.model = data
                return True
            except Exception as e:
                logging.warning(f"⚠️  [ML] Không thể nạp mô hình từ {self.model_path}: {e}")
                self.model = None
        return False

    def predict(self, feature_vector: list[float]) -> dict[str, Any]:
        """
        Predict whether a feature vector is anomalous using Isolation Forest.
        Gracefully falls back to Rule-Based Baseline if model is not loaded.
        """
        if not SKLEARN_AVAILABLE or self.model is None:
            # Explicit fallback
            result = self.baseline.evaluate(feature_vector)
            result["fallback_active"] = True
            return result

        try:
            X = np.array([feature_vector], dtype=float)
            # Isolation Forest decision_function: higher = normal, lower (negative) = anomaly
            raw_score = float(self.model.decision_function(X)[0])
            pred_label = int(self.model.predict(X)[0])  # 1: normal, -1: anomaly
            is_anomalous = (pred_label == -1)

            # Map decision function to Risk Score [0, 100]
            # Typically raw_score is in [-0.5, 0.5]
            # More negative -> higher risk
            normalized_risk = max(0.0, min(100.0, (0.25 - raw_score) * 150.0))

            if normalized_risk >= 85.0:
                risk_level = "CRITICAL"
            elif normalized_risk >= 70.0:
                risk_level = "HIGH"
            elif normalized_risk >= 40.0:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            explanations = explain_features(feature_vector)

            return {
                "is_anomalous": is_anomalous,
                "risk_score": round(normalized_risk, 1),
                "raw_decision_score": round(raw_score, 4),
                "risk_level": risk_level,
                "reasons": explanations,
                "method": "ISOLATION_FOREST_ML",
                "fallback_active": False
            }
        except Exception as exc:
            logging.error(f"❌ [ML] Lỗi suy luận Isolation Forest: {exc}")
            result = self.baseline.evaluate(feature_vector)
            result["fallback_active"] = True
            return result

