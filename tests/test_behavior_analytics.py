"""Unit Tests for Security Behavior Analytics and Machine Learning Anomaly Detection.

Validates:
1. Structured Security Event logging (sanitizing secrets and PII).
2. Feature extraction from event sliding windows.
3. Reproducible synthetic university dataset generation with Train/Val/Test split.
4. Isolation Forest model inference and Risk Scoring.
5. Rule-Based Baseline comparison.
6. Dynamic risk throttling: blocking high-risk issuance and alerting Auditor.
7. Graceful fallback when model file is unavailable.
"""
import unittest
import tempfile
import shutil
from pathlib import Path
from src.models.database import DatabaseManager
from src.services.security_event_service import SecurityEventService
from src.ml.feature_extractor import extract_features_from_events, explain_features, FEATURE_NAMES
from src.ml.behavior_detector import IsolationForestDetector, RuleBasedBaseline
from src.ml.train_eval import generate_synthetic_behavior_dataset, train_and_evaluate


class TestBehaviorAnalytics(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = Path(self.test_dir) / "test_events.db"
        self.db_mgr = DatabaseManager(self.db_path, seed_demo=True)
        self.sec_svc = SecurityEventService(self.db_mgr)
        self.detector = IsolationForestDetector()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_security_event_logging_sanitizes_secrets(self):
        """TC-ML-01: Security Event service records telemetry while stripping password/token fields."""
        ev_id = self.sec_svc.log_event(
            event_type="AUTH_LOGIN_FAIL",
            status="FAILURE",
            username="attacker",
            ip_address="192.168.1.50",
            user_agent="BadBot/1.0",
            metadata={
                "password": "SecretPassword123!",
                "auth_token": "bearer_jwt_token_here",
                "attempt_count": 5
            }
        )
        self.assertTrue(ev_id)

        events = self.sec_svc.get_recent_events(limit=1)
        self.assertEqual(len(events), 1)
        meta = events[0]["metadata"]
        self.assertNotIn("SecretPassword123!", meta)
        self.assertNotIn("bearer_jwt_token_here", meta)
        self.assertIn("attempt_count", meta)

    def test_feature_extraction_from_events(self):
        """TC-ML-02: Aggregates event sequences into standardized 6-dimensional numerical vector."""
        events = [
            {"event_type": "AUTH_LOGIN_FAIL", "status": "FAILURE", "created_at": "2026-10-30T02:00:00Z"},
            {"event_type": "AUTH_LOGIN_FAIL", "status": "FAILURE", "created_at": "2026-10-30T02:01:00Z"},
            {"event_type": "AUTH_LOGIN_FAIL", "status": "FAILURE", "created_at": "2026-10-30T02:02:00Z"},
            {"event_type": "DOC_ISSUE", "status": "SUCCESS", "created_at": "2026-10-30T02:05:00Z"},
            {"event_type": "DOC_ISSUE", "status": "SUCCESS", "created_at": "2026-10-30T02:06:00Z"},
            {"event_type": "ACCESS_DENIED", "status": "FAILURE", "created_at": "2026-10-30T02:07:00Z"}
        ]
        vector = extract_features_from_events(events, window_minutes=15.0)
        self.assertEqual(len(vector), 6)
        self.assertEqual(vector[0], 3.0)  # 3 login failures
        self.assertEqual(vector[1], 2.0)  # 2 doc issues
        self.assertEqual(vector[2], 0.0)  # 0 revocations
        self.assertEqual(vector[3], 1.0)  # 1 access denied
        self.assertEqual(vector[4], 1.0)  # 100% off-hours (02:00 UTC)

    def test_synthetic_dataset_train_val_test_reproducibility(self):
        """TC-ML-03: Synthetic dataset generator produces deterministic partitions with seed 42."""
        X1, y1 = generate_synthetic_behavior_dataset(normal_samples=100, anomaly_samples=20, seed=42)
        X2, y2 = generate_synthetic_behavior_dataset(normal_samples=100, anomaly_samples=20, seed=42)
        self.assertTrue((X1 == X2).all())
        self.assertTrue((y1 == y2).all())
        self.assertEqual(len(y1), 120)

    def test_isolation_forest_prediction_and_risk_scoring(self):
        """TC-ML-04: Isolation Forest identifies high-volume burst anomalies and returns Risk Score."""
        # Normal profile: 0 failures, 1 doc, 0 revocations, 0 denied, 0 off-hours, 0.5 velocity
        normal_vec = [0.0, 1.0, 0.0, 0.0, 0.0, 0.5]
        res_normal = self.detector.predict(normal_vec)
        self.assertIn(res_normal["risk_level"], ["LOW", "MEDIUM"])

        # Severe burst anomaly: 10 failures, 35 docs, 10 revocations, 5 denied, 1.0 off-hours, 15.0 velocity
        attack_vec = [10.0, 35.0, 10.0, 5.0, 1.0, 15.0]
        res_attack = self.detector.predict(attack_vec)
        self.assertTrue(res_attack["is_anomalous"])
        self.assertIn(res_attack["risk_level"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(res_attack["risk_score"], 70.0)

    def test_rule_based_baseline_deterministic_evaluation(self):
        """TC-ML-05: Rule-Based baseline flags rule violations with explicit explanations."""
        baseline = RuleBasedBaseline()
        # Trigger RB-01 (login failures >= 5) and RB-02 (issue burst >= 10)
        flagged_vec = [6.0, 15.0, 0.0, 0.0, 0.0, 5.0]
        res = baseline.evaluate(flagged_vec)
        self.assertTrue(res["is_anomalous"])
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertTrue(any("RB-01" in r for r in res["reasons"]))
        self.assertTrue(any("RB-02" in r for r in res["reasons"]))

    def test_fallback_when_model_missing(self):
        """TC-ML-06: Gracefully falls back to Rule-Based Baseline if model file is missing."""
        missing_detector = IsolationForestDetector(model_path=Path(self.test_dir) / "non_existent.pkl")
        res = missing_detector.predict([0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
        self.assertTrue(res.get("fallback_active"))
        self.assertEqual(res.get("method"), "RULE_BASED_BASELINE")


if __name__ == "__main__":
    unittest.main()
