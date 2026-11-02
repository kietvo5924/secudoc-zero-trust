"""Feature Engineering for Security Behavior Analytics.

Extracts normalized numerical feature vectors from structured security events
for Machine Learning anomaly detection and Rule-based baselining.
"""
from datetime import datetime
from typing import Any


FEATURE_NAMES = [
    "login_failure_count",       # Number of failed login attempts
    "issue_burst_count",         # Number of documents issued in window
    "revoke_burst_count",        # Number of document revocations in window
    "access_denied_count",       # Number of unauthorized access attempts (401/403)
    "off_hours_ratio",           # Fraction of actions outside standard business hours (07:00-19:00 UTC)
    "action_velocity_per_min"    # Event frequency per minute
]


def extract_features_from_events(
    events: list[dict[str, Any]],
    window_minutes: float = 15.0
) -> list[float]:
    """
    Extract a 6-dimensional numeric feature vector from a sequence of security events.
    """
    if not events:
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    login_failures = 0
    issue_count = 0
    revoke_count = 0
    access_denied = 0
    off_hours_count = 0

    for ev in events:
        etype = ev.get("event_type", "")
        status = ev.get("status", "")

        if etype == "AUTH_LOGIN_FAIL" or (etype == "AUTH_LOGIN" and status == "FAILURE"):
            login_failures += 1
        elif etype == "DOC_ISSUE":
            issue_count += 1
        elif etype == "DOC_REVOKE":
            revoke_count += 1
        elif etype == "ACCESS_DENIED" or (etype == "ACCESS" and status == "FAILURE"):
            access_denied += 1

        # Check off-hours (normal work hours: 07:00 to 19:00 UTC)
        ts_str = ev.get("created_at")
        if ts_str:
            try:
                # Support ISO format with or without timezone
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                hour = dt.hour
                if hour < 7 or hour >= 19:
                    off_hours_count += 1
            except Exception:
                pass

    total_events = len(events)
    off_hours_ratio = float(off_hours_count) / float(total_events) if total_events > 0 else 0.0
    effective_window = max(1.0, float(window_minutes))
    action_velocity = float(total_events) / effective_window

    return [
        float(login_failures),
        float(issue_count),
        float(revoke_count),
        float(access_denied),
        round(off_hours_ratio, 4),
        round(action_velocity, 4)
    ]


def explain_features(feature_vector: list[float]) -> list[str]:
    """
    Generate human-readable explanations for features that deviate from normal thresholds.
    Ensures model explainability for Auditors.
    """
    explanations: list[str] = []
    if len(feature_vector) < 6:
        return ["Dữ liệu đặc trưng không đầy đủ"]

    login_fails, issue_burst, revoke_burst, access_denied, off_hours, velocity = feature_vector[:6]

    if login_fails >= 3:
        explanations.append(f"Số lần đăng nhập thất bại tăng vọt: {int(login_fails)} lần (nguy cơ Brute-force / chiếm quyền)")
    if issue_burst >= 8:
        explanations.append(f"Tần suất phát hành tài liệu tăng bất thường: {int(issue_burst)} văn bản trong cửa sổ ngắn (Burst Issuance)")
    if revoke_burst >= 3:
        explanations.append(f"Thu hồi hàng loạt văn bản liên tiếp: {int(revoke_burst)} văn bản (nguy cơ phá hoại)")
    if access_denied >= 2:
        explanations.append(f"Cố gắng truy cập trái quyền: {int(access_denied)} lần bị từ chối (Privilege Escalation)")
    if off_hours > 0.6:
        explanations.append(f"Phần lớn thao tác diễn ra ngoài giờ làm việc ({int(off_hours * 100)}% thao tác ban đêm/ngoài giờ)")
    if velocity >= 5.0:
        explanations.append(f"Tốc độ thao tác bất thường: {velocity:.1f} thao tác/phút (nghi vấn sử dụng công cụ tự động/bot)")

    return explanations if explanations else ["Hành vi phù hợp với mẫu hoạt động bình thường"]

