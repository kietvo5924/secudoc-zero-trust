"""Security Event Logging Service for Behavior Analytics and Threat Detection.

Records structured security telemetry (Authentication, Document Operations, Access Control)
with strict privacy protection: NEVER logs passwords, private keys, or raw confidential payloads.
"""
import uuid
import json
from datetime import datetime, timezone
from typing import Any
from ..models.database import DatabaseManager, get_db


class SecurityEventService:
    """Manages recording and querying structured security audit events."""

    def __init__(self, db_manager: DatabaseManager | None = None):
        self.db = db_manager or get_db()

    def log_event(
        self,
        event_type: str,
        status: str,
        user_id: int | None = None,
        username: str | None = None,
        ip_address: str = "127.0.0.1",
        user_agent: str = "SecuDoc-Client/1.0",
        response_time_ms: float = 0.0,
        metadata: dict[str, Any] | None = None
    ) -> str:
        """
        Record a structured security event.
        Returns the generated event_id (UUID).
        """
        event_id = str(uuid.uuid4())
        now_str = datetime.now(timezone.utc).isoformat()

        clean_meta = {}
        if metadata:
            # Privacy filter: exclude any sensitive tokens or passwords
            for k, v in metadata.items():
                if any(secret_term in k.lower() for secret_term in ("pass", "token", "secret", "key", "auth_header")):
                    continue
                clean_meta[k] = v

        meta_json = json.dumps(clean_meta, ensure_ascii=False) if clean_meta else "{}"

        # Sanitize IP and user agent strings
        clean_ip = ip_address.split(",")[0].strip()[:45] if ip_address else "127.0.0.1"
        clean_ua = (user_agent or "Unknown")[:200]

        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_events (
                    event_id, user_id, username, event_type, status,
                    ip_address, user_agent, response_time_ms, created_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                event_id, user_id, username, event_type, status,
                clean_ip, clean_ua, float(response_time_ms), now_str, meta_json
            ))

        return event_id

    def get_recent_events(self, limit: int = 50, user_id: int | None = None) -> list[dict[str, Any]]:
        """Retrieve recent security events for auditor dashboard inspection."""
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            if user_id is not None:
                cursor.execute("""
                    SELECT * FROM security_events
                    WHERE user_id = ?
                    ORDER BY id DESC LIMIT ?;
                """, (user_id, limit))
            else:
                cursor.execute("""
                    SELECT * FROM security_events
                    ORDER BY id DESC LIMIT ?;
                """, (limit,))
            return [dict(r) for r in cursor.fetchall()]

    def get_user_events_window(self, user_id: int, window_seconds: int = 900) -> list[dict[str, Any]]:
        """Fetch all events for a user within the specified sliding window in seconds."""
        cutoff_dt = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() - window_seconds,
            tz=timezone.utc
        ).isoformat()

        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM security_events
                WHERE user_id = ? AND created_at >= ?
                ORDER BY id ASC;
            """, (user_id, cutoff_dt))
            return [dict(r) for r in cursor.fetchall()]

    def get_event_statistics(self) -> dict[str, Any]:
        """Aggregate high-level security event statistics for dashboard display."""
        with self.db.connection_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM security_events;")
            total_events = cursor.fetchone()["count"]

            cursor.execute("""
                SELECT event_type, COUNT(*) as count
                FROM security_events
                GROUP BY event_type;
            """)
            type_counts = {r["event_type"]: r["count"] for r in cursor.fetchall()}

            cursor.execute("""
                SELECT COUNT(*) as count FROM security_events
                WHERE event_type IN ('AUTH_LOGIN_FAIL', 'ACCESS_DENIED')
                   OR status IN ('FAILURE', 'WARNING');
            """)
            anomaly_candidates = cursor.fetchone()["count"]

        return {
            "total_events": total_events,
            "type_counts": type_counts,
            "anomaly_candidates": anomaly_candidates
        }

