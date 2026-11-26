import csv
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

from core.attack_taxonomy import build_attack_distribution
from core.auth import hash_password
from utils import json_dumps, to_epoch, to_iso, utc_now

try:
    from psycopg import connect as pg_connect
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - optional dependency at runtime
    pg_connect = None
    dict_row = None


@dataclass
class HistorySnapshot:
    ip_request_count_window: int = 0
    ip_block_count_window: int = 0
    ip_monitor_count_window: int = 0
    session_request_count_window: int = 0
    fingerprint_reuse_count: int = 0
    path_hits_window: int = 0
    unique_paths_window: int = 0
    ip_avg_risk_score_window: float = 0.0
    ip_max_risk_score_window: float = 0.0

    @property
    def ip_block_ratio(self) -> float:
        if not self.ip_request_count_window:
            return 0.0
        return round(self.ip_block_count_window / float(self.ip_request_count_window), 4)

    @property
    def ip_flagged_count_window(self) -> int:
        return int(self.ip_block_count_window + self.ip_monitor_count_window)

    @property
    def ip_flagged_ratio(self) -> float:
        if not self.ip_request_count_window:
            return 0.0
        return round(self.ip_flagged_count_window / float(self.ip_request_count_window), 4)

    def as_dict(self) -> Dict[str, float]:
        return {
            "ip_request_count_window": self.ip_request_count_window,
            "ip_block_count_window": self.ip_block_count_window,
            "ip_monitor_count_window": self.ip_monitor_count_window,
            "ip_flagged_count_window": self.ip_flagged_count_window,
            "session_request_count_window": self.session_request_count_window,
            "fingerprint_reuse_count": self.fingerprint_reuse_count,
            "path_hits_window": self.path_hits_window,
            "unique_paths_window": self.unique_paths_window,
            "ip_block_ratio": self.ip_block_ratio,
            "ip_flagged_ratio": self.ip_flagged_ratio,
            "ip_avg_risk_score_window": round(float(self.ip_avg_risk_score_window or 0.0), 4),
            "ip_max_risk_score_window": round(float(self.ip_max_risk_score_window or 0.0), 4),
        }


@dataclass
class BlacklistRecord:
    ip_address: str
    reason: str
    source: str
    created_at: str
    expires_at: Optional[str]

    def as_dict(self) -> Dict[str, Optional[str]]:
        return {
            "ip_address": self.ip_address,
            "reason": self.reason,
            "source": self.source,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


@dataclass
class ManualBlockRule:
    rule_id: str
    scope_type: str
    reason: str
    source: str
    created_at: str
    expires_at: Optional[str]
    criteria: Dict[str, object]

    def matches_values(
        self,
        request_fingerprint: str,
        method: str,
        path: str,
        session_id: str,
        remote_addr: str,
    ) -> bool:
        scope = (self.scope_type or "signature").strip().lower()
        criteria = self.criteria or {}

        if scope == "signature":
            return (
                criteria.get("request_fingerprint") == request_fingerprint
                and criteria.get("method") == method
                and criteria.get("path") == path
            )

        if scope == "path":
            return criteria.get("method") == method and criteria.get("path") == path

        if scope == "session":
            session_value = str(criteria.get("session_id") or "")
            return bool(session_value and session_value == session_id)

        if scope == "ip":
            return criteria.get("remote_addr") == remote_addr

        return False

    def as_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "scope_type": self.scope_type,
            "reason": self.reason,
            "source": self.source,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "criteria": self.criteria,
        }


class Storage:
    class _ConnectionAdapter:
        def __init__(self, storage, raw_connection):
            self._storage = storage
            self._raw_connection = raw_connection

        def execute(self, query, params=()):
            normalized_query = self._storage._normalize_query(query)
            normalized_params = tuple(params or ())
            return self._raw_connection.execute(normalized_query, normalized_params)

        def executescript(self, script: str):
            return self._storage._executescript(self._raw_connection, script)

        def __enter__(self):
            self._raw_connection.__enter__()
            return self

        def __exit__(self, exc_type, exc, tb):
            return self._raw_connection.__exit__(exc_type, exc, tb)

        def close(self):
            return self._raw_connection.close()

        def __getattr__(self, item):
            return getattr(self._raw_connection, item)

    def __init__(self, db_path, database_url: str = ""):
        raw_target = str(db_path)
        inferred_database_url = str(database_url or "").strip()
        if not inferred_database_url and raw_target.startswith(("postgres://", "postgresql://", "sqlite:///")):
            inferred_database_url = raw_target
            raw_target = ""

        if inferred_database_url.startswith("sqlite:///"):
            sqlite_path = inferred_database_url.replace("sqlite:///", "", 1)
            self.db_path = Path(sqlite_path)
        else:
            self.db_path = Path(raw_target) if raw_target else Path("data/waf.sqlite3")
        self.database_url = inferred_database_url
        self.database_backend = self._detect_backend()

        if self.database_backend == "sqlite":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _detect_backend(self) -> str:
        if self.database_url.startswith(("postgres://", "postgresql://")):
            return "postgresql"
        return "sqlite"

    def _normalize_query(self, query: str) -> str:
        if self.database_backend != "postgresql":
            return query
        return query.replace("?", "%s")

    def _executescript(self, raw_connection, script: str):
        if self.database_backend == "sqlite":
            return raw_connection.executescript(script)

        statements = [statement.strip() for statement in script.split(";") if statement.strip()]
        for statement in statements:
            raw_connection.execute(statement)
        return None

    def _connect(self) -> sqlite3.Connection:
        if self.database_backend == "postgresql":
            if pg_connect is None:
                raise RuntimeError("psycopg is required for PostgreSQL support. Install dependencies from requirements.txt")
            raw_connection = pg_connect(self.database_url, row_factory=dict_row)
            return self._ConnectionAdapter(self, raw_connection)

        raw_connection = sqlite3.connect(str(self.db_path), timeout=30, check_same_thread=False)
        raw_connection.row_factory = sqlite3.Row
        return self._ConnectionAdapter(self, raw_connection)

    def _column_exists(self, connection, table_name: str, column_name: str) -> bool:
        if self.database_backend == "postgresql":
            row = connection.execute(
                """
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = %s
                  AND column_name = %s
                """,
                (table_name, column_name),
            ).fetchone()
            return row is not None

        rows = connection.execute("PRAGMA table_info({0})".format(table_name)).fetchall()
        return any(str(row["name"]) == column_name for row in rows)

    def _request_traffic_origin(self, request_record) -> str:
        origin = str(getattr(request_record, "traffic_origin", "live") or "live").strip().lower()
        return origin if origin in {"live", "simulation"} else "live"

    def _ensure_requests_schema(self, connection) -> None:
        if not self._column_exists(connection, "requests", "traffic_origin"):
            connection.execute("ALTER TABLE requests ADD COLUMN traffic_origin TEXT NOT NULL DEFAULT 'live'")
        if not self._column_exists(connection, "requests", "endpoint_policy_json"):
            connection.execute("ALTER TABLE requests ADD COLUMN endpoint_policy_json TEXT")
        if not self._column_exists(connection, "requests", "decision_json"):
            connection.execute("ALTER TABLE requests ADD COLUMN decision_json TEXT")
        if not self._column_exists(connection, "requests", "history_json"):
            connection.execute("ALTER TABLE requests ADD COLUMN history_json TEXT")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_requests_origin_timestamp ON requests(traffic_origin, timestamp_epoch DESC)")
        connection.execute(
            """
            UPDATE requests
            SET traffic_origin = 'simulation'
            WHERE traffic_origin = 'live'
              AND remote_addr LIKE ?
              AND (path LIKE ? OR gateway_path LIKE ?)
            """,
            ("198.51.%", "/inspect%", "/inspect%"),
        )

    def initialize(self, app_settings=None) -> None:
        with closing(self._connect()) as connection, connection:
            if self.database_backend == "sqlite":
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA foreign_keys = ON")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    timestamp_epoch REAL NOT NULL,
                    method TEXT NOT NULL,
                    scheme TEXT,
                    host TEXT,
                    path TEXT NOT NULL,
                    query_string TEXT,
                    full_url TEXT,
                    gateway_path TEXT,
                    remote_addr TEXT,
                    user_agent TEXT,
                    session_id TEXT,
                    request_fingerprint TEXT,
                    content_type TEXT,
                    body_length INTEGER,
                    payload_hash TEXT,
                    payload_preview TEXT,
                    feature_json TEXT,
                    score_json TEXT,
                    rule_json TEXT,
                    decision_json TEXT,
                    history_json TEXT,
                    attack_types_json TEXT,
                    decision_action TEXT NOT NULL,
                    decision_status_code INTEGER NOT NULL,
                    risk_score REAL NOT NULL,
                    latency_ms REAL NOT NULL,
                    backend_status INTEGER,
                    was_proxied INTEGER NOT NULL DEFAULT 0,
                    traffic_origin TEXT NOT NULL DEFAULT 'live',
                    label TEXT,
                    notes TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp_epoch DESC);
                CREATE INDEX IF NOT EXISTS idx_requests_remote_addr ON requests(remote_addr, timestamp_epoch DESC);
                CREATE INDEX IF NOT EXISTS idx_requests_session_id ON requests(session_id, timestamp_epoch DESC);
                CREATE INDEX IF NOT EXISTS idx_requests_request_fingerprint ON requests(request_fingerprint, timestamp_epoch DESC);
                CREATE INDEX IF NOT EXISTS idx_requests_path ON requests(path, timestamp_epoch DESC);
                CREATE INDEX IF NOT EXISTS idx_requests_decision_action ON requests(decision_action, timestamp_epoch DESC);

                CREATE TABLE IF NOT EXISTS blacklist (
                    ip_address TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_at_epoch REAL NOT NULL,
                    expires_at TEXT,
                    expires_at_epoch REAL
                );

                CREATE TABLE IF NOT EXISTS rate_limit_state (
                    ip_address TEXT PRIMARY KEY,
                    tokens REAL NOT NULL,
                    updated_at_epoch REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS model_registry (
                    model_version TEXT PRIMARY KEY,
                    model_type TEXT NOT NULL,
                    artifact_path TEXT NOT NULL,
                    metrics_json TEXT,
                    created_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS manual_block_rules (
                    rule_id TEXT PRIMARY KEY,
                    scope_type TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    source TEXT NOT NULL,
                    criteria_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_at_epoch REAL NOT NULL,
                    expires_at TEXT,
                    expires_at_epoch REAL
                );

                CREATE INDEX IF NOT EXISTS idx_manual_block_rules_expiry
                ON manual_block_rules(expires_at_epoch);

                CREATE TABLE IF NOT EXISTS endpoint_policies (
                    policy_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    path_pattern TEXT NOT NULL,
                    methods_json TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 50,
                    sensitivity TEXT NOT NULL DEFAULT 'protected',
                    settings_json TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'custom',
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_endpoint_policies_enabled_priority
                ON endpoint_policies(is_enabled, priority DESC, updated_at DESC);

                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_at_epoch REAL NOT NULL,
                    expires_at TEXT NOT NULL,
                    expires_at_epoch REAL NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    last_seen_epoch REAL NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);
                CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at_epoch);

                CREATE TABLE IF NOT EXISTS audit_log (
                    event_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    created_at_epoch REAL NOT NULL,
                    actor_user_id TEXT,
                    actor_username TEXT,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT,
                    details_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at_epoch DESC);

                CREATE TABLE IF NOT EXISTS system_settings (
                    setting_key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT
                );
                """
            )
            self._ensure_requests_schema(connection)
        if app_settings is not None:
            self.seed_default_users(app_settings)

    def purge_expired_blacklist(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                DELETE FROM blacklist
                WHERE expires_at_epoch IS NOT NULL
                  AND expires_at_epoch <= ?
                """,
                (to_epoch(),),
            )

    def is_blacklisted(self, ip_address: str) -> Optional[BlacklistRecord]:
        self.purge_expired_blacklist()
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT ip_address, reason, source, created_at, expires_at
                FROM blacklist
                WHERE ip_address = ?
                """,
                (ip_address,),
            ).fetchone()

        if row is None:
            return None

        return BlacklistRecord(
            ip_address=row["ip_address"],
            reason=row["reason"],
            source=row["source"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def add_blacklist(
        self,
        ip_address: str,
        reason: str,
        source: str = "manual",
        ttl_seconds: Optional[int] = None,
    ) -> None:
        now = utc_now()
        expires_at = now + timedelta(seconds=ttl_seconds) if ttl_seconds else None
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO blacklist (
                    ip_address,
                    reason,
                    source,
                    created_at,
                    created_at_epoch,
                    expires_at,
                    expires_at_epoch
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    reason = excluded.reason,
                    source = excluded.source,
                    created_at = excluded.created_at,
                    created_at_epoch = excluded.created_at_epoch,
                    expires_at = excluded.expires_at,
                    expires_at_epoch = excluded.expires_at_epoch
                """,
                (
                    ip_address,
                    reason,
                    source,
                    to_iso(now),
                    to_epoch(now),
                    to_iso(expires_at) if expires_at else None,
                    to_epoch(expires_at) if expires_at else None,
                ),
            )

    def remove_blacklist(self, ip_address: str) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute("DELETE FROM blacklist WHERE ip_address = ?", (ip_address,))

    def list_blacklist(self) -> List[Dict[str, Optional[str]]]:
        self.purge_expired_blacklist()
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT ip_address, reason, source, created_at, expires_at
                FROM blacklist
                ORDER BY created_at_epoch DESC
                """
            ).fetchall()

        return [
            BlacklistRecord(
                ip_address=row["ip_address"],
                reason=row["reason"],
                source=row["source"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
            ).as_dict()
            for row in rows
        ]

    def count_users(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM users").fetchone()
        return int(row["total"] or 0)

    def seed_default_users(self, app_settings) -> None:
        if self.count_users() > 0:
            return
        self.upsert_user(
            username=app_settings.admin_username,
            password_hash=hash_password(app_settings.admin_password),
            display_name="Administrator",
            role="admin",
            is_active=True,
        )
        self.upsert_user(
            username=app_settings.analyst_username,
            password_hash=hash_password(app_settings.analyst_password),
            display_name="Security Analyst",
            role="analyst",
            is_active=True,
        )
        self.upsert_user(
            username=app_settings.viewer_username,
            password_hash=hash_password(app_settings.viewer_password),
            display_name="Read Only Viewer",
            role="viewer",
            is_active=True,
        )

    def upsert_user(
        self,
        username: str,
        password_hash: str,
        display_name: str,
        role: str,
        is_active: bool = True,
        user_id: Optional[str] = None,
    ) -> Dict[str, object]:
        normalized_username = (username or "").strip().lower()
        normalized_role = (role or "viewer").strip().lower()
        now_iso = to_iso()
        resolved_user_id = user_id or uuid4().hex[:12]
        with closing(self._connect()) as connection, connection:
            existing = connection.execute(
                "SELECT user_id FROM users WHERE username = ?",
                (normalized_username,),
            ).fetchone()
            if existing is not None:
                resolved_user_id = existing["user_id"]
                connection.execute(
                    """
                    UPDATE users
                    SET password_hash = ?, display_name = ?, role = ?, is_active = ?, updated_at = ?
                    WHERE user_id = ?
                    """,
                    (
                        password_hash,
                        display_name,
                        normalized_role,
                        int(bool(is_active)),
                        now_iso,
                        resolved_user_id,
                    ),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO users (
                        user_id,
                        username,
                        password_hash,
                        display_name,
                        role,
                        is_active,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        resolved_user_id,
                        normalized_username,
                        password_hash,
                        display_name,
                        normalized_role,
                        int(bool(is_active)),
                        now_iso,
                        now_iso,
                    ),
                )
        return self.get_user_by_id(resolved_user_id) or {}

    def get_user_by_username(self, username: str, include_password_hash: bool = True) -> Optional[Dict[str, object]]:
        normalized_username = (username or "").strip().lower()
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT user_id, username, password_hash, display_name, role, is_active, created_at, updated_at
                FROM users
                WHERE username = ?
                """,
                (normalized_username,),
            ).fetchone()
        if row is None:
            return None
        payload = {
            "user_id": row["user_id"],
            "username": row["username"],
            "display_name": row["display_name"],
            "role": row["role"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        if include_password_hash:
            payload["password_hash"] = row["password_hash"]
        return payload

    def get_user_by_id(self, user_id: str, include_password_hash: bool = False) -> Optional[Dict[str, object]]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT user_id, username, password_hash, display_name, role, is_active, created_at, updated_at
                FROM users
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        payload = {
            "user_id": row["user_id"],
            "username": row["username"],
            "display_name": row["display_name"],
            "role": row["role"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        if include_password_hash:
            payload["password_hash"] = row["password_hash"]
        return payload

    def list_users(self) -> List[Dict[str, object]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT user_id, username, display_name, role, is_active, created_at, updated_at
                FROM users
                ORDER BY
                    CASE role WHEN 'admin' THEN 0 WHEN 'analyst' THEN 1 ELSE 2 END,
                    username ASC
                """
            ).fetchall()
        return [
            {
                "user_id": row["user_id"],
                "username": row["username"],
                "display_name": row["display_name"],
                "role": row["role"],
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def update_user(
        self,
        user_id: str,
        display_name: Optional[str] = None,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
        password_hash: Optional[str] = None,
    ) -> Optional[Dict[str, object]]:
        updates = []
        params: List[object] = []
        if display_name is not None:
            updates.append("display_name = ?")
            params.append(display_name)
        if role is not None:
            updates.append("role = ?")
            params.append((role or "viewer").strip().lower())
        if is_active is not None:
            updates.append("is_active = ?")
            params.append(int(bool(is_active)))
        if password_hash is not None:
            updates.append("password_hash = ?")
            params.append(password_hash)
        if not updates:
            return self.get_user_by_id(user_id)

        updates.append("updated_at = ?")
        params.append(to_iso())
        params.append(user_id)

        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                "UPDATE users SET {0} WHERE user_id = ?".format(", ".join(updates)),
                tuple(params),
            )
        if not cursor.rowcount:
            return None
        return self.get_user_by_id(user_id)

    def purge_expired_auth_sessions(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                DELETE FROM auth_sessions
                WHERE expires_at_epoch <= ?
                """,
                (to_epoch(),),
            )

    def create_auth_session(
        self,
        token: str,
        user_id: str,
        ttl_seconds: int,
        ip_address: str = "",
        user_agent: str = "",
    ) -> Dict[str, object]:
        now = utc_now()
        expires_at = now + timedelta(seconds=max(int(ttl_seconds or 1), 1))
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO auth_sessions (
                    token,
                    user_id,
                    created_at,
                    created_at_epoch,
                    expires_at,
                    expires_at_epoch,
                    last_seen_at,
                    last_seen_epoch,
                    ip_address,
                    user_agent
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(token) DO UPDATE SET
                    user_id = excluded.user_id,
                    created_at = excluded.created_at,
                    created_at_epoch = excluded.created_at_epoch,
                    expires_at = excluded.expires_at,
                    expires_at_epoch = excluded.expires_at_epoch,
                    last_seen_at = excluded.last_seen_at,
                    last_seen_epoch = excluded.last_seen_epoch,
                    ip_address = excluded.ip_address,
                    user_agent = excluded.user_agent
                """,
                (
                    token,
                    user_id,
                    to_iso(now),
                    to_epoch(now),
                    to_iso(expires_at),
                    to_epoch(expires_at),
                    to_iso(now),
                    to_epoch(now),
                    ip_address,
                    user_agent,
                ),
            )
        return self.get_auth_session(token) or {}

    def get_auth_session(self, token: str) -> Optional[Dict[str, object]]:
        self.purge_expired_auth_sessions()
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    s.token,
                    s.user_id,
                    s.created_at,
                    s.expires_at,
                    s.last_seen_at,
                    s.ip_address,
                    s.user_agent,
                    u.username,
                    u.display_name,
                    u.role,
                    u.is_active
                FROM auth_sessions s
                INNER JOIN users u ON u.user_id = s.user_id
                WHERE s.token = ?
                LIMIT 1
                """,
                (token,),
            ).fetchone()
        if row is None or not bool(row["is_active"]):
            return None
        return {
            "token": row["token"],
            "user_id": row["user_id"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "last_seen_at": row["last_seen_at"],
            "ip_address": row["ip_address"] or "",
            "user_agent": row["user_agent"] or "",
            "user": {
                "user_id": row["user_id"],
                "username": row["username"],
                "display_name": row["display_name"],
                "role": row["role"],
                "is_active": bool(row["is_active"]),
            },
        }

    def touch_auth_session(self, token: str, ttl_seconds: Optional[int] = None) -> Optional[Dict[str, object]]:
        self.purge_expired_auth_sessions()
        current = self.get_auth_session(token)
        if current is None:
            return None

        now = utc_now()
        expires_at = now + timedelta(seconds=max(int(ttl_seconds or 1), 1)) if ttl_seconds else None
        with closing(self._connect()) as connection, connection:
            if expires_at is not None:
                connection.execute(
                    """
                    UPDATE auth_sessions
                    SET last_seen_at = ?, last_seen_epoch = ?, expires_at = ?, expires_at_epoch = ?
                    WHERE token = ?
                    """,
                    (to_iso(now), to_epoch(now), to_iso(expires_at), to_epoch(expires_at), token),
                )
            else:
                connection.execute(
                    """
                    UPDATE auth_sessions
                    SET last_seen_at = ?, last_seen_epoch = ?
                    WHERE token = ?
                    """,
                    (to_iso(now), to_epoch(now), token),
                )
        return self.get_auth_session(token)

    def delete_auth_session(self, token: str) -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute("DELETE FROM auth_sessions WHERE token = ?", (token,))
        return bool(cursor.rowcount)

    def delete_auth_sessions_for_user(self, user_id: str) -> int:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
        return int(cursor.rowcount or 0)

    def log_audit_event(
        self,
        action: str,
        target_type: str,
        details: Dict[str, object],
        actor_user_id: Optional[str] = None,
        actor_username: str = "",
        target_id: str = "",
    ) -> Dict[str, object]:
        event_id = uuid4().hex[:12]
        now = utc_now()
        payload = {
            "event_id": event_id,
            "created_at": to_iso(now),
            "actor_user_id": actor_user_id,
            "actor_username": actor_username,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": details,
        }
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO audit_log (
                    event_id,
                    created_at,
                    created_at_epoch,
                    actor_user_id,
                    actor_username,
                    action,
                    target_type,
                    target_id,
                    details_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    payload["created_at"],
                    to_epoch(now),
                    actor_user_id,
                    actor_username,
                    action,
                    target_type,
                    target_id,
                    json_dumps(details),
                ),
            )
        return payload

    def list_audit_events(self, limit: int = 100) -> List[Dict[str, object]]:
        safe_limit = min(max(int(limit or 100), 1), 500)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT event_id, created_at, actor_user_id, actor_username, action, target_type, target_id, details_json
                FROM audit_log
                ORDER BY created_at_epoch DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "created_at": row["created_at"],
                "actor_user_id": row["actor_user_id"],
                "actor_username": row["actor_username"] or "",
                "action": row["action"],
                "target_type": row["target_type"],
                "target_id": row["target_id"] or "",
                "details": json.loads(row["details_json"] or "{}"),
            }
            for row in rows
        ]

    def get_latest_audit_event(self, action: str) -> Optional[Dict[str, object]]:
        normalized_action = (action or "").strip()
        if not normalized_action:
            return None

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT event_id, created_at, created_at_epoch, actor_user_id, actor_username, action, target_type, target_id, details_json
                FROM audit_log
                WHERE action = ?
                ORDER BY created_at_epoch DESC
                LIMIT 1
                """,
                (normalized_action,),
            ).fetchone()

        if row is None:
            return None

        return {
            "event_id": row["event_id"],
            "created_at": row["created_at"],
            "created_at_epoch": float(row["created_at_epoch"] or 0.0),
            "actor_user_id": row["actor_user_id"],
            "actor_username": row["actor_username"] or "",
            "action": row["action"],
            "target_type": row["target_type"],
            "target_id": row["target_id"] or "",
            "details": json.loads(row["details_json"] or "{}"),
        }

    def get_runtime_setting_overrides(self) -> Dict[str, object]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT setting_key, value_json
                FROM system_settings
                ORDER BY setting_key ASC
                """
            ).fetchall()
        overrides = {}
        for row in rows:
            overrides[row["setting_key"]] = json.loads(row["value_json"])
        return overrides

    def get_auto_tuning_telemetry(self, window_seconds: int) -> Dict[str, object]:
        safe_window = max(int(window_seconds or 3600), 60)
        since_epoch = to_epoch() - float(safe_window)

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_requests,
                    SUM(CASE WHEN decision_action = 'block' THEN 1 ELSE 0 END) AS blocked_requests,
                    SUM(CASE WHEN decision_action = 'monitor' THEN 1 ELSE 0 END) AS monitored_requests,
                    SUM(CASE WHEN decision_action = 'allow' THEN 1 ELSE 0 END) AS allowed_requests,
                    SUM(CASE WHEN COALESCE(label, '') <> '' THEN 1 ELSE 0 END) AS labeled_requests,
                    SUM(CASE WHEN label = 'benign' THEN 1 ELSE 0 END) AS benign_labeled,
                    SUM(CASE WHEN label = 'malicious' THEN 1 ELSE 0 END) AS malicious_labeled,
                    SUM(CASE WHEN label = 'benign' AND decision_action IN ('block', 'monitor') THEN 1 ELSE 0 END) AS benign_false_positive_count,
                    SUM(CASE WHEN label = 'malicious' AND decision_action = 'allow' THEN 1 ELSE 0 END) AS malicious_allowed,
                    SUM(CASE WHEN COALESCE(attack_types_json, '[]') <> '[]' THEN 1 ELSE 0 END) AS attack_marked_requests,
                    SUM(CASE WHEN decision_action IN ('block', 'monitor') THEN 1 ELSE 0 END) AS flagged_requests,
                    AVG(risk_score) AS avg_risk_score
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                """,
                (since_epoch, "live"),
            ).fetchone()

        return {
            "window_seconds": safe_window,
            "since_epoch": since_epoch,
            "total_requests": int(row["total_requests"] or 0),
            "blocked_requests": int(row["blocked_requests"] or 0),
            "monitored_requests": int(row["monitored_requests"] or 0),
            "allowed_requests": int(row["allowed_requests"] or 0),
            "labeled_requests": int(row["labeled_requests"] or 0),
            "benign_labeled": int(row["benign_labeled"] or 0),
            "malicious_labeled": int(row["malicious_labeled"] or 0),
            "benign_false_positive_count": int(row["benign_false_positive_count"] or 0),
            "malicious_allowed": int(row["malicious_allowed"] or 0),
            "attack_marked_requests": int(row["attack_marked_requests"] or 0),
            "flagged_requests": int(row["flagged_requests"] or 0),
            "avg_risk_score": round(float(row["avg_risk_score"] or 0.0), 4),
        }

    def get_dynamic_threshold_telemetry(self, window_seconds: int, endpoint_policy: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        safe_window = max(int(window_seconds or 1800), 60)
        since_epoch = to_epoch() - float(safe_window)
        endpoint_policy = dict(endpoint_policy or {})
        matched_path = str(endpoint_policy.get("matched_path") or "").strip()
        endpoint_scope = bool(matched_path)

        with closing(self._connect()) as connection:
            if endpoint_scope:
                row = connection.execute(
                    """
                    SELECT
                        COUNT(*) AS total_requests,
                        SUM(CASE WHEN decision_action = 'block' THEN 1 ELSE 0 END) AS blocked_requests,
                        SUM(CASE WHEN decision_action = 'monitor' THEN 1 ELSE 0 END) AS monitored_requests,
                        SUM(CASE WHEN decision_action = 'allow' THEN 1 ELSE 0 END) AS allowed_requests,
                        SUM(CASE WHEN COALESCE(label, '') <> '' THEN 1 ELSE 0 END) AS labeled_requests,
                        SUM(CASE WHEN label = 'benign' THEN 1 ELSE 0 END) AS benign_labeled,
                        SUM(CASE WHEN label = 'malicious' THEN 1 ELSE 0 END) AS malicious_labeled,
                        SUM(CASE WHEN label = 'benign' AND decision_action IN ('block', 'monitor') THEN 1 ELSE 0 END) AS benign_false_positive_count,
                        AVG(risk_score) AS avg_risk_score,
                        AVG(risk_score * risk_score) AS avg_squared_risk_score,
                        MIN(risk_score) AS min_risk_score,
                        MAX(risk_score) AS max_risk_score
                    FROM requests
                    WHERE timestamp_epoch >= ?
                      AND traffic_origin = ?
                      AND path = ?
                    """,
                    (since_epoch, "live", matched_path),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT
                        COUNT(*) AS total_requests,
                        SUM(CASE WHEN decision_action = 'block' THEN 1 ELSE 0 END) AS blocked_requests,
                        SUM(CASE WHEN decision_action = 'monitor' THEN 1 ELSE 0 END) AS monitored_requests,
                        SUM(CASE WHEN decision_action = 'allow' THEN 1 ELSE 0 END) AS allowed_requests,
                        SUM(CASE WHEN COALESCE(label, '') <> '' THEN 1 ELSE 0 END) AS labeled_requests,
                        SUM(CASE WHEN label = 'benign' THEN 1 ELSE 0 END) AS benign_labeled,
                        SUM(CASE WHEN label = 'malicious' THEN 1 ELSE 0 END) AS malicious_labeled,
                        SUM(CASE WHEN label = 'benign' AND decision_action IN ('block', 'monitor') THEN 1 ELSE 0 END) AS benign_false_positive_count,
                        AVG(risk_score) AS avg_risk_score,
                        AVG(risk_score * risk_score) AS avg_squared_risk_score,
                        MIN(risk_score) AS min_risk_score,
                        MAX(risk_score) AS max_risk_score
                    FROM requests
                    WHERE timestamp_epoch >= ?
                      AND traffic_origin = ?
                    """,
                    (since_epoch, "live"),
                ).fetchone()

        avg_risk_score = float(row["avg_risk_score"] or 0.0)
        avg_squared_risk_score = float(row["avg_squared_risk_score"] or 0.0)
        variance = max(avg_squared_risk_score - (avg_risk_score * avg_risk_score), 0.0)
        total_requests = int(row["total_requests"] or 0)
        blocked_requests = int(row["blocked_requests"] or 0)
        monitored_requests = int(row["monitored_requests"] or 0)
        benign_labeled = int(row["benign_labeled"] or 0)
        benign_false_positive_count = int(row["benign_false_positive_count"] or 0)
        flagged_requests = blocked_requests + monitored_requests
        false_positive_rate = (
            benign_false_positive_count / float(max(benign_labeled, 1))
            if benign_labeled
            else 0.0
        )
        request_rate_per_second = total_requests / float(max(safe_window, 1))
        requests_per_minute = request_rate_per_second * 60.0
        flagged_ratio = flagged_requests / float(max(total_requests, 1)) if total_requests else 0.0

        return {
            "window_seconds": safe_window,
            "since_epoch": since_epoch,
            "scope": "endpoint" if endpoint_scope else "global",
            "matched_path": matched_path,
            "endpoint_policy_id": str(endpoint_policy.get("policy_id") or ""),
            "endpoint_policy_name": str(endpoint_policy.get("name") or ""),
            "endpoint_sensitivity": str(endpoint_policy.get("sensitivity") or "standard"),
            "target_requests_per_min": int(endpoint_policy.get("requests_per_min", 0) or 0),
            "total_requests": total_requests,
            "blocked_requests": blocked_requests,
            "monitored_requests": monitored_requests,
            "allowed_requests": int(row["allowed_requests"] or 0),
            "labeled_requests": int(row["labeled_requests"] or 0),
            "benign_labeled": benign_labeled,
            "malicious_labeled": int(row["malicious_labeled"] or 0),
            "benign_false_positive_count": benign_false_positive_count,
            "false_positive_rate": round(false_positive_rate, 4),
            "flagged_ratio": round(flagged_ratio, 4),
            "request_rate_per_second": round(request_rate_per_second, 4),
            "requests_per_minute": round(requests_per_minute, 2),
            "avg_risk_score": round(avg_risk_score, 4),
            "stddev_risk_score": round(variance ** 0.5, 4),
            "min_risk_score": round(float(row["min_risk_score"] or 0.0), 4),
            "max_risk_score": round(float(row["max_risk_score"] or 0.0), 4),
        }

    def get_adaptive_rate_limit_telemetry(
        self,
        window_seconds: int,
        suspicious_request_threshold: int,
        unique_paths_threshold: int,
        block_ratio_threshold: float,
        flagged_ratio_threshold: float,
        avg_risk_threshold: float,
    ) -> Dict[str, object]:
        safe_window = max(int(window_seconds or 900), 60)
        since_epoch = to_epoch() - float(safe_window)
        safe_request_threshold = max(int(suspicious_request_threshold or 8), 1)
        safe_unique_paths_threshold = max(int(unique_paths_threshold or 4), 1)
        safe_block_ratio_threshold = max(float(block_ratio_threshold or 0.25), 0.0)
        safe_flagged_ratio_threshold = max(float(flagged_ratio_threshold or 0.35), 0.0)
        safe_avg_risk_threshold = max(float(avg_risk_threshold or 0.55), 0.0)

        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT
                    remote_addr,
                    COUNT(*) AS total_requests,
                    SUM(CASE WHEN decision_action = 'block' THEN 1 ELSE 0 END) AS blocked_requests,
                    SUM(CASE WHEN decision_action = 'monitor' THEN 1 ELSE 0 END) AS monitored_requests,
                    COUNT(DISTINCT path) AS unique_paths,
                    AVG(risk_score) AS avg_risk_score,
                    MAX(risk_score) AS max_risk_score
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                GROUP BY remote_addr
                ORDER BY COUNT(*) DESC, remote_addr ASC
                """,
                (since_epoch, "live"),
            ).fetchall()

        ip_rows = []
        total_requests = 0
        high_volume_ips = 0
        recon_like_ips = 0
        offender_ips = 0
        flagged_ips = 0
        suspicious_candidate_ips = 0
        high_risk_ips = 0
        for row in rows:
            total = int(row["total_requests"] or 0)
            blocked = int(row["blocked_requests"] or 0)
            monitored = int(row["monitored_requests"] or 0)
            unique_paths = int(row["unique_paths"] or 0)
            avg_risk_score = round(float(row["avg_risk_score"] or 0.0), 4)
            max_risk_score = round(float(row["max_risk_score"] or 0.0), 4)
            block_ratio = round((blocked / float(total)) if total else 0.0, 4)
            flagged_ratio = round(((blocked + monitored) / float(total)) if total else 0.0, 4)
            total_requests += total
            if total >= safe_request_threshold:
                high_volume_ips += 1
            if unique_paths >= safe_unique_paths_threshold:
                recon_like_ips += 1
            if block_ratio >= safe_block_ratio_threshold and total > 0:
                offender_ips += 1
            if flagged_ratio >= safe_flagged_ratio_threshold and total > 0:
                flagged_ips += 1
            if avg_risk_score >= safe_avg_risk_threshold or max_risk_score >= safe_avg_risk_threshold:
                high_risk_ips += 1
            if (
                total >= safe_request_threshold
                or unique_paths >= safe_unique_paths_threshold
                or block_ratio >= safe_block_ratio_threshold
                or flagged_ratio >= safe_flagged_ratio_threshold
                or avg_risk_score >= safe_avg_risk_threshold
            ):
                suspicious_candidate_ips += 1
            ip_rows.append(
                {
                    "remote_addr": row["remote_addr"] or "",
                    "total_requests": total,
                    "blocked_requests": blocked,
                    "monitored_requests": monitored,
                    "flagged_requests": blocked + monitored,
                    "unique_paths": unique_paths,
                    "avg_risk_score": avg_risk_score,
                    "max_risk_score": max_risk_score,
                    "block_ratio": block_ratio,
                    "flagged_ratio": flagged_ratio,
                }
            )

        return {
            "window_seconds": safe_window,
            "since_epoch": since_epoch,
            "distinct_ips": len(ip_rows),
            "total_requests": int(total_requests),
            "avg_requests_per_ip": round((total_requests / float(len(ip_rows))) if ip_rows else 0.0, 4),
            "max_requests_per_ip": max((int(item["total_requests"] or 0) for item in ip_rows), default=0),
            "high_volume_ips": int(high_volume_ips),
            "recon_like_ips": int(recon_like_ips),
            "offender_ips": int(offender_ips),
            "flagged_ips": int(flagged_ips),
            "high_risk_ips": int(high_risk_ips),
            "suspicious_candidate_ips": int(suspicious_candidate_ips),
            "ip_rows": ip_rows,
        }

    def get_feedback_loop_telemetry(self, window_seconds: int) -> Dict[str, object]:
        safe_window = max(int(window_seconds or 86400), 60)
        since_epoch = to_epoch() - float(safe_window)

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    SUM(CASE WHEN label IN ('benign', 'malicious') THEN 1 ELSE 0 END) AS total_feedback,
                    SUM(CASE WHEN label = 'benign' THEN 1 ELSE 0 END) AS benign_feedback,
                    SUM(CASE WHEN label = 'malicious' THEN 1 ELSE 0 END) AS malicious_feedback,
                    SUM(CASE WHEN label = 'benign' AND decision_action = 'block' THEN 1 ELSE 0 END) AS benign_blocked,
                    SUM(CASE WHEN label = 'benign' AND decision_action = 'monitor' THEN 1 ELSE 0 END) AS benign_monitored,
                    SUM(CASE WHEN label = 'malicious' AND decision_action = 'allow' THEN 1 ELSE 0 END) AS malicious_allowed,
                    SUM(CASE WHEN label = 'malicious' AND decision_action = 'monitor' THEN 1 ELSE 0 END) AS malicious_monitored
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                """,
                (since_epoch, "live"),
            ).fetchone()

        return {
            "window_seconds": safe_window,
            "since_epoch": since_epoch,
            "total_feedback": int(row["total_feedback"] or 0),
            "benign_feedback": int(row["benign_feedback"] or 0),
            "malicious_feedback": int(row["malicious_feedback"] or 0),
            "benign_blocked": int(row["benign_blocked"] or 0),
            "benign_monitored": int(row["benign_monitored"] or 0),
            "malicious_allowed": int(row["malicious_allowed"] or 0),
            "malicious_monitored": int(row["malicious_monitored"] or 0),
        }

    def get_ml_log_training_telemetry(self, window_seconds: int) -> Dict[str, object]:
        safe_window = max(int(window_seconds or 604800), 60)
        since_epoch = to_epoch() - float(safe_window)

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_live_requests,
                    SUM(CASE WHEN label IN ('benign', 'malicious') THEN 1 ELSE 0 END) AS labeled_rows,
                    SUM(CASE WHEN label = 'benign' THEN 1 ELSE 0 END) AS benign_rows,
                    SUM(CASE WHEN label = 'malicious' THEN 1 ELSE 0 END) AS malicious_rows,
                    COUNT(DISTINCT CASE WHEN label IN ('benign', 'malicious') THEN path END) AS distinct_labeled_paths,
                    MAX(CASE WHEN label IN ('benign', 'malicious') THEN timestamp_epoch END) AS latest_label_epoch
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                """,
                (since_epoch, "live"),
            ).fetchone()

        total_live_requests = int(row["total_live_requests"] or 0)
        labeled_rows = int(row["labeled_rows"] or 0)
        return {
            "window_seconds": safe_window,
            "since_epoch": since_epoch,
            "total_live_requests": total_live_requests,
            "labeled_rows": labeled_rows,
            "benign_rows": int(row["benign_rows"] or 0),
            "malicious_rows": int(row["malicious_rows"] or 0),
            "distinct_labeled_paths": int(row["distinct_labeled_paths"] or 0),
            "latest_label_epoch": float(row["latest_label_epoch"] or 0.0),
            "label_coverage_rate": round((labeled_rows / float(max(total_live_requests, 1))) if total_live_requests else 0.0, 4),
        }

    def list_labeled_training_rows(self, window_seconds: int) -> List[Dict[str, object]]:
        safe_window = max(int(window_seconds or 604800), 60)
        since_epoch = to_epoch() - float(safe_window)

        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT
                    request_id,
                    timestamp,
                    method,
                    path,
                    remote_addr,
                    label,
                    attack_types_json,
                    feature_json
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                  AND label IN ('benign', 'malicious')
                ORDER BY timestamp_epoch DESC
                """,
                (since_epoch, "live"),
            ).fetchall()

        items = []
        for row in rows:
            items.append(
                {
                    "request_id": row["request_id"],
                    "timestamp": row["timestamp"],
                    "method": row["method"],
                    "path": row["path"],
                    "remote_addr": row["remote_addr"],
                    "label": row["label"],
                    "attack_types": json.loads(row["attack_types_json"] or "[]"),
                    "features": json.loads(row["feature_json"] or "{}"),
                }
            )
        return items

    def set_runtime_setting_overrides(self, values: Dict[str, object], updated_by: str = "") -> Dict[str, object]:
        updated_at = to_iso()
        with closing(self._connect()) as connection, connection:
            for key, value in values.items():
                connection.execute(
                    """
                    INSERT INTO system_settings (setting_key, value_json, updated_at, updated_by)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(setting_key) DO UPDATE SET
                        value_json = excluded.value_json,
                        updated_at = excluded.updated_at,
                        updated_by = excluded.updated_by
                    """,
                    (key, json_dumps(value), updated_at, updated_by),
                )
        return self.get_runtime_setting_overrides()

    def purge_expired_manual_block_rules(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                DELETE FROM manual_block_rules
                WHERE expires_at_epoch IS NOT NULL
                  AND expires_at_epoch <= ?
                """,
                (to_epoch(),),
            )

    def _manual_block_row_to_record(self, row) -> ManualBlockRule:
        return ManualBlockRule(
            rule_id=row["rule_id"],
            scope_type=row["scope_type"],
            reason=row["reason"],
            source=row["source"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            criteria=json.loads(row["criteria_json"] or "{}"),
        )

    def list_manual_block_rules(self) -> List[Dict[str, object]]:
        self.purge_expired_manual_block_rules()
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT rule_id, scope_type, reason, source, criteria_json, created_at, expires_at
                FROM manual_block_rules
                ORDER BY created_at_epoch DESC
                """
            ).fetchall()

        return [self._manual_block_row_to_record(row).as_dict() for row in rows]

    def _active_manual_block_records(self) -> List[ManualBlockRule]:
        self.purge_expired_manual_block_rules()
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT rule_id, scope_type, reason, source, criteria_json, created_at, expires_at
                FROM manual_block_rules
                ORDER BY created_at_epoch DESC
                """
            ).fetchall()

        return [self._manual_block_row_to_record(row) for row in rows]

    def add_manual_block_rule(
        self,
        scope_type: str,
        criteria: Dict[str, object],
        reason: str,
        source: str = "manual",
        ttl_seconds: Optional[int] = None,
    ) -> Dict[str, object]:
        now = utc_now()
        normalized_scope = (scope_type or "signature").strip().lower()
        normalized_criteria = dict(criteria or {})
        criteria_json = json_dumps(normalized_criteria)
        expires_at = now + timedelta(seconds=ttl_seconds) if ttl_seconds else None

        with closing(self._connect()) as connection, connection:
            existing = connection.execute(
                """
                SELECT rule_id
                FROM manual_block_rules
                WHERE scope_type = ?
                  AND criteria_json = ?
                LIMIT 1
                """,
                (normalized_scope, criteria_json),
            ).fetchone()

            rule_id = existing["rule_id"] if existing else uuid4().hex[:12]
            connection.execute(
                """
                INSERT INTO manual_block_rules (
                    rule_id,
                    scope_type,
                    reason,
                    source,
                    criteria_json,
                    created_at,
                    created_at_epoch,
                    expires_at,
                    expires_at_epoch
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    scope_type = excluded.scope_type,
                    reason = excluded.reason,
                    source = excluded.source,
                    criteria_json = excluded.criteria_json,
                    created_at = excluded.created_at,
                    created_at_epoch = excluded.created_at_epoch,
                    expires_at = excluded.expires_at,
                    expires_at_epoch = excluded.expires_at_epoch
                """,
                (
                    rule_id,
                    normalized_scope,
                    reason,
                    source,
                    criteria_json,
                    to_iso(now),
                    to_epoch(now),
                    to_iso(expires_at) if expires_at else None,
                    to_epoch(expires_at) if expires_at else None,
                ),
            )

        return {
            "rule_id": rule_id,
            "scope_type": normalized_scope,
            "reason": reason,
            "source": source,
            "created_at": to_iso(now),
            "expires_at": to_iso(expires_at) if expires_at else None,
            "criteria": normalized_criteria,
        }

    def remove_manual_block_rule(self, rule_id: str) -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute("DELETE FROM manual_block_rules WHERE rule_id = ?", (rule_id,))
        return bool(cursor.rowcount)

    def build_manual_block_criteria(self, request_detail: Dict[str, object], scope_type: str) -> Dict[str, object]:
        normalized_scope = (scope_type or "signature").strip().lower()
        if normalized_scope == "path":
            return {
                "method": request_detail["method"],
                "path": request_detail["path"],
            }

        if normalized_scope == "session":
            session_id = str(request_detail.get("session_id") or "")
            if not session_id or session_id == "anonymous":
                raise ValueError("session scope requires a non-anonymous session_id")
            return {"session_id": session_id}

        if normalized_scope == "ip":
            return {"remote_addr": request_detail["remote_addr"]}

        return {
            "request_fingerprint": request_detail["request_fingerprint"],
            "method": request_detail["method"],
            "path": request_detail["path"],
        }

    def create_manual_block_rule_from_request(
        self,
        request_detail: Dict[str, object],
        scope_type: str,
        reason: str,
        source: str = "manual",
        ttl_seconds: Optional[int] = None,
    ) -> Dict[str, object]:
        criteria = self.build_manual_block_criteria(request_detail, scope_type)
        return self.add_manual_block_rule(
            scope_type=scope_type,
            criteria=criteria,
            reason=reason,
            source=source,
            ttl_seconds=ttl_seconds,
        )

    def match_manual_block_rule(
        self,
        request_fingerprint: str,
        method: str,
        path: str,
        session_id: str,
        remote_addr: str,
    ) -> Optional[Dict[str, object]]:
        for rule in self._active_manual_block_records():
            if rule.matches_values(
                request_fingerprint=request_fingerprint,
                method=method,
                path=path,
                session_id=session_id,
                remote_addr=remote_addr,
            ):
                return rule.as_dict()
        return None

    def match_manual_block_rule_for_request(self, request_record) -> Optional[Dict[str, object]]:
        return self.match_manual_block_rule(
            request_fingerprint=request_record.request_fingerprint,
            method=request_record.method,
            path=request_record.path,
            session_id=request_record.session_id,
            remote_addr=request_record.remote_addr,
        )

    def list_endpoint_policies(self, enabled_only: bool = False) -> List[Dict[str, object]]:
        query = """
            SELECT
                policy_id,
                name,
                description,
                path_pattern,
                methods_json,
                priority,
                sensitivity,
                settings_json,
                source,
                is_enabled,
                created_at,
                updated_at
            FROM endpoint_policies
        """
        params: list[object] = []
        if enabled_only:
            query += " WHERE is_enabled = ?"
            params.append(1)
        query += " ORDER BY priority DESC, updated_at DESC"

        with closing(self._connect()) as connection:
            rows = connection.execute(query, tuple(params)).fetchall()

        items = []
        for row in rows:
            items.append(
                {
                    "policy_id": row["policy_id"],
                    "name": row["name"],
                    "description": row["description"] or "",
                    "path_pattern": row["path_pattern"],
                    "methods": json.loads(row["methods_json"] or "[]"),
                    "priority": int(row["priority"] or 0),
                    "sensitivity": row["sensitivity"] or "protected",
                    "settings": json.loads(row["settings_json"] or "{}"),
                    "source": row["source"] or "custom",
                    "is_enabled": bool(row["is_enabled"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
            )
        return items

    def save_endpoint_policy(
        self,
        *,
        policy_id: Optional[str] = None,
        name: str,
        description: str,
        path_pattern: str,
        methods: List[str],
        priority: int,
        sensitivity: str,
        settings_map: Dict[str, object],
        source: str = "custom",
        is_enabled: bool = True,
    ) -> Dict[str, object]:
        current_time = to_iso()
        resolved_policy_id = policy_id or uuid4().hex[:12]
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO endpoint_policies (
                    policy_id,
                    name,
                    description,
                    path_pattern,
                    methods_json,
                    priority,
                    sensitivity,
                    settings_json,
                    source,
                    is_enabled,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(policy_id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    path_pattern = excluded.path_pattern,
                    methods_json = excluded.methods_json,
                    priority = excluded.priority,
                    sensitivity = excluded.sensitivity,
                    settings_json = excluded.settings_json,
                    source = excluded.source,
                    is_enabled = excluded.is_enabled,
                    updated_at = excluded.updated_at
                """,
                (
                    resolved_policy_id,
                    name,
                    description,
                    path_pattern,
                    json_dumps(methods),
                    int(priority or 0),
                    sensitivity,
                    json_dumps(settings_map or {}),
                    source,
                    int(bool(is_enabled)),
                    current_time,
                    current_time,
                ),
            )

        for item in self.list_endpoint_policies(enabled_only=False):
            if item["policy_id"] == resolved_policy_id:
                return item
        raise RuntimeError("Failed to save endpoint policy")

    def delete_endpoint_policy(self, policy_id: str) -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute("DELETE FROM endpoint_policies WHERE policy_id = ?", (policy_id,))
        return bool(cursor.rowcount)

    def consume_rate_limit_token(
        self,
        ip_address: str,
        capacity: int,
        refill_rate: float,
        now_epoch: Optional[float] = None,
    ) -> Dict[str, float | bool]:
        current_epoch = float(now_epoch if now_epoch is not None else to_epoch())
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT tokens, updated_at_epoch FROM rate_limit_state WHERE ip_address = ?",
                (ip_address,),
            ).fetchone()

            if row is None:
                tokens = float(capacity)
                updated_at_epoch = current_epoch
            else:
                tokens = float(row["tokens"])
                updated_at_epoch = float(row["updated_at_epoch"])

            elapsed_seconds = max(current_epoch - updated_at_epoch, 0.0)
            tokens = min(float(capacity), tokens + elapsed_seconds * float(refill_rate))
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0

            connection.execute(
                """
                INSERT INTO rate_limit_state (ip_address, tokens, updated_at_epoch)
                VALUES (?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    tokens = excluded.tokens,
                    updated_at_epoch = excluded.updated_at_epoch
                """,
                (ip_address, tokens, current_epoch),
            )

        return {
            "allowed": allowed,
            "remaining_tokens": round(tokens, 4),
            "capacity": float(capacity),
            "refill_rate": float(refill_rate),
        }

    def get_history_snapshot(self, request_record, window_seconds: int) -> HistorySnapshot:
        since_epoch = request_record.timestamp_epoch - float(window_seconds)
        traffic_origin = self._request_traffic_origin(request_record)
        with closing(self._connect()) as connection:
            ip_row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_requests,
                    SUM(CASE WHEN decision_action = 'block' THEN 1 ELSE 0 END) AS blocked_requests,
                    SUM(CASE WHEN decision_action = 'monitor' THEN 1 ELSE 0 END) AS monitored_requests,
                    COUNT(DISTINCT path) AS unique_paths,
                    AVG(risk_score) AS avg_risk_score,
                    MAX(risk_score) AS max_risk_score
                FROM requests
                WHERE remote_addr = ?
                  AND timestamp_epoch >= ?
                  AND traffic_origin = ?
                """,
                (request_record.remote_addr, since_epoch, traffic_origin),
            ).fetchone()

            session_row = None
            if request_record.session_id and request_record.session_id != "anonymous":
                session_row = connection.execute(
                    """
                    SELECT COUNT(*) AS total_requests
                    FROM requests
                    WHERE session_id = ?
                      AND timestamp_epoch >= ?
                      AND traffic_origin = ?
                    """,
                    (request_record.session_id, since_epoch, traffic_origin),
                ).fetchone()

            fingerprint_row = connection.execute(
                """
                SELECT COUNT(*) AS total_requests
                FROM requests
                WHERE remote_addr = ?
                  AND request_fingerprint = ?
                  AND timestamp_epoch >= ?
                  AND traffic_origin = ?
                """,
                (request_record.remote_addr, request_record.request_fingerprint, since_epoch, traffic_origin),
            ).fetchone()

            path_row = connection.execute(
                """
                SELECT COUNT(*) AS total_requests
                FROM requests
                WHERE remote_addr = ?
                  AND path = ?
                  AND timestamp_epoch >= ?
                  AND traffic_origin = ?
                """,
                (request_record.remote_addr, request_record.path, since_epoch, traffic_origin),
            ).fetchone()

        return HistorySnapshot(
            ip_request_count_window=int(ip_row["total_requests"] or 0),
            ip_block_count_window=int(ip_row["blocked_requests"] or 0),
            ip_monitor_count_window=int(ip_row["monitored_requests"] or 0),
            session_request_count_window=int(session_row["total_requests"] or 0) if session_row else 0,
            fingerprint_reuse_count=int(fingerprint_row["total_requests"] or 0),
            path_hits_window=int(path_row["total_requests"] or 0),
            unique_paths_window=int(ip_row["unique_paths"] or 0),
            ip_avg_risk_score_window=float(ip_row["avg_risk_score"] or 0.0),
            ip_max_risk_score_window=float(ip_row["max_risk_score"] or 0.0),
        )

    def record_request(
        self,
        request_record,
        features: Dict[str, float],
        score_result,
        rule_result,
        decision,
        history_snapshot,
        latency_ms: float,
        attack_types: List[str],
        backend_status: Optional[int],
        was_proxied: bool,
        endpoint_policy: Optional[Dict[str, object]] = None,
    ) -> None:
        traffic_origin = self._request_traffic_origin(request_record)
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """
                INSERT INTO requests (
                    request_id,
                    timestamp,
                    timestamp_epoch,
                    method,
                    scheme,
                    host,
                    path,
                    query_string,
                    full_url,
                    gateway_path,
                    remote_addr,
                    user_agent,
                    session_id,
                    request_fingerprint,
                    content_type,
                    body_length,
                    payload_hash,
                    payload_preview,
                    feature_json,
                    score_json,
                    rule_json,
                    decision_json,
                    history_json,
                    attack_types_json,
                    decision_action,
                    decision_status_code,
                    risk_score,
                    latency_ms,
                    backend_status,
                    was_proxied,
                    traffic_origin,
                    endpoint_policy_json,
                    label,
                    notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                ON CONFLICT(request_id) DO UPDATE SET
                    timestamp = excluded.timestamp,
                    timestamp_epoch = excluded.timestamp_epoch,
                    method = excluded.method,
                    scheme = excluded.scheme,
                    host = excluded.host,
                    path = excluded.path,
                    query_string = excluded.query_string,
                    full_url = excluded.full_url,
                    gateway_path = excluded.gateway_path,
                    remote_addr = excluded.remote_addr,
                    user_agent = excluded.user_agent,
                    session_id = excluded.session_id,
                    request_fingerprint = excluded.request_fingerprint,
                    content_type = excluded.content_type,
                    body_length = excluded.body_length,
                    payload_hash = excluded.payload_hash,
                    payload_preview = excluded.payload_preview,
                    feature_json = excluded.feature_json,
                    score_json = excluded.score_json,
                    rule_json = excluded.rule_json,
                    decision_json = excluded.decision_json,
                    history_json = excluded.history_json,
                    attack_types_json = excluded.attack_types_json,
                    decision_action = excluded.decision_action,
                    decision_status_code = excluded.decision_status_code,
                    risk_score = excluded.risk_score,
                    latency_ms = excluded.latency_ms,
                    backend_status = excluded.backend_status,
                    was_proxied = excluded.was_proxied,
                    traffic_origin = excluded.traffic_origin,
                    endpoint_policy_json = excluded.endpoint_policy_json,
                    label = requests.label,
                    notes = requests.notes
                """,
                (
                    request_record.request_id,
                    request_record.timestamp,
                    request_record.timestamp_epoch,
                    request_record.method,
                    request_record.scheme,
                    request_record.host,
                    request_record.path,
                    request_record.query_string,
                    request_record.url,
                    request_record.gateway_path,
                    request_record.remote_addr,
                    request_record.user_agent,
                    request_record.session_id,
                    request_record.request_fingerprint,
                    request_record.content_type,
                    request_record.body_length,
                    request_record.payload_hash,
                    request_record.payload_preview,
                    json_dumps(features),
                    json_dumps(score_result.as_dict()),
                    json_dumps(rule_result.as_dict()),
                    json_dumps(decision.as_dict()),
                    json_dumps(history_snapshot.as_dict() if history_snapshot else {}),
                    json_dumps(sorted(set(attack_types))),
                    decision.action,
                    decision.status_code,
                    decision.risk_score,
                    round(latency_ms, 4),
                    backend_status,
                    int(bool(was_proxied)),
                    traffic_origin,
                    json_dumps(endpoint_policy or {}),
                ),
            )

    def update_request_label(self, request_id: str, label: str, notes: str = "") -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                "UPDATE requests SET label = ?, notes = ? WHERE request_id = ?",
                (label, notes, request_id),
            )
        return bool(cursor.rowcount)

    def register_model_version(
        self,
        model_version: str,
        model_type: str,
        artifact_path: str,
        metrics: Dict[str, float],
        is_active: bool = True,
    ) -> None:
        with closing(self._connect()) as connection, connection:
            if is_active:
                connection.execute("UPDATE model_registry SET is_active = 0")
            connection.execute(
                """
                INSERT INTO model_registry (
                    model_version,
                    model_type,
                    artifact_path,
                    metrics_json,
                    created_at,
                    is_active
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(model_version) DO UPDATE SET
                    model_type = excluded.model_type,
                    artifact_path = excluded.artifact_path,
                    metrics_json = excluded.metrics_json,
                    created_at = excluded.created_at,
                    is_active = excluded.is_active
                """,
                (
                    model_version,
                    model_type,
                    artifact_path,
                    json_dumps(metrics),
                    to_iso(),
                    int(bool(is_active)),
                ),
            )

    def get_active_model_metadata(self) -> Optional[Dict[str, object]]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT model_version, model_type, artifact_path, metrics_json, created_at
                FROM model_registry
                WHERE is_active = 1
                ORDER BY created_at DESC
                LIMIT 1
                """
            ).fetchone()

        if row is None:
            return None

        return {
            "model_version": row["model_version"],
            "model_type": row["model_type"],
            "artifact_path": row["artifact_path"],
            "metrics": json.loads(row["metrics_json"]) if row["metrics_json"] else {},
            "created_at": row["created_at"],
        }

    def get_request(self, request_id: str) -> Optional[Dict[str, object]]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT request_id, timestamp, method, path, remote_addr, decision_action, risk_score,
                       traffic_origin,
                       attack_types_json, label, notes
                FROM requests
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()

        if row is None:
            return None

        return {
            "request_id": row["request_id"],
            "timestamp": row["timestamp"],
            "method": row["method"],
            "path": row["path"],
            "remote_addr": row["remote_addr"],
            "decision_action": row["decision_action"],
            "risk_score": row["risk_score"],
            "traffic_origin": row["traffic_origin"] or "live",
            "attack_types": json.loads(row["attack_types_json"] or "[]"),
            "label": row["label"],
            "notes": row["notes"],
        }

    def _request_row_to_summary(
        self,
        row,
        manual_block_rule: Optional[Dict[str, object]] = None,
        source_blacklisted: bool = False,
    ) -> Dict[str, object]:
        return {
            "request_id": row["request_id"],
            "timestamp": row["timestamp"],
            "remote_addr": row["remote_addr"],
            "method": row["method"],
            "path": row["path"],
            "action": row["decision_action"],
            "risk_score": round(float(row["risk_score"] or 0.0), 4),
            "latency_ms": round(float(row["latency_ms"] or 0.0), 3),
            "backend_status": row["backend_status"],
            "label": row["label"],
            "notes": row["notes"] or "",
            "traffic_origin": row["traffic_origin"] or "live",
            "attack_types": json.loads(row["attack_types_json"] or "[]"),
            "payload_preview": row["payload_preview"] or "",
            "manual_block_rule": manual_block_rule,
            "manually_blocked": bool(manual_block_rule),
            "source_blacklisted": bool(source_blacklisted),
        }

    def list_requests(
        self,
        page: int = 1,
        page_size: int = 20,
        search: str = "",
        action: Optional[str] = None,
        label: Optional[str] = None,
        attack_type: Optional[str] = None,
        remote_addr: Optional[str] = None,
        include_simulated: bool = False,
    ) -> Dict[str, object]:
        safe_page = max(int(page or 1), 1)
        safe_page_size = min(max(int(page_size or 20), 1), 100)
        offset = (safe_page - 1) * safe_page_size

        clauses = []
        params: List[object] = []

        if not include_simulated:
            clauses.append("traffic_origin = ?")
            params.append("live")

        if search:
            search_value = "%{0}%".format(search.strip())
            clauses.append(
                """
                (
                    request_id LIKE ?
                    OR path LIKE ?
                    OR remote_addr LIKE ?
                    OR method LIKE ?
                    OR payload_preview LIKE ?
                )
                """
            )
            params.extend([search_value, search_value, search_value, search_value, search_value])

        if action:
            clauses.append("decision_action = ?")
            params.append(action.strip().lower())

        if label:
            clauses.append("COALESCE(label, '') = ?")
            params.append(label.strip())

        if attack_type:
            clauses.append("LOWER(attack_types_json) LIKE ?")
            params.append("%{0}%".format(attack_type.strip().lower()))

        if remote_addr:
            clauses.append("remote_addr = ?")
            params.append(remote_addr.strip())

        where_clause = ""
        if clauses:
            where_clause = "WHERE " + " AND ".join(clauses)

        count_query = "SELECT COUNT(*) AS total FROM requests {0}".format(where_clause)
        rows_query = """
            SELECT
                request_id,
                timestamp,
                remote_addr,
                method,
                path,
                session_id,
                request_fingerprint,
                decision_action,
                risk_score,
                latency_ms,
                backend_status,
                label,
                notes,
                traffic_origin,
                attack_types_json,
                payload_preview
            FROM requests
            {0}
            ORDER BY timestamp_epoch DESC
            LIMIT ? OFFSET ?
        """.format(where_clause)

        with closing(self._connect()) as connection:
            total = int(connection.execute(count_query, tuple(params)).fetchone()["total"] or 0)
            rows = connection.execute(rows_query, tuple(params + [safe_page_size, offset])).fetchall()

        active_manual_rules = self._active_manual_block_records()
        active_blacklist = {item["ip_address"] for item in self.list_blacklist()}

        items = []
        for row in rows:
            matched_rule = None
            for rule in active_manual_rules:
                if rule.matches_values(
                    request_fingerprint=row["request_fingerprint"],
                    method=row["method"],
                    path=row["path"],
                    session_id=row["session_id"] or "",
                    remote_addr=row["remote_addr"],
                ):
                    matched_rule = rule.as_dict()
                    break

            items.append(
                self._request_row_to_summary(
                    row,
                    manual_block_rule=matched_rule,
                    source_blacklisted=row["remote_addr"] in active_blacklist,
                )
            )

        return {
            "items": items,
            "pagination": {
                "page": safe_page,
                "page_size": safe_page_size,
                "total": total,
                "pages": max((total + safe_page_size - 1) // safe_page_size, 1),
            },
            "filters": {
                "search": search,
                "action": action,
                "label": label,
                "attack_type": attack_type,
                "remote_addr": remote_addr,
                "include_simulated": include_simulated,
            },
        }

    def get_request_detail(self, request_id: str) -> Optional[Dict[str, object]]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    request_id,
                    timestamp,
                    timestamp_epoch,
                    method,
                    scheme,
                    host,
                    path,
                    query_string,
                    full_url,
                    gateway_path,
                    remote_addr,
                    user_agent,
                    session_id,
                    request_fingerprint,
                    content_type,
                    body_length,
                    payload_hash,
                    payload_preview,
                    feature_json,
                    score_json,
                    rule_json,
                    decision_json,
                    history_json,
                    attack_types_json,
                    decision_action,
                    decision_status_code,
                    risk_score,
                    latency_ms,
                    backend_status,
                    was_proxied,
                    traffic_origin,
                    endpoint_policy_json,
                    label,
                    notes
                FROM requests
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()

        if row is None:
            return None

        manual_block_rule = self.match_manual_block_rule(
            request_fingerprint=row["request_fingerprint"] or "",
            method=row["method"] or "GET",
            path=row["path"] or "/",
            session_id=row["session_id"] or "",
            remote_addr=row["remote_addr"] or "",
        )
        source_blacklisted = self.is_blacklisted(row["remote_addr"] or "") is not None

        return {
            "request_id": row["request_id"],
            "timestamp": row["timestamp"],
            "timestamp_epoch": float(row["timestamp_epoch"] or 0.0),
            "method": row["method"],
            "scheme": row["scheme"],
            "host": row["host"],
            "path": row["path"],
            "query_string": row["query_string"] or "",
            "full_url": row["full_url"],
            "gateway_path": row["gateway_path"],
            "remote_addr": row["remote_addr"],
            "user_agent": row["user_agent"] or "",
            "session_id": row["session_id"] or "",
            "request_fingerprint": row["request_fingerprint"] or "",
            "content_type": row["content_type"] or "",
            "body_length": int(row["body_length"] or 0),
            "payload_hash": row["payload_hash"] or "",
            "payload_preview": row["payload_preview"] or "",
            "features": json.loads(row["feature_json"] or "{}"),
            "score_breakdown": json.loads(row["score_json"] or "{}"),
            "rule_result": json.loads(row["rule_json"] or "{}"),
            "decision_engine": json.loads(row["decision_json"] or "{}"),
            "history_snapshot": json.loads(row["history_json"] or "{}"),
            "attack_types": json.loads(row["attack_types_json"] or "[]"),
            "decision_action": row["decision_action"],
            "decision_status_code": int(row["decision_status_code"] or 0),
            "risk_score": round(float(row["risk_score"] or 0.0), 4),
            "latency_ms": round(float(row["latency_ms"] or 0.0), 3),
            "backend_status": row["backend_status"],
            "was_proxied": bool(row["was_proxied"]),
            "traffic_origin": row["traffic_origin"] or "live",
            "endpoint_policy": json.loads(row["endpoint_policy_json"] or "{}"),
            "label": row["label"],
            "notes": row["notes"] or "",
            "manual_block_rule": manual_block_rule,
            "manually_blocked": bool(manual_block_rule),
            "source_blacklisted": source_blacklisted,
        }

    def delete_request(self, request_id: str) -> bool:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute("DELETE FROM requests WHERE request_id = ?", (request_id,))
        return bool(cursor.rowcount)

    def request_timeline(self, window_seconds: int, bucket_seconds: int = 3600) -> Dict[str, object]:
        safe_window = max(int(window_seconds or 3600), 60)
        safe_bucket = max(int(bucket_seconds or 3600), 60)
        since_epoch = to_epoch() - float(safe_window)

        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT timestamp_epoch, decision_action
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                ORDER BY timestamp_epoch ASC
                """,
                (since_epoch, "live"),
            ).fetchall()

        buckets: Dict[int, Dict[str, int]] = {}
        current_bucket = int(since_epoch // safe_bucket) * safe_bucket
        end_bucket = int(to_epoch() // safe_bucket) * safe_bucket

        while current_bucket <= end_bucket:
            buckets[current_bucket] = {"allow": 0, "monitor": 0, "block": 0}
            current_bucket += safe_bucket

        for row in rows:
            bucket = int(float(row["timestamp_epoch"]) // safe_bucket) * safe_bucket
            if bucket not in buckets:
                buckets[bucket] = {"allow": 0, "monitor": 0, "block": 0}
            action = (row["decision_action"] or "allow").strip().lower()
            if action not in buckets[bucket]:
                buckets[bucket][action] = 0
            buckets[bucket][action] += 1

        items = []
        for bucket_start in sorted(buckets.keys()):
            bucket_time = datetime.fromtimestamp(bucket_start, tz=timezone.utc).isoformat(timespec="seconds")
            items.append(
                {
                    "bucket_start": bucket_time,
                    "allow": buckets[bucket_start].get("allow", 0),
                    "monitor": buckets[bucket_start].get("monitor", 0),
                    "block": buckets[bucket_start].get("block", 0),
                }
            )

        return {
            "generated_at": to_iso(),
            "window_seconds": safe_window,
            "bucket_seconds": safe_bucket,
            "items": items,
        }

    def get_security_scope_telemetry(self, window_seconds: int) -> Dict[str, object]:
        safe_window = max(int(window_seconds or 3600), 60)
        since_epoch = to_epoch() - float(safe_window)

        with closing(self._connect()) as connection:
            path_rows = connection.execute(
                """
                SELECT
                    path,
                    method,
                    COUNT(*) AS total_requests,
                    SUM(CASE WHEN decision_action = 'block' THEN 1 ELSE 0 END) AS blocked_requests,
                    SUM(CASE WHEN LOWER(attack_types_json) LIKE '%ddos%' THEN 1 ELSE 0 END) AS ddos_events,
                    AVG(risk_score) AS avg_risk_score,
                    MAX(risk_score) AS max_risk_score
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                GROUP BY path, method
                ORDER BY ddos_events DESC, total_requests DESC, avg_risk_score DESC
                LIMIT 12
                """,
                (since_epoch, "live"),
            ).fetchall()
            feature_rows = connection.execute(
                """
                SELECT feature_json
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                """,
                (since_epoch, "live"),
            ).fetchall()
            metric_row = connection.execute(
                """
                SELECT
                    SUM(CASE WHEN LOWER(attack_types_json) LIKE '%ddos%' THEN 1 ELSE 0 END) AS ddos_events,
                    SUM(
                        CASE
                            WHEN LOWER(attack_types_json) LIKE '%ddos%'
                             AND decision_action = 'block' THEN 1
                            ELSE 0
                        END
                    ) AS blocked_ddos_events,
                    SUM(
                        CASE
                            WHEN path LIKE '%auth%'
                              OR path LIKE '%login%'
                              OR path LIKE '%admin%'
                              OR path LIKE '/config%' THEN 1
                            ELSE 0
                        END
                    ) AS sensitive_path_hits
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                """,
                (since_epoch, "live"),
            ).fetchone()

        top_paths = []
        for row in path_rows:
            top_paths.append(
                {
                    "path": row["path"],
                    "method": row["method"],
                    "total_requests": int(row["total_requests"] or 0),
                    "blocked_requests": int(row["blocked_requests"] or 0),
                    "ddos_events": int(row["ddos_events"] or 0),
                    "avg_risk_score": round(float(row["avg_risk_score"] or 0.0), 4),
                    "max_risk_score": round(float(row["max_risk_score"] or 0.0), 4),
                }
            )

        syn_like_events = 0
        connection_reset_events = 0
        abnormal_session_events = 0
        udp_transport_events = 0
        connection_churn_events = 0
        short_lived_abusive_events = 0
        retry_timeout_events = 0
        malformed_transport_events = 0
        transport_enriched_requests = 0
        for row in feature_rows:
            feature_map = json.loads(row["feature_json"] or "{}")
            if float(feature_map.get("syn_like_flood_signal", 0.0) or 0.0) > 0.0:
                syn_like_events += 1
            if float(feature_map.get("connection_reset_signal", 0.0) or 0.0) > 0.0:
                connection_reset_events += 1
            if float(feature_map.get("abnormal_session_establishment_signal", 0.0) or 0.0) > 0.0:
                abnormal_session_events += 1
            if float(feature_map.get("udp_flood_signal", 0.0) or 0.0) > 0.0:
                udp_transport_events += 1
            if float(feature_map.get("connection_churn_signal", 0.0) or 0.0) > 0.0:
                connection_churn_events += 1
            if float(feature_map.get("short_lived_abusive_signal", 0.0) or 0.0) > 0.0:
                short_lived_abusive_events += 1
            if float(feature_map.get("retry_timeout_signal", 0.0) or 0.0) > 0.0:
                retry_timeout_events += 1
            if float(feature_map.get("malformed_transport_signal", 0.0) or 0.0) > 0.0:
                malformed_transport_events += 1
            if float(feature_map.get("transport_enriched_signal", 0.0) or 0.0) > 0.0:
                transport_enriched_requests += 1

        return {
            "window_seconds": safe_window,
            "top_paths": top_paths,
            "ddos_events": int(metric_row["ddos_events"] or 0),
            "blocked_ddos_events": int(metric_row["blocked_ddos_events"] or 0),
            "sensitive_path_hits": int(metric_row["sensitive_path_hits"] or 0),
            "syn_like_events": syn_like_events,
            "connection_reset_events": connection_reset_events,
            "abnormal_session_events": abnormal_session_events,
            "udp_transport_events": udp_transport_events,
            "connection_churn_events": connection_churn_events,
            "short_lived_abusive_events": short_lived_abusive_events,
            "retry_timeout_events": retry_timeout_events,
            "malformed_transport_events": malformed_transport_events,
            "transport_enriched_requests": transport_enriched_requests,
        }

    def dashboard_snapshot(self, limit: int, window_seconds: int) -> Dict[str, object]:
        since_epoch = to_epoch() - float(window_seconds)
        with closing(self._connect()) as connection:
            metrics_row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_requests,
                    SUM(CASE WHEN decision_action = 'allow' THEN 1 ELSE 0 END) AS allowed_requests,
                    SUM(CASE WHEN decision_action = 'monitor' THEN 1 ELSE 0 END) AS monitored_requests,
                    SUM(CASE WHEN decision_action = 'block' THEN 1 ELSE 0 END) AS blocked_requests,
                    COUNT(DISTINCT remote_addr) AS unique_ips,
                    AVG(latency_ms) AS avg_latency_ms,
                    AVG(risk_score) AS avg_risk_score
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                """,
                (since_epoch, "live"),
            ).fetchone()

            offender_rows = connection.execute(
                """
                SELECT
                    remote_addr,
                    COUNT(*) AS total_requests,
                    SUM(CASE WHEN decision_action = 'block' THEN 1 ELSE 0 END) AS blocked_requests
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                GROUP BY remote_addr
                ORDER BY blocked_requests DESC, total_requests DESC
                LIMIT 5
                """,
                (since_epoch, "live"),
            ).fetchall()

            request_rows = connection.execute(
                """
                SELECT
                    request_id,
                    timestamp,
                    remote_addr,
                    method,
                    path,
                    decision_action,
                    risk_score,
                    latency_ms,
                    backend_status,
                    attack_types_json,
                    payload_preview
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                ORDER BY timestamp_epoch DESC
                LIMIT ?
                """,
                (since_epoch, "live", limit),
            ).fetchall()

            attack_rows = connection.execute(
                """
                SELECT attack_types_json
                FROM requests
                WHERE timestamp_epoch >= ?
                  AND traffic_origin = ?
                """,
                (since_epoch, "live"),
            ).fetchall()

            blacklist_count = connection.execute("SELECT COUNT(*) AS count FROM blacklist").fetchone()["count"]

        attack_counts: Dict[str, int] = {}
        for row in attack_rows:
            for attack_type in json.loads(row["attack_types_json"] or "[]"):
                attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

        top_attack_types = build_attack_distribution(attack_counts.keys(), attack_counts)

        events = []
        for row in request_rows:
            events.append(
                {
                    "request_id": row["request_id"],
                    "timestamp": row["timestamp"],
                    "remote_addr": row["remote_addr"],
                    "method": row["method"],
                    "path": row["path"],
                    "action": row["decision_action"],
                    "risk_score": float(row["risk_score"]),
                    "latency_ms": float(row["latency_ms"]),
                    "backend_status": row["backend_status"],
                    "attack_types": json.loads(row["attack_types_json"] or "[]"),
                    "payload_preview": row["payload_preview"],
                }
            )

        return {
            "generated_at": to_iso(),
            "window_seconds": window_seconds,
            "total_requests": int(metrics_row["total_requests"] or 0),
            "allowed": int(metrics_row["allowed_requests"] or 0),
            "monitored": int(metrics_row["monitored_requests"] or 0),
            "blocked": int(metrics_row["blocked_requests"] or 0),
            "unique_ips": int(metrics_row["unique_ips"] or 0),
            "avg_latency_ms": round(float(metrics_row["avg_latency_ms"] or 0.0), 3),
            "avg_risk_score": round(float(metrics_row["avg_risk_score"] or 0.0), 4),
            "blacklist_size": int(blacklist_count or 0),
            "top_attack_types": top_attack_types,
            "top_offenders": [
                {
                    "remote_addr": row["remote_addr"],
                    "total_requests": int(row["total_requests"] or 0),
                    "blocked_requests": int(row["blocked_requests"] or 0),
                }
                for row in offender_rows
            ],
            "events": events,
        }

    def summary_report(self, window_seconds: int) -> Dict[str, object]:
        summary = self.dashboard_snapshot(limit=25, window_seconds=window_seconds)
        summary["blacklist"] = self.list_blacklist()
        summary["manual_block_rules"] = self.list_manual_block_rules()
        summary["active_model"] = self.get_active_model_metadata()
        return summary

    def export_requests_csv(self, output_path: Path) -> Path:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT
                    request_id,
                    timestamp,
                    method,
                    path,
                    remote_addr,
                    session_id,
                    decision_action,
                    risk_score,
                    latency_ms,
                    backend_status,
                    label,
                    attack_types_json,
                    feature_json
                FROM requests
                WHERE traffic_origin = ?
                ORDER BY timestamp_epoch DESC
                """
            ,
                ("live",),
            ).fetchall()

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "request_id",
                    "timestamp",
                    "method",
                    "path",
                    "remote_addr",
                    "session_id",
                    "decision_action",
                    "risk_score",
                    "latency_ms",
                    "backend_status",
                    "label",
                    "attack_types_json",
                    "feature_json",
                ]
            )
            for row in rows:
                writer.writerow(
                    [
                        row["request_id"],
                        row["timestamp"],
                        row["method"],
                        row["path"],
                        row["remote_addr"],
                        row["session_id"],
                        row["decision_action"],
                        row["risk_score"],
                        row["latency_ms"],
                        row["backend_status"],
                        row["label"] or "",
                        row["attack_types_json"] or "[]",
                        row["feature_json"] or "{}",
                    ]
                )
        return output_path

    def export_labeled_dataset(self, output_path: Path, include_unlabeled: bool = False) -> Path:
        with closing(self._connect()) as connection:
            if include_unlabeled:
                rows = connection.execute(
                    """
                    SELECT request_id, timestamp, method, path, remote_addr, label, attack_types_json, feature_json
                    FROM requests
                    WHERE traffic_origin = ?
                    ORDER BY timestamp_epoch DESC
                    """
                ,
                    ("live",),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT request_id, timestamp, method, path, remote_addr, label, attack_types_json, feature_json
                    FROM requests
                    WHERE label IS NOT NULL
                      AND traffic_origin = ?
                    ORDER BY timestamp_epoch DESC
                    """
                ,
                    ("live",),
                ).fetchall()

        feature_names = set()
        parsed_rows = []
        for row in rows:
            feature_map = json.loads(row["feature_json"] or "{}")
            feature_names.update(feature_map.keys())
            parsed_rows.append((row, feature_map))

        ordered_features = sorted(feature_names)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "request_id",
                    "timestamp",
                    "method",
                    "path",
                    "remote_addr",
                    "label",
                    "attack_types_json",
                ]
                + ordered_features
            )
            for row, feature_map in parsed_rows:
                writer.writerow(
                    [
                        row["request_id"],
                        row["timestamp"],
                        row["method"],
                        row["path"],
                        row["remote_addr"],
                        row["label"] or "",
                        row["attack_types_json"] or "[]",
                    ]
                    + [feature_map.get(feature_name, 0.0) for feature_name in ordered_features]
                )
        return output_path
