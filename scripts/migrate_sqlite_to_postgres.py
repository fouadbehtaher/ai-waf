import argparse
import sqlite3
from contextlib import closing
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import settings
from core.storage import Storage


TABLES = [
    ("users", ["user_id", "username", "password_hash", "display_name", "role", "is_active", "created_at", "updated_at"]),
    (
        "requests",
        [
            "request_id",
            "timestamp",
            "timestamp_epoch",
            "method",
            "scheme",
            "host",
            "path",
            "query_string",
            "full_url",
            "gateway_path",
            "remote_addr",
            "user_agent",
            "session_id",
            "request_fingerprint",
            "content_type",
            "body_length",
            "payload_hash",
            "payload_preview",
            "feature_json",
            "score_json",
            "rule_json",
            "attack_types_json",
            "decision_action",
            "decision_status_code",
            "risk_score",
            "latency_ms",
            "backend_status",
            "was_proxied",
            "label",
            "notes",
        ],
    ),
    ("blacklist", ["ip_address", "reason", "source", "created_at", "created_at_epoch", "expires_at", "expires_at_epoch"]),
    ("rate_limit_state", ["ip_address", "tokens", "updated_at_epoch"]),
    ("model_registry", ["model_version", "model_type", "artifact_path", "metrics_json", "created_at", "is_active"]),
    (
        "manual_block_rules",
        ["rule_id", "scope_type", "reason", "source", "criteria_json", "created_at", "created_at_epoch", "expires_at", "expires_at_epoch"],
    ),
    (
        "auth_sessions",
        ["token", "user_id", "created_at", "created_at_epoch", "expires_at", "expires_at_epoch", "last_seen_at", "last_seen_epoch", "ip_address", "user_agent"],
    ),
    ("audit_log", ["event_id", "created_at", "created_at_epoch", "actor_user_id", "actor_username", "action", "target_type", "target_id", "details_json"]),
    ("system_settings", ["setting_key", "value_json", "updated_at", "updated_by"]),
]


def fetch_rows(sqlite_db_path: Path, table_name: str, columns: list[str]) -> list[tuple]:
    query = "SELECT {0} FROM {1}".format(", ".join(columns), table_name)
    with closing(sqlite3.connect(str(sqlite_db_path))) as connection:
        rows = connection.execute(query).fetchall()
    return [tuple(row) for row in rows]


def clear_postgres_target(target_storage: Storage) -> None:
    ordered_tables = [name for name, _ in TABLES]
    with closing(target_storage._connect()) as connection, connection:
        for table_name in reversed(ordered_tables):
            connection.execute("DELETE FROM {0}".format(table_name))


def migrate_table(target_storage: Storage, table_name: str, columns: list[str], rows: list[tuple]) -> int:
    if not rows:
        return 0
    placeholders = ", ".join("?" for _ in columns)
    insert_sql = "INSERT INTO {0} ({1}) VALUES ({2})".format(table_name, ", ".join(columns), placeholders)
    with closing(target_storage._connect()) as connection, connection:
        for row in rows:
            connection.execute(insert_sql, row)
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate the local SQLite WAF database into PostgreSQL.")
    parser.add_argument("--sqlite-db", default=str(settings.db_path), help="Path to the source SQLite database.")
    parser.add_argument("--postgres-url", default=settings.database_url, help="Destination PostgreSQL URL.")
    parser.add_argument("--truncate", action="store_true", help="Clear destination tables before migration.")
    parser.add_argument("--schema-only", action="store_true", help="Create the PostgreSQL schema without copying data.")
    args = parser.parse_args()

    sqlite_db_path = Path(args.sqlite_db)
    postgres_url = str(args.postgres_url or "").strip()

    if not postgres_url:
        raise SystemExit("A PostgreSQL URL is required. Set --postgres-url or WAF_DATABASE_URL.")
    if not sqlite_db_path.exists():
        raise SystemExit("SQLite database not found: {0}".format(sqlite_db_path))

    target_storage = Storage("", database_url=postgres_url)
    target_storage.initialize()

    if args.truncate:
        clear_postgres_target(target_storage)

    migrated_counts = {}
    if not args.schema_only:
        for table_name, columns in TABLES:
            rows = fetch_rows(sqlite_db_path, table_name, columns)
            migrated_counts[table_name] = migrate_table(target_storage, table_name, columns, rows)
    else:
        migrated_counts = {table_name: 0 for table_name, _ in TABLES}

    print("Migration completed")
    for table_name, count in migrated_counts.items():
        print("{0}: {1}".format(table_name, count))


if __name__ == "__main__":
    main()
