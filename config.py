import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, Tuple


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"
DOCS_DIR = BASE_DIR / "docs"
SCRIPTS_DIR = BASE_DIR / "scripts"
TESTS_DIR = BASE_DIR / "tests"
LOG_FILE = BASE_DIR / "waf.log"


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    return int(raw)


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    return float(raw)


def _tuple_env(name: str, default: Tuple[str, ...]) -> Tuple[str, ...]:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    values = tuple(item.strip() for item in raw.split(",") if item.strip())
    return values or default


@dataclass(frozen=True)
class Settings:
    app_name: str = "AI-Based WAF"
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False
    secret_key: str = "change-me-in-production"
    backend_base_url: str = "http://127.0.0.1:5001"
    database_url: str = ""
    transparent_proxy: bool = True
    frontend_dev_server_url: str = "http://127.0.0.1:5173"
    frontend_use_dev_server: bool = False
    frontend_public_url: str = "http://127.0.0.1:5173"
    cors_allowed_origins: Tuple[str, ...] = ("http://127.0.0.1:5173", "http://localhost:5173")
    redis_url: str = ""
    rate_limit_backend: str = "auto"
    redis_key_prefix: str = "waf"
    request_timeout_seconds: int = 10
    pre_app_filter_enabled: bool = True
    pre_app_filter_window_seconds: int = 10
    pre_app_filter_ip_request_threshold: int = 120
    pre_app_filter_ip_burst_threshold: int = 40
    pre_app_filter_global_request_threshold: int = 600
    pre_app_filter_ip_bytes_threshold: int = 1048576
    pre_app_filter_block_ttl_seconds: int = 15
    proxy_transport_controls_enabled: bool = True
    proxy_connect_timeout_seconds: float = 3.0
    proxy_read_timeout_seconds: float = 10.0
    proxy_idle_pool_recycle_seconds: int = 30
    proxy_upstream_pool_connections: int = 16
    proxy_upstream_pool_maxsize: int = 32
    proxy_upstream_concurrency_limit: int = 24
    proxy_upstream_pool_block: bool = True
    proxy_keepalive_abuse_protection_enabled: bool = True
    proxy_keepalive_monitor_score: int = 3
    proxy_keepalive_block_score: int = 5
    block_threshold: float = 0.72
    monitor_threshold: float = 0.48
    analytics_window_seconds: int = 900
    dashboard_window_seconds: int = 86400
    recent_event_limit: int = 100
    security_scope_window_seconds: int = 3600
    connection_tracking_enabled: bool = True
    connection_window_seconds: int = 30
    connection_stale_seconds: int = 20
    connection_monitor_active_threshold: int = 6
    connection_block_active_threshold: int = 12
    connection_monitor_burst_threshold: int = 10
    connection_block_burst_threshold: int = 18
    connection_monitor_stale_threshold: int = 2
    connection_block_stale_threshold: int = 5
    connection_monitor_per_ip_threshold: int = 6
    connection_block_per_ip_threshold: int = 12
    connection_monitor_new_connections_per_second: int = 4
    connection_block_new_connections_per_second: int = 8
    connection_monitor_sessions_per_source: int = 3
    connection_block_sessions_per_source: int = 6
    transport_awareness_enabled: bool = True
    transport_syn_monitor_burst_threshold: int = 6
    transport_syn_block_burst_threshold: int = 10
    transport_reset_monitor_stale_threshold: int = 1
    transport_reset_block_stale_threshold: int = 2
    transport_abnormal_session_monitor_score: int = 4
    transport_abnormal_session_block_score: int = 6
    transport_udp_monitor_burst_threshold: int = 5
    transport_udp_block_burst_threshold: int = 9
    transport_churn_monitor_ratio: float = 2.5
    transport_churn_block_ratio: float = 4.0
    transport_short_lived_duration_ms_threshold: int = 250
    transport_short_lived_monitor_score: int = 3
    transport_short_lived_block_score: int = 5
    transport_retry_monitor_score: int = 3
    transport_retry_block_score: int = 5
    transport_malformed_monitor_score: int = 2
    transport_malformed_block_score: int = 4
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 30
    token_bucket_capacity: int = 45
    token_bucket_refill_rate: float = 0.75
    ddos_protection_enabled: bool = True
    ddos_monitor_request_threshold: int = 14
    ddos_block_request_threshold: int = 24
    ddos_monitor_pressure_threshold: float = 0.85
    ddos_block_pressure_threshold: float = 0.97
    temporary_blacklist_seconds: int = 900
    targeted_block_ttl_seconds: int = 3600
    blacklist_repeat_offense_threshold: int = 3
    max_body_length: int = 8192
    max_payload_preview_chars: int = 240
    heuristic_weight: float = 0.55
    ml_weight: float = 0.45
    waitress_threads: int = 8
    auth_token_ttl_seconds: int = 28800
    auto_tuning_enabled: bool = False
    auto_tuning_window_seconds: int = 3600
    auto_tuning_min_samples: int = 12
    auto_tuning_cooldown_seconds: int = 900
    auto_tuning_target_false_positive_rate: float = 0.12
    auto_tuning_target_attack_rate: float = 0.18
    dynamic_thresholds_enabled: bool = False
    dynamic_thresholds_window_seconds: int = 1800
    dynamic_thresholds_min_samples: int = 20
    dynamic_thresholds_std_multiplier: float = 1.0
    dynamic_thresholds_min_block_threshold: float = 0.32
    dynamic_thresholds_max_block_threshold: float = 0.92
    adaptive_rate_limiting_enabled: bool = False
    adaptive_rate_limit_window_seconds: int = 900
    adaptive_rate_limit_normal_requests_per_min: int = 60
    adaptive_rate_limit_elevated_requests_per_min: int = 30
    adaptive_rate_limit_suspicious_requests_per_min: int = 10
    adaptive_rate_limit_restricted_requests_per_min: int = 3
    adaptive_rate_limit_min_suspicion_score: int = 2
    adaptive_rate_limit_suspicious_request_threshold: int = 8
    adaptive_rate_limit_unique_paths_threshold: int = 4
    adaptive_rate_limit_block_ratio_threshold: float = 0.25
    adaptive_rate_limit_flagged_ratio_threshold: float = 0.35
    adaptive_rate_limit_avg_risk_threshold: float = 0.55
    feedback_loop_enabled: bool = False
    feedback_loop_window_seconds: int = 86400
    feedback_loop_min_feedback: int = 3
    feedback_loop_cooldown_seconds: int = 900
    feedback_loop_relax_step: float = 0.04
    feedback_loop_harden_step: float = 0.05
    ml_log_training_enabled: bool = False
    ml_log_training_window_seconds: int = 604800
    ml_log_training_min_labeled_rows: int = 40
    ml_log_training_min_benign_rows: int = 15
    ml_log_training_min_malicious_rows: int = 15
    ml_log_training_cooldown_seconds: int = 86400
    ml_log_training_algorithm: str = "random_forest"
    db_path: Path = DATA_DIR / "waf.sqlite3"
    model_artifact_path: Path = MODELS_DIR / "active_model.joblib"
    fallback_model_path: Path = MODELS_DIR / "fallback_model.json"
    labeled_dataset_path: Path = DATA_DIR / "labeled_requests.csv"
    attack_pattern_dataset_path: Path = DATA_DIR / "attack_pattern_dataset.csv"
    training_corpus_path: Path = DATA_DIR / "training_corpus.csv"
    prepared_public_dataset_path: Path = DATA_DIR / "public_dataset_prepared.csv"
    benchmark_output_path: Path = REPORTS_DIR / "benchmark_summary.json"
    model_verification_report_path: Path = REPORTS_DIR / "model_pattern_verification.json"
    attack_simulation_report_path: Path = REPORTS_DIR / "attack_simulation_last_run.json"
    session_header_candidates: Tuple[str, ...] = ("X-Session-ID", "Authorization")
    session_cookie_candidates: Tuple[str, ...] = ("session", "sessionid", "PHPSESSID", "JSESSIONID")
    trusted_ips: Tuple[str, ...] = ("127.0.0.1", "::1")
    reserved_prefixes: Tuple[str, ...] = (
        "/dashboard",
        "/health",
        "/reports",
        "/api",
        "/proxy",
        "/inspect",
    )
    suspicious_keywords: Tuple[str, ...] = (
        "bad_keyword",
        "union select",
        "drop table",
        "or 1=1",
        "<script",
        "../",
        "..\\",
        ";--",
        "sleep(",
        "waitfor delay",
        "cmd=",
        "/etc/passwd",
    )
    automation_user_agents: Tuple[str, ...] = (
        "curl",
        "wget",
        "python-requests",
        "aiohttp",
        "sqlmap",
        "nikto",
        "nmap",
        "go-http-client",
        "postmanruntime",
    )
    bot_detection_enabled: bool = True
    browser_user_agent_markers: Tuple[str, ...] = (
        "mozilla/",
        "chrome/",
        "firefox/",
        "safari/",
        "edg/",
        "applewebkit",
    )
    automation_fingerprint_tokens: Tuple[str, ...] = (
        "headlesschrome",
        "selenium",
        "webdriver",
        "playwright",
        "puppeteer",
        "phantomjs",
        "scrapy",
        "crawler",
        "spider",
        "httpclient",
        "bot",
    )
    headless_browser_tokens: Tuple[str, ...] = (
        "headlesschrome",
        "selenium",
        "playwright",
        "puppeteer",
        "phantomjs",
        "webdriver",
    )
    scraping_path_tokens: Tuple[str, ...] = (
        "search",
        "query",
        "catalog",
        "browse",
        "feed",
        "export",
        "download",
        "api/public",
        "sitemap",
    )
    bot_browser_integrity_gap_threshold: int = 2
    bot_scraping_request_threshold: int = 6
    admin_username: str = "admin"
    admin_password: str = "Admin123!"
    analyst_username: str = "analyst"
    analyst_password: str = "Analyst123!"
    viewer_username: str = "viewer"
    viewer_password: str = "Viewer123!"
    model_bias: float = 0.05
    model_weights: Dict[str, float] = field(
        default_factory=lambda: {
            "suspicious_keyword_hits": 0.10,
            "sql_injection_signal": 0.20,
            "xss_signal": 0.18,
            "traversal_signal": 0.17,
            "command_injection_signal": 0.18,
            "ddos_signal": 0.16,
            "brute_force_signal": 0.11,
            "automation_abuse_signal": 0.09,
            "automation_fingerprint_signal": 0.11,
            "headless_browser_signal": 0.12,
            "browser_integrity_signal": 0.08,
            "browser_integrity_gap_score": 0.04,
            "scraping_surface_signal": 0.05,
            "scraping_pattern_signal": 0.11,
            "bot_likelihood_score": 0.0,
            "query_attack_signal": 0.1,
            "payload_evasion_signal": 0.16,
            "special_character_score": 0.08,
            "method_is_mutating": 0.03,
            "body_length_score": 0.07,
            "query_length_score": 0.05,
            "encoded_character_ratio": 0.12,
            "ip_request_rate_score": 0.08,
            "session_request_rate_score": 0.04,
            "ip_block_ratio": 0.12,
            "fingerprint_reuse_score": 0.05,
            "path_novelty_score": 0.04,
            "token_bucket_pressure": 0.10,
            "automation_user_agent_signal": 0.07,
            "browser_claim_signal": 0.02,
            "admin_path_signal": 0.05,
            "login_path_signal": 0.03,
            "login_failure_signal": 0.18,
            "failed_login_attempts_window": 0.03,
            "active_connection_pressure": 0.11,
            "connection_per_ip_pressure": 0.12,
            "connection_burst_pressure": 0.12,
            "new_connections_per_second_pressure": 0.14,
            "stale_connection_pressure": 0.10,
            "concurrent_sessions_pressure": 0.11,
            "half_open_signal": 0.07,
            "layer4_connection_signal": 0.14,
            "per_connection_throttle_signal": 0.15,
            "transport_enriched_signal": 0.03,
            "syn_like_flood_signal": 0.17,
            "connection_reset_signal": 0.09,
            "abnormal_session_establishment_signal": 0.12,
            "udp_flood_signal": 0.16,
            "connection_churn_signal": 0.12,
            "short_lived_abusive_signal": 0.12,
            "retry_timeout_signal": 0.11,
            "malformed_transport_signal": 0.14,
        }
    )

    def with_overrides(self, **changes) -> "Settings":
        return replace(self, **changes)


def ensure_runtime_dirs() -> None:
    for path in (DATA_DIR, MODELS_DIR, REPORTS_DIR, DOCS_DIR, SCRIPTS_DIR, TESTS_DIR):
        path.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    ensure_runtime_dirs()
    return Settings(
        host=os.getenv("WAF_HOST", "0.0.0.0"),
        port=_int_env("WAF_PORT", 5000),
        debug=_bool_env("WAF_DEBUG", False),
        secret_key=os.getenv("WAF_SECRET_KEY", "change-me-in-production"),
        backend_base_url=os.getenv("WAF_BACKEND_URL", "http://127.0.0.1:5001"),
        database_url=os.getenv("WAF_DATABASE_URL", ""),
        transparent_proxy=_bool_env("WAF_TRANSPARENT_PROXY", True),
        frontend_dev_server_url=os.getenv("WAF_FRONTEND_DEV_SERVER_URL", "http://127.0.0.1:5173"),
        frontend_use_dev_server=_bool_env("WAF_FRONTEND_USE_DEV_SERVER", False),
        frontend_public_url=os.getenv("WAF_FRONTEND_PUBLIC_URL", "http://127.0.0.1:5173"),
        cors_allowed_origins=_tuple_env("WAF_CORS_ALLOWED_ORIGINS", ("http://127.0.0.1:5173", "http://localhost:5173")),
        redis_url=os.getenv("WAF_REDIS_URL", ""),
        rate_limit_backend=os.getenv("WAF_RATE_LIMIT_BACKEND", "auto"),
        redis_key_prefix=os.getenv("WAF_REDIS_KEY_PREFIX", "waf"),
        request_timeout_seconds=_int_env("WAF_BACKEND_TIMEOUT", 10),
        pre_app_filter_enabled=_bool_env("WAF_PRE_APP_FILTER_ENABLED", True),
        pre_app_filter_window_seconds=_int_env("WAF_PRE_APP_FILTER_WINDOW_SECONDS", 10),
        pre_app_filter_ip_request_threshold=_int_env("WAF_PRE_APP_FILTER_IP_REQUEST_THRESHOLD", 120),
        pre_app_filter_ip_burst_threshold=_int_env("WAF_PRE_APP_FILTER_IP_BURST_THRESHOLD", 40),
        pre_app_filter_global_request_threshold=_int_env("WAF_PRE_APP_FILTER_GLOBAL_REQUEST_THRESHOLD", 600),
        pre_app_filter_ip_bytes_threshold=_int_env("WAF_PRE_APP_FILTER_IP_BYTES_THRESHOLD", 1048576),
        pre_app_filter_block_ttl_seconds=_int_env("WAF_PRE_APP_FILTER_BLOCK_TTL_SECONDS", 15),
        proxy_transport_controls_enabled=_bool_env("WAF_PROXY_TRANSPORT_CONTROLS_ENABLED", True),
        proxy_connect_timeout_seconds=_float_env("WAF_PROXY_CONNECT_TIMEOUT_SECONDS", 3.0),
        proxy_read_timeout_seconds=_float_env("WAF_PROXY_READ_TIMEOUT_SECONDS", 10.0),
        proxy_idle_pool_recycle_seconds=_int_env("WAF_PROXY_IDLE_POOL_RECYCLE_SECONDS", 30),
        proxy_upstream_pool_connections=_int_env("WAF_PROXY_UPSTREAM_POOL_CONNECTIONS", 16),
        proxy_upstream_pool_maxsize=_int_env("WAF_PROXY_UPSTREAM_POOL_MAXSIZE", 32),
        proxy_upstream_concurrency_limit=_int_env("WAF_PROXY_UPSTREAM_CONCURRENCY_LIMIT", 24),
        proxy_upstream_pool_block=_bool_env("WAF_PROXY_UPSTREAM_POOL_BLOCK", True),
        proxy_keepalive_abuse_protection_enabled=_bool_env("WAF_PROXY_KEEPALIVE_ABUSE_PROTECTION_ENABLED", True),
        proxy_keepalive_monitor_score=_int_env("WAF_PROXY_KEEPALIVE_MONITOR_SCORE", 3),
        proxy_keepalive_block_score=_int_env("WAF_PROXY_KEEPALIVE_BLOCK_SCORE", 5),
        block_threshold=_float_env("WAF_BLOCK_THRESHOLD", 0.72),
        monitor_threshold=_float_env("WAF_MONITOR_THRESHOLD", 0.48),
        analytics_window_seconds=_int_env("WAF_ANALYTICS_WINDOW_SECONDS", 900),
        dashboard_window_seconds=_int_env("WAF_DASHBOARD_WINDOW_SECONDS", 86400),
        recent_event_limit=_int_env("WAF_RECENT_EVENT_LIMIT", 100),
        security_scope_window_seconds=_int_env("WAF_SECURITY_SCOPE_WINDOW_SECONDS", 3600),
        connection_tracking_enabled=_bool_env("WAF_CONNECTION_TRACKING_ENABLED", True),
        connection_window_seconds=_int_env("WAF_CONNECTION_WINDOW_SECONDS", 30),
        connection_stale_seconds=_int_env("WAF_CONNECTION_STALE_SECONDS", 20),
        connection_monitor_active_threshold=_int_env("WAF_CONNECTION_MONITOR_ACTIVE_THRESHOLD", 6),
        connection_block_active_threshold=_int_env("WAF_CONNECTION_BLOCK_ACTIVE_THRESHOLD", 12),
        connection_monitor_burst_threshold=_int_env("WAF_CONNECTION_MONITOR_BURST_THRESHOLD", 10),
        connection_block_burst_threshold=_int_env("WAF_CONNECTION_BLOCK_BURST_THRESHOLD", 18),
        connection_monitor_stale_threshold=_int_env("WAF_CONNECTION_MONITOR_STALE_THRESHOLD", 2),
        connection_block_stale_threshold=_int_env("WAF_CONNECTION_BLOCK_STALE_THRESHOLD", 5),
        connection_monitor_per_ip_threshold=_int_env("WAF_CONNECTION_MONITOR_PER_IP_THRESHOLD", 6),
        connection_block_per_ip_threshold=_int_env("WAF_CONNECTION_BLOCK_PER_IP_THRESHOLD", 12),
        connection_monitor_new_connections_per_second=_int_env("WAF_CONNECTION_MONITOR_NEW_CONNECTIONS_PER_SECOND", 4),
        connection_block_new_connections_per_second=_int_env("WAF_CONNECTION_BLOCK_NEW_CONNECTIONS_PER_SECOND", 8),
        connection_monitor_sessions_per_source=_int_env("WAF_CONNECTION_MONITOR_SESSIONS_PER_SOURCE", 3),
        connection_block_sessions_per_source=_int_env("WAF_CONNECTION_BLOCK_SESSIONS_PER_SOURCE", 6),
        transport_awareness_enabled=_bool_env("WAF_TRANSPORT_AWARENESS_ENABLED", True),
        transport_syn_monitor_burst_threshold=_int_env("WAF_TRANSPORT_SYN_MONITOR_BURST_THRESHOLD", 6),
        transport_syn_block_burst_threshold=_int_env("WAF_TRANSPORT_SYN_BLOCK_BURST_THRESHOLD", 10),
        transport_reset_monitor_stale_threshold=_int_env("WAF_TRANSPORT_RESET_MONITOR_STALE_THRESHOLD", 1),
        transport_reset_block_stale_threshold=_int_env("WAF_TRANSPORT_RESET_BLOCK_STALE_THRESHOLD", 2),
        transport_abnormal_session_monitor_score=_int_env("WAF_TRANSPORT_ABNORMAL_SESSION_MONITOR_SCORE", 4),
        transport_abnormal_session_block_score=_int_env("WAF_TRANSPORT_ABNORMAL_SESSION_BLOCK_SCORE", 6),
        transport_udp_monitor_burst_threshold=_int_env("WAF_TRANSPORT_UDP_MONITOR_BURST_THRESHOLD", 5),
        transport_udp_block_burst_threshold=_int_env("WAF_TRANSPORT_UDP_BLOCK_BURST_THRESHOLD", 9),
        transport_churn_monitor_ratio=_float_env("WAF_TRANSPORT_CHURN_MONITOR_RATIO", 2.5),
        transport_churn_block_ratio=_float_env("WAF_TRANSPORT_CHURN_BLOCK_RATIO", 4.0),
        transport_short_lived_duration_ms_threshold=_int_env("WAF_TRANSPORT_SHORT_LIVED_DURATION_MS_THRESHOLD", 250),
        transport_short_lived_monitor_score=_int_env("WAF_TRANSPORT_SHORT_LIVED_MONITOR_SCORE", 3),
        transport_short_lived_block_score=_int_env("WAF_TRANSPORT_SHORT_LIVED_BLOCK_SCORE", 5),
        transport_retry_monitor_score=_int_env("WAF_TRANSPORT_RETRY_MONITOR_SCORE", 3),
        transport_retry_block_score=_int_env("WAF_TRANSPORT_RETRY_BLOCK_SCORE", 5),
        transport_malformed_monitor_score=_int_env("WAF_TRANSPORT_MALFORMED_MONITOR_SCORE", 2),
        transport_malformed_block_score=_int_env("WAF_TRANSPORT_MALFORMED_BLOCK_SCORE", 4),
        rate_limit_window_seconds=_int_env("WAF_RATE_LIMIT_WINDOW_SECONDS", 60),
        rate_limit_max_requests=_int_env("WAF_RATE_LIMIT_MAX_REQUESTS", 30),
        token_bucket_capacity=_int_env("WAF_TOKEN_BUCKET_CAPACITY", 45),
        token_bucket_refill_rate=_float_env("WAF_TOKEN_BUCKET_REFILL_RATE", 0.75),
        ddos_protection_enabled=_bool_env("WAF_DDOS_PROTECTION_ENABLED", True),
        ddos_monitor_request_threshold=_int_env("WAF_DDOS_MONITOR_REQUEST_THRESHOLD", 14),
        ddos_block_request_threshold=_int_env("WAF_DDOS_BLOCK_REQUEST_THRESHOLD", 24),
        ddos_monitor_pressure_threshold=_float_env("WAF_DDOS_MONITOR_PRESSURE_THRESHOLD", 0.85),
        ddos_block_pressure_threshold=_float_env("WAF_DDOS_BLOCK_PRESSURE_THRESHOLD", 0.97),
        temporary_blacklist_seconds=_int_env("WAF_TEMP_BLACKLIST_SECONDS", 900),
        targeted_block_ttl_seconds=_int_env("WAF_TARGETED_BLOCK_TTL_SECONDS", 3600),
        blacklist_repeat_offense_threshold=_int_env("WAF_BLACKLIST_REPEAT_OFFENSES", 3),
        max_body_length=_int_env("WAF_MAX_BODY_LENGTH", 8192),
        max_payload_preview_chars=_int_env("WAF_MAX_PAYLOAD_PREVIEW_CHARS", 240),
        heuristic_weight=_float_env("WAF_HEURISTIC_WEIGHT", 0.55),
        ml_weight=_float_env("WAF_ML_WEIGHT", 0.45),
        waitress_threads=_int_env("WAF_WAITRESS_THREADS", 8),
        auth_token_ttl_seconds=_int_env("WAF_AUTH_TOKEN_TTL_SECONDS", 28800),
        auto_tuning_enabled=_bool_env("WAF_AUTO_TUNING_ENABLED", False),
        auto_tuning_window_seconds=_int_env("WAF_AUTO_TUNING_WINDOW_SECONDS", 3600),
        auto_tuning_min_samples=_int_env("WAF_AUTO_TUNING_MIN_SAMPLES", 12),
        auto_tuning_cooldown_seconds=_int_env("WAF_AUTO_TUNING_COOLDOWN_SECONDS", 900),
        auto_tuning_target_false_positive_rate=_float_env("WAF_AUTO_TUNING_TARGET_FALSE_POSITIVE_RATE", 0.12),
        auto_tuning_target_attack_rate=_float_env("WAF_AUTO_TUNING_TARGET_ATTACK_RATE", 0.18),
        dynamic_thresholds_enabled=_bool_env("WAF_DYNAMIC_THRESHOLDS_ENABLED", False),
        dynamic_thresholds_window_seconds=_int_env("WAF_DYNAMIC_THRESHOLDS_WINDOW_SECONDS", 1800),
        dynamic_thresholds_min_samples=_int_env("WAF_DYNAMIC_THRESHOLDS_MIN_SAMPLES", 20),
        dynamic_thresholds_std_multiplier=_float_env("WAF_DYNAMIC_THRESHOLDS_STD_MULTIPLIER", 1.0),
        dynamic_thresholds_min_block_threshold=_float_env("WAF_DYNAMIC_THRESHOLDS_MIN_BLOCK_THRESHOLD", 0.32),
        dynamic_thresholds_max_block_threshold=_float_env("WAF_DYNAMIC_THRESHOLDS_MAX_BLOCK_THRESHOLD", 0.92),
        adaptive_rate_limiting_enabled=_bool_env("WAF_ADAPTIVE_RATE_LIMITING_ENABLED", False),
        adaptive_rate_limit_window_seconds=_int_env("WAF_ADAPTIVE_RATE_LIMIT_WINDOW_SECONDS", 900),
        adaptive_rate_limit_normal_requests_per_min=_int_env("WAF_ADAPTIVE_RATE_LIMIT_NORMAL_REQUESTS_PER_MIN", 60),
        adaptive_rate_limit_elevated_requests_per_min=_int_env("WAF_ADAPTIVE_RATE_LIMIT_ELEVATED_REQUESTS_PER_MIN", 30),
        adaptive_rate_limit_suspicious_requests_per_min=_int_env("WAF_ADAPTIVE_RATE_LIMIT_SUSPICIOUS_REQUESTS_PER_MIN", 10),
        adaptive_rate_limit_restricted_requests_per_min=_int_env("WAF_ADAPTIVE_RATE_LIMIT_RESTRICTED_REQUESTS_PER_MIN", 3),
        adaptive_rate_limit_min_suspicion_score=_int_env("WAF_ADAPTIVE_RATE_LIMIT_MIN_SUSPICION_SCORE", 2),
        adaptive_rate_limit_suspicious_request_threshold=_int_env("WAF_ADAPTIVE_RATE_LIMIT_SUSPICIOUS_REQUEST_THRESHOLD", 8),
        adaptive_rate_limit_unique_paths_threshold=_int_env("WAF_ADAPTIVE_RATE_LIMIT_UNIQUE_PATHS_THRESHOLD", 4),
        adaptive_rate_limit_block_ratio_threshold=_float_env("WAF_ADAPTIVE_RATE_LIMIT_BLOCK_RATIO_THRESHOLD", 0.25),
        adaptive_rate_limit_flagged_ratio_threshold=_float_env("WAF_ADAPTIVE_RATE_LIMIT_FLAGGED_RATIO_THRESHOLD", 0.35),
        adaptive_rate_limit_avg_risk_threshold=_float_env("WAF_ADAPTIVE_RATE_LIMIT_AVG_RISK_THRESHOLD", 0.55),
        feedback_loop_enabled=_bool_env("WAF_FEEDBACK_LOOP_ENABLED", False),
        feedback_loop_window_seconds=_int_env("WAF_FEEDBACK_LOOP_WINDOW_SECONDS", 86400),
        feedback_loop_min_feedback=_int_env("WAF_FEEDBACK_LOOP_MIN_FEEDBACK", 3),
        feedback_loop_cooldown_seconds=_int_env("WAF_FEEDBACK_LOOP_COOLDOWN_SECONDS", 900),
        feedback_loop_relax_step=_float_env("WAF_FEEDBACK_LOOP_RELAX_STEP", 0.04),
        feedback_loop_harden_step=_float_env("WAF_FEEDBACK_LOOP_HARDEN_STEP", 0.05),
        ml_log_training_enabled=_bool_env("WAF_ML_LOG_TRAINING_ENABLED", False),
        ml_log_training_window_seconds=_int_env("WAF_ML_LOG_TRAINING_WINDOW_SECONDS", 604800),
        ml_log_training_min_labeled_rows=_int_env("WAF_ML_LOG_TRAINING_MIN_LABELED_ROWS", 40),
        ml_log_training_min_benign_rows=_int_env("WAF_ML_LOG_TRAINING_MIN_BENIGN_ROWS", 15),
        ml_log_training_min_malicious_rows=_int_env("WAF_ML_LOG_TRAINING_MIN_MALICIOUS_ROWS", 15),
        ml_log_training_cooldown_seconds=_int_env("WAF_ML_LOG_TRAINING_COOLDOWN_SECONDS", 86400),
        ml_log_training_algorithm=os.getenv("WAF_ML_LOG_TRAINING_ALGORITHM", "random_forest"),
        admin_username=os.getenv("WAF_ADMIN_USERNAME", "admin"),
        admin_password=os.getenv("WAF_ADMIN_PASSWORD", "Admin123!"),
        analyst_username=os.getenv("WAF_ANALYST_USERNAME", "analyst"),
        analyst_password=os.getenv("WAF_ANALYST_PASSWORD", "Analyst123!"),
        viewer_username=os.getenv("WAF_VIEWER_USERNAME", "viewer"),
        viewer_password=os.getenv("WAF_VIEWER_PASSWORD", "Viewer123!"),
    )


settings = load_settings()
