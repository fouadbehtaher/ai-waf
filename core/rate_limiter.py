from dataclasses import dataclass
from time import time

try:
    from redis import Redis
    from redis.exceptions import RedisError
except ImportError:  # pragma: no cover - optional dependency
    Redis = None

    class RedisError(Exception):
        pass


@dataclass
class RateLimitResult:
    allowed: bool
    remaining_tokens: float
    capacity: float
    refill_rate: float
    backend: str = "storage"
    error: str = ""
    profile: str = "static"
    profile_rank: int = 0
    requests_per_min: int = 0
    adaptive_enabled: bool = False
    suspicion_score: int = 0
    risk_score: float = 0.0
    risk_band: str = "low"
    reasons: list[str] | None = None
    scope: str = "ip"
    subject_key: str = ""
    endpoint_policy_id: str = ""
    endpoint_policy_name: str = ""
    endpoint_policy_sensitivity: str = "standard"

    @property
    def pressure(self) -> float:
        if self.capacity <= 0:
            return 0.0
        return round(1.0 - max(self.remaining_tokens, 0.0) / float(self.capacity), 4)

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "remaining_tokens": self.remaining_tokens,
            "capacity": self.capacity,
            "refill_rate": self.refill_rate,
            "pressure": self.pressure,
            "backend": self.backend,
            "error": self.error,
            "profile": self.profile,
            "profile_rank": self.profile_rank,
            "requests_per_min": self.requests_per_min,
            "adaptive_enabled": self.adaptive_enabled,
            "suspicion_score": self.suspicion_score,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "reasons": list(self.reasons or []),
            "scope": self.scope,
            "subject_key": self.subject_key,
            "endpoint_policy_id": self.endpoint_policy_id,
            "endpoint_policy_name": self.endpoint_policy_name,
            "endpoint_policy_sensitivity": self.endpoint_policy_sensitivity,
        }


class StorageRateLimiter:
    backend_name = "storage"

    def consume(self, storage, subject_key: str, settings) -> RateLimitResult:
        state = storage.consume_rate_limit_token(
            ip_address=subject_key,
            capacity=settings.token_bucket_capacity,
            refill_rate=settings.token_bucket_refill_rate,
        )
        return RateLimitResult(
            allowed=bool(state["allowed"]),
            remaining_tokens=float(state["remaining_tokens"]),
            capacity=float(state["capacity"]),
            refill_rate=float(state["refill_rate"]),
            backend=self.backend_name,
        )


class RedisRateLimiter:
    backend_name = "redis"
    TOKEN_BUCKET_SCRIPT = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local capacity = tonumber(ARGV[2])
    local refill = tonumber(ARGV[3])
    local ttl = tonumber(ARGV[4])
    local payload = redis.call('HMGET', key, 'tokens', 'updated_at')
    local tokens = tonumber(payload[1])
    local updated_at = tonumber(payload[2])

    if tokens == nil then
      tokens = capacity
    end
    if updated_at == nil then
      updated_at = now
    end

    local elapsed = math.max(now - updated_at, 0)
    tokens = math.min(capacity, tokens + (elapsed * refill))

    local allowed = 0
    if tokens >= 1 then
      allowed = 1
      tokens = tokens - 1
    end

    redis.call('HMSET', key, 'tokens', tokens, 'updated_at', now)
    redis.call('EXPIRE', key, ttl)

    return {allowed, tostring(tokens), tostring(capacity), tostring(refill)}
    """

    def __init__(self, redis_url: str, key_prefix: str = "waf"):
        if Redis is None:
            raise RuntimeError("redis package is required to use the Redis rate limiter backend")
        self.redis_url = redis_url
        self.key_prefix = (key_prefix or "waf").strip() or "waf"
        self.client = Redis.from_url(redis_url, decode_responses=True)
        self.script = self.client.register_script(self.TOKEN_BUCKET_SCRIPT)

    def ping(self) -> bool:
        return bool(self.client.ping())

    def consume(self, storage, subject_key: str, settings) -> RateLimitResult:
        del storage
        key = "{0}:ratelimit:{1}".format(self.key_prefix, subject_key)
        ttl_seconds = max(int(settings.rate_limit_window_seconds or 60) * 2, 60)
        now_epoch = float(time())
        values = self.script(
            keys=[key],
            args=[
                now_epoch,
                float(settings.token_bucket_capacity),
                float(settings.token_bucket_refill_rate),
                ttl_seconds,
            ],
        )
        allowed_flag = int(values[0])
        remaining_tokens = float(values[1])
        return RateLimitResult(
            allowed=bool(allowed_flag),
            remaining_tokens=remaining_tokens,
            capacity=float(settings.token_bucket_capacity),
            refill_rate=float(settings.token_bucket_refill_rate),
            backend=self.backend_name,
        )


def build_rate_limiter(settings):
    requested_backend = str(settings.rate_limit_backend or "auto").strip().lower()
    redis_configured = bool(str(settings.redis_url or "").strip())

    if requested_backend == "storage":
        return StorageRateLimiter()

    if requested_backend in {"redis", "auto"} and redis_configured:
        try:
            limiter = RedisRateLimiter(settings.redis_url, key_prefix=settings.redis_key_prefix)
            limiter.ping()
            return limiter
        except (RedisError, RuntimeError, OSError):
            if requested_backend == "redis":
                return StorageRateLimiter()

    return StorageRateLimiter()


def enforce_rate_limit(storage, request_record, history_snapshot, settings, limiter=None, policy=None) -> RateLimitResult:
    active_limiter = limiter or build_rate_limiter(settings)
    effective_capacity = float((policy or {}).get("capacity", getattr(settings, "token_bucket_capacity", 45)) or 45)
    effective_refill_rate = float((policy or {}).get("refill_rate", getattr(settings, "token_bucket_refill_rate", 0.75)) or 0.75)
    effective_requests_per_min = int(
        (policy or {}).get(
            "requests_per_min",
            max(int(round(effective_refill_rate * 60.0)), 1),
        )
    )
    effective_profile = str((policy or {}).get("profile", "static") or "static")
    effective_profile_rank = int((policy or {}).get("profile_rank", 0) or 0)
    effective_suspicion_score = int((policy or {}).get("suspicion_score", 0) or 0)
    effective_risk_score = float((policy or {}).get("risk_score", 0.0) or 0.0)
    effective_risk_band = str((policy or {}).get("risk_band", "low") or "low")
    effective_reasons = list((policy or {}).get("reasons") or [])
    effective_scope = str((policy or {}).get("scope", "ip") or "ip")
    effective_subject_key = str((policy or {}).get("rate_limit_key", getattr(request_record, "remote_addr", "")) or getattr(request_record, "remote_addr", ""))
    endpoint_policy_id = str((policy or {}).get("endpoint_policy_id", "") or "")
    endpoint_policy_name = str((policy or {}).get("endpoint_policy_name", "") or "")
    endpoint_policy_sensitivity = str((policy or {}).get("endpoint_policy_sensitivity", "standard") or "standard")
    effective_settings = settings.with_overrides(
        token_bucket_capacity=int(round(effective_capacity)),
        token_bucket_refill_rate=effective_refill_rate,
        rate_limit_max_requests=effective_requests_per_min,
    )
    try:
        result = active_limiter.consume(storage, effective_subject_key, effective_settings)
    except (RedisError, OSError) as exc:
        result = StorageRateLimiter().consume(storage, effective_subject_key, effective_settings)
        result.error = str(exc)

    result.profile = effective_profile
    result.profile_rank = effective_profile_rank
    result.requests_per_min = effective_requests_per_min
    result.adaptive_enabled = bool((policy or {}).get("enabled", False))
    result.suspicion_score = effective_suspicion_score
    result.risk_score = round(effective_risk_score, 4)
    result.risk_band = effective_risk_band
    result.reasons = effective_reasons
    result.scope = effective_scope
    result.subject_key = effective_subject_key
    result.endpoint_policy_id = endpoint_policy_id
    result.endpoint_policy_name = endpoint_policy_name
    result.endpoint_policy_sensitivity = endpoint_policy_sensitivity
    if result.error:
        return result
    return result
