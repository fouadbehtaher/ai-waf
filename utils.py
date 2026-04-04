import json
import socket
from datetime import datetime, timezone
from hashlib import sha1, sha256
from typing import Iterable, Mapping, Optional, Sequence


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(value: Optional[datetime] = None) -> str:
    current = value or utc_now()
    return current.isoformat(timespec="seconds")


def to_epoch(value: Optional[datetime] = None) -> float:
    current = value or utc_now()
    return current.timestamp()


def clamp(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(value, upper))


def get_client_ip(headers: Mapping[str, str], remote_addr: Optional[str]) -> str:
    forwarded_for = headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if remote_addr:
        return remote_addr
    return "127.0.0.1"


def build_full_url(scheme: str, host: str, path: str, query_string: str) -> str:
    url = "{0}://{1}{2}".format(scheme or "http", host or "localhost", path or "/")
    if query_string:
        return "{0}?{1}".format(url, query_string)
    return url


def sha256_hex(value: bytes | str) -> str:
    payload = value if isinstance(value, bytes) else value.encode("utf-8", errors="ignore")
    return sha256(payload).hexdigest()


def fingerprint(method: str, path: str, query_string: str, body: str) -> str:
    digest = sha1()
    digest.update((method or "GET").encode("utf-8"))
    digest.update((path or "/").encode("utf-8"))
    digest.update((query_string or "").encode("utf-8"))
    digest.update((body or "").encode("utf-8"))
    return digest.hexdigest()


def shorten(text: str, limit: int = 120) -> str:
    if len(text) <= limit:
        return text
    return "{0}...".format(text[: limit - 3])


def extract_session_identifier(
    headers: Mapping[str, str],
    cookies: Mapping[str, str],
    header_candidates: Sequence[str],
    cookie_candidates: Sequence[str],
) -> str:
    for header_name in header_candidates:
        if headers.get(header_name):
            return headers[header_name][:128]
    for cookie_name in cookie_candidates:
        if cookies.get(cookie_name):
            return cookies[cookie_name][:128]
    return "anonymous"


def json_dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def percentile(values: Iterable[float], q: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    q = clamp(q, 0.0, 1.0)
    index = (len(ordered) - 1) * q
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    if lower == upper:
        return ordered[lower]
    weight = index - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def discover_local_ipv4_addresses() -> list[str]:
    candidates: set[str] = set()

    try:
        hostname = socket.gethostname()
        for result in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            address = result[4][0]
            if address and not address.startswith("127."):
                candidates.add(address)
    except OSError:
        pass

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        address = probe.getsockname()[0]
        probe.close()
        if address and not address.startswith("127."):
            candidates.add(address)
    except OSError:
        pass

    return sorted(candidates)
