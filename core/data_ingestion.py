import logging
from dataclasses import dataclass
from typing import Dict
from urllib.parse import urljoin
from uuid import uuid4

import requests
from flask import Response

from utils import (
    build_full_url,
    extract_session_identifier,
    fingerprint,
    get_client_ip,
    sha256_hex,
    shorten,
    to_epoch,
    to_iso,
)


logger = logging.getLogger(__name__)

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


@dataclass
class RequestRecord:
    request_id: str
    timestamp: str
    timestamp_epoch: float
    traffic_origin: str
    method: str
    scheme: str
    host: str
    path: str
    gateway_path: str
    query_string: str
    url: str
    headers: Dict[str, str]
    body_text: str
    body_bytes: bytes
    body_length: int
    remote_addr: str
    user_agent: str
    referer: str
    content_type: str
    session_id: str
    request_fingerprint: str
    payload_hash: str
    payload_preview: str
    cookies_count: int

    @property
    def text(self) -> str:
        return self.body_text


@dataclass
class ProxyResponseRecord:
    status_code: int
    headers: Dict[str, str]
    body: bytes
    elapsed_ms: float
    final_url: str


def capture_request(request_obj, settings, forwarded_path: str | None = None) -> RequestRecord:
    headers = dict(request_obj.headers.items())
    body_bytes = request_obj.get_data(cache=True)
    body_text = request_obj.get_data(cache=True, as_text=True)
    query_string = request_obj.query_string.decode("utf-8", errors="ignore")
    scheme = getattr(request_obj, "scheme", "http")
    host = headers.get("Host", getattr(request_obj, "host", "localhost"))
    gateway_path = getattr(request_obj, "path", "/")
    path = forwarded_path or gateway_path
    method = getattr(request_obj, "method", "GET").upper()
    url = build_full_url(scheme, host, path, query_string)
    remote_addr = get_client_ip(headers, getattr(request_obj, "remote_addr", None))
    request_fingerprint = fingerprint(method, path, query_string, body_text)
    simulation_header = request_obj.headers.get("X-WAF-Simulation", "")
    traffic_origin = "simulation" if str(simulation_header).strip().lower() in {"1", "true", "yes", "on"} else "live"
    session_id = extract_session_identifier(
        headers=headers,
        cookies=request_obj.cookies,
        header_candidates=settings.session_header_candidates,
        cookie_candidates=settings.session_cookie_candidates,
    )
    now_iso = to_iso()
    now_epoch = to_epoch()

    record = RequestRecord(
        request_id=uuid4().hex[:12],
        timestamp=now_iso,
        timestamp_epoch=now_epoch,
        traffic_origin=traffic_origin,
        method=method,
        scheme=scheme,
        host=host,
        path=path,
        gateway_path=gateway_path,
        query_string=query_string,
        url=url,
        headers=headers,
        body_text=body_text,
        body_bytes=body_bytes,
        body_length=len(body_bytes),
        remote_addr=remote_addr,
        user_agent=headers.get("User-Agent", "unknown"),
        referer=headers.get("Referer", ""),
        content_type=headers.get("Content-Type", ""),
        session_id=session_id,
        request_fingerprint=request_fingerprint,
        payload_hash=sha256_hex(body_bytes),
        payload_preview=shorten(body_text, settings.max_payload_preview_chars),
        cookies_count=len(request_obj.cookies),
    )

    logger.info(
        "Captured request %s %s from %s",
        record.method,
        record.url,
        record.remote_addr,
    )
    return record


def _filter_request_headers(headers: Dict[str, str], client_ip: str, request_id: str) -> Dict[str, str]:
    forwarded_headers = {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() not in {"host", "content-length"}
    }

    prior_forwarded = headers.get("X-Forwarded-For", "").strip()
    if prior_forwarded:
        forwarded_headers["X-Forwarded-For"] = "{0}, {1}".format(prior_forwarded, client_ip)
    else:
        forwarded_headers["X-Forwarded-For"] = client_ip
    forwarded_headers["X-WAF-Request-ID"] = request_id
    return forwarded_headers


def proxy_request(record: RequestRecord, backend_url: str, timeout: int = 10) -> ProxyResponseRecord:
    normalized_base = backend_url.rstrip("/") + "/"
    target_url = urljoin(normalized_base, record.path.lstrip("/"))
    if record.query_string:
        target_url = "{0}?{1}".format(target_url, record.query_string)

    response = requests.request(
        method=record.method,
        url=target_url,
        headers=_filter_request_headers(record.headers, record.remote_addr, record.request_id),
        data=record.body_bytes,
        timeout=timeout,
        allow_redirects=False,
    )
    logger.info("Proxied request %s to %s with status %s", record.request_id, target_url, response.status_code)
    return ProxyResponseRecord(
        status_code=response.status_code,
        headers={
            key: value
            for key, value in response.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS
        },
        body=response.content,
        elapsed_ms=response.elapsed.total_seconds() * 1000.0,
        final_url=target_url,
    )


def to_flask_response(proxy_response: ProxyResponseRecord) -> Response:
    response = Response(proxy_response.body, status=proxy_response.status_code)
    for key, value in proxy_response.headers.items():
        response.headers[key] = value
    return response
