import os
import time

from flask import Flask, jsonify, request


app = Flask(__name__)

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


@app.route("/", defaults={"subpath": ""}, methods=ALL_METHODS)
@app.route("/<path:subpath>", methods=ALL_METHODS)
def echo(subpath: str):
    sleep_ms = int(request.args.get("sleep_ms", "0") or 0)
    if sleep_ms > 0:
        time.sleep(sleep_ms / 1000.0)
    payload = request.get_json(silent=True)
    return jsonify(
        {
            "backend": "sample-backend",
            "method": request.method,
            "path": "/" + subpath if subpath else "/",
            "args": request.args.to_dict(flat=True),
            "json": payload,
            "body": request.get_data(as_text=True),
            "headers": {
                "X-Forwarded-For": request.headers.get("X-Forwarded-For", ""),
                "X-WAF-Request-ID": request.headers.get("X-WAF-Request-ID", ""),
                "X-WAF-Proxy-Connection-Mode": request.headers.get("X-WAF-Proxy-Connection-Mode", ""),
                "X-WAF-Upstream-Pool-Generation": request.headers.get("X-WAF-Upstream-Pool-Generation", ""),
                "Connection": request.headers.get("Connection", ""),
            },
        }
    )


if __name__ == "__main__":
    host = os.getenv("SAMPLE_BACKEND_HOST", "127.0.0.1")
    port = int(os.getenv("SAMPLE_BACKEND_PORT", "5001"))
    app.run(host=host, port=port, debug=False)
