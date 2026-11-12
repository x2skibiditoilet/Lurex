import json
import os
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

from darcobfuscator.obfuscator import obfuscate

SECRET = os.environ.get("LUREX_ENGINE_SECRET", "")
PORT = int(os.environ.get("PORT", "8080"))
MAX_BYTES = int(os.environ.get("MAX_BYTES", str(1024 * 1024)))


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {
                "status": "ok",
                "engine": "LUREX",
                "protocol": 1,
            })
        return self.send_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/obfuscate":
            return self.send_json(404, {"error": "not_found"})

        auth = self.headers.get("Authorization", "")
        if not SECRET or auth != f"Bearer {SECRET}":
            return self.send_json(401, {"error": "unauthorized"})

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_json(400, {"error": "invalid_content_length"})

        if length <= 0 or length > MAX_BYTES:
            return self.send_json(413, {"error": "payload_too_large"})

        try:
            payload = json.loads(self.rfile.read(length))
            source = payload.get("source")
            options = payload.get("options") or {}

            if not isinstance(source, str) or not source:
                return self.send_json(400, {"error": "source_required"})
            if not isinstance(options, dict):
                return self.send_json(400, {"error": "options_must_be_object"})

            output = obfuscate(source, options)
            return self.send_json(200, {
                "output": output,
                "request_id": self.headers.get(
                    "X-Lurex-Request-Id", str(uuid.uuid4())
                ),
            })

        except Exception as exc:
            print(f"obfuscation error: {exc}", flush=True)
            return self.send_json(500, {
                "error": "obfuscation_failed",
                "message": str(exc),
            })

    def log_message(self, fmt, *args):
        print(fmt % args, flush=True)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
