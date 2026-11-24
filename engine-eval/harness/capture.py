"""Pilot-only fixed-upstream recorder shared by the OCR and Mortis arms.

The manifest retains the actual saved upstream. Only the executing arm's observed
base URL points at this loopback listener. Request bodies and provider bodies are
forwarded unchanged and are never retained in events. Responses SSE is buffered
to its terminal event; this does not measure time to first token.
"""

import copy
import gzip
import io
import json
import math
import threading
import time
import zlib
from contextlib import closing, contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import httpx

MAX_REQUEST_BYTES = 32_000_000
MAX_RESPONSE_BYTES = 20_000_000
KNOWN_REJECTIONS = {400, 401, 403, 404, 405, 413, 415, 422, 429}
QUOTA_CODES = {"insufficient_quota", "billing_hard_limit_reached", "credit_balance_too_low"}
HOP_HEADERS = {
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
}
TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
)


class CapturePersistenceError(RuntimeError):
    pass


def _number(value):
    if type(value) is int and value >= 0:
        return value
    return value if type(value) is float and math.isfinite(value) and value >= 0 else None


def _tokens(value):
    return value if type(value) is int and value >= 0 else None


def _usage(data):
    usage = data.get("usage")
    values = dict.fromkeys(TOKEN_FIELDS)
    if not isinstance(usage, dict):
        return values
    values["input_tokens"] = _tokens(usage.get("input_tokens", usage.get("prompt_tokens")))
    values["output_tokens"] = _tokens(usage.get("output_tokens", usage.get("completion_tokens")))
    reported = _tokens(usage.get("total_tokens"))
    if values["input_tokens"] is not None and values["output_tokens"] is not None:
        computed = values["input_tokens"] + values["output_tokens"]
        if reported is None or reported == computed:
            values["total_tokens"] = computed
        else:
            # Inconsistent accounting is not sufficient evidence to spend again.
            values["input_tokens"] = values["output_tokens"] = None
    for names, field, key in (
        (["input_tokens_details", "prompt_tokens_details"], "cache_read_tokens", "cached_tokens"),
        (["output_tokens_details", "completion_tokens_details"], "reasoning_tokens", "reasoning_tokens"),
    ):
        details = next((usage[name] for name in names if isinstance(usage.get(name), dict)), {})
        values[field] = _tokens(details.get(key))
    values["cache_write_tokens"] = _tokens(
        usage.get("cache_creation_input_tokens", usage.get("cache_write_tokens"))
    )
    if values["cache_read_tokens"] is None:
        values["cache_read_tokens"] = _tokens(
            usage.get("cache_read_input_tokens", usage.get("cache_read_tokens"))
        )
    return values


def _json(raw):
    def invalid_number(_):
        raise ValueError("Non-finite JSON number")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_number)
    if not isinstance(value, dict):
        raise TypeError("Expected a JSON object")
    return value


def _response_data(raw, headers):
    encoding = headers.get("content-encoding", "identity").lower()
    if encoding == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            raw = stream.read(MAX_RESPONSE_BYTES + 1)
    elif encoding == "deflate":
        raw = zlib.decompressobj().decompress(raw, MAX_RESPONSE_BYTES + 1)
    elif encoding not in {"", "identity"}:
        raise ValueError("Unsupported response encoding")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Decoded response exceeds byte limit")
    if "text/event-stream" not in headers.get("content-type", "").lower():
        return _json(raw)
    # Only terminal Responses events or Chat's final usage chunk can establish
    # consumption. A response.created event is not the completed request's usage.
    terminal = None
    for block in raw.decode("utf-8").replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(line[5:].lstrip(" ") for line in block.splitlines() if line.startswith("data:"))
        if not data or data == "[DONE]":
            continue
        event = _json(data)
        kind = event.get("type", "")
        if kind in {"response.completed", "response.incomplete", "response.failed"}:
            terminal = event.get("response")
        elif not kind and isinstance(event.get("usage"), dict):
            terminal = event
    if not isinstance(terminal, dict):
        raise TypeError("No terminal stream usage")
    return terminal


class Recorder:
    def __init__(self, connection, credentials, *, allow_insecure_loopback=False):
        self.upstream = connection["base_url"].rstrip("/")
        parsed = urlsplit(self.upstream)
        test_http = (
            allow_insecure_loopback and parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "::1"}
        )
        if (
            parsed.scheme != "https"
            and not test_http
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Capture requires the exact HTTPS upstream (literal loopback HTTP is test-only)")
        if connection.get("kind") != "api" or connection.get("protocol") not in {
            "openai",
            "openai-responses",
        }:
            raise ValueError(
                "The pilot recorder supports the selected shared OpenAI-compatible endpoint only"
            )
        self.model = connection["model"]
        self._api_key = credentials.get("api_key")
        if (
            not isinstance(self._api_key, str)
            or not self._api_key
            or not isinstance(self.model, str)
            or not self.model
        ):
            raise ValueError("The selected model and server-side API credential are required")
        self._secrets = [self._api_key, *credentials.get("extra_headers", {}).values()]
        duration = connection.get("options", {}).get("timeout_sec", 600)
        if type(duration) not in {int, float} or not 0 < duration <= 600:
            raise ValueError("Capture request timeout must be positive and at most the pilot's 600 seconds")
        self.timeout = duration
        self.events = []
        self.on_event = None
        self.blocked_reason = None
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(4)
        self._active = 0
        self._peak = 0
        self._client = httpx.Client(
            trust_env=False,
            follow_redirects=False,
            timeout=duration,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=4),
        )

    def _identifier(self, value):
        if (
            isinstance(value, str)
            and 0 < len(value) <= 250
            and value.isprintable()
            and not any(secret and secret in value for secret in self._secrets)
        ):
            return value
        return None

    def _event(self, *, sequence=None, **fields):
        event = {
            "sequence": None,
            "status": None,
            "request_id": None,
            "returned_model": None,
            "error_code": None,
            "elapsed_ms": 0,
            "forwarded": False,
            "consumption_unknown": False,
            "state": "finished",
            "opencode_allowance": {},
            **dict.fromkeys(TOKEN_FIELDS),
            **fields,
        }
        with self._lock:
            event["sequence"] = sequence or len(self.events) + 1
            if sequence:
                self.events[sequence - 1] = event
            else:
                self.events.append(event)
            if (
                event["state"] == "finished"
                and event["forwarded"]
                and (event["consumption_unknown"] or event["error_code"] in {"authentication", "quota"})
            ):
                self.blocked_reason = self.blocked_reason or event["error_code"] or "unknown_consumption"
        if self.on_event:
            try:
                self.on_event(copy.deepcopy(event))
            except Exception as exc:
                with self._lock:
                    self.blocked_reason = "capture_persistence"
                raise CapturePersistenceError("Provider accounting could not be retained") from exc
        return event

    def _account(self, raw, headers, status):
        event = {
            "status": status,
            "request_id": self._identifier(headers.get("x-request-id") or headers.get("request-id")),
            "consumption_unknown": status not in KNOWN_REJECTIONS,
            **dict.fromkeys(TOKEN_FIELDS),
        }
        try:
            data = _response_data(raw, headers)
        except (TypeError, ValueError, UnicodeError, RecursionError, OSError, EOFError, zlib.error):
            data = {}
        event["request_id"] = event["request_id"] or self._identifier(data.get("id"))
        event["returned_model"] = self._identifier(data.get("model"))
        if status >= 400:
            error = data.get("error", {})
            kind = (error.get("code") or error.get("type")) if isinstance(error, dict) else None
            kind = kind if isinstance(kind, str) else None
            event["error_code"] = (
                "quota"
                if kind in QUOTA_CODES
                else "authentication"
                if status in {401, 403}
                else "rate_limit"
                if status == 429
                else "provider_error"
            )
            if status in KNOWN_REJECTIONS:
                event.update({name: 0 for name in TOKEN_FIELDS})
        elif 300 <= status < 400:
            event.update(
                error_code="redirect", consumption_unknown=False, **{name: 0 for name in TOKEN_FIELDS}
            )
        else:
            event.update(_usage(data))
            event["consumption_unknown"] = event["total_tokens"] is None
            if event["consumption_unknown"]:
                event["error_code"] = "unknown_consumption"
        allowance = {}
        usage = data.get("usage", {})
        if isinstance(usage, dict):
            for key in (
                "cost",
                "total_cost",
                "remaining_tokens",
                "remaining_requests",
                "remaining_allowance",
            ):
                value = _number(usage.get(key))
                if value is not None:
                    allowance[key] = value
        for key in (
            "x-opencode-remaining",
            "x-opencode-remaining-tokens",
            "x-ratelimit-remaining-tokens",
            "x-ratelimit-remaining-requests",
        ):
            try:
                value = _number(float(headers[key]))
            except (KeyError, ValueError):
                continue
            if value is not None:
                allowance[key] = value
        event["opencode_allowance"] = allowance
        return event

    def _forward(self, handler, body):
        with self._slots:
            with self._lock:
                if self.blocked_reason:
                    return None
                self._active += 1
                self._peak = max(self._peak, self._active)
            start = time.monotonic()
            event = {"forwarded": True}
            sequence = None
            status, headers, raw = 502, {}, b'{"error":{"code":"capture_transport"}}'
            try:
                sequence = self._event(state="started", forwarded=True, consumption_unknown=True)["sequence"]
                headers_in = [
                    (key, value) for key, value in handler.headers.items() if key.lower() not in HOP_HEADERS
                ]
                request = self._client.build_request(
                    "POST", self.upstream + handler.path.removeprefix("/v1"), headers=headers_in, content=body
                )
                if "cookie" not in handler.headers:
                    request.headers.pop("cookie", None)
                with closing(
                    self._client.send(request, stream=True, follow_redirects=False, auth=None)
                ) as response:
                    status = response.status_code
                    headers = response.headers
                    pieces, size = [], 0
                    for chunk in response.iter_raw():
                        size += len(chunk)
                        if size > MAX_RESPONSE_BYTES or time.monotonic() - start > self.timeout:
                            raise ValueError("Response exceeded the pilot transport bound")
                        pieces.append(chunk)
                    raw = b"".join(pieces)
                    event.update(self._account(raw, headers, status))
                    if 300 <= status < 400:
                        # A client must not escape recording by following the
                        # provider's Location with repository data/credentials.
                        headers = {key: value for key, value in headers.items() if key.lower() != "location"}
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout):
                event.update(
                    status=None,
                    error_code="connection",
                    consumption_unknown=False,
                    **{name: 0 for name in TOKEN_FIELDS},
                )
            except (httpx.HTTPError, ValueError):
                event.update(
                    status=status if status != 502 else None, error_code="transport", consumption_unknown=True
                )
                status, headers, raw = 502, {}, b'{"error":{"code":"capture_consumption_unknown"}}'
            finally:
                event["elapsed_ms"] = round((time.monotonic() - start) * 1000, 3)
                try:
                    if sequence is not None:
                        self._event(sequence=sequence, **event)
                finally:
                    with self._lock:
                        self._active -= 1
            return status, headers, raw


@contextmanager
def capture(connection, credentials, *, allow_insecure_loopback=False):
    recorder = Recorder(connection, credentials, allow_insecure_loopback=allow_insecure_loopback)

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, body, headers=None):
            with suppress(BrokenPipeError, ConnectionResetError):
                self.send_response(status)
                for key, value in (headers or {}).items():
                    if key.lower() not in HOP_HEADERS:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            self.close_connection = True

        def reject(self, status, code):
            recorder._event(status=status, error_code=code, **{name: 0 for name in TOKEN_FIELDS})
            self.reply(status, json.dumps({"error": {"code": code}}).encode())

        def do_POST(self):
            if self.path not in {"/v1/chat/completions", "/v1/responses"}:
                return self.reject(404, "capture_path")
            if self.headers.get("authorization") != "Bearer " + recorder._api_key:
                return self.reject(401, "capture_credentials")
            try:
                length = int(self.headers.get("content-length", "-1"))
                if not 0 < length <= MAX_REQUEST_BYTES or self.headers.get("transfer-encoding"):
                    raise ValueError()
                self.connection.settimeout(recorder.timeout)
                body = self.rfile.read(length)
                if len(body) != length or _json(body).get("model") != recorder.model:
                    raise ValueError()
            except (TypeError, ValueError, UnicodeError, RecursionError, OSError):
                return self.reject(400, "capture_request")
            try:
                response = recorder._forward(self, body)
            except CapturePersistenceError:
                return self.reply(503, b'{"error":{"code":"capture_persistence"}}')
            if response is None:
                return self.reject(503, "capture_stopped")
            status, headers, raw = response
            self.reply(status, raw, headers)

        def do_GET(self):
            self.reject(405, "capture_method")

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = do_GET

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    recorder.base_url = f"http://127.0.0.1:{server.server_port}/v1"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield recorder
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        recorder._client.close()
