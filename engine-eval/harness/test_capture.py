"""Real loopback upstream/recorder checks; no database or provider account."""

import gzip
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from capture import capture

SECRET = "synthetic-provider-key"
MODEL = "selected-model"


def result():
    return {
        "id": "request-17",
        "model": "selected-model-v1",
        "output": "untrusted-provider-output",
        "usage": {
            "input_tokens": 9,
            "output_tokens": 3,
            "total_tokens": 12,
            "input_tokens_details": {"cached_tokens": 4},
            "output_tokens_details": {"reasoning_tokens": 2},
            "cost": 0.001,
        },
    }


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.state = {
            "requests": [],
            "status": 200,
            "body": json.dumps(result()).encode(),
            "headers": {"Content-Type": "application/json", "x-request-id": "header-request"},
        }
        state = self.state

        class Upstream(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["content-length"]))
                state["requests"].append((self.path, dict(self.headers), body))
                if state.get("on_request"):
                    state["on_request"]()
                self.send_response(state["status"])
                for key, value in state["headers"].items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(state["body"])))
                self.end_headers()
                self.wfile.write(state["body"])

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = {
            "kind": "api",
            "protocol": "openai-responses",
            "model": MODEL,
            "base_url": f"http://127.0.0.1:{self.server.server_port}/exact/v1",
            "options": {},
        }

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @contextmanager
    def recording(self):
        with capture(
            self.connection,
            {"api_key": SECRET, "extra_headers": {"x-extra": "private-extra"}},
            allow_insecure_loopback=True,
        ) as recording:
            yield recording

    def post(self, recording, *, body=None, path="responses", method="POST", headers=None):
        body = body if body is not None else json.dumps({"model": MODEL, "input": "private-source"}).encode()
        request = Request(
            recording.base_url + "/" + path,
            data=body,
            method=method,
            headers={
                "Authorization": "Bearer " + SECRET,
                "Content-Type": "application/json",
                **(headers or {}),
            },
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as response:
            return response.code, response.read()

    def test_exact_body_headers_and_sanitized_usage(self):
        body = json.dumps(
            {
                "model": MODEL,
                "input": "private-source",
                "stream": False,
                "reasoning": {"effort": "high"},
                "unknown_option": {"keep": True},
            }
        ).encode()
        self.state["headers"]["x-ratelimit-remaining-tokens"] = "876"
        with self.recording() as recording:
            status, response = self.post(
                recording,
                body=body,
                headers={"User-Agent": "code-mortis/0.1.0", "x-opencode-session": "session-per-attempt"},
            )
        self.assertEqual((status, response), (200, self.state["body"]))
        path, headers, sent = self.state["requests"][0]
        self.assertEqual((path, sent), ("/exact/v1/responses", body))
        headers = {key.lower(): value for key, value in headers.items()}
        self.assertEqual(headers["user-agent"], "code-mortis/0.1.0")
        self.assertEqual(headers["x-opencode-session"], "session-per-attempt")
        self.assertEqual(headers["authorization"], "Bearer " + SECRET)
        event = recording.events[0]
        self.assertEqual(
            [event[key] for key in ("input_tokens", "output_tokens", "total_tokens")], [9, 3, 12]
        )
        self.assertEqual((event["cache_read_tokens"], event["reasoning_tokens"]), (4, 2))
        self.assertEqual(event["request_id"], "header-request")
        self.assertEqual(event["returned_model"], "selected-model-v1")
        self.assertEqual(event["opencode_allowance"], {"cost": 0.001, "x-ratelimit-remaining-tokens": 876.0})
        self.assertGreater(event["elapsed_ms"], 0)
        self.assertFalse(event["consumption_unknown"])
        encoded = json.dumps(recording.events)
        for value in (
            SECRET,
            "private-extra",
            "private-source",
            "untrusted-provider-output",
            "session-per-attempt",
        ):
            self.assertNotIn(value, encoded)

    def test_responses_sse_records_terminal_usage_and_preserves_bytes(self):
        created = {
            "type": "response.created",
            "response": {"id": "partial", "usage": {"input_tokens": 0, "output_tokens": 0}},
        }
        completed = {"type": "response.completed", "response": result()}
        self.state["body"] = (
            "event: response.created\r\ndata: "
            + json.dumps(created)
            + "\r\n\r\nevent: response.completed\r\ndata: "
            + json.dumps(completed)
            + "\r\n\r\n"
        ).encode()
        self.state["headers"]["Content-Type"] = "text/event-stream"
        with self.recording() as recording:
            self.assertEqual(self.post(recording), (200, self.state["body"]))
        self.assertEqual(recording.events[0]["total_tokens"], 12)

    def test_nonterminal_sse_stops_future_dispatch_as_unknown(self):
        self.state["body"] = (
            b'data: {"type":"response.created","response":{"usage":{"input_tokens":0,"output_tokens":0}}}\n\n'
        )
        self.state["headers"]["Content-Type"] = "text/event-stream"
        with self.recording() as recording:
            self.assertEqual(self.post(recording)[0], 200)
            self.assertEqual(self.post(recording)[0], 503)
        self.assertEqual(len(self.state["requests"]), 1)
        self.assertTrue(recording.events[0]["consumption_unknown"])
        self.assertIsNone(recording.events[0]["total_tokens"])

    def test_known_rate_limit_can_retry_without_proxy_retries(self):
        self.state.update(status=429, body=b'{"error":{"code":"rate_limit"}}')
        with self.recording() as recording:
            self.assertEqual(self.post(recording)[0], 429)
            self.assertEqual(len(self.state["requests"]), 1)
            self.assertIsNone(recording.blocked_reason)
            self.state.update(status=200, body=json.dumps(result()).encode())
            self.assertEqual(self.post(recording)[0], 200)
        self.assertEqual([event["total_tokens"] for event in recording.events], [0, 12])

    def test_auth_quota_unavailable_malformed_and_inconsistent_usage_stop_dispatch(self):
        cases = [
            (401, b'{"error":{}}', "authentication", 0),
            (429, b'{"error":{"code":"insufficient_quota"}}', "quota", 0),
            (503, b'{"error":{}}', "provider_error", None),
            (200, b"not json", "unknown_consumption", None),
            (
                200,
                b'{"usage":{"input_tokens":2,"output_tokens":3,"total_tokens":4}}',
                "unknown_consumption",
                None,
            ),
            (200, b'{"usage":{"total_tokens":12}}', "unknown_consumption", None),
        ]
        for status, body, code, tokens in cases:
            with self.subTest(status=status, body=body):
                self.state.update(status=status, body=body, requests=[])
                with self.recording() as recording:
                    self.assertEqual(self.post(recording)[0], status)
                    self.assertEqual(self.post(recording)[0], 503)
                self.assertEqual(len(self.state["requests"]), 1)
                self.assertEqual(recording.events[0]["error_code"], code)
                self.assertEqual(recording.events[0]["total_tokens"], tokens)
                self.assertFalse(recording.events[1]["forwarded"])

    def test_nonselected_path_model_method_and_credentials_never_forward(self):
        with self.recording() as recording:
            self.assertEqual(self.post(recording, path="responses?target=other")[0], 404)
            self.assertEqual(self.post(recording, method="GET")[0], 405)
            self.assertEqual(self.post(recording, body=b'{"model":"different"}')[0], 400)
            self.assertEqual(self.post(recording, headers={"Authorization": "Bearer other"})[0], 401)
            self.assertEqual(
                self.post(recording, body=b'{"model":"selected-model","model":"different"}')[0], 400
            )
        self.assertEqual(self.state["requests"], [])
        self.assertTrue(all(not row["forwarded"] and row["total_tokens"] == 0 for row in recording.events))

    def test_shared_ceiling_is_four_real_upstream_requests(self):
        full, release, lock = threading.Event(), threading.Event(), threading.Lock()
        active = 0

        def pause():
            nonlocal active
            with lock:
                active += 1
                if active == 4:
                    full.set()
            self.assertTrue(release.wait(5))

        self.state["on_request"] = pause
        with self.recording() as recording, ThreadPoolExecutor(max_workers=5) as workers:
            pending = [workers.submit(self.post, recording) for _ in range(5)]
            try:
                self.assertTrue(full.wait(5))
                self.assertEqual(len(self.state["requests"]), 4)
            finally:
                release.set()
            self.assertEqual([future.result()[0] for future in pending], [200] * 5)
        self.assertEqual(recording._peak, 4)
        self.assertEqual(len(recording.events), 5)

    def test_provider_cookies_do_not_cross_calls(self):
        self.state["headers"]["Set-Cookie"] = "provider_cookie=private; Path=/"
        with self.recording() as recording:
            self.post(recording)
            self.post(recording)
        for _path, headers, _body in self.state["requests"]:
            self.assertNotIn("cookie", {key.lower() for key in headers})

    def test_started_and_finished_callbacks_bracket_dispatch_and_do_not_duplicate_attempts(self):
        retained = []

        def retain(event):
            self.assertEqual(len(self.state["requests"]), 0 if event["state"] == "started" else 1)
            retained.append(dict(event))
            event.clear()

        with self.recording() as recording:
            recording.on_event = retain
            self.assertEqual(self.post(recording)[0], 200)
        self.assertEqual([event["state"] for event in retained], ["started", "finished"])
        self.assertEqual([event["sequence"] for event in retained], [1, 1])
        self.assertTrue(retained[0]["consumption_unknown"])
        self.assertIsNone(retained[0]["total_tokens"])
        self.assertEqual(len(recording.events), 1)
        self.assertEqual(recording.events[0]["total_tokens"], 12)

    def test_failed_durable_start_prevents_provider_dispatch(self):
        def fail(_event):
            raise RuntimeError("Synthetic persistence failure with private detail")

        with self.recording() as recording:
            recording.on_event = fail
            self.assertEqual(self.post(recording)[0], 503)
            recording.on_event = None
            self.assertEqual(self.post(recording)[0], 503)
        self.assertEqual(self.state["requests"], [])
        self.assertEqual(recording.blocked_reason, "capture_persistence")
        self.assertNotIn("private detail", json.dumps(recording.events))

    def test_failed_durable_finish_keeps_prior_unknown_and_blocks_further_dispatch(self):
        retained = []

        def retain(event):
            if event["state"] == "finished":
                raise RuntimeError("Synthetic final persistence failure")
            retained.append(event)

        with self.recording() as recording:
            recording.on_event = retain
            self.assertEqual(self.post(recording)[0], 503)
            recording.on_event = None
            self.assertEqual(self.post(recording)[0], 503)
        self.assertEqual(len(self.state["requests"]), 1)
        self.assertTrue(retained[0]["consumption_unknown"])
        self.assertEqual(recording.blocked_reason, "capture_persistence")

    def test_compressed_response_is_forwarded_unchanged_and_accounted(self):
        self.state["body"] = gzip.compress(json.dumps(result()).encode())
        self.state["headers"]["Content-Encoding"] = "gzip"
        with self.recording() as recording:
            self.assertEqual(self.post(recording), (200, self.state["body"]))
        self.assertEqual(recording.events[0]["total_tokens"], 12)

    def test_oversized_upstream_remains_unknown_and_stops_new_dispatch(self):
        with patch("capture.MAX_RESPONSE_BYTES", 20), self.recording() as recording:
            self.assertEqual(self.post(recording)[0], 502)
            self.assertEqual(self.post(recording)[0], 503)
        self.assertEqual(len(self.state["requests"]), 1)
        self.assertTrue(recording.events[0]["consumption_unknown"])

    def test_redirect_cannot_send_client_outside_the_fixed_recorder(self):
        self.state["status"] = 302
        self.state["headers"]["Location"] = "https://forbidden.example/responses"
        with self.recording() as recording:
            self.assertEqual(self.post(recording)[0], 302)
        self.assertEqual(len(self.state["requests"]), 1)
        self.assertEqual(recording.events[0]["error_code"], "redirect")
        self.assertEqual(recording.events[0]["total_tokens"], 0)

    def test_http_upstream_requires_explicit_literal_loopback_test_mode(self):
        with self.assertRaises(ValueError), capture(self.connection, {"api_key": SECRET}):
            self.fail("Plain HTTP must be refused by default")
        invalid = {**self.connection, "base_url": "http://localhost:1234/v1"}
        with (
            self.assertRaises(ValueError),
            capture(invalid, {"api_key": SECRET}, allow_insecure_loopback=True),
        ):
            self.fail("The test exception cannot authorize a DNS name")


if __name__ == "__main__":
    unittest.main()
