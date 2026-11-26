#!/usr/bin/env python3
"""Loopback-only real subprocess proof of engine startup report ownership.

Build first: cd engine && dub build --config=startup-test
Run from repo root: python3 test/test_engine_startup.py
No production configuration, credentials, databases or external network required.
"""
import http.server
import json
import os
from pathlib import Path
import subprocess
import threading
import unittest


BINARY = Path(__file__).resolve().parents[1] / "engine" / "startup-test"


class EngineStartupProcessTest(unittest.TestCase):
    def test_process_status_and_single_private_report(self):
        cases = [("success", 0, None), ("timeout", 75, "bootstrap"),
                 ("rejected", 78, "bootstrap"), ("unexpected", 79, "terminal"),
                 ("bootstrap-unexpected", 79, "bootstrap")]
        for scenario, expected_status, operation in cases:
            with self.subTest(scenario=scenario):
                reports = []

                class Handler(http.server.BaseHTTPRequestHandler):
                    def do_POST(self):
                        size = int(self.headers.get("Content-Length", "0"))
                        body = self.rfile.read(size)
                        reports.append((self.path, body))
                        self.send_response(200)
                        self.send_header("Content-Length", "0")
                        self.end_headers()

                    def log_message(self, *_args):
                        pass

                with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
                    worker = threading.Thread(target=server.serve_forever, daemon=True)
                    worker.start()
                    try:
                        env = dict(os.environ)
                        env.pop("IRCFIBER_BUGSINK_DSN_FILE", None)
                        env.update(IRCFIBER_STARTUP_TEST_REPORT="1", IRCFIBER_BUGSINK_ENABLED="1",
                                   IRCFIBER_BUGSINK_ENVIRONMENT="test",
                                   IRCFIBER_BUGSINK_DSN=f"http://synthetic@127.0.0.1:{server.server_port}/42")
                        result = subprocess.run([str(BINARY), scenario], env=env,
                                                capture_output=True, timeout=15, check=False)
                        self.assertEqual(result.returncode, expected_status, result.stderr)
                        self.assertEqual(result.stdout + result.stderr, b"", "private details leaked locally")
                    finally:
                        server.shutdown()
                        worker.join()
                self.assertEqual(len(reports), 0 if operation is None else 1,
                                 "only the terminal process owner may report a failure")
                if operation is not None:
                    path, body = reports[0]
                    self.assertEqual(path, "/api/42/store/")
                    self.assertLessEqual(len(body), 8192)
                    self.assertNotIn(b"private startup failure", body)
                    self.assertNotIn(b"private unrelated failure", body)
                    self.assertNotIn(b"synthetic", body)
                    event = json.loads(body)
                    self.assertEqual(event["tags"], {"component": "engine", "operation": operation,
                                                     "service": "ircfiber-engine"})
                    self.assertEqual(event["message"], operation)
                    self.assertEqual(event["exception"]["values"][0]["value"], operation)


if __name__ == "__main__":
    unittest.main(verbosity=2)
