import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import local_ai_setup as ai


class LocalAISetupTest(unittest.TestCase):
    def prepare(self, *responses):
        def respond(endpoint, *args, **kwargs):
            expected, value = next(sequence)
            self.assertEqual(endpoint, expected)
            if isinstance(value, Exception):
                raise value
            return io.BytesIO(value if isinstance(value, bytes) else json.dumps(value).encode())
        sequence = iter(responses)
        progress = []
        with patch.object(ai, "call", side_effect=respond):
            ai.prepare("qwen2.5:1.5b", progress.append)
        self.assertIsNone(next(sequence, None))
        return progress

    version = ("version", {"version": "0.20.0"})
    missing = ("show", HTTPError("local", 404, "missing", {}, None))
    found = ("show", {"details": {"family": "qwen2"}})

    def test_present(self):
        self.assertEqual(self.prepare(self.version, self.found), [])

    def test_download(self):
        updates = b'{"completed":2,"total":4}\n{"status":"success"}\n'
        self.assertIn("50%", self.prepare(self.version, self.missing, ("pull", updates), self.found)[-1])

    def test_incomplete(self):
        with self.assertRaisesRegex(ValueError, "прервана"):
            self.prepare(self.version, self.missing, ("pull", b""))

    def test_cloud_model(self):
        with self.assertRaisesRegex(ValueError, "локальная"):
            self.prepare(self.version, ("show", {"details": {}, "remote_host": "example.org"}))
