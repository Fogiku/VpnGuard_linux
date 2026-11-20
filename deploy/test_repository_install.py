import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import repository_install as installer


class ReleaseDownloadTests(unittest.TestCase):
    def test_download_checks_content_before_making_it_executable(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for data, limit, succeeds in [(b"binary", 64, True), (b"damaged", 64, False), (b"binary", 2, False)]:
                with self.subTest(data=data, limit=limit):
                    target = directory / (str(limit) + data.hex())
                    with patch.object(installer.urllib.request, "urlopen", return_value=io.BytesIO(data)), patch.object(installer, "MAX_BINARY", limit):
                        digest = hashlib.sha256(b"binary").hexdigest()
                        if succeeds:
                            installer.download("https://example.invalid", target, digest)
                            self.assertEqual(target.read_bytes(), data)
                            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                        else:
                            with self.assertRaises(ValueError):
                                installer.download("https://example.invalid", target, digest)
                            self.assertFalse(target.stat().st_mode & 0o111)
