import subprocess
import tempfile
import unittest
from pathlib import Path

from build_release import release_changes
from publish_release import git, promote


class PublicationTests(unittest.TestCase):
    def test_notes_belong_to_requested_version(self):
        log = "## 1.9.27 — date\n\n- First\n- Second\n## 1.9.26 — date\n- Older\n"
        self.assertEqual(release_changes(log, "1.9.27"), ["First", "Second"])
        with self.assertRaises(ValueError):
            release_changes(log, "1.9.2")

    def test_parallel_commit_rejects_entire_publication(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            remote, local = root / "remote.git", root / "local"
            git(root, "init", "--quiet", "--bare", str(remote))
            git(root, "init", "--quiet", str(local))
            git(local, "config", "user.name", "Release test")
            git(local, "config", "user.email", "test@localhost")
            git(local, "remote", "add", "origin", str(remote))
            git(local, "commit", "--allow-empty", "-qm", "base")
            base = git(local, "rev-parse", "HEAD")
            git(local, "push", "origin", "HEAD:refs/heads/main", "HEAD:refs/heads/releases")
            git(local, "commit", "--allow-empty", "-qm", "candidate")
            candidate = git(local, "rev-parse", "HEAD")
            git(local, "tag", "v1.9.27")
            git(local, "checkout", "--quiet", "--detach", base)
            git(local, "commit", "--allow-empty", "-qm", "binary")
            binary = git(local, "rev-parse", "HEAD")
            git(local, "tag", "bin-v1.9.27")
            git(local, "checkout", "--quiet", "--detach", base)
            git(local, "commit", "--allow-empty", "-qm", "parallel change")
            competitor = git(local, "rev-parse", "HEAD")
            git(local, "push", "origin", "HEAD:refs/heads/main")
            with self.assertRaises(subprocess.CalledProcessError):
                promote(local, "1.9.27", candidate, binary, True)
            self.assertEqual(git(remote, "rev-parse", "main"), competitor)
            self.assertEqual(git(remote, "rev-parse", "releases"), base)
            self.assertEqual(git(remote, "tag", "--list"), "")
