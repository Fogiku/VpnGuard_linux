import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


DEPLOY = Path(__file__).resolve().parent


class PairedRunnerTest(unittest.TestCase):
    def test_capture_compare_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            # Replace only the privileged launcher and browser capture.
            launcher = work / "sudo"
            launcher.write_text("""#!/usr/bin/env python3
import hashlib, json, os, sys
from pathlib import Path
from test_compare_client_profiles import report
args = sys.argv[1:]
if args == ['-v']:
    sys.exit(0)
assert args[:4] == ['-n', 'ip', 'netns', 'exec']
namespace = args[4]
assert args[5:8] == ['sudo', '-H', '-u'] and args[9] == '--'
if namespace == os.environ.get('FAIL_CAPTURE'):
    sys.exit(3)
path = Path(next(a.split('=', 1)[1] for a in args if a.startswith('--profile-file=')))
index = int(namespace == 'candidate')
r = report(hashlib.sha256(path.read_bytes()).hexdigest(), 1 + index)
r['schema'] = 4
r['lab'].update(session=args[args.index('--lab-session') + 1], probe_version=1)
assert args[args.index('--egress-v4') + 2] == ['192.0.2.0/24', '198.51.100.0/24'][index]
print(json.dumps(r))
""")
            launcher.chmod(0o755)
            (work / "base file").write_text("base\n")
            (work / "candidate file").write_text("candidate\n")
            args = [DEPLOY / "run_client_comparison.sh", "base", "base file",
                    "candidate", "candidate file", "--control", "https://example.org",
                    "--discord", "--egress-v4", "https://example.org/ip",
                    "192.0.2.0/24", "198.51.100.0/24"]
            env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ["PATH"], PYTHONPATH=str(DEPLOY))
            result = subprocess.run(args, cwd=work, env=env, capture_output=True, text=True, check=True)
            output = work / result.stdout.strip()
            self.assertEqual(json.loads(output.read_text())["comparison"]["discord_gateway"]["outcome"], "both_observed")
            failed = subprocess.run(args, cwd=work, env=dict(env, FAIL_CAPTURE="candidate"), capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(list(work.glob("lab-*/comparison.json")), [output])
