import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('guarded_update.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def test_dns_settings_are_validated_and_rolled_back_without_wg_restart(self):
        settings = {'dns.serveWG': 'true', 'dns.lanAddress': '192.168.1.66',
                    'dns.allowLAN': '192.168.1.0/24', 'wg.dns': '192.168.15.1'}
        directory, job = self.prepare(settings)
        self.assertEqual(json.loads((self.data / 'config.json').read_text()), settings)
        self.assertTrue(any('--check-network-settings' in command for command in self.calls))
        with patch.object(guard, 'run', self.command), patch.object(guard, 'restore_network'):
            guard.rollback(directory, job)
        self.assertEqual(json.loads((self.data / 'config.json').read_text()), {})
        self.assertFalse(any('wg-quick@wg_server' in command for command in self.calls))

    def test_registry_restore_preserves_foreign_rules(self):
        resources = guard.route_registry.legacy_resources() + [dict(owner='vpn2', mark=0x20, mask=0xffffffff, table='103', priority=1103)]
        self.assertIsNotNone(guard.owned_rule('1103: from all fwmark 0x20 lookup 103', resources))
        self.assertIsNone(guard.owned_rule('1104: from all fwmark 0x21 lookup 104', resources))
        with patch.object(guard, 'run') as command:
            with self.assertRaises(RuntimeError):
                guard.restore_network({'resources': [], 'defaults': {}})
            command.assert_not_called()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / 'data'
        self.data.mkdir()
        self.binary = self.root / 'vpnguard'
        self.binary.write_text('previous')
        self.candidate = self.root / 'candidate'
        self.candidate.write_text('candidate')
        for name in ['config.json', 'routes.json']:
            (self.data / name).write_text('{}')
        for attr, value in [('BASE', self.root / 'updates'), ('DATA', self.data), ('BINARY', self.binary)]:
            p = patch.object(guard, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.calls = []

    def command(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == str(self.candidate):
            return '1.0\n'
        if args[0] == 'systemd-run':
            # Timer must be armed while the original executable is still installed.
            self.assertEqual(self.binary.read_text(), 'previous')
        return ''

    def prepare(self, settings=None):
        with patch.object(guard, 'run', self.command), patch.object(guard, 'snapshot', return_value={}), patch.object(guard, 'identity', return_value={'tunnel': {'state': 'connected'}}):
            guard.prepare(str(self.candidate), '1.0', guard.hashlib.sha256(self.candidate.read_bytes()).hexdigest(), settings)
        directory = next(guard.BASE.glob('*/job.json')).parent
        return directory, json.loads((directory / 'job.json').read_text())

    def test_timer_armed_before_install_and_rollback_restores_files(self):
        directory, job = self.prepare()
        self.assertEqual(self.binary.read_text(), 'candidate')
        (self.data / 'routes.json').write_text('changed')
        with patch.object(guard, 'run', self.command), patch.object(guard, 'restore_network') as restore:
            guard.rollback(directory, job)
            restore.assert_called_once_with({})
        self.assertEqual(self.binary.read_text(), 'previous')
        self.assertEqual((self.data / 'routes.json').read_text(), '{}')
        self.assertEqual(json.loads((directory / 'job.json').read_text())['status'], 'rolled_back')
        self.assertFalse(any('meduzavpnd' in c or 'wg-quick@wg_server' in c for c in self.calls))

    def test_confirmed_job_is_not_rolled_back_by_late_timer(self):
        directory, job = self.prepare()
        job['status'] = 'confirmed'
        with patch.object(guard, 'run') as command:
            guard.rollback(directory, job)
            command.assert_not_called()
        self.assertEqual(self.binary.read_text(), 'candidate')

    def test_sha_mismatch_leaves_current_binary_intact(self):
        with self.assertRaisesRegex(RuntimeError, 'SHA256'):
            guard.prepare(str(self.candidate), '1.0', 'wrong')
        self.assertEqual(self.binary.read_text(), 'previous')

    def test_foreign_rules_are_not_selected(self):
        self.assertIsNone(guard.owned_rule('28814: from all fwmark 0x4d555052 lookup 52807'))
        self.assertIsNone(guard.owned_rule('1101: from 192.168.1.0/24 fwmark 0x11 lookup 101'))
        self.assertIsNotNone(guard.owned_rule('1101: from all fwmark 0x11 lookup 101'))

    def test_network_settings_are_validated_before_install_and_restored(self):
        directory, job = self.prepare({'net.localNetworks': '192.168.1.0/24'})
        self.assertTrue(any('--check-network-settings' in c for c in self.calls))
        self.assertEqual(json.loads((self.data / 'config.json').read_text())['net.localNetworks'], '192.168.1.0/24')
        with patch.object(guard, 'run', self.command), patch.object(guard, 'restore_network'):
            guard.rollback(directory, job)
        self.assertEqual(json.loads((self.data / 'config.json').read_text()), {})

    def test_settings_outside_allowlist_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'declared network settings'):
            self.prepare({'web.token': 'must-not-change'})
        self.assertEqual(self.binary.read_text(), 'previous')

    def test_release_rollback_cancels_candidate_route_journal(self):
        directory, job = self.prepare()
        pending = self.data / 'routes-pending.json'
        pending.write_text(json.dumps({'id': '77', 'timer': 'vpnguard-routes-77'}))
        with patch.object(guard, 'run', self.command), patch.object(guard, 'restore_network'):
            guard.rollback(directory, job)
        self.assertFalse(pending.exists())
        self.assertTrue((directory / 'route-pending-before-version-rollback.json').exists())
        self.assertIn(('systemctl', 'stop', 'vpnguard-routes-77.timer'), self.calls)

    def test_release_rollback_handles_corrupt_candidate_journal(self):
        directory, job = self.prepare()
        pending = self.data / 'routes-pending.json'
        pending.write_text('{broken')
        with patch.object(guard, 'run', self.command), patch.object(guard, 'restore_network'):
            guard.rollback(directory, job)
        self.assertFalse(pending.exists())
        self.assertEqual(self.binary.read_text(), 'previous')
        self.assertEqual((directory / 'route-pending-before-version-rollback.json').read_text(), '{broken')


if __name__ == '__main__':
    unittest.main()
