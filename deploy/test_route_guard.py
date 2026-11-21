import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('route_guard', Path(__file__).with_name('route_guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class RouteGuardTests(unittest.TestCase):
    def test_extra_vpn_restore_uses_saved_registry_and_preserves_foreign_table(self):
        resources = guard.legacy_resources() + [dict(owner='vpn2', mark=0x20, mask=0xffffffff, table='103', priority=1103)]
        state = dict(resources=resources, nft='', rules=[['priority', '1103', 'from', 'all', 'fwmark', '0x20', 'lookup', '103']], defaults={'103': ['default dev old0 table 103']})
        calls = []
        def command(*args, **kwargs):
            calls.append(args)
            if args == ('ip', '-4', '-N', '-o', 'route', 'show', 'table', 'all'):
                return 'default dev new0 table 103\ndefault dev foreign0 table 104\n'
            if args == ('ip', '-4', '-N', '-o', 'rule', 'show'):
                return '1103: from all fwmark 0x20 lookup 103\n1104: from all fwmark 0x21 lookup 104\n'
            return ''
        with patch.object(guard, 'run', command):
            guard.restore_network(state)
        self.assertIn(('ip', '-4', 'route', 'flush', 'table', '103', 'default'), calls)
        self.assertIn(('ip', '-4', 'route', 'add', 'default', 'dev', 'old0', 'table', '103'), calls)
        self.assertFalse(any('104' in args or '1104' in args for args in calls))

    def test_main_table_is_recognized_in_numeric_output(self):
        rule = guard.owned_rule("1201: from all fwmark 0x40000000/0x40000000 lookup 254")
        self.assertEqual(rule, ["priority", "1201", "from", "all", "fwmark", "0x40000000/0x40000000", "lookup", "254"])

    def test_invalid_registry_is_rejected_before_any_command(self):
        resources = guard.legacy_resources() + [dict(owner='vpn2', mark=0x20, mask=0xffffffff, table='52807', priority=53807)]
        with patch.object(guard, 'run') as command:
            with self.assertRaises(RuntimeError):
                guard.restore_network({'resources': resources})
            command.assert_not_called()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.change = {'id': '123', 'status': 'awaiting_confirmation', 'kernelChanged': True,
                       'reason': 'test', 'keepLast': True, 'routesExisted': False,
                       'before': {}, 'network': {'net.pinFlows': None}}
        (self.directory / 'config.json').write_text(json.dumps({'net.pinFlows': 'true', 'unrelated': 'keep'}))
        self.write_pending()

    def write_pending(self):
        (self.directory / 'routes-pending.json').write_text(json.dumps(self.change))

    def test_recovery_restores_files_and_keeps_unrelated_settings(self):
        with patch.object(guard, 'run') as command, patch.object(guard, 'restore_network') as restore:
            guard.recover('recover', self.directory, '123')
            restore.assert_called_once_with({})
            self.assertEqual([c.args for c in command.call_args_list], [('systemctl', 'stop', 'vpnguard'), ('systemctl', 'start', 'vpnguard')])
        self.assertEqual(json.loads((self.directory / 'config.json').read_text()), {'unrelated': 'keep'})
        self.assertFalse((self.directory / 'routes-pending.json').exists())

    def test_old_timer_does_not_touch_new_operation(self):
        with patch.object(guard, 'run') as command, patch.object(guard, 'restore_network') as restore:
            guard.recover('recover', self.directory, '122')
            command.assert_not_called()
            restore.assert_not_called()
        self.assertTrue((self.directory / 'routes-pending.json').exists())

    def test_committed_journal_is_finalized_without_rollback(self):
        self.change['status'] = 'committed'
        self.write_pending()
        with patch.object(guard, 'run') as command, patch.object(guard, 'restore_network') as restore:
            guard.recover('recover', self.directory, '123')
            command.assert_not_called()
            restore.assert_not_called()
        self.assertEqual(json.loads((self.directory / 'config.json').read_text())['net.pinFlows'], 'true')
        self.assertTrue((self.directory / 'routes-last.json').exists())

    def test_failed_recovery_retains_journal_and_restarts_agent(self):
        with patch.object(guard, 'run') as command, patch.object(guard, 'restore_network', side_effect=RuntimeError('injected')):
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                guard.recover('recover', self.directory, '123')
            self.assertEqual(command.call_args.args, ('systemctl', 'start', 'vpnguard'))
        self.assertTrue((self.directory / 'routes-pending.json').exists())


if __name__ == '__main__':
    unittest.main()
