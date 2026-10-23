"""Parser and failure-path tests; live fixture smoke tests are recorded separately."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from pipeline.scan.common import ScanError, local_url, run_command
from pipeline.scan import nuclei_runner, secrets_runner, semgrep_runner, zap_runner


class RunnerTests(unittest.TestCase):
    def test_missing_binary(self):
        with self.assertRaisesRegex(ScanError, 'Missing tool'):
            run_command(['/vibeshield-nonexistent-scanner'], timeout=1)

    def test_timeout(self):
        with self.assertRaisesRegex(ScanError, 'timed out'):
            run_command([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.1)

    def test_tool_failure_does_not_echo_credentials(self):
        with self.assertRaises(ScanError) as result:
            run_command([sys.executable, '-c', 'import sys; print("secret-value", file=sys.stderr); sys.exit(3)'])
        self.assertNotIn('secret-value', str(result.exception))

    def test_local_scope(self):
        for url in ('http://localhost:5000', 'http://127.0.0.1:5000/api/health', 'http://[::1]:5000'):
            self.assertEqual(local_url(url), url)
        for url in ('https://example.com', 'file:///tmp/a', 'http://localhost.evil', 'http://user@localhost', 'http://localhost:bad'):
            with self.assertRaises(ScanError):
                local_url(url)

    def test_semgrep_parser(self):
        raw = {'results': [{'path': 'app.py', 'start': {'line': 4}, 'check_id': 'rule',
                            'extra': {'message': 'review', 'severity': 'WARNING', 'lines': 'app.run(debug=True)'}}]}
        item = semgrep_runner.parse_output(json.dumps(raw), Path('/tmp'))[0]
        self.assertEqual((item.source, item.line), ('semgrep', 4))

    def test_semgrep_errors_not_clean(self):
        with self.assertRaises(ScanError):
            semgrep_runner.parse_output('{"results": [], "errors": [{"message": "parse failed"}]}', Path('/tmp'))

    def test_semgrep_diagnostics_show_location_without_source(self):
        report = {'results': [], 'errors': [{'type': 'PartialParsing',
                  'message': 'secret-value', 'spans': [{'file': 'app.py', 'start': {'line': 12},
                                                       'source_hash': 'secret-value'}]}]}
        with self.assertRaises(ScanError) as result:
            semgrep_runner.parse_output(json.dumps(report), Path('/tmp'))
        message = str(result.exception)
        self.assertIn('PartialParsing in app.py:12', message)
        self.assertIn('Scan incomplete', message)
        self.assertNotIn('secret-value', message)

    def test_semgrep_diagnostics_bound_output_and_handle_timeout(self):
        errors = [{'type': 'Timeout', 'path': '/outside/private.py'}] * 7
        message = semgrep_runner.error_summary(errors, Path('/tmp'))
        self.assertIn('2 more errors', message)
        self.assertIn('internal timeout', message)
        self.assertNotIn('/outside', message)

    def test_semgrep_tagged_errors_preserve_valid_findings(self):
        report = {'results': [{'path': 'app.py', 'start': {'line': 4}, 'check_id': 'rule',
                  'extra': {'message': 'review', 'severity': 'WARNING', 'lines': 'app.run(debug=True)'}}],
                  'errors': [{'type': ['PartialParsing', [{'secret': 'do-not-display'}]],
                              'path': 'templates/base.html', 'start': {'line': 16}}]}
        with self.assertRaises(ScanError) as result:
            semgrep_runner.parse_output(json.dumps(report), Path('/tmp'))
        self.assertIn('PartialParsing in templates/base.html:16', str(result.exception))
        self.assertNotIn('do-not-display', str(result.exception))
        self.assertEqual(len(result.exception.findings), 1)
        self.assertEqual(result.exception.findings[0].rule_id, 'rule')

    def test_secrets_redacted(self):
        raw = [{'File': 'config.py', 'StartLine': 1, 'RuleID': 'key', 'Description': 'Key',
                'Secret': 'sensitive-value', 'Match': 'sensitive-value'}]
        item = secrets_runner.parse_output(json.dumps(raw))[0]
        self.assertNotIn('sensitive-value', str(item))
        self.assertEqual(item.source_snippet, '[REDACTED]')

    def test_nuclei_jsonl(self):
        raw = {'matched-at': 'http://localhost:5000', 'template-id': 'headers',
               'info': {'name': 'Header', 'severity': 'info'}}
        items = nuclei_runner.parse_output(json.dumps(raw) + '\n' + json.dumps(raw))
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].source, 'nuclei')

    def test_malformed_nuclei_is_failure(self):
        for value in ('not-json', '{"info": {}}', 'null'):
            with self.assertRaises(ScanError):
                nuclei_runner.parse_output(value)

    def test_zap_instances(self):
        raw = {'site': [{'@name': 'http://localhost:5000', 'alerts': [
            {'pluginid': '10038', 'name': 'CSP missing', 'riskcode': '2',
             'instances': [{'uri': 'http://localhost:5000/a'}, {'uri': 'http://localhost:5000/b'}]}]}]}
        items = zap_runner.parse_output(json.dumps(raw))
        self.assertEqual(len(items), 2)
        self.assertEqual((items[0].source, items[0].severity), ('zap', 'MEDIUM'))

    def test_zap_empty_sites_not_clean(self):
        with self.assertRaises(ScanError):
            zap_runner.parse_output('{"site": []}')

    def test_zap_warning_exit_is_success(self):
        def fake_command(command, *args, **kwargs):
            report = Path(command[command.index('-J') + 1])
            report.write_text('{"site": [{"@name": "http://localhost", "alerts": []}]}')
            self.assertEqual(kwargs['accepted'], (0, 1, 2))
            return subprocess.CompletedProcess(command, 2, '', '')
        with patch.object(zap_runner, 'run_command', side_effect=fake_command):
            self.assertEqual(zap_runner.scan('http://localhost', mode='cli'), [])

    def test_zap_cleanup_after_timeout(self):
        with patch.object(zap_runner, 'run_command', side_effect=[ScanError('timed out'), subprocess.CompletedProcess([], 0)]) as run:
            with self.assertRaises(ScanError):
                zap_runner.scan('http://localhost', mode='docker')
            self.assertEqual(run.call_args_list[-1].args[0][1:3], ['rm', '-f'])

    def test_zap_native_plan_has_only_passive_jobs(self):
        def fake_command(command, *args, **kwargs):
            plan = json.loads(Path(command[command.index('-autorun') + 1]).read_text())
            self.assertEqual([j['type'] for j in plan['jobs']],
                             ['passiveScan-config', 'spider', 'passiveScan-wait', 'report'])
            params = plan['jobs'][-1]['parameters']
            Path(params['reportDir'], params['reportFile']).write_text(
                '{"site": [{"@name": "http://localhost", "alerts": []}]}')
            return subprocess.CompletedProcess(command, 0, '', '')
        with patch.object(zap_runner, 'run_command', side_effect=fake_command):
            self.assertEqual(zap_runner.scan('http://localhost', mode='native'), [])

    def test_gitleaks_missing_report_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(secrets_runner, 'run_command', return_value=subprocess.CompletedProcess([], 0)):
                with self.assertRaisesRegex(ScanError, 'did not write'):
                    secrets_runner.scan(directory)


if __name__ == '__main__':
    unittest.main()
