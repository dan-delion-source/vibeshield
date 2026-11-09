import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from dashboard.server import ScanStore, validate_target, ScanError, ScanCoverageError, TOOLS
from pipeline.report.report_builder import json_report, pdf_report
from pipeline.scan.common import RawFinding

class DashboardTests(unittest.TestCase):
    def test_local_targets(self):
        for value in ['localhost:5000','127.0.0.1:5000','[::1]:5000']:
            self.assertTrue(validate_target('website',value).startswith('http://'))
    def test_external_targets_rejected(self):
        for value in ['https://example.com','192.168.1.2','http://127.0.0.1@example.com','http://localhost.evil.test']:
            with self.assertRaises(ScanError): validate_target('website',value)
    def test_github_validation(self):
        self.assertEqual(validate_target('github','https://github.com/owner/repo'), 'https://github.com/owner/repo.git')
        for value in ['https://github.com/owner/repo/tree/main','https://evil.test/owner/repo','https://user:pass@github.com/owner/repo']:
            with self.assertRaises(ScanError): validate_target('github',value)
    def test_consent_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=ScanStore(tmp)
            with self.assertRaises(ScanError): store.create({'target_type':'local','target':'.'})
            store.executor.shutdown()
    def test_partial_real_ast_and_exports(self):
        def missing(*args,**kwargs): raise ScanError('PartialParsing', findings=[RawFinding('example.py', 1, 'test-rule', 'review', 'WARNING', '', 'semgrep')])
        with tempfile.TemporaryDirectory() as tmp:
            store=ScanStore(tmp)
            tools=[('semgrep','Semgrep',missing),TOOLS[1],('gitleaks','Gitleaks',lambda *a,**k:[])]
            with patch('dashboard.server.TOOLS', tools):
                job=store.create({'target_type':'local','target':'fixtures/idor-notes-app','authorized':True})
                store.executor.shutdown(wait=True)
            result=store.get(job['id'])
            self.assertEqual(result['status'],'partial')
            self.assertEqual(result['stages'][0]['finding_count'], 1)
            self.assertEqual(result['stages'][0]['status'], 'failed')
            self.assertEqual(result['findings'][1]['vulnerability_type'],'IDOR')
            data=json.loads(json_report(result))
            self.assertFalse(data['complete'])
            self.assertEqual(data['summary']['candidate_count'],2)
            self.assertEqual(data['findings'][1]['display_severity'],'UNRATED')
            self.assertTrue(pdf_report(result).startswith(b'%PDF-'))
            loaded=ScanStore(tmp)
            self.assertEqual(loaded.get(job['id'])['findings'],result['findings'])
            loaded.executor.shutdown()
    def test_restart_marks_interrupted(self):
        with tempfile.TemporaryDirectory() as tmp:
            job={'id':'abc','status':'running','created_at':'2026-01-01','errors':[], 'stages':[{'status':'running'}]}
            Path(tmp,'abc.json').write_text(json.dumps(job))
            store=ScanStore(tmp)
            self.assertEqual(store.get('abc')['status'],'interrupted')
            store.executor.shutdown()

    def test_partial_parser_coverage_retains_findings_and_exports(self):
        for with_findings in [True, False]:
            def partial(*args, **kwargs):
                findings = [RawFinding('example.py', 1, 'test-rule', 'review', 'WARNING', '', 'semgrep')] if with_findings else []
                raise ScanCoverageError('PartialParsing in templates/base.html:1', findings=findings)
            with tempfile.TemporaryDirectory() as tmp:
                store = ScanStore(tmp)
                # Even when other scanners fail, a valid limited-coverage report
                # is partial rather than a total process failure.
                def failed(*args, **kwargs):
                    raise ScanError('Missing tool')
                tools = [('semgrep','Semgrep',partial), ('ast','Python AST',failed), ('gitleaks','Gitleaks',failed)]
                with patch('dashboard.server.TOOLS', tools):
                    job = store.create({'target_type':'local','target':'fixtures/idor-notes-app','authorized':True})
                    store.executor.shutdown(wait=True)
                result = store.get(job['id'])
                self.assertEqual(result['status'], 'partial')
                self.assertEqual(result['stages'][0]['status'], 'partial')
                self.assertEqual(result['stages'][0]['finding_count'], int(with_findings))
                self.assertEqual(result['stages'][1]['status'], 'failed')
                exported = json.loads(json_report(result))
                self.assertFalse(exported['complete'])
                self.assertEqual(len(exported['findings']), int(with_findings))
                self.assertIn('PartialParsing', exported['errors'][0]['error'])

    def test_python_scope_is_applied_persisted_and_exported(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ScanStore(tmp)
            from unittest.mock import Mock
            semgrep = Mock(return_value=[])
            tools = [('semgrep','Semgrep',semgrep), ('ast','Python AST',lambda *a,**k:[]),
                     ('gitleaks','Gitleaks',lambda *a,**k:[])]
            with patch('dashboard.server.TOOLS', tools):
                job = store.create({'target_type':'local','target':'fixtures/idor-notes-app',
                                    'authorized':True,'semgrep_profile':'python'})
                store.executor.shutdown(wait=True)
            semgrep.assert_called_once_with(job['target'], timeout=300, profile='python')
            result = store.get(job['id'])
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['stages'][0]['name'], 'Semgrep (Python only)')
            data = json.loads(json_report(result))
            self.assertEqual(data['semgrep_profile'], 'python')
            self.assertIn('HTML templates', data['scope_notes'][0])
            self.assertTrue(pdf_report(result).startswith(b'%PDF-'))
            loaded = ScanStore(tmp)
            self.assertEqual(loaded.get(job['id'])['scope_notes'], data['scope_notes'])
            loaded.executor.shutdown()

    def test_unknown_semgrep_scope_rejected_before_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ScanStore(tmp)
            try:
                for value in ['unknown', [], None]:
                    with self.assertRaises(ScanError):
                        store.create({'target_type':'local','target':'fixtures/idor-notes-app',
                                      'authorized':True,'semgrep_profile':value})
                self.assertEqual(store.list(), [])
            finally:
                store.executor.shutdown()

if __name__=='__main__': unittest.main()
