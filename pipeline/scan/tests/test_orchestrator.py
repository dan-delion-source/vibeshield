import contextlib
import io
import json
from unittest.mock import patch
import unittest

from pipeline.scan import run_scan
from pipeline.scan.ast_heuristic_analyzer import HeuristicFinding
from pipeline.scan.common import RawFinding, ScanError


class OrchestratorTests(unittest.TestCase):
    def test_both_modes_keep_overlaps(self):
        raw = lambda tool: RawFinding('http://localhost', 0, 'missing-header', 'Review', 'INFO', '', tool)
        heuristic = HeuristicFinding('app.py', 122, 'get_note', 'IDOR-AST-01', 'MEDIUM', 'Missing check')
        with patch.object(run_scan.semgrep_runner, 'scan', return_value=[]), \
             patch.object(run_scan.ast_heuristic_analyzer, 'scan', return_value=[heuristic]), \
             patch.object(run_scan.secrets_runner, 'scan', return_value=[]), \
             patch.object(run_scan.nuclei_runner, 'scan', return_value=[raw('nuclei')]), \
             patch.object(run_scan.zap_runner, 'scan', return_value=[raw('zap')]):
            findings, errors = run_scan.scan('.', 'http://localhost')
        self.assertEqual(errors, [])
        self.assertEqual([f.source_tool for f in findings], ['ast', 'nuclei', 'zap'])
        self.assertEqual(findings[0].vulnerability_type, 'IDOR')
        self.assertTrue(all(f.details['status'] == 'CANDIDATE' for f in findings))

    def test_partial_failure_is_nonzero_with_json_list(self):
        heuristic = HeuristicFinding('app.py', 1, 'get_note', 'IDOR-AST-01', 'MEDIUM', 'Review')
        out, err = io.StringIO(), io.StringIO()
        with patch.object(run_scan.semgrep_runner, 'scan', side_effect=ScanError('PartialParsing', findings=[RawFinding('app.py', 4, 'rule', 'review', 'WARNING', '', 'semgrep')])), \
             patch.object(run_scan.ast_heuristic_analyzer, 'scan', return_value=[heuristic]), \
             patch.object(run_scan.secrets_runner, 'scan', return_value=[]), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = run_scan.main(['--repo-path', '.'])
        self.assertEqual(status, 2)
        self.assertEqual(len(json.loads(out.getvalue())), 2)
        self.assertEqual({f['source_tool'] for f in json.loads(out.getvalue())}, {'ast', 'semgrep'})
        self.assertFalse(json.loads(err.getvalue())['complete'])

    def test_requires_target(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            run_scan.main([])
        self.assertEqual(result.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
