"""Offline checks for installer failure handling and project tool discovery."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import setup
from project_env import ROOT, tool_environment
from pipeline.scan.ast_heuristic_analyzer import scan


class SetupTests(unittest.TestCase):
    def test_local_path_and_explicit_override(self):
        with patch.dict(os.environ, {'PATH': '/usr/bin', 'SEMGREP_BIN': '/custom/semgrep'}):
            env = tool_environment()
        self.assertEqual(env['PATH'].split(os.pathsep)[0], str(ROOT / '.tools' / 'bin'))
        self.assertEqual(env['SEMGREP_BIN'], '/custom/semgrep')

    def test_dry_run_never_executes_commands(self):
        with patch('setup.subprocess.run') as command, contextlib.redirect_stdout(io.StringIO()):
            setup.run(['sudo', 'pacman', '-Syu'], dry_run=True)
        command.assert_not_called()

    def test_failed_install_is_not_success(self):
        with patch('setup.subprocess.run') as command, contextlib.redirect_stdout(io.StringIO()):
            command.return_value.returncode = 1
            with self.assertRaises(setup.SetupError):
                setup.run(['npm', 'ci'])

    def test_inaccessible_docker_fails_check(self):
        with tempfile.TemporaryDirectory() as directory:
            web = Path(directory)
            (web / 'dist').mkdir()
            (web / 'dist' / 'index.html').touch()
            def available(command, env=None):
                return 'docker' not in str(command[0])
            with patch.object(setup, 'WEB', web), patch.object(setup, 'succeeds', side_effect=available), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup.check(), 1)

    def test_skip_system_reports_missing_dependencies(self):
        with patch('setup.shutil.which', return_value=None):
            with self.assertRaisesRegex(setup.SetupError, 'Missing system commands'):
                setup.system_packages(False, True)

    def test_ast_skips_installed_scanner_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            tools = Path(directory) / '.tools'
            tools.mkdir()
            (tools / 'invalid.py').write_text('invalid python : : :')
            self.assertEqual(scan(directory), [])


if __name__ == '__main__':
    unittest.main()
