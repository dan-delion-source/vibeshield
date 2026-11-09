import subprocess
import io
import json
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard.folder_picker import pick_directory
from dashboard.server import Handler
from pipeline.scan.common import ScanError


class FolderPickerTests(unittest.TestCase):
    def test_selection_returns_absolute_path_without_shell(self):
        with tempfile.TemporaryDirectory(prefix='project with spaces ') as directory:
            with patch('dashboard.folder_picker.shutil.which', return_value='/usr/bin/zenity'), \
                 patch('dashboard.folder_picker.subprocess.run') as run:
                run.return_value = subprocess.CompletedProcess([], 0, directory + '\n', '')
                self.assertEqual(pick_directory(directory), str(Path(directory).resolve()))
                self.assertIn('--directory', run.call_args.args[0])
                self.assertNotIn('shell', run.call_args.kwargs)

    def test_cancel_returns_no_selection(self):
        with patch('dashboard.folder_picker.shutil.which', return_value='zenity'), \
             patch('dashboard.folder_picker.subprocess.run',
                   return_value=subprocess.CompletedProcess([], 1, '', '')):
            self.assertIsNone(pick_directory())

    def test_missing_picker_is_actionable(self):
        with patch('dashboard.folder_picker.shutil.which', return_value=None):
            with self.assertRaisesRegex(ScanError, 'manually'):
                pick_directory()

    def test_timeout_and_desktop_failure(self):
        with patch('dashboard.folder_picker.shutil.which', return_value='zenity'):
            with patch('dashboard.folder_picker.subprocess.run', side_effect=subprocess.TimeoutExpired([], 300)):
                with self.assertRaisesRegex(ScanError, 'timed out'):
                    pick_directory()
            with patch('dashboard.folder_picker.subprocess.run',
                       return_value=subprocess.CompletedProcess([], 2, '', 'private error')):
                with self.assertRaisesRegex(ScanError, 'desktop session'):
                    pick_directory()

    def test_invalid_initial_path(self):
        for initial in [42, 'a' * 2049, '\0']:
            with self.assertRaises(ScanError):
                pick_directory(initial)

    def test_endpoint_requires_session_token_and_does_not_start_scan(self):
        payload = json.dumps({'initial': '/tmp'}).encode()
        handler = Handler.__new__(Handler)
        handler.server = SimpleNamespace(csrf='session-token')
        handler.trusted = lambda: True
        handler.path = '/api/pick-directory'
        handler.headers = {'Content-Length':str(len(payload)), 'X-VibeShield-Token':'wrong-token'}
        handler.rfile = io.BytesIO(payload)
        with patch.object(handler, 'send') as send, patch('dashboard.server.pick_directory') as picker:
            handler.do_POST()
            self.assertEqual(send.call_args.args[0], 403)
            picker.assert_not_called()
            handler.headers['X-VibeShield-Token'] = 'session-token'
            picker.return_value = '/tmp'
            handler.do_POST()
            send.assert_called_with(200, {'path':'/tmp'})
            picker.assert_called_once_with('/tmp')
