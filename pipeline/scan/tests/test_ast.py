"""Regression cases use temporary source; they never modify the fixture."""
import ast
from pathlib import Path
import tempfile
import unittest

from pipeline.scan.ast_heuristic_analyzer import analyze_function, scan
from pipeline.scan.common import ScanError


class AstTests(unittest.TestCase):
    def findings(self, body, path='/api/notes/<int:note_id>', decorator='app.get'):
        source = f'@{decorator}({path!r})\ndef get_note(note_id):\n' + '\n'.join('    ' + line for line in body.splitlines())
        function = ast.parse(source).body[0]
        return analyze_function(function, 'app.py')

    def test_missing_ownership(self):
        result = self.findings('token = request.headers.get("Authorization")\nif not token:\n    abort(401)\nnote = NOTES.get(note_id)\nreturn jsonify(note)')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].heuristic_id, 'IDOR-AST-01')
        self.assertIn('note_id', result[0].reason)

    def test_owner_guard(self):
        self.assertEqual(self.findings('note = NOTES.get(note_id)\nif note is None:\n    abort(404)\nif note["owner"] != current_user.id:\n    abort(403)\nreturn jsonify(note)'), [])

    def test_direct_prelookup_guard(self):
        self.assertEqual(self.findings('if note_id != session["user_id"]:\n    abort(403)\nreturn db.get(note_id)'), [])

    def test_token_alias_owner_guard(self):
        self.assertEqual(self.findings('token = request.headers.get("Authorization")\nuser = TOKENS.get(token)\nnote = NOTES.get(note_id)\nif note.owner_id != user.id:\n    abort(403)\nreturn note'), [])

    def test_log_only_comparison_not_guard(self):
        self.assertEqual(len(self.findings('if note_id != current_user.id:\n    print("denied")\nreturn db.get(note_id)')), 1)

    def test_unrelated_identity_comparison(self):
        self.assertEqual(len(self.findings('if current_user.id != other_user.id:\n    abort(403)\nreturn db.get(note_id)')), 1)

    def test_guard_after_return_not_guard(self):
        self.assertEqual(len(self.findings('note = db.get(note_id)\nreturn note\nif note.owner_id != current_user.id:\n    abort(403)')), 1)

    def test_leak_before_guard_not_suppressed(self):
        self.assertEqual(len(self.findings('note = db.get(note_id)\nprint(note)\nif note.owner_id != current_user.id:\n    abort(403)\nreturn note')), 1)

    def test_nested_helper_not_guard(self):
        self.assertEqual(len(self.findings('def check():\n    if note_id != current_user.id:\n        abort(403)\nreturn db.get(note_id)')), 1)

    def test_nested_conditional_not_guard(self):
        self.assertEqual(len(self.findings('if debug:\n    if note_id != current_user.id:\n        abort(403)\nreturn db.get(note_id)')), 1)

    def test_blueprint(self):
        self.assertEqual(len(self.findings('return db.filter_by(id=note_id)', decorator='notes_bp.route')), 1)

    def test_no_route_id(self):
        self.assertEqual(self.findings('return db.get(note_id)', path='/api/notes'), [])

    def test_id_not_used_in_lookup(self):
        self.assertEqual(self.findings('print(note_id)\nreturn db.get(1)'), [])

    def test_parse_error_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'bad.py').write_text('def broken(')
            with self.assertRaises(ScanError):
                scan(directory)

    def test_recovered_fixture(self):
        fixture = Path(__file__).resolve().parents[3] / 'fixtures' / 'idor-notes-app'
        if not fixture.exists():
            self.skipTest('Original fixture is unavailable')
        findings = scan(fixture)
        self.assertEqual([f.function_name for f in findings], ['get_note'])

    def test_clean_sqlite_fixture_copy(self):
        fixture = Path(__file__).resolve().parents[3] / 'fixtures' / 'idor-notes-app' / 'app.py'
        if not fixture.exists():
            self.skipTest('Original fixture is unavailable')
        source = fixture.read_text()
        marker = '    # BUG: no check that note["owner_id"] == user["id"]'
        self.assertIn(marker, source)
        clean = source.replace(marker, '    if note["owner_id"] != user["id"]:\n        return jsonify({"error": "forbidden"}), 403')
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'app.py').write_text(clean)
            self.assertEqual(scan(directory), [])


if __name__ == '__main__':
    unittest.main()
