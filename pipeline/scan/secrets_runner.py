"""Scan working-tree files with Gitleaks; report redacted secret candidates."""

import os
from pathlib import Path
import tempfile

try:
    from .common import RawFinding, ScanError, read_json, repo_directory, run_cli, run_command, tool_environment
except ImportError:
    from common import RawFinding, ScanError, read_json, repo_directory, run_cli, run_command, tool_environment


def parse_output(output):
    report = read_json(output, 'Gitleaks')
    if not isinstance(report, list):
        raise ScanError('Gitleaks report must be a list.')
    try:
        return [RawFinding(item['File'], int(item['StartLine']), item['RuleID'],
                           item['Description'], 'HIGH', '[REDACTED]', 'gitleaks') for item in report]
    except (KeyError, TypeError, ValueError) as exc:
        raise ScanError('Malformed Gitleaks finding.') from exc


def scan(repo_path, timeout=180):
    repo = repo_directory(repo_path)
    with tempfile.TemporaryDirectory(prefix='vibeshield-gitleaks-') as directory:
        report = Path(directory) / 'report.json'
        result = run_command([os.environ.get('GITLEAKS_BIN', 'gitleaks'), 'dir', str(repo),
                              '--report-format', 'json', '--report-path', str(report),
                              '--redact=100', '--no-banner', '--exit-code', '10'],
                             timeout, cwd=directory, env=tool_environment(), accepted=(0, 10))
        if not report.is_file():
            raise ScanError('Gitleaks did not write its report; scan incomplete.')
        findings = parse_output(report.read_text())
        if (result.returncode == 10) != bool(findings):
            raise ScanError('Gitleaks exit status and report disagree; scan incomplete.')
        return findings


if __name__ == '__main__':
    raise SystemExit(run_cli(__doc__, scan))
