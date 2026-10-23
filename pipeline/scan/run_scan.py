"""Consolidate deterministic static and local dynamic vulnerability candidates."""

import argparse
from dataclasses import asdict, dataclass
import json
import sys

try:
    from . import ast_heuristic_analyzer, nuclei_runner, secrets_runner, semgrep_runner, zap_runner
    from .common import ScanError
except ImportError:
    import ast_heuristic_analyzer
    import nuclei_runner
    import secrets_runner
    import semgrep_runner
    import zap_runner
    from common import ScanError


@dataclass(frozen=True)
class CandidateFinding:
    file_or_endpoint: str
    vulnerability_type: str
    confidence: str
    source_tool: str
    details: dict


def consolidate(finding):
    details = asdict(finding)
    details['status'] = 'CANDIDATE'
    if isinstance(finding, ast_heuristic_analyzer.HeuristicFinding):
        return CandidateFinding(finding.file, 'IDOR', finding.confidence, 'ast', details)
    # Confidence describes evidence specificity, not severity or exploitability.
    confidence = 'HIGH' if finding.source == 'gitleaks' else 'MEDIUM'
    if finding.severity.upper() in {'INFO', 'INFORMATIONAL'}:
        confidence = 'LOW'
    vulnerability = 'SECRET_EXPOSURE' if finding.source == 'gitleaks' else finding.rule_id
    return CandidateFinding(finding.file, vulnerability, confidence, finding.source, details)


def scan(repo_path=None, url=None, timeout=300):
    jobs = []
    if repo_path is not None:
        jobs.extend([('semgrep', semgrep_runner.scan, repo_path),
                     ('ast', ast_heuristic_analyzer.scan, repo_path),
                     ('gitleaks', secrets_runner.scan, repo_path)])
    if url is not None:
        jobs.extend([('nuclei', nuclei_runner.scan, url), ('zap', zap_runner.scan, url)])
    findings, errors = [], []
    for source, runner, target in jobs:
        try:
            findings.extend(consolidate(item) for item in runner(target, timeout=timeout))
        except (ScanError, OSError) as exc:
            findings.extend(consolidate(item) for item in getattr(exc, 'findings', ()))
            errors.append({'source_tool': source, 'error': str(exc)})
    findings.sort(key=lambda f: (f.source_tool, f.file_or_endpoint, f.vulnerability_type,
                                 f.details.get('line', 0), json.dumps(f.details, sort_keys=True)))
    return findings, errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-path', help='Local checkout of an owned/authorized GitHub repository')
    parser.add_argument('--url', help='Local fixture URL, e.g. http://localhost:5000/api/health')
    parser.add_argument('--timeout', type=int, default=300, help='Per-tool timeout in seconds')
    args = parser.parse_args(argv)
    if not args.repo_path and not args.url:
        parser.error('provide --repo-path, --url, or both')
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    findings, errors = scan(args.repo_path, args.url, args.timeout)
    print(json.dumps([asdict(item) for item in findings], indent=2))
    if errors:
        print(json.dumps({'complete': False, 'errors': errors}), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
