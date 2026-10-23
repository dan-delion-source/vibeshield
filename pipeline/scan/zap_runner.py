"""Run a local ZAP passive baseline. Findings may overlap Nuclei; no deduplication."""

import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

try:
    from .common import RawFinding, ScanError, local_url, read_json, run_cli, run_command, tool_environment
except ImportError:
    from common import RawFinding, ScanError, local_url, read_json, run_cli, run_command, tool_environment


DEFAULT_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
SEVERITIES = {'0': 'INFO', '1': 'LOW', '2': 'MEDIUM', '3': 'HIGH'}


def parse_output(output):
    report = read_json(output, 'ZAP')
    if not isinstance(report, dict) or not isinstance(report.get('site'), list) or not report['site']:
        raise ScanError('ZAP report has no scanned site; scan incomplete.')
    findings = []
    try:
        for site in report['site']:
            if not isinstance(site['alerts'], list):
                raise TypeError('alerts must be a list')
            for alert in site['alerts']:
                instances = alert.get('instances') or [{'uri': site['@name']}]
                for instance in instances:
                    findings.append(RawFinding(instance['uri'], 0, str(alert['pluginid']),
                                               alert.get('name') or alert['alert'],
                                               SEVERITIES[str(alert['riskcode'])], '', 'zap'))
    except (KeyError, TypeError) as exc:
        raise ScanError('Malformed ZAP finding.') from exc
    return findings


def scan_native(target, binary, directory, timeout):
    """Equivalent passive baseline via ZAP's official Automation Framework CLI."""
    report = Path(directory) / 'report.json'
    plan = {
        'env': {
            'contexts': [{'name': 'local-fixture', 'urls': [target]}],
            'parameters': {'failOnError': True, 'failOnWarning': True, 'progressToStdout': False},
        },
        'jobs': [
            {'type': 'passiveScan-config', 'parameters': {'scanOnlyInScope': True}},
            {'type': 'spider', 'parameters': {'context': 'local-fixture', 'url': target, 'maxDuration': 1}},
            {'type': 'passiveScan-wait', 'parameters': {'maxDuration': 2}},
            {'type': 'report', 'parameters': {'template': 'traditional-json', 'reportDir': directory,
                                            'reportFile': 'report.json', 'reportTitle': 'Local fixture baseline'}},
        ],
    }
    plan_file = Path(directory) / 'baseline.yaml'
    # JSON is a YAML subset: the wrapper needs no YAML dependency.
    plan_file.write_text(json.dumps(plan))
    command = [binary, '-cmd', '-silent', '-host', '127.0.0.1', '-dir', str(Path(directory) / 'state'),
               '-autorun', str(plan_file), '-config', 'autoupdate.checkOnStart=false',
               '-config', 'autoupdate.downloadNewRelease=false']
    # AF statuses 1/2 mean plan errors/warnings, unlike packaged-baseline statuses.
    run_command(command, timeout, cwd=directory, env=tool_environment())
    if not report.is_file():
        raise ScanError('ZAP CLI did not write its JSON report; scan incomplete.')
    return parse_output(report.read_text())


def scan(url, timeout=300, mode='auto', image=None):
    target = local_url(url)
    if mode not in {'auto', 'cli', 'docker', 'native'}:
        raise ScanError('ZAP mode must be auto, cli, native, or docker.')
    baseline = os.environ.get('ZAP_BIN') or shutil.which('zap-baseline.py')
    native = os.environ.get('ZAP_CLI_BIN') or shutil.which('zap.sh')
    use_docker = mode == 'docker' or (mode == 'auto' and not baseline)
    with tempfile.TemporaryDirectory(prefix='vibeshield-zap-') as directory:
        if mode == 'native' or (mode == 'auto' and native and not baseline):
            return scan_native(target, native or 'zap.sh', directory, timeout)
        report = Path(directory) / 'report.json'
        container_name = 'vibeshield-zap-' + uuid.uuid4().hex[:12]
        arguments = ['-t', target, '-J', 'report.json' if use_docker else str(report),
                     '-m', '1', '-T', '2', '-z',
                     '-silent -host 127.0.0.1 -config api.addrs.addr.name=127.0.0.1 '
                     '-config api.addrs.addr.regex=false -config autoupdate.checkOnStart=false '
                     '-config autoupdate.downloadNewRelease=false']
        if use_docker:
            # Linux host networking makes loopback refer to the local fixture host.
            command = [os.environ.get('DOCKER_BIN', 'docker'), 'run', '--rm', '--name', container_name,
                       '--network', 'host', '--user', f'{os.getuid()}:{os.getgid()}',
                       '--mount', f'type=bind,source={directory},target=/zap/wrk',
                       os.environ.get('ZAP_IMAGE', image or DEFAULT_IMAGE), 'zap-baseline.py', *arguments]
        else:
            command = [baseline or 'zap-baseline.py', *arguments]
        try:
            run_command(command, timeout, cwd=directory, env=tool_environment(), accepted=(0, 1, 2))
            if not report.is_file():
                raise ScanError('ZAP did not write its JSON report; scan incomplete.')
            return parse_output(report.read_text())
        finally:
            if use_docker:
                # A timed-out Docker client can leave its container running.
                try:
                    run_command([command[0], 'rm', '-f', container_name], timeout=15, accepted=(0, 1))
                except ScanError:
                    pass


if __name__ == '__main__':
    raise SystemExit(run_cli(__doc__, scan, kind='url', default_timeout=300))
