"""Run deterministic local HTTP templates. Nuclei and ZAP results may overlap."""

import os
from pathlib import Path
import tempfile

try:
    from .common import RawFinding, ScanError, local_url, read_json, run_cli, run_command, tool_environment
except ImportError:
    from common import RawFinding, ScanError, local_url, read_json, run_cli, run_command, tool_environment


TEMPLATES = Path(__file__).with_name('templates')


def parse_output(output):
    findings = []
    for number, line in enumerate(output.splitlines(), 1):
        if not line.strip():
            continue
        item = read_json(line, f'Nuclei line {number}')
        try:
            info = item['info']
            findings.append(RawFinding(item['matched-at'], 0, item['template-id'],
                                       info['name'], info['severity'].upper(), '', 'nuclei'))
        except (KeyError, TypeError, AttributeError) as exc:
            raise ScanError(f'Malformed Nuclei finding on line {number}.') from exc
    return findings


def scan(url, timeout=180):
    target = local_url(url)
    with tempfile.TemporaryDirectory(prefix='vibeshield-nuclei-') as directory:
        config = Path(directory) / 'config.yaml'
        config.write_text('{}\n')
        env = tool_environment()
        for kind in ('CONFIG', 'CACHE', 'DATA'):
            state = Path(directory) / kind.lower()
            state.mkdir()
            env[f'XDG_{kind}_HOME'] = str(state)
        # Use only the reviewed, bundled HTTP templates. No AI generation, cloud upload,
        # template download, out-of-band callbacks, or cross-host redirects.
        for provider in ('PUBLIC', 'GITHUB', 'GITLAB', 'AWS', 'AZURE'):
            env[f'DISABLE_NUCLEI_TEMPLATES_{provider}_DOWNLOAD'] = 'true'
        command = [os.environ.get('NUCLEI_BIN', 'nuclei'), '-u', target, '-jsonl',
                   '-silent', '-no-color', '-omit-raw', '-duc', '-ni', '-dr',
                   '-config', str(config), '-t', str(TEMPLATES), '-rl', '5', '-c', '1']
        result = run_command(command, timeout, cwd=directory, env=env)
    return parse_output(result.stdout)


if __name__ == '__main__':
    raise SystemExit(run_cli(__doc__, scan, kind='url'))
