#!/usr/bin/env python3
"""Install VibeShield and its scanners. Run with Python 3.10+ as a normal user."""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from project_env import ROOT, tool_environment

PYTHON = ROOT / '.venv' / 'bin' / 'python'
SEMGREP_PYTHON = ROOT / '.tools' / 'semgrep' / 'bin' / 'python'
WEB = ROOT / 'dashboard' / 'web'
IMAGE = os.environ.get('ZAP_IMAGE', 'ghcr.io/zaproxy/zaproxy:stable')


class SetupError(Exception):
    pass


def run(command, *, dry_run=False, env=None, cwd=ROOT):
    command = [str(part) for part in command]
    print('+ ' + shlex.join(command), flush=True)
    if dry_run:
        return
    result = subprocess.run(command, cwd=cwd, env=env or tool_environment())
    if result.returncode:
        raise SetupError(f'{Path(command[0]).name} failed (exit {result.returncode}). '
                         'Fix the error above and rerun setup; existing scan data is preserved.')


def succeeds(command, env=None):
    try:
        return subprocess.run([str(x) for x in command], env=env or tool_environment(),
                              cwd=ROOT, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def system_packages(dry_run, skip):
    required = ['git', 'go', 'node', 'npm', 'docker', 'cc', 'zenity']
    missing = [name for name in required if not shutil.which(name)]
    if not missing:
        return
    if skip:
        raise SetupError('Missing system commands: ' + ', '.join(missing) +
                         '. Install them first or rerun without --skip-system.')
    if shutil.which('pacman'):
        command = ['sudo', 'pacman', '-Syu', '--needed', 'python', 'git', 'go',
                   'nodejs', 'npm', 'docker', 'base-devel', 'zenity']
    elif shutil.which('apt-get'):
        run(['sudo', 'apt-get', 'update'], dry_run=dry_run)
        command = ['sudo', 'apt-get', 'install', '-y', 'python3-venv', 'python3-pip',
                   'git', 'golang-go', 'nodejs', 'npm', 'docker.io', 'build-essential', 'zenity']
    else:
        raise SetupError('Automatic system installation supports Arch/CachyOS and Debian/Ubuntu. '
                         'Install these commands manually: ' + ', '.join(missing))
    run(command, dry_run=dry_run)


def install(args):
    dry = args.dry_run
    system_packages(dry, args.skip_system)
    # Debian can have Python but lack the separate venv/ensurepip package.
    if shutil.which('apt-get') and not succeeds([sys.executable, '-c', 'import ensurepip']):
        if args.skip_system:
            raise SetupError('Install python3-venv first, then rerun setup.')
        run(['sudo', 'apt-get', 'install', '-y', 'python3-venv'], dry_run=dry)
    for directory, python in [(ROOT / '.venv', PYTHON),
                              (ROOT / '.tools' / 'semgrep', SEMGREP_PYTHON)]:
        if not python.exists():
            run([sys.executable, '-m', 'venv', directory], dry_run=dry)
    run([PYTHON, '-m', 'pip', 'install', '-r', ROOT / 'dashboard' / 'requirements.txt',
         '-r', ROOT / 'pipeline' / 'requirements.txt'], dry_run=dry)
    run([SEMGREP_PYTHON, '-m', 'pip', 'install', 'semgrep'], dry_run=dry)
    env = tool_environment()
    env.update(GOBIN=str(ROOT / '.tools' / 'bin'),
               GOPATH=str(ROOT / '.tools' / 'go'),
               GOCACHE=str(ROOT / '.tools' / 'go-cache'), GOTOOLCHAIN='auto')
    if not dry:
        (ROOT / '.tools' / 'bin').mkdir(parents=True, exist_ok=True)
    for name, module in [('gitleaks', 'github.com/zricethezav/gitleaks/v8'),
                         ('nuclei', 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei')]:
        binary = ROOT / '.tools' / 'bin' / name
        version_flag = 'version' if name == 'gitleaks' else '-version'
        if not binary.exists() or (not dry and not succeeds([binary, version_flag])):
            run(['go', 'install', module + '@latest'], dry_run=dry, env=env)
    run(['npm', 'ci'], dry_run=dry, cwd=WEB)
    run(['npm', 'run', 'build'], dry_run=dry, cwd=WEB)
    docker = env.get('DOCKER_BIN', 'docker')
    if dry:
        print('If needed, start the local Docker service using sudo systemctl start docker.')
    elif not succeeds([docker, 'info']):
        if shutil.which('systemctl') and not succeeds(['systemctl', 'is-active', '--quiet', 'docker']):
            run(['sudo', 'systemctl', 'start', 'docker'])
        if not succeeds([docker, 'info']):
            raise SetupError('Docker is not accessible to your user. Configure rootless Docker, '
                             'or run sudo usermod -aG docker "$USER" and log out and back in. '
                             'The docker group grants root-level access. Then rerun setup. '
                             'Do not run this whole script with sudo.')
    run([docker, 'pull', IMAGE], dry_run=dry)
    if dry:
        print('Preview only: no packages installed, services started, or project files changed.')
        return 0
    status = check()
    if status == 0:
        print('\nSetup complete. Start: python3 setup.py --run\n'
              'Dashboard: http://127.0.0.1:8787\nStop: Ctrl+C (scan data is preserved).')
    return status


def check():
    env = tool_environment()
    probes = [
        ('Dashboard Python and PDF support', [PYTHON, '-c',
         'import ast, io; from reportlab.pdfgen.canvas import Canvas; '
         'pdf = Canvas(io.BytesIO()); pdf.save()']),
        ('Semgrep', [env.get('SEMGREP_BIN', 'semgrep'), '--version']),
        ('Gitleaks', [env.get('GITLEAKS_BIN', 'gitleaks'), 'version']),
        ('Nuclei', [env.get('NUCLEI_BIN', 'nuclei'), '-version']),
        ('Git', [env.get('GIT_BIN', 'git'), '--version']),
        ('Docker access', [env.get('DOCKER_BIN', 'docker'), 'info']),
        ('ZAP image', [env.get('DOCKER_BIN', 'docker'), 'image', 'inspect', IMAGE]),
    ]
    ready = True
    for label, command in probes:
        passed = succeeds(command, env)
        print(f'{"OK" if passed else "MISSING/FAILED"}: {label}', flush=True)
        ready &= passed
    built = (WEB / 'dist' / 'index.html').is_file()
    print(f'{"OK" if built else "MISSING"}: Dashboard build')
    print('Availability checks only; no target scans were run.')
    return 0 if ready and built else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--dry-run', action='store_true', help='Preview installation without changing files')
    modes.add_argument('--check', action='store_true', help='Check installations without installing')
    modes.add_argument('--run', action='store_true', help='Start dashboard without installing')
    parser.add_argument('--skip-system', action='store_true', help='Do not install system packages')
    args = parser.parse_args(argv)
    if sys.version_info < (3, 10):
        raise SetupError('Python 3.10 or newer is required.')
    if sys.platform != 'linux':
        raise SetupError('This installer targets Linux; the ZAP runner uses Linux host networking.')
    if args.check:
        return check()
    if args.run:
        if not PYTHON.exists() or not (WEB / 'dist' / 'index.html').is_file():
            raise SetupError('Run python3 setup.py first to install and build the dashboard.')
        print('Starting VibeShield. Stop with Ctrl+C; scan data is preserved.', flush=True)
        return subprocess.call([str(PYTHON), str(ROOT / 'run_dashboard.py')],
                               cwd=ROOT, env=tool_environment())
    if os.geteuid() == 0:
        raise SetupError('Run setup as your normal user. Only system steps use sudo.')
    return install(args)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('\nStopped. Existing scan data is preserved.')
        raise SystemExit(130)
    except (SetupError, OSError) as exc:
        print(f'\nSetup failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
