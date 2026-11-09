"""Expose project-local scanner installations without shell activation."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def tool_environment():
    env = os.environ.copy()
    paths = [ROOT / '.tools' / 'bin', ROOT / '.tools' / 'semgrep' / 'bin']
    env['PATH'] = os.pathsep.join([*(str(path) for path in paths), env.get('PATH', '')])
    return env
