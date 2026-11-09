"""Open a native directory chooser on the desktop running the local server."""
from pathlib import Path
import shutil
import subprocess
import threading

from pipeline.scan.common import ScanError

_lock = threading.Lock()
ROOT = Path(__file__).resolve().parents[1]


def pick_directory(initial=''):
    if not isinstance(initial, str) or len(initial) > 2048 or '\0' in initial:
        raise ScanError('Enter a valid project directory before browsing.')
    start = Path(initial).expanduser() if initial.strip() else Path.home()
    if not start.is_absolute():
        start = ROOT / start
    if not start.is_dir():
        start = Path.home()
    if shutil.which('zenity'):
        command = ['zenity', '--file-selection', '--directory',
                   '--title=Select a VibeShield project', '--filename=' + str(start.resolve()) + '/']
    elif shutil.which('kdialog'):
        command = ['kdialog', '--getexistingdirectory', str(start.resolve()),
                   '--title', 'Select a VibeShield project']
    else:
        raise ScanError('Folder browsing needs Zenity or KDialog. Run python3 setup.py '
                        'to install Zenity, or enter the project path manually.')
    if not _lock.acquire(blocking=False):
        raise ScanError('A folder picker is already open. Select a folder or cancel that window first.')
    try:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired as exc:
            raise ScanError('Folder selection timed out. Click Browse to try again.') from exc
        except OSError as exc:
            raise ScanError('Cannot open the folder picker. Enter the project path manually.') from exc
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise ScanError('Cannot open the folder picker. Run the dashboard in your desktop '
                            'session, or enter the project path manually.')
        path = result.stdout.rstrip('\n')
        if not path:
            return None
        directory = Path(path)
        if not directory.is_absolute() or not directory.is_dir():
            raise ScanError('The selected folder is unavailable. Please select an existing directory.')
        return str(directory.resolve())
    finally:
        _lock.release()
