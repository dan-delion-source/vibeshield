"""Shared scanner records and subprocess/CLI error handling (standard library only)."""

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from urllib.parse import urlsplit


@dataclass(frozen=True)
class RawFinding:
    file: str
    line: int
    rule_id: str
    message: str
    severity: str
    source_snippet: str
    source: str


class ScanError(Exception):
    """An incomplete scan may still carry valid findings from completed work."""

    def __init__(self, message, findings=()):
        super().__init__(message)
        self.findings = tuple(findings)


class ScanCoverageError(ScanError):
    """A scanner returned a valid report with known gaps in source coverage."""


def run_command(command, timeout=180, cwd=None, env=None, accepted=(0,)):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, cwd=cwd, env=env, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            # Kill the process group too: shell launchers may leave a Java child behind.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except FileNotFoundError as exc:
        raise ScanError(f"Missing tool: {command[0]}. Install it or set its binary path.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"{command[0]} timed out after {timeout} seconds; scan incomplete.") from exc
    except OSError as exc:
        raise ScanError(f"Cannot run {command[0]}: {exc}") from exc
    if result.returncode not in accepted:
        # Avoid echoing scanner diagnostics that may contain discovered credentials.
        raise ScanError(f"{command[0]} exited with status {result.returncode}; scan incomplete.")
    return result


def read_json(value, source):
    try:
        return json.loads(value)
    except (ValueError, TypeError) as exc:
        raise ScanError(f"Invalid JSON from {source}; scan incomplete.") from exc


def repo_directory(value):
    path = Path(value).resolve()
    if not path.is_dir():
        raise ScanError(f"Repository directory does not exist: {path}")
    return path


def local_url(value):
    """Development scope check, not network isolation or a redirect sandbox."""
    try:
        url = urlsplit(value)
        url.port  # Validate a supplied port without resolving the host.
    except ValueError as exc:
        raise ScanError(f"Invalid target URL: {exc}") from exc
    if (url.scheme not in {"http", "https"} or
            url.hostname not in {"localhost", "127.0.0.1", "::1"} or
            url.username or url.password or url.fragment):
        raise ScanError("This phase accepts only http(s) localhost/127.0.0.1/[::1] URLs without credentials or fragments.")
    return value


def tool_environment():
    env = os.environ.copy()
    # No cloud credentials are needed by these local scanner processes.
    for key in list(env):
        if key.startswith(("OPENAI_", "ANTHROPIC_", "SEMGREP_APP_", "PDCP_")):
            env.pop(key)
    return env


def run_cli(description, scan, kind="repo", default_timeout=180):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--repo-path" if kind == "repo" else "--url", required=True)
    parser.add_argument("--timeout", type=int, default=default_timeout)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        target = args.repo_path if kind == "repo" else args.url
        findings = scan(target, timeout=args.timeout)
    except (ScanError, OSError) as exc:
        print(json.dumps([asdict(item) for item in getattr(exc, "findings", ())], indent=2))
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps([asdict(item) for item in findings], indent=2))
    return 0
