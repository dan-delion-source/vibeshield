"""Run Semgrep OSS rules; missing ownership checks belong to the AST analyzer."""

import os
import re
from pathlib import Path
import tempfile

try:
    from .common import RawFinding, ScanError, read_json, repo_directory, run_cli, run_command, tool_environment
except ImportError:
    from common import RawFinding, ScanError, read_json, repo_directory, run_cli, run_command, tool_environment


RULES = Path(__file__).with_name("rules") / "flask.yaml"


def error_summary(errors, repo):
    """Expose diagnostic metadata, never messages/snippets that may contain secrets."""
    if not isinstance(errors, list):
        return "Semgrep returned malformed error metadata; scan incomplete."
    summaries = []
    kinds = set()
    for error in errors[:5]:
        if not isinstance(error, dict):
            summaries.append("Unspecified scanner error")
            continue
        kind = error.get("type", "Unspecified scanner error")
        # Payload-bearing variants serialize as [tag, payload], e.g. PartialParsing.
        if isinstance(kind, list) and kind:
            kind = kind[0]
        if not isinstance(kind, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]{0,79}", kind):
            kind = "Unspecified scanner error"
        kinds.add(kind.lower())
        spans = error.get("spans")
        span = spans[0] if isinstance(spans, list) and spans and isinstance(spans[0], dict) else {}
        path = error.get("path") or span.get("file")
        location = ""
        if isinstance(path, str):
            # Only show paths belonging to the scanned checkout.
            resolved = (repo / path).resolve()
            if resolved.is_relative_to(repo.resolve()):
                location = " in " + re.sub(r"[\x00-\x1f\x7f]", "?", str(resolved.relative_to(repo.resolve())))[:240]
        start = span.get("start") or error.get("start")
        if location and isinstance(start, dict) and type(start.get("line")) is int:
            location += f":{start['line']}"
        summaries.append(kind + location)
    extra = f"; {len(errors) - 5} more errors" if len(errors) > 5 else ""
    hint = "Review the affected file/rule with Semgrep locally."
    if any("pars" in kind or "syntax" in kind for kind in kinds):
        hint = "Some source regions could not be parsed. HTML containing template syntax may not be fully supported; this does not by itself mean the application syntax is invalid. Exclude a file only if it is intentionally outside scan scope."
    elif any("timeout" in kind for kind in kinds):
        hint = "A rule/file exceeded Semgrep's internal timeout; review that rule or its timeout setting."
    return f"Semgrep reported {len(errors)} diagnostic(s): {'; '.join(summaries)}{extra}. Scan incomplete. {hint}"


def parse_output(output, repo):
    report = read_json(output, "Semgrep")
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ScanError("Semgrep report has no results list.")
    findings = []
    try:
        for item in report["results"]:
            extra = item["extra"]
            line = int(item["start"]["line"])
            filename = item["path"]
            snippet = extra.get("lines", "")
            if not snippet or snippet == "requires login":
                source = (repo / filename).resolve()
                snippet = ""
                if source.is_relative_to(repo):
                    lines = source.read_text(errors="replace").splitlines()
                    if 0 < line <= len(lines):
                        snippet = lines[line - 1]
            findings.append(RawFinding(filename, line, item["check_id"],
                                       extra["message"], extra["severity"], snippet, "semgrep"))
    except (KeyError, TypeError, ValueError, AttributeError, OSError) as exc:
        raise ScanError("Malformed Semgrep finding or unreadable source.") from exc
    if report.get("errors"):
        raise ScanError(error_summary(report["errors"], repo), findings=findings)
    return findings


def scan(repo_path, timeout=180, configs=None):
    repo = repo_directory(repo_path)
    selected_configs = configs if configs is not None else ["auto", str(RULES)]
    # Semgrep's auto resolver requires metrics; pinned local rules can disable them.
    metrics = "auto" if "auto" in selected_configs else "off"
    command = [os.environ.get("SEMGREP_BIN", "semgrep"), "scan", "--json",
               f"--metrics={metrics}", "--disable-version-check", "--jobs", "1"]
    for config in selected_configs:
        command.extend(["--config", str(config)])
    command.append(str(repo))
    with tempfile.TemporaryDirectory(prefix="vibeshield-semgrep-") as directory:
        env = tool_environment()
        env.update(SEMGREP_SETTINGS_FILE=str(Path(directory) / "settings.yml"),
                   SEMGREP_LOG_FILE=str(Path(directory) / "semgrep.log"),
                   SEMGREP_SEND_METRICS=metrics, SEMGREP_ENABLE_VERSION_CHECK="0")
        result = run_command(command, timeout, cwd=repo, env=env)
    return parse_output(result.stdout, repo)


if __name__ == "__main__":
    raise SystemExit(run_cli(__doc__, scan))
