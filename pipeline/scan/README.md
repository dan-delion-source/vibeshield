# Deterministic scan pipeline

This phase emits **candidates**, not confirmed vulnerabilities. It uses Python's
standard library plus external Semgrep, Gitleaks, Nuclei, and OWASP ZAP processes.
There is no LLM client, prompt, classifier, AI template generation, or AI API call
in this implementation. `pipeline/requirements.txt` contains no Python packages.
The exploit and scoring phases remain unimplemented in this checkout. The dashboard now adds deterministic PDF/JSON reports in `pipeline/report`; see the root README.

## Run

Use Python 3.10+ and install the external tools from their official distributions:
[Semgrep](https://semgrep.dev/docs/getting-started/),
[Gitleaks](https://github.com/gitleaks/gitleaks),
[Nuclei](https://github.com/projectdiscovery/nuclei), and
[ZAP baseline](https://www.zaproxy.org/docs/docker/baseline-scan/).
Put executables on `PATH`, or set `SEMGREP_BIN`, `GITLEAKS_BIN`, `NUCLEI_BIN`,
`ZAP_BIN` (a compatible executable `zap-baseline.py` installation), `ZAP_CLI_BIN`
(native `zap.sh`), and `DOCKER_BIN` to absolute paths.
These variables specify one executable, not a shell command with arguments.

From the project root:

```bash
python3 run_scan.py --repo-path fixtures/idor-notes-app
python3 pipeline/scan/run_scan.py --repo-path fixtures/idor-notes-app
python3 pipeline/scan/run_scan.py --url http://127.0.0.1:5000/api/health
python3 pipeline/scan/run_scan.py --repo-path fixtures/idor-notes-app \
  --url http://127.0.0.1:5000/api/health --timeout 300
```

From `pipeline/scan`, `python3 run_scan.py --repo-path ../../fixtures/idor-notes-app`
works too. Repo paths are local checkouts; this CLI does not clone GitHub URLs. The dashboard provides a separate public GitHub checkout workflow.
Each runner also accepts `--repo-path` or `--url`, and `--timeout`.

The recovered fixture has no `/` page: use `/api/health` for the dynamic smoke
test. With the existing `vibeshield-idor-notes-app:latest` image:

```bash
docker run --rm --name vibeshield-scan-fixture \
  -p 127.0.0.1:5000:5000 vibeshield-idor-notes-app:latest
```

This image was already present locally; no fixture image build is provided here.
The original `app.py` was recovered byte-for-byte from it into the initially
empty workspace. The existing prober was unavailable and has not been recreated.

## Output and errors

Successful runs write one JSON **list** to stdout and exit 0, including runs with
findings. Each item has these fields:

```json
{
  "file_or_endpoint": "app.py",
  "vulnerability_type": "IDOR",
  "confidence": "MEDIUM",
  "source_tool": "ast",
  "details": {
    "file": "app.py",
    "line": 122,
    "function_name": "get_note",
    "heuristic_id": "IDOR-AST-01",
    "confidence": "MEDIUM",
    "reason": "The route ID reaches a database lookup without a recognized ownership guard.",
    "status": "CANDIDATE"
  }
}
```

`details` preserves the underlying dataclass fields. Native tool findings use
`RawFinding(file, line, rule_id, message, severity, source_snippet, source)`;
HTTP findings use `line: 0`. Gitleaks snippets are always `[REDACTED]`.
Raw request/response bodies from Nuclei and ZAP are not included.

`vulnerability_type` is `IDOR` for the AST heuristic, `SECRET_EXPOSURE` for
Gitleaks, and the native rule/template/plugin ID for the other tools. This avoids
inventing a vulnerability classification. Confidence follows an explicit fixed
policy: AST `MEDIUM`, Gitleaks `HIGH` for pattern evidence (not credential validity),
other native findings `MEDIUM`, and informational findings `LOW`. Severity remains
a separate native-tool field. No scoring is performed. Findings are sorted for
stable output; ZAP and Nuclei findings are intentionally **not deduplicated**.

If any tool fails, the orchestrator still emits the successful tools' candidates
as a list, writes `{"complete": false, "errors": [...]}` to stderr, and exits **2**.
Consumers must check the exit status: an empty partial list is not a clean scan.
Standalone runners also exit 2 on failures. Missing binaries, timeouts, malformed
reports, parse failures, and missing report files are failures. ZAP baseline exit
codes 1 (alerts) and 2 (warnings) are valid completed scans when a report exists;
code 3 is a scan failure. Native Automation Framework exit codes 1/2 instead mean
plan errors/warnings and are treated as incomplete scans. Scanner diagnostic text is not echoed because it can
contain credentials. The CLI identifies the failing tool and exit code.

## Exactly what IDOR-AST-01 does

For each Python source file, the analyzer uses `ast.parse` without importing or
executing target code. It ignores `.git`, `.venv`, `venv`, `node_modules`,
`__pycache__`, and symlink files. Invalid Python makes the AST scan incomplete.

1. Find a function decorated with a literal Flask-style `.route`, `.get`, `.post`,
   `.put`, `.patch`, `.delete`, `.head`, or `.options` call. App and Blueprint
   receiver names may vary. The analyzer recognizes shapes, not framework types.
2. Extract a path variable that is also a function argument, named `id`, `pk`,
   `uuid`, or ending in `_id`, `_pk`, or `_uuid`, including Flask converters such
   as `<int:note_id>`.
3. Find that variable in arguments to a method named `execute`, `executemany`,
   `query`, `get`, `get_or_404`, `filter`, or `filter_by`. Nested tuple arguments
   in parameterized SQL count. Dictionary `.get()` counts to support simple
   in-memory fixtures. Resource ID aliases are not tracked.
4. Look for a recognized inline ownership **deny guard**. A standalone comparison
   or a logging-only branch is insufficient. A top-level `if id != identity:
   abort(403)` before lookup is recognized. So is a fetched resource's ownership
   guard after lookup but before further use, such as
   `if note['owner_id'] != user['id']: return jsonify({'error': 'forbidden'}), 403`.
   This latter case avoids flagging ordinary safe fetch-then-authorize handlers.
   A prior missing-resource guard (`if note is None` or `if not note`) is allowed.
5. Identity hints include `current_user`, `user_id`, `uid`, `auth_user`,
   `authenticated_user`, `authenticated_user_id`, `session[...]`, supported
   `session.get(...)`, `g.user`, `request.authorization`, and token aliases derived
   from `request.headers.get('Authorization')` / `X-Auth-Token`. Straight-line
   assignments propagate these hints, including `user = get_user_from_token(token)`.
   Owner fields are `owner`, `owner_id`, `user_id`, `created_by`, and `author_id`.
6. Emit one `MEDIUM` candidate per unchecked lookup/route-parameter pair, with the
   exact file, lookup line, function name, and explanation.

Recognized denials are an unconditional first-statement `raise`, an `abort` with
401/403/404, or a static error payload returned with 401/403/404. An equality guard
with a rejecting `else` also counts. Fetched resources must be directly assigned,
optionally through `.fetchone()`, `.first()`, `.one()`, or `.one_or_none()`.

For the recovered fixture, `get_note()` authenticates a token, then passes
`note_id` to `db.execute()` at **app.py:122**. It returns the note without comparing
`note['owner_id']` to `user['id']`. Authentication does not imply ownership.
The analyzer emits `IDOR-AST-01`; only a later authorized probe could confirm it.

### Explicit limitations

- Flask/common decorator shapes only. Dynamic route strings, `add_url_rule`,
  class-based routes, and other frameworks are unsupported.
- No decorator, middleware, helper-function, interprocedural, type, or general
  control-flow analysis. Ownership enforced elsewhere can cause false positives.
- No SQL semantics or query-scoped ownership analysis. A correctly constrained
  `WHERE owner_id = ?`, ORM filter, or policy layer can still be flagged.
- No general taint tracking. Resource-ID aliases, unusual lookup names, direct
  dictionary indexing, non-ID path names, request-body IDs, and IDs not explicitly
  passed into a recognized lookup can be missed.
- Complex guards in loops, nested branches, boolean expressions, `assert`, or
  unconventional error-return shapes may be missed. Owner and identity aliases
  are heuristic; familiar names can be misleading and cause false negatives.
- Comparing a resource ID with a user ID is only a syntactic signal; it does not
  prove a valid authorization policy. A suppressed finding is not proof of safety.
- Public resources may be flagged. Multiple lookups may produce several candidates.
- File parsing is sequential; `--timeout` bounds external scanner subprocesses,
  not an individual Python AST parse.

## Tool scope and reproducibility

Semgrep runs `scan --config auto --config rules/flask.yaml`. The custom rule checks
Flask debug mode, not IDOR. Default rules are not expected to find the fixture's
missing ownership check. `auto` downloads rules and requires Semgrep metrics in
the verified installation; this is **not an offline scan** and the registry is not
an AI API. No login, cloud analysis, or AI post-processing is invoked. Auto rules
can change: archive rule versions/tool versions for academic repeatability. For a
frozen offline experiment, the Python `semgrep_runner.scan(..., configs=[...])`
API accepts pinned local rule files and disables metrics when `auto` is absent.

Gitleaks uses `dir` (working tree, not commit history), JSON reports, and redaction.
Nuclei uses the modern `-jsonl` output flag and the bundled `templates/` directory.
Its present coverage is deliberately **one missing-nosniff header check**, not the
entire community template library. Template updates/downloads, AI generation,
out-of-band callbacks, cloud upload, and redirects are not enabled. The bundled
HTTP template and its informational severity are reviewable and versionable.

ZAP prefers `zap-baseline.py` on PATH or `ZAP_BIN`, then native `zap.sh` on PATH or
`ZAP_CLI_BIN`, then `ghcr.io/zaproxy/zaproxy:stable`. Set `ZAP_IMAGE` to a pinned digest for reproducible
Docker runs. It spiders for one minute and performs passive analysis, without the
AJAX spider or active attack scan. Docker mode uses Linux host networking so the
container can reach the loopback fixture. The official packaged baseline script
normally expects Docker even when invoked from a host. Native CLI mode instead
uses the official [Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
with `passiveScan-config`, `spider`, `passiveScan-wait`, and `report` jobs, and needs
only the ZAP distribution and Java 17+. JSON-as-YAML plans keep Python free of
extra dependencies. Both modes use `-silent` to disable update checks. A timed-out
Docker scan triggers cleanup of its own uniquely named container; subprocess
timeouts also terminate child processes such as Java.

Unauthenticated crawlers may only see health/error pages; they do not infer seeded
credentials or enumerate authenticated notes. Neither dynamic runner is expected
to prove the fixture's IDOR. Runtime results depend on server responses and tool
versions even though all decision rules are deterministic.

## Verification

Run the offline regression suite:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s pipeline/scan/tests -v
```

Tests cover vulnerable and clean routes, false suppression risks, report parsers,
redaction, missing tools, timeouts, partial failures, and combined-mode routing.
Clean examples are created in memory or temporary files; the original fixture is
not edited. Live smoke-test results and exact tool versions are recorded separately
in `VERIFICATION.md`.

## Scope & Ethics

Built for academic cybersecurity coursework. Use only on applications you own or
have explicit authorization to test. This phase's dynamic CLI accepts only
`localhost`, `127.0.0.1`, or `[::1]` HTTP(S) targets. Verification targets only the
owned local IDOR fixture. This input check is **not network isolation**; a sandbox,
redirect/DNS enforcement across all external tools, and broader authorized-target
management remain later work. Findings require review and consented verification.

## Troubleshooting Semgrep diagnostics

When Semgrep returns parsing or scanning diagnostics, the scan remains incomplete.
The wrapper reports up to five diagnostic types and checkout-relative file/line
locations (when provided by Semgrep). It omits free-form messages and source text
from errors because those can contain credentials. For example, `PartialParsing
in app.py:12` means that the file was not fully parsed; review its syntax and
whether the installed Semgrep version supports that language construct. A
`Timeout` diagnostic refers to Semgrep's internal rule/file timeout, which is
separate from the wrapper's whole-process timeout.

After updating the wrapper, restart the Python dashboard and submit a new scan.
Existing history retains the error recorded at the time; it is not rewritten.
Do not suppress diagnostics to make a scan look complete. Exclude files only
when they are intentionally outside the assessment scope, and record that limit.

Semgrep payload-bearing diagnostic types (such as `PartialParsing`) are decoded
from their tagged JSON form. Valid findings returned alongside diagnostics are
retained in CLI output, dashboard history, and reports. Coverage remains incomplete
and the CLI exits 2. Templates may contain syntax that Semgrep cannot fully parse;
a parse diagnostic alone does not establish that the application template is invalid.
No template exclusion is enabled automatically.

### Choosing a Python-only Semgrep scope

In the dashboard's **Local project** or **GitHub repository** form, select
**Semgrep scope → Python source only — skip templates** when HTML templates and
other file types are intentionally outside Semgrep's scope. The same default
rules are used, with explicit `--include '*.py' --include '*.pyi'` target filters.
AST and Gitleaks coverage is unchanged. Broad remains the default.

The selected profile and scope limits are persisted with each scan, shown on the
Findings page, and included in both PDF and JSON exports. A completed result
applies to this selected scope, not to the whole repository. Python parser errors,
timeouts, missing tools, and other failures still cause incomplete coverage.
Analyzing no Python files is an error, not an empty successful scan. The Python
API also accepts `semgrep_runner.scan(path, profile='python')`; standalone CLI
commands retain their existing broad scope.

Reports containing only `PartialParsing` diagnostics mark the Semgrep dashboard
stage **Incomplete**, with its candidate count preserved. This means Semgrep
returned a valid report but could not parse every source region; it is different
from a missing executable or scanner failure. Mixed or unknown diagnostics still
mark the stage Failed. Broad scanning remains enabled and templates are not
excluded or rewritten. The overall assessment remains incomplete, including JSON
and PDF exports, and the CLI still exits 2. Restart the dashboard and run a new
scan to see the updated stage labels; existing records are preserved.
