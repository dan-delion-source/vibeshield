# Verification record — 2026-10-05

## Environment and provenance

- Python: 3.14.7 (implementation supports Python 3.10+).
- Semgrep: 1.178.0, existing installation at
  `/home/dandadan/Projects/Builds/VibeShield/.venv/bin/semgrep`.
- Gitleaks: 8.30.1, existing binary at
  `/home/dandadan/Projects/Builds/VibeShield/.tools/gitleaks`.
- Nuclei: 3.11.1, official Linux AMD64 release, downloaded into
  `/tmp/vibeshield-verification/nuclei` for verification.
  Archive SHA256: `ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6`,
  matched against the official release checksums before execution.
- ZAP: 2.17.0, official standalone Linux distribution, native Automation Framework.
  Archive SHA256: `efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a`,
  matched against the official GitHub release asset digest before execution.
- Java: Temurin OpenJDK JRE 17.0.20.1+1, official Adoptium release.
  Archive SHA256: `0b2b640e3046b64c8ec504de0ab9d91bb5610182bda21fad454681ce54d45a62`,
  matched against the official Adoptium release metadata before execution.
- Fixture source recovered unchanged from the pre-existing Docker image
  `vibeshield-idor-notes-app:latest`, image ID
  `sha256:5d1ed9ec32ec8d50d2be5254494e1af2dcb072a9cc8f93e66fd96b9c7705d925`.
- `fixtures/idor-notes-app/app.py` SHA256:
  `52065bc7979beed837562c4e888e5838fc6f527e3cf2f28537f482c85ea471e9`.
  Direct byte comparison with `/app/app.py` in the fixture container passed.
- No `idor_prober.py`, Compose file, or scope document was present in the initial
  workspace. None was recreated. The old `.gitignore` remains removed as requested.

## Completed checks

| Check | Observed result |
| --- | --- |
| Semgrep auto + custom rule on recovered fixture | Exit 0; one Flask `0.0.0.0` bind warning at app.py:139. No IDOR finding expected from Semgrep. |
| AST on recovered fixture | Exit 0; `get_note`, `app.py:122`, `IDOR-AST-01`, `MEDIUM`. |
| Clean temporary dictionary-backed route | No AST findings. |
| Clean temporary SQLite fixture copy | No AST findings after adding the inline owner/user comparison; original fixture unchanged. |
| Gitleaks on recovered fixture | Exit 0; `[]`. |
| Static orchestrator | Exit 0; two candidates (AST IDOR and Semgrep bind warning). |
| Nuclei on `http://127.0.0.1:5000/api/health` | Exit 0; one informational missing-nosniff header candidate. |
| ZAP native CLI on the same local endpoint | Exit 0; two passive candidates: Server version disclosure (10036), missing nosniff header (10021). |
| URL-only orchestrator | Exit 0; three candidates: Nuclei 1, ZAP 2. |
| Combined `--repo-path` + `--url` orchestrator | Exit 0; five candidates: AST 1, Semgrep 1, Nuclei 1, ZAP 2. Required five-field schema checked; overlap preserved. |
| Regression tests | 34 passed at the last recorded run. |
| LLM dependency/import audit | No LLM imports in scanner modules; no packages in `pipeline/requirements.txt`. |

The fixture's authentication lookup derives `user` from a bearer token. The note
query uses `note_id`, but there is no inline comparison of `note['owner_id']` to
`user['id']` before the response. The AST result records this reasoning, without
claiming exploit confirmation.

## Verification boundaries

Official ZAP Docker pulls stalled and were stopped; Docker-mode execution has not
been verified live. The native ZAP CLI was verified against the owned local fixture.
No external application was targeted, no exploit verification was run, and no
claim of comprehensive vulnerability coverage is made. The no-LLM check is based
on source/dependency inspection and configured scanner modes, not a network packet
capture. Semgrep's rule registry and tool downloads require non-AI network access.
The temporary fixture container was stopped after verification; its original
Docker image and recovered source remain available. Generated Python bytecode and
temporary download chunks were removed.

## Reproduce the verified static command on this machine

```bash
SEMGREP_BIN=/home/dandadan/Projects/Builds/VibeShield/.venv/bin/semgrep \
GITLEAKS_BIN=/home/dandadan/Projects/Builds/VibeShield/.tools/gitleaks \
python3 pipeline/scan/run_scan.py --repo-path fixtures/idor-notes-app
```

For dynamic scans on this machine, while the fixture container is running:

```bash
NUCLEI_BIN=/tmp/vibeshield-verification/nuclei \
JAVA_HOME=/tmp/vibeshield-verification/runtime/jdk-17.0.20.1+1-jre \
ZAP_CLI_BIN=/tmp/vibeshield-verification/runtime/ZAP_2.17.0/zap.sh \
python3 run_scan.py --url http://127.0.0.1:5000/api/health
```

Tool downloads, temporary clean source, and scan outputs used during verification
are under `/tmp/vibeshield-verification/`; this directory is temporary and is not
part of the project. Future runs require installed external tools on PATH or the
binary-path environment variables documented in README.md. Semgrep's auto rule
registry is mutable and requires network access; no AI API is used by this pipeline.
