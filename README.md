# VibeShield

A deterministic cybersecurity coursework scanner with a React dashboard and Python backend. Findings are **candidates**, not confirmed exploits. Website scanning accepts loopback targets only; repository scanning accepts local directories or authorized public GitHub repositories.

## Start the dashboard

For automatic setup on Linux (CachyOS/Arch or Debian/Ubuntu), run as your normal
user from the project directory:

```bash
python3 setup.py --dry-run   # Preview the installation
python3 setup.py             # Install dependencies, scanners, and build the dashboard
python3 setup.py --check     # Check installed tools without running a scan
python3 setup.py --run       # Start the dashboard; stop with Ctrl+C
```

Setup uses `sudo` for system prerequisites and starting Docker when needed.
Arch's package step includes a full system upgrade to avoid partial upgrades.
It installs the dashboard requirements into `.venv`, Semgrep into its own
environment under `.tools`, and Gitleaks/Nuclei into `.tools/bin`. Go may download
a newer compiler automatically. It runs `npm ci` and builds the frontend, then
pulls the official ZAP Docker image. Internet access and several GB of free disk
space may be needed; Go compilation can take several minutes. Python AST is built
into Python and needs no separate package. Browser-test Chromium is optional and
is not installed by setup.

Use `--skip-system` if you manage system prerequisites yourself. Docker must be
accessible without sudo; setup reports how to resolve access problems and does
not change your group membership. Rerunning setup preserves scan history and
reuses installed Go scanner binaries. Semgrep and new Go installations use the
currently published versions; `npm ci` uses the committed lockfile. This is not a
version-frozen scanner environment. Existing scanner executable environment
overrides still take precedence. Both root entry points automatically discover
the local tools, without shell activation or PATH changes.

Open **http://127.0.0.1:8787** after starting. Ctrl+C stops the dashboard and keeps
scan history; setup does not enable Docker at boot or stop a shared Docker daemon.

For manual dependency installation instead:

```bash
python3 -m venv .venv
.venv/bin/pip install -r dashboard/requirements.txt
npm install --prefix dashboard/web
npm run build --prefix dashboard/web
.venv/bin/python run_dashboard.py
```

Open **http://127.0.0.1:8787**. Choose a target type, enter the target, confirm authorization, and start a scan. “Use test fixture” selects `fixtures/idor-notes-app`. Findings shows real scanner evidence; Reports downloads PDF or JSON, including incomplete coverage and errors.

For **Local project**, click **Browse** to open the desktop folder picker and
select a project directory. Cancel keeps your current path; selecting a folder
does not start a scan. Zenity (installed by setup) or KDialog must be available,
and the server must run in your graphical desktop session. Manual path entry
remains available. The picker opens on the machine running the Python server.

For Python/Flask repositories with HTML template parsing diagnostics, choose
**Semgrep scope → Python source only — skip templates** before starting a new
scan. This deliberately limits Semgrep to `.py` and `.pyi` files; templates and
other file types remain outside its scope. The choice is recorded in the scan
and PDF/JSON reports. Broad scanning remains the default. This option prevents
HTML parsing diagnostics; it does not repair templates or suppress Python errors.

Install the scanner executables separately. Set `SEMGREP_BIN`, `GITLEAKS_BIN`, `NUCLEI_BIN`, `ZAP_BIN` or `ZAP_CLI_BIN` as needed. Settings displays executable availability, not a guarantee that scans will succeed. Native ZAP needs a compatible Java installation. See [scanner instructions](pipeline/scan/README.md).

Public GitHub URLs trigger a shallow static checkout; application code and dependency installation are not executed. Private repositories and branch URLs are unsupported. Website inputs must use `localhost`, `127.0.0.1`, or `[::1]`. LAN and external IP addresses are rejected.

Jobs persist under `.vibeshield/scans`; use `--data-dir` to change this and `--port` to change the default port. Stop the server with Ctrl+C. This is a local coursework application, not a multi-user hosted service. Reports may include source context: review them before sharing.

## Documentation and verification

- [Project documentation PDF](docs/VibeShield_Project_Documentation.pdf)
- [Editable project documentation](docs/VibeShield_Project_Documentation.md)
- [Scanner verification record](pipeline/scan/VERIFICATION.md)
- [Visual design system](DESIGN.md)

```bash
.venv/bin/python -m unittest discover -s pipeline/scan/tests -v
.venv/bin/python -m unittest discover -s dashboard/tests -v
# With the dashboard running and Chromium installed:
cd dashboard/web
npx playwright test --workers=1
```

Rebuild the documentation with `.venv/bin/python docs/build_documentation.py`.

## Scope & Ethics

Built for academic coursework. Scan only systems you own or have explicit authorization to test. Detection, classification, and report guidance use deterministic rules and heuristics, without LLM SDKs or AI API calls. Exploit verification and numeric risk scoring remain outside this dashboard.
