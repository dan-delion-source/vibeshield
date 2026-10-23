# VibeShield

A deterministic cybersecurity coursework scanner with a React dashboard and Python backend. Findings are **candidates**, not confirmed exploits. Website scanning accepts loopback targets only; repository scanning accepts local directories or authorized public GitHub repositories.

## Start the dashboard

```bash
python3 -m venv .venv
.venv/bin/pip install -r dashboard/requirements.txt
npm install --prefix dashboard/web
npm run build --prefix dashboard/web
.venv/bin/python run_dashboard.py
```

Open **http://127.0.0.1:8787**. Choose a target type, enter the target, confirm authorization, and start a scan. “Use test fixture” selects `fixtures/idor-notes-app`. Findings shows real scanner evidence; Reports downloads PDF or JSON, including incomplete coverage and errors.

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
