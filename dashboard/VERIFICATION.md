# Dashboard verification — 2026-10-06

- Production React build: passed.
- Existing scanner suite: 34 tests passed.
- Dashboard backend suite: 6 tests passed.
- Local HTTP smoke: external target rejected (400), invalid session token rejected (403), project PDF returned valid PDF bytes.
- Chromium end-to-end workflow: passed against the unchanged local fixture directory. Actual Semgrep and AST each returned one candidate; Gitleaks returned zero. All three stages completed.
- Finding drawer displayed IDOR-AST-01 and closed with Escape. Downloaded assessment PDF includes actual evidence, candidate limitations, coverage, and deterministic guidance; text extraction verified.
- Automated axe audit of the populated findings view: zero violations. This is scoped automated coverage, not a full accessibility certification.
- Viewport overflow checks passed at 320, 390, and 768px. Desktop screenshot reviewed at 1440px; mobile at 390px. Mobile Reports navigation passed.
- Fresh Impeccable finish reviewer: ship, with no remaining material blockers after accessibility and responsive fixes.
- Project PDF: 15 pages; text extraction and representative AST page rendering checked.
- Fixture SHA256 unchanged: 52065bc7979beed837562c4e888e5838fc6f527e3cf2f28537f482c85ea471e9.

No third-party repository was cloned or external application scanned during these tests. GitHub URL validation was unit-tested; live GitHub cloning was not exercised. Nuclei and ZAP runtime executables are currently unavailable; this dashboard verification does not claim a fresh dynamic smoke test. Earlier scanner-specific evidence remains in pipeline/scan/VERIFICATION.md.

Browser tests append real fixture runs to local history. Screenshots and downloaded test reports are ignored under .impeccable/review. Generated job records remain in .vibeshield/scans.
