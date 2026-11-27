# Changelog

## 1.1.1 — 2026-11-27

- Added `.gitignore` and stopped tracking compiled Python cache files (`__pycache__` / `*.pyc`).
- Added GitHub Actions workflow (`.github/workflows/test.yml`) to run `python -m unittest discover -v` on Python 3.9–3.12, plus a smoke scan of `assets/sample_vulnerable_agent.json` (exit code 2 is expected).
- Added `pyproject.toml` so the project can be installed with `pip` or `pipx` and exposes the `agent-shield-auditor` console command. There are still no runtime third-party dependencies; `python scripts/audit_scanner.py --target ...` continues to work without installing the package.
- Updated `README.md` and `README.zh-CN.md` with optional install instructions, a CI badge, and a short support link to Afdian.
- Synced package and documentation versions to `1.1.1`.


## 1.1.0 — 2026-11-27

- Added `--format md` to generate structured Markdown security review reports directly from scan results.
- Added `--output <FILE>` to write JSON or Markdown reports directly to disk.
- Added unit tests covering Markdown report rendering and file output (`tests/test_audit_scanner.py`).
- Updated `README.md`, `README.zh-CN.md`, and `SKILL.md` with Markdown report generation examples and contact details.

## 1.0.2 — 2026-11-27

- Added bidirectional language switchers (`README.md` <-> `README.zh-CN.md`) and aligned bilingual documentation structure.
- Updated quickstart archive/clone instructions, badges, and repository tree documentation (including `CHANGELOG.md` and `tests/`).
- Added GitHub Actions CI workflow (`.github/workflows/test.yml`) to automatically run `unittest` across Python 3.9–3.12.
- Synced package metadata version to `1.0.2`.

## 1.0.1 — 2026-11-26

- Clarified that results are heuristic static findings and not verified vulnerabilities.
- Reduced a broad prompt-injection pattern that treated the generic phrase `system prompt` as a finding.
- Redacted common secret-like strings in finding snippets.
- Added common generated/dependency directory exclusions, symlink skipping, and a 1 MiB default file-size limit.
- Added repeatable `--exclude` patterns and clearer CLI exit codes for missing targets/read errors.
- Added unit tests and updated documentation to state the scanner's limitations.
