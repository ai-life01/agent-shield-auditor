# Changelog

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
