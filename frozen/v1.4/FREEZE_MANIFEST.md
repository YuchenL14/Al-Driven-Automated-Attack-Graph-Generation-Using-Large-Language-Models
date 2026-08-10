# Frozen v1.4 baseline

This directory preserves the last verified v1.4 implementation before any
v1.5 evidence-bounded rule or pipeline work begins.

## Archive

- File: `python_project_v1.4_frozen.zip`
- SHA-256: `80D0D138135B3916A1A84CFFD755B22008D584191B0FFE68FEBAFC0465543326`
- Created: 2026-07-21 (Europe/London)

## Included scope

- `app.py` and `student_app.py`
- `src/` extraction, schema, rendering, graph and lookup code
- `rules/` rule sets v1 through v1.4
- `data/attack_lookup.json`
- `scripts/` lookup maintenance code
- `examples/`
- `requirements.txt`, `README.md`, and `README_folders.txt`

The archive intentionally excludes `reports/`, `outputs/`, IDE settings,
temporary files, and environment variables/API keys.

## Verification performed before freezing

- Python compilation passed for both Flask applications and the runtime modules.
- The v1.4 two-stage mock extraction completed with 3 events and 4 preconditions.
- Professional Flask application GET check returned HTTP 200.
- Student Flask application GET check returned HTTP 200.

## Rollback procedure

Do not overwrite the working project immediately. First extract the ZIP into a
new comparison directory, verify the archive SHA-256, review the differences,
and then restore only the required files. This avoids overwriting reports,
outputs, API configuration, or later dissertation material.

