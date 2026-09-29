"""
Pytest configuration for the SecureMailScope test suite.

All tests live here in tests/ and import from the `analysis` package.
Running `pytest` from the repo root (SES-v1/) works because pyproject.toml
sets pythonpath = ["."], which puts SES-v1/ on sys.path so that
`import analysis` resolves correctly.
"""
