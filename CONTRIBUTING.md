# Contributing to Airlock Protocol

Thank you for your interest in contributing to Airlock. This guide covers everything you need to get started.

## Development Setup

```bash
# Clone your fork
git clone https://github.com/<your-username>/airlock-protocol.git
cd airlock-protocol

# Create a virtual environment (Python 3.11+)
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
python -m pytest tests/ -v
```

All new code must include tests. The test suite must maintain 338+ passing tests.

## Linting

```bash
ruff check airlock tests
```

All code must pass ruff without errors before merging.

## Type Checking

```bash
mypy airlock
```

Type hints are required on all function signatures. No `Any` unless justified.

## Code Style

- **Formatter/linter**: ruff (enforced in CI)
- **Type hints**: required on all public and private functions
- **Docstrings**: required on all public APIs (Google style)
- **Imports**: sorted by ruff, one import per line for clarity

## Contributor License Agreement (CLA)

This project requires a [Contributor License Agreement](CLA.md). When you open
your first pull request, the CLA Assistant bot will ask you to sign electronically.
You only need to sign once.

The CLA ensures the project maintainers can manage licensing across the open-core
model (Apache 2.0 for SDKs, BSL 1.1 for gateway).

All commits must also be signed off (DCO). Sign off your commits with the `-s` flag:

```bash
git commit -s -m "feat: add new verification check"
```

If you forgot to sign off previous commits:

```bash
git rebase HEAD~N --signoff  # sign off the last N commits
git push --force-with-lease
```

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes in focused, atomic commits with clear messages.
3. Sign off all commits (`git commit -s`).
4. Ensure all tests pass and linting/type checking is clean.
5. Open a PR against `main` with a description of what changed and why.
6. Address review feedback promptly.

Keep PRs small and focused. One feature or fix per PR.

## What We Look For in Reviews

- Tests covering new functionality and edge cases
- Type annotations on all signatures
- Docstrings on public APIs
- No regressions in existing tests
- Clear commit messages

## Security Vulnerabilities

If you discover a security vulnerability, **do NOT open a public issue**.
See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

This project uses a multi-license model:

| Component | License |
|-----------|---------|
| SDKs, crypto, schemas (`sdks/`, `airlock/crypto/`, `airlock/schemas/`) | Apache 2.0 |
| Gateway, engine (`airlock/gateway/`, `airlock/engine/`) | BSL 1.1 (converts to Apache 2.0 on 2030-04-04) |
| Specification (`docs/spec/`) | CC-BY-4.0 |

By contributing, you agree to the terms of the [CLA](CLA.md), which allows your
contributions to be distributed under the applicable license for the component.
