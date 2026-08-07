# Contributing to IndustrialScanner

Thank you for your interest in contributing to IndustrialScanner! This document
describes the process for contributing code, reporting issues, and improving the
project.

## Code of Conduct

By participating in this project, you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md). Please be respectful and constructive.

## How to Contribute

### Reporting Bugs

1. Search existing [issues](https://github.com/frangelbarrera/IndustrialScanner/issues)
   to avoid duplicates.
2. Open a new issue with:
   - A clear title and description.
   - Steps to reproduce.
   - Expected vs actual behavior.
   - Affected version (`industrial-scanner --version`).
   - PCAP sample (if applicable and you can anonymize it).

### Suggesting Enhancements

Open an issue with the `enhancement` label. Describe:

- The use case.
- The proposed solution.
- Alternatives considered.

### Pull Requests

1. Fork the repository and create a branch:
   ```bash
   git checkout -b feature/my-awesome-feature
   ```

2. Set up your development environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   pre-commit install
   ```

3. Make your changes. Follow these guidelines:

   - **Code style**: enforced by `ruff` (line length 100, double quotes).
   - **Type hints**: required on all public functions.
   - **Tests**: every new feature or bug fix must include tests.
   - **Docstrings**: required on all public functions (Google style).
   - **No `print()`** in production code — use `logging` (or `rich` for CLI
     output).

4. Run the quality checks before pushing:

   ```bash
   ruff check .
   ruff format .
   mypy modbus_scanner s7_comm_analyzer dnp3_monitor ics_scanner
   pytest --cov=modbus_scanner --cov=s7_comm_analyzer --cov=dnp3_monitor
   bandit -r modbus_scanner s7_comm_analyzer dnp3_monitor ics_scanner -c pyproject.toml
   ```

5. Commit using [Conventional Commits](https://www.conventionalcommits.org/):

   ```
   feat: add new protocol parser for PROFINET
   fix: correct S7Comm function code offset in parameter block
   sec: prevent XSS in DNP3 HTML report via markupsafe.escape
   docs: add MITRE ATT&CK for ICS mapping reference
   ci: add Python 3.13 to test matrix
   refactor: extract shared security primitives to ics_scanner module
   ```

6. Open a Pull Request. Fill out the PR template, including the security
   checklist if your change touches any I/O or output rendering code.

## Security Considerations

This is a security tool. Please pay special attention to:

- **Read-only by design**: the Modbus scanner must NEVER issue write function
  codes (0x05, 0x06, 0x0F, 0x10, etc.). Active probing is restricted to
  0x01-0x04.
- **Output escaping**: any data derived from PCAPs, Modbus responses, or
  network input must be escaped before rendering into HTML/JSON reports.
  Use `ics_scanner.security.html_escape()` or `safe_render()`.
- **Target safety policy**: any new active-scan code must respect the
  `is_safe_target()` policy. Public IPs require explicit `--allow-public`.
- **No secrets in logs**: use `ics_scanner.security.configure_logging()`
  and never log credentials, tokens, or PII.

If you find a security vulnerability, please follow the
[Security Policy](SECURITY.md) and report it privately before disclosing.

## Adding a New Protocol Parser

IndustrialScanner uses a plugin architecture. To add a new protocol:

1. Create a new module under a package (yours or `industrial_scanner/protocols/`).
2. Implement the `ProtocolParser` protocol from `ics_scanner.plugins`:

   ```python
   class MyProtocolParser:
       @property
       def protocol_name(self) -> str:
           return "MyProtocol"

       def can_parse(self, packet) -> bool: ...

       def parse(self, packet) -> Optional[dict]: ...
   ```

3. Register it via entry points in your `pyproject.toml`:

   ```toml
   [project.entry-points."industrial_scanner.parsers"]
   my_protocol = "my_package.parser:MyProtocolParser"
   ```

4. Add tests under `tests/test_my_protocol.py`.

5. Update the README with the new protocol in the supported list.

## Style Guide

- **Python version**: 3.11+ (target 3.12).
- **Line length**: 100 characters.
- **Imports**: sorted by `isort` rules (handled by ruff).
- **Docstrings**: Google style.
- **Type hints**: required on all public functions; prefer `dict[str, Any]`
  over `Dict[str, Any]` (Python 3.9+).
- **Error handling**: prefer specific exceptions over bare `except:`.
  Use `ics_scanner.security.safe_str()` to stringify exceptions in logs.
- **Logging**: lazy formatting (`LOG.info("Probing %s", ip)` not
  `LOG.info(f"Probing {ip}")`).

## Testing

- Unit tests live in `tests/` and follow the `test_*.py` pattern.
- Use `pytest` fixtures for setup.
- For parsers, prefer property-based testing with `hypothesis`.
- For HTML/JSON output, write regression tests that verify escaping
  (see `tests/test_xss_regression.py` as a template).
- Integration tests (with real PCAPs) live in `tests/integration/`.

## Release Process

Releases are managed via GitHub Actions and triggered by a tag push:

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

The `release.yml` workflow will:

1. Build wheel and sdist.
2. Publish to PyPI (using `PYPI_API_TOKEN` secret).
3. Create a GitHub Release with auto-generated release notes.

Versioning follows [Semantic Versioning 2.0.0](https://semver.org/).

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.

---

Thank you for helping make IndustrialScanner better!
