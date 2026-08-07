# Contributing

Thanks for your interest in contributing to IndustrialScanner!

## Getting started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/<your-username>/IndustrialScanner.git
   cd IndustrialScanner
   ```
3. Set up the development environment:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -e ".[dev]"
   pre-commit install
   ```
4. Create a branch:
   ```bash
   git checkout -b feature/my-awesome-feature
   ```

## Development workflow

### Run quality checks before pushing

```bash
ruff check .
ruff format .
mypy modbus_scanner s7_comm_analyzer dnp3_monitor ics_scanner
pytest --cov=modbus_scanner --cov=s7_comm_analyzer --cov=dnp3_monitor
bandit -r modbus_scanner s7_comm_analyzer dnp3_monitor ics_scanner -c pyproject.toml
```

### Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add PROFINET parser
fix: correct S7Comm parameter block offset
sec: prevent XSS in DNP3 HTML report
docs: add MITRE ATT&CK mapping reference
ci: add Python 3.13 to test matrix
test: add property-based tests for DNP3 parser
refactor: extract shared security primitives to ics_scanner module
```

### Adding a new protocol parser

IndustrialScanner uses a plugin system via setuptools entry points. To add
a new protocol:

1. Create a parser module that implements the `ProtocolParser` protocol:
   ```python
   from ics_scanner.plugins import ProtocolParser


   class ProfinetParser(ProtocolParser):
       @property
       def protocol_name(self) -> str:
           return "PROFINET"

       def can_parse(self, packet) -> bool: ...

       def parse(self, packet) -> dict | None: ...
   ```

2. Register it via entry points in your `pyproject.toml`:
   ```toml
   [project.entry-points."industrial_scanner.parsers"]
   profinet = "my_package.profinet_parser:ProfinetParser"
   ```

3. Add tests in `tests/test_profinet_parser.py`

4. Update the docs with the new protocol page

## Testing

- **Unit tests**: `tests/test_*.py`
- **Property-based tests**: `tests/test_*_property.py` (Hypothesis)
- **Snapshot tests**: `tests/test_html_snapshots.py` (use `UPDATE_SNAPSHOTS=1`
  to update baselines)
- **Coverage target**: 80%+

## Pull request checklist

- [ ] Tests pass locally
- [ ] Coverage did not decrease
- [ ] `ruff check` and `ruff format --check` pass
- [ ] `mypy` passes
- [ ] `bandit` passes (no HIGH severity findings)
- [ ] Commit messages follow Conventional Commits
- [ ] PR template filled out (including security checklist)

## Code of Conduct

By participating, you agree to abide by our
[Code of Conduct](https://github.com/frangelbarrera/IndustrialScanner/blob/main/CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under
the MIT License.
