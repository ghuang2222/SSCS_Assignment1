# Contributing Guidelines

Thank you for considering contributing to the Rekor Verifier project!

## Code Style & Formatting
* Follow standard Python PEP 8 guidelines.
* Keep imports clean and organized (`isort` / `black` preferred).

## Pull Request Guidelines
1. **Branch Naming:** Use descriptive branch names like `feature/add-logging` or `fix/merkle-calculation`.
2. **Commit Rules:** Keep commits clean and focused. Do not merge into `main` directly.
3. **Tests:** All code changes must include corresponding unit tests inside `tests/`.
4. **Coverage:** PRs must maintain or improve repository test coverage (minimum **75%** overall coverage required).
5. **Code Review:** Every PR requires at least 1 approval from a code owner before merging.

## Running Tests Locally
Before opening a PR, ensure all tests pass:
```bash
poetry run pytest