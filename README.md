# Rekor Monitor

## Overview

This project implements a Python-based verifier for artifacts recorded in the [Sigstore Rekor transparency log](https://rekor.sigstore.dev/).

It supports:

- Retrieving entries from the Rekor transparency log.
- Verifying artifact signatures.
- Verifying Merkle inclusion proofs.
- Verifying consistency proofs between transparency log checkpoints.

## Requirements

- Python 3.10+
- `requests`
- `pytest` (for testing)

Install the dependencies:

```bash
pip install requests pytest
```

## Usage

Run `main.py` with the desired command-line options.

```bash
python main.py --help
```

Verify an artifact's inclusion in the log:

```bash
python main.py --inclusion LOG_INDEX --artifact PATH_TO_ARTIFACT
```

Check the latest log checkpoint:

```bash
python main.py --checkpoint
```

Verify log consistency:

```bash
python main.py --consistency
```

Replace `LOG_INDEX` and `PATH_TO_ARTIFACT` with the appropriate log entry index and local artifact path. Use `python main.py --help` to confirm the exact arguments supported by your version.

## Testing

Run the test suite:

```bash
pytest
```

If coverage is configured, run:

```bash
pytest --cov=. --cov-report=term-missing
```

## Security

This project is intended for educational purposes. Verification results depend on the correctness of the implementation and the trustworthiness of the supplied keys, certificates, checkpoints, and proofs.

Do not treat a successful verification as a guarantee that an artifact is safe to execute.

Report suspected vulnerabilities privately to the repository maintainer rather than publicly disclosing exploitable details.

## License

See [LICENSE](LICENSE).
