# Contributing to CyberTrace

Thank you for contributing to **CyberTrace: DNS Exfiltration Detection**. To preserve model integrity, evaluation reproducibility, and team collaboration standards, all contributors must adhere to the following workflow rules.

---

## 1. Branching Strategy

- **`main`**: Protected branch containing verified, passing code. Direct commits to `main` are strictly forbidden.
- **Feature Branches**: Branch from the latest `main` using standard naming conventions:
  - `feature/<name>-<topic>` (e.g. `feature/harshul-evaluation`)
  - `fix/<name>-<issue>` (e.g. `fix/param-remediation`)
  - `integration/<name>-<topic>` (e.g. `integration/soham-e2e`)

---

## 2. Pull Request & Review Process

1. **Open Focused Pull Requests**: Keep pull requests scoped to a single logical deliverable. Avoid combining unrelated data changes, modeling changes, and frontend modifications in a single pull request.
2. **Review Ownership**:
   - The Integration Lead (**Soham**) reviews all changes touching `api/`, `frontend/src/api/`, data contracts (`docs/CONTRACTS.md`), and end-to-end integration tests.
   - Module owners review their assigned directories per `CODEOWNERS`.
3. **Automated Verification**: Before submitting a PR, ensure all local checks pass:
   ```bash
   # Run full backend test suite
   python -m pytest -q

   # Verify exact reproduction of saved model probabilities
   python -m scripts.verify_release_models

   # Run frontend test suite and build
   cd frontend && npm test && npm run build
   ```

---

## 3. Strict Machine Learning & Model Preservation Rules

> [!CAUTION]
> The saved Random Forest model bundle (`artifacts/aws_benign_expansion_v0.1/random_forest.joblib`) is frozen. Any uncoordinated changes break reproducibility.

- **Never Retrain or Replace Model Bundles Silently**: The calibrated operating threshold is locked at **`0.89`**.
- **Inference Invocations**: Always invoke inference via `src.ml.artifact.load_model` and `predict_features()`. **Never invoke `bundle["model"].predict()` directly.**
- **No Metadata Tampering**: Never modify recorded SHA-256 digests in verification JSON files to bypass hash checks. Genuine discrepancies must be investigated and documented.
- **Reporting Label**: Any quoted or displayed evaluation metric must be labeled:
  `"diagnostic/development evaluation, not independent final test"`
- **Data Leakage Prohibition**: Feature extractors must never accept raw IP addresses, domain names, timestamps, or class labels.

---

## 4. Conventional Commit Messages

Follow the Conventional Commits specification:
- `feat`: A new feature (e.g., `feat(api): add multipart /analyze/csv endpoint`)
- `fix`: A bug fix (e.g., `fix(api): sort queries chronologically before extraction`)
- `docs`: Documentation updates (e.g., `docs(contracts): define schema contracts`)
- `test`: Adding or updating test cases
- `ci`: Changes to CI/CD workflows or scripts
- `chore`: Maintenance, dependencies, or repository hygiene
