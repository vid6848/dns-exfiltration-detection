## Description
<!-- Provide a clear, concise summary of the changes introduced in this pull request. -->

## Changes Checklist
- [ ] Conforms to repository contracts (`docs/CONTRACTS.md`)
- [ ] Preprocessing and feature extraction use canonical implementations
- [ ] Model inference called strictly via `src.ml.artifact.load_model` and `predict_features` (never `bundle["model"].predict()`)
- [ ] No hardcoded metrics, raw IP/domain features, or metadata leakage
- [ ] All metrics labeled "diagnostic/development evaluation, not independent final test"
- [ ] Passes `python -m pytest -q`
- [ ] Passes `python -m scripts.verify_release_models`
- [ ] Passes frontend `npm test && npm run build`

## Related Issues or Pull Requests
<!-- Link related PRs or issues (e.g. Closes #123, Follow-up to PR #4) -->

## Reviewer Instructions
<!-- Note any specific instructions, test environments, or edge cases for the reviewer. -->
