# Pull request creation

When the user asks to create or draft a PR description for this repo:

1. **Use the template** at `.github/pull_request_template.md`.

2. **Fill every section** according to the change:
   - **Description**: Purpose, background, impacts, implementation details, breaking changes, alternatives considered.
   - **References**: Links to issues/PRs (e.g. "closes #407"), or remove the section if none.
   - **Testing**: How to test, manual steps, environment; confirm or add checkbox for test coverage.
   - **Checklist**: Documentation/tests, GitHub checks, base branch; keep the Code of Conduct line as-is.

3. **Output** the full PR description so it can be pasted into GitHub or used with `gh pr create --body-file ...`. Do not remove the checklist or the Paycrest Contributor Code of Conduct line.
