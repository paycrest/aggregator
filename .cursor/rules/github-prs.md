# Pull request creation

When the user asks to create or draft a PR description for this repo:

1. **Use the template** at `.github/pull_request_template.md`.

2. **Fill every section** according to the change:
   - **Description**: Purpose, background, impacts, implementation details, breaking changes, alternatives considered.
   - **References**: Links to issues/PRs (e.g. "closes #407"), or remove the section if none.
   - **Testing**: How to test, manual steps, environment; confirm or add checkbox for test coverage.
   - **Checklist**: Documentation/tests, GitHub checks, base branch; keep the Code of Conduct line as-is.

3. **Formatting:** Do not use blockquote markers (`>`) in the PR body. Use plain markdown only (headings, lists, bold).

4. **Create the PR:**
   - **If using `gh` CLI:** Write the PR body to a temp file, run `gh pr create ... --body-file <path>`, then **delete the temp file** after the PR is created.
   - **If manual flow** (e.g. `gh` fails or user will create in browser): **do not create a temp file**. Output the full PR description (markdown) directly in the response so the user can paste into the GitHub PR form.
   - Do not remove the checklist or the Paycrest Contributor Code of Conduct line from the description.
