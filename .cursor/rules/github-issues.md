# GitHub issue (ticket) creation

When the user asks to create a ticket, issue, or bug report for this repo:

1. **Choose the template** from `.github/ISSUE_TEMPLATE/`:
   - Use **feature_request.md** for new features, enhancements, or product changes. Fill: User Story, Acceptance Criteria (GIVEN/WHEN/THEN), Tech Details, Notes/Assumptions.
   - Use **bug_report.md** for bugs. Fill: Describe the bug, To Reproduce, Expected behavior, Screenshots (if applicable), Environment, Additional context.

2. **Read the chosen template** and follow its structure exactly. Do not omit sections.

3. **Create the issue:**
   - **If using `gh` CLI:** Write the issue body to a temp file (e.g. in `.github/` or a temp path), run `gh issue create --repo paycrest/aggregator --title "..." --body-file <path> [--label enhancement|bug]`, then **delete the temp file** after the issue is created (whether success or not, to avoid leaving stray files).
   - **If manual flow** (e.g. connection error, auth/TLS failure, `gh` not available, or user will create in browser): **do not create a temp file**. Output the full issue **title** and **body** (markdown) directly in the response so the user can paste into the GitHub issue form. Do not write to a file for manual creation.
