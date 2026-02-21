# GitHub issue (ticket) creation

When the user asks to create a ticket, issue, or bug report for this repo:

1. **Choose the template** from `.github/ISSUE_TEMPLATE/`:
   - Use **feature_request.md** for new features, enhancements, or product changes. Fill: User Story, Acceptance Criteria (GIVEN/WHEN/THEN), Tech Details, Notes/Assumptions.
   - Use **bug_report.md** for bugs. Fill: Describe the bug, To Reproduce, Expected behavior, Screenshots (if applicable), Environment, Additional context.

2. **Read the chosen template** and follow its structure exactly. Do not omit sections.

3. **Create the issue:**
   - **First:** Write the issue body to a file (e.g. in `.github/` or a temp path), then run:
     `gh issue create --repo paycrest/aggregator --title "..." --body-file <path> [--label enhancement|bug]`
   - **Only if that fails** (e.g. connection error, auth/TLS failure, `gh` not available): output the full issue body and title so the user can create the issue manually in the browser or retry the CLI after fixing the failure.
