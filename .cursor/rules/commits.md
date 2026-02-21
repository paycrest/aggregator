# Commit messages

When creating or suggesting git commit messages for this repo, use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

- Format: `type(scope): short description` (e.g. `feat(priority_queue): add stuck-order threshold`).
- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`.
- Optional scope: e.g. `sender`, `provider`, `priority_queue`, `tasks`, `config`.
- For breaking changes: add `!` after scope (e.g. `feat(api)!: change response shape`) or use footer `BREAKING CHANGE: description`.

Do not add Co-authored-by (or any trailer) for Cursor, Claude, or other AI agents to commits. Do not use `--trailer "Co-authored-by: ..."` with cursoragent@cursor.com, Claude, or similar.
