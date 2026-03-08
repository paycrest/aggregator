# Paycrest Aggregator — Agent instructions

Go service that indexes payment orders (from chain or Sender API), assigns orders to providers via a priority queue (Redis + DB), and runs background tasks for refunds, fulfillments, and indexing. Full setup and protocol overview: see [README.md](README.md).

## Architecture (short)

- **Create order:** (1) Sender API → `controllers/sender` → DB; or (2) On-chain Gateway → `services/indexer/*` and `tasks/indexing.go` → `services/common/order.go` (`ProcessPaymentOrderFromBlockchain`) → provider assignment.
- **Assign provider:** `services/priority_queue.go` — `AssignPaymentOrder`, `matchRate`; Redis keys `bucket_{currency}_{min}_{max}`; exclude list and balance checks. Do not change assignment logic without considering exclude list, balance, and bucket keys.
- **Background:** All cron jobs in `tasks/startup.go` (rates, bucket queues, webhooks, fulfillments, receive address, stale ops, mishaps, stuck validated, indexing, refunds).
- **Data:** DB = [Ent](https://entgo.io/) — schema in `ent/schema/`; generate with `make gen-ent`. Migrations in `ent/migrate/migrations/` (Atlas). Redis = bucket queues + order request keys. Do not edit generated files under `ent/`; only change `ent/schema/*.go`, then run codegen and migrations.

## Build & test

- Build: `go build -o paycrest` or `make run` (runs `gen-ent` then `air`).
- Generate Ent: `make gen-ent` or `go run -mod=mod entgo.io/ent/cmd/ent generate ./ent/schema/`.
- Tests: `go test ./...` or `make test`. Coverage: `make test-coverage` (excludes ent, config, database, routers). Use test env: `ENV_FILE_PATH=utils/test/test.env`.
- Single package: `go test ./services/...` or `go test ./controllers/sender/...`.

## Code style & conventions

- Follow existing patterns in `services/`, `controllers/`, `tasks/`. Config via `config/` and env (see `.env.example`).
- New features: add or update tests; use helpers in `utils/test/db.go` where applicable.
- **GitHub issues:** Use `.github/ISSUE_TEMPLATE/` (feature_request.md or bug_report.md). Prefer `gh issue create --repo paycrest/aggregator --title "..." --body-file <path> [--label enhancement|bug]`; only suggest manual creation if that fails.
- **GitHub PRs:** Use `.github/pull_request_template.md` for PR descriptions.

## Commit convention

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

- Format: `<type>[optional scope]: <description>` (e.g. `feat(priority_queue): add stuck-order threshold`).
- Types: `feat` (new feature), `fix` (bug fix), `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`. Use `fix` for patches and `feat` for new features.
- Scope (optional): area of the codebase, e.g. `sender`, `provider`, `priority_queue`, `tasks`, `ent`.
- Breaking changes: add `!` after type/scope (e.g. `feat(api)!: change response shape`) or footer `BREAKING CHANGE: <description>`.
- Examples: `fix(sender): validate rate before order create`, `feat(config): add PROVIDER_STUCK_FULFILLMENT_THRESHOLD`, `docs: update AGENTS.md`.

## Security & boundaries

- **NEVER** commit `.env` or real secrets; never hardcode `HD_WALLET_MNEMONIC` or API keys.
- **NEVER** edit generated files under `ent/` except `ent/schema/`; change schema then run `make gen-ent` and add/apply migrations.
- **ASK** before changing: provider assignment (`services/priority_queue.go`), refund/fulfillment flows (`tasks/stale_ops.go`, `tasks/refunds.go`, fulfillments), or order lifecycle in `services/common/order.go`.
