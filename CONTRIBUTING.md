# Contributing to BeeBox

BeeBox is currently a pre-release Go project. Contributions should preserve the repository invariants in `Instruction.md`, especially correctness, tenant isolation, migration safety, explicit contracts, and modular-monolith-first delivery.

## Tooling baseline

The current repository requires:

- Go 1.26.x (`go.mod` declares Go 1.26.0);
- Git;
- PostgreSQL when running the repository's integration tests.

Use the exact repository-native commands documented below. Do not add wrapper commands or tooling assumptions that the repository does not currently provide.

## Branch and pull-request workflow

- Do not push feature work directly to `main`.
- Create a short-lived branch from the current verified `main`.
- Keep each PR focused on one reviewable outcome. Do not mix unrelated refactors, dependency upgrades, generated churn, or speculative infrastructure with feature work.
- Open feature/change PRs as **Draft** while implementation and evidence are still being assembled.
- Keep the PR current enough for the repository's merge policy and resolve review conversations that apply to the current head.
- A human performs the final squash merge after the independent Checker and required gates allow it. Agents/automation used by this project must not merge, mark a Draft PR ready, or push feature work directly to `main` unless the repository's human process is explicitly changed.

## Required verification

Current CI verifies formatting, static analysis, tests, PostgreSQL integration behavior, and the race detector.

Format Go code:

```bash
gofmt -w .
```

Before publishing, `gofmt -l .` should produce no unexpected paths.

Run static analysis and tests:

```bash
go vet ./...
go test ./...
go test -race ./...
```

Run the current PostgreSQL integration suite with a disposable test database:

```bash
BEEBOX_TEST_DATABASE_URL='postgres://beebox:test-password@127.0.0.1:5432/beebox_test?sslmode=disable' go test -tags=integration ./internal/platform/database ./internal/platform/migration ./internal/applicationinstance/postgres ./internal/identity/postgres
```

The URI above is a fake/local test placeholder. Never substitute a production credential into documentation, fixtures, issue text, or PR evidence.

GitHub Actions must pass on the exact final PR head. A green CI run does not replace task-specific tests, security evidence, or acceptance criteria.

## Security and tenant testing

Tests are risk-based.

When a change introduces the corresponding surface, add tests for the risks it creates, including as applicable:

- unauthorized and default-deny access;
- cross-application/cross-tenant access using otherwise valid foreign resource IDs;
- cross-organization access where organization scope applies;
- enumeration, replay, expiry, recovery, and credential/token failure cases;
- transaction, concurrency, idempotency, retry, and partial-failure behavior;
- secret/PII redaction and safe public errors;
- audit evidence for security-sensitive actions.

Do not claim tenant or security behavior is complete because only a happy-path handler test passes.

## Database migration policy

BeeBox migrations are forward-only in production-facing workflows.

- Never rewrite, renumber, or replace a migration that has already been merged to `main`.
- Add a new ordered migration for each subsequent schema change.
- Use expand/contract sequencing for breaking schema evolution so rolling deployment remains safe.
- Keep important uniqueness, referential, and domain invariants in PostgreSQL constraints rather than relying only on application pre-checks.
- Backfills, when introduced, must be bounded, observable, restartable, and separated from dangerous long-lock migrations.
- `beebox migrate` is the explicit migration mode. Normal serve startup must not silently apply schema changes.
- A schema PR must document rollout, compatibility, failure handling, and roll-forward/rollback implications.

## Contracts and architecture

Before changing a public API, event, schema, tenant/security boundary, or persistence model, read:

- `Instruction.md`;
- `docs/contracts/conventions.md`;
- `docs/threat-model/initial.md`.

Public API/event models must remain BeeBox-owned and versioned; do not leak database or vendor SDK models into public contracts. Do not silently decide account-linking semantics, token trust boundaries, public compatibility policy, universal organization tenancy, or future service data ownership.

## Pull-request evidence

PR descriptions should include the repository-required evidence relevant to the change:

- Summary and outcome;
- why the change is needed;
- explicit scope and non-goals;
- design/alternatives where a design decision exists;
- security, privacy, authorization, and tenant-isolation impact;
- API/event/data/migration compatibility impact;
- exact tests/checks and results on the final head;
- performance evidence when performance is claimed;
- rollout/monitoring and rollback;
- known risks and explicit follow-ups.

Do not paste real credentials, tokens, private keys, PII, production database URLs, or unnecessary exploit details into a PR.

## Scope hygiene

- Stage/commit only files required for the PR outcome.
- Do not include generated churn unless the changed contract requires regenerated artifacts and the repository actually owns those artifacts.
- Do not perform unrelated cleanup/refactoring in a feature PR.
- Do not weaken CI, suppress errors, lower assertions, or skip tests merely to make a check green.
- Preserve existing public behavior unless the reviewed task explicitly changes it.

## Security reports

For suspected vulnerabilities or sensitive security findings, follow `SECURITY.md` instead of opening a public issue containing credentials, PII, tokens, exploit secrets, or details that would unnecessarily increase exposure.
