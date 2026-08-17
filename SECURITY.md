# BeeBox Security Policy

BeeBox is currently a pre-release project with no published releases. Security reports are welcome, but the repository must not pretend to provide a private reporting channel, bounty, SLA, CVE program, or supported-release range that has not been established.

## What to treat as security-sensitive

Examples include:

- authentication or authorization bypass;
- cross-application, cross-tenant, or cross-organization access;
- account takeover, unsafe account linking, session/token/key compromise, replay, or privilege escalation;
- exposure of credentials, tokens, private keys, secrets, PII, or sensitive audit/security data;
- SQL injection, unsafe migration behavior, or unauthorized schema/data mutation;
- cryptographic misuse;
- request/resource-exhaustion weaknesses with meaningful availability impact;
- dependency, CI, build, artifact, or release-chain compromise;
- vulnerabilities in a provider integration that allow BeeBox security boundaries to be bypassed.

Ordinary bugs with no security impact can use the normal project issue/PR workflow once such reporting is safe and appropriate.

## Current reporting-channel limitation

At the time this policy was added, the repository's GitHub Private Vulnerability Reporting setting is **disabled**, and the repository does not publish another verified private security-reporting address or channel.

Because no private channel is currently verified, do **not** put credentials, access tokens, private keys, production database URLs, PII, exploit secrets, or unnecessary step-by-step weaponization details into a public GitHub issue.

If a report cannot be made safely without exposing sensitive material, retain the sensitive evidence privately until the repository enables and documents an authorized private reporting mechanism. A future change that enables such a mechanism should update this file in the same governance change.

This limitation is intentional documentation of current capability; it is not an invitation to invent or guess an email address or contact destination.

## Safe evidence to include

When disclosure can be made without exposing sensitive material, include enough sanitized evidence for maintainers to understand and reproduce the issue:

- affected BeeBox commit/ref or version identifier;
- affected component, endpoint, migration, workflow, or contract;
- security impact and preconditions;
- a minimal reproduction using synthetic/local data;
- expected versus observed behavior;
- whether authentication/authorization/tenant boundaries are involved;
- logs or traces only after removing credentials, tokens, PII, provider secrets, internal production addresses, and unrelated customer data;
- suggested mitigations if known, clearly separated from verified facts.

Do not test against systems, tenants, accounts, or data you are not authorized to access.

## Coordinated disclosure expectations

Please avoid publicizing sensitive exploit details before maintainers have had a reasonable opportunity to validate and prepare a reviewed fix. Maintainers should minimize sensitive details during triage and remediation while preserving enough evidence for independent review.

Security fixes still follow BeeBox's normal correctness requirements: scoped change, threat/tenant analysis where applicable, tests, current-head CI, review, and human merge. Sensitive disclosure handling does not justify bypassing security checks or silently weakening assertions.

When a fix changes a public contract, migration, trust boundary, tenant behavior, credential lifecycle, or other compatibility-sensitive behavior, the same architecture/change-control rules in `Instruction.md` still apply.

## No unsupported promises

This policy currently makes no promise of:

- a response or remediation SLA;
- a bug bounty or payment;
- CVE assignment;
- long-term support or a supported-release matrix;
- production hosting or managed-service incident response;
- acceptance of every report as a vulnerability.

Those commitments may be introduced only when the project actually establishes and can operate them.

## Related security baseline

Read `docs/threat-model/initial.md` for the current architecture threat model and `docs/contracts/conventions.md` for tenant, error, audit, idempotency, time, pagination, ID, and versioning semantics that future product/security changes must preserve.
