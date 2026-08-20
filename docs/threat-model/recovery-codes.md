# Recovery-code threat model

This document covers the P2.7 recovery-code implementation and its dedicated TOTP replacement lifecycle. Recovery codes are a narrowly scoped alternative for completing an existing pending-MFA authentication; they are not a second primary method, a generic reverification mechanism or authority for arbitrary factor removal.

## Generation and storage

Every recovery set contains exactly ten independently generated codes. A code contains 26 symbols selected uniformly from the 32-symbol Crockford Base32 alphabet, providing 130 random bits. BeeBox may group the symbols as `5-5-5-5-6` for display. Input normalization accepts only ASCII letter case and those exact expected hyphens; it does not map visually similar symbols, trim whitespace or perform Unicode normalization.

Codes are returned exactly once after initial TOTP activation, successful regeneration or successful TOTP replacement. Later state responses expose only whether an unused code exists and the bounded remaining count. PostgreSQL stores only SHA-256 over `beebox:v1:recovery-code\0 || application || user || recovery-set ID || normalized code`. Codes and hashes never appear in logs, metric labels or audit facts.

## Authentication completion

A recovery code can complete only a valid five-minute pending-MFA authentication created after one of BeeBox's implemented primary proofs. The pending transaction remains bound to exact application, user, primary method and proof context and retains the shared five-failure ceiling. Completion locks the pending transaction, active recovery set and candidate code; it then consumes the code and pending token, creates session/refresh state and appends audit evidence in one transaction.

Successful ordinary use does not update, delete, disable or replace the active TOTP credential. Two concurrent uses of one code can create at most one session. A code from an invalidated, other-user or other-application set cannot match because both lookup scope and verifier input are bound.

## Regeneration

Regeneration requires the exact current application/user/session and accepted reverification evidence. The transaction locks the active TOTP credential, invalidates the entire previous set, inserts the new set and ten hash-only code rows and appends audit evidence. A failed transaction leaves the old set active. PostgreSQL admits at most three successful regenerations per user/session per hour; the hosted UI does not create a second counter.

## Dedicated TOTP replacement

Recovery codes cannot remove TOTP or mint generic step-up authority. The only factor-recovery use is a dedicated replacement flow that additionally requires current primary-proof session authority and accepted reverification:

1. one unused recovery code authorizes creation of a short-lived replacement enrollment;
2. the existing TOTP credential and recovery set remain active while that enrollment is pending;
3. the new TOTP secret is encrypted under the same keyring/AAD contract as ordinary enrollment;
4. only a valid proof from the replacement secret commits the replacement;
5. confirmation atomically replaces the credential, invalidates the previous recovery set, creates a fresh ten-code set and appends audit evidence.

Abandoning or failing replacement cannot silently disable the old TOTP. The recovery code used to start replacement is consumed and cannot be reused for another purpose.

## Threats and evidence

| Threat | Control |
| --- | --- |
| Offline database disclosure | 130-bit independent codes; domain-separated, application/user/set-bound SHA-256 only. |
| Code replay/concurrent use | Code row and pending transaction are locked and consumed atomically; concurrency test permits one session at most. |
| Old code survives regeneration | One transaction invalidates the old set before the unique new active set is committed. |
| Recovery silently disables MFA | Ordinary completion never mutates TOTP; replacement keeps old TOTP active until confirmed. |
| Recovery becomes generic step-up | No recovery endpoint returns a reverification grant; handlers call only pending-auth completion, regeneration or dedicated replacement services. |
| Tenant/principal substitution | Set lookup and code verifier include exact application/user; pending state is independently bound to the same context. |
| Audit outage leaves authority | Authority, code/set mutation and audit share a transaction; induced audit failure rolls all authority back. |
| Code leakage | Responses show new codes once; state is count-only; audit uses opaque recovery-set ID; metrics use bounded operation/outcome. |

## Residual risk

Anyone holding a still-unused code plus a valid pending-MFA token can complete that transaction. Users must store codes separately from primary credentials and TOTP devices. A compromised application database does not reveal codes directly but still exposes account/security metadata and requires incident response. BeeBox does not claim recovery against loss of every primary method and every recovery code; such administrative identity proofing is outside Phase 2.
