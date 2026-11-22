# Project: BeyondVPN release 0.0.0.1 — task record and checkpoints

Owner decisions (chat, 2026-11-21): harden code-side P0 items first, then publish **v0.0.0.1 as a GitHub pre-release**;
merge PR #5 (beyond-v2 → main); afterwards delete branches beyond-v2 and the four codex/* branches (closes PR #4).
Additional authority granted in chat: push to origin, merge PR #5, publish release v0.0.0.1, delete those 5 branches.
Not granted: production deployment, making anything public beyond the already-public repo, purchases.

Usage rule (§9): daily allowance figure is not available to this worker → special 80% rule inactive; recorded, not inferred.

| ID | Requirement | Acceptance criteria | Verification | Rollback | State |
|---|---|---|---|---|---|
| R1 | Alembic migrations (P0 #6) | `alembic upgrade head` creates the full schema on empty SQLite; app startup runs migrations; existing pre-migration DB is stamped, not recreated; tests use migrations | pytest + fresh-DB upgrade + metadata diff = none | revert commit; DB unaffected (additive) | todo |
| R2 | Shared rate limiter (P0 #7) | `BEYOND_REDIS_URL` set → limiter uses Redis fixed window (atomic INCR+EXPIRE); unset → in-process; Redis down → fail open with warning (auth lockout stays DB-backed) | unit tests with a fake client; existing auth tests pass | unset env var | todo |
| R3 | Agent Windows service (P0 #2) | `beyond-agent service install/uninstall`, runs under SCM reporting Running/Stopped | Windows build in CI; local install/start/stop/uninstall (elevated) | `service uninstall` | todo |
| R4 | Agent token + key protection (P0 #4, #5) | token and state written by the agent with restrictive permissions: Linux 0640 root:beyondvpn (group if present) else 0600; Windows ACL SYSTEM+Administrators full, Interactive users read on token only; WireGuard private key DPAPI-protected (machine scope) on Windows | unit tests; icacls output check | files re-written on next start | todo |
| R5 | Dependency advisories | pip-audit, npm audit (prod), cargo audit: no High/Critical left unaddressed | tool output recorded | — | todo |
| R6 | Version 0.0.0.1 | version strings updated where the format allows; release notes list gaps | grep | — | todo |
| R7 | Integrate + release | CI green on beyond-v2 → PR #5 merged → tag v0.0.0.1 on main → GitHub pre-release with assets | gh output | delete release/tag | todo |
| R8 | Branch cleanup | only `main` remains on origin; PR #4 closed | `git ls-remote --heads` | branches restorable from PR refs | todo |

Completion = verified criteria / total criteria (8 tasks, equal weight).

## Checkpoints (UTC; owner display Asia/Kathmandu UTC+05:45)

### 2026-11-21T19:45Z (2026-11-22 01:30 NPT) — worker: main session, generation 1 — DONE
- R7 verified: CI 7/7 green on d3e405a → PR #5 merged (merge commit 0cae02f) → tag v0.0.0.1 → release workflow 7/7 green → GitHub pre-release "Beyond VPN 0.0.0.1", 11 assets incl. SHA256SUMS.txt; Windows agent checksum re-verified after download; wheel contains migrations.
- R8 verified: origin heads = main only; PR #4 CLOSED; local beyond-v2 deleted.
- Completion: 8/8 tasks verified (100%). Stages: implemented, verified, merged, released. NOT deployed (no servers).
- This checkpoint is not committed: main is the only branch and repo rules forbid direct commits to main.

### 2026-11-21T19:10Z (2026-11-22 00:55 NPT) — worker: main session, generation 1
- R5 verified: cargo audit 0.23 (1555 advisories, 237 crates) → 0 vulnerabilities; 1 unmaintained warning RUSTSEC-2025-0134 rustls-pemfile (no fix release; replace with rustls-pki-types PemObject in a follow-up with a TLS-loading test). pip-audit, npm audit clean.
- Rust workspace tests 54 passed; e2e passed; first CI run on 203d127 failed: Linux clippy dead-code on Windows-only helpers → fixed in 6f3b3df (cfg(windows)); CI re-running (run 44936789458).
- Completion: R1–R6 verified (6/8 = 75%); R7, R8 pending CI.

### 2026-11-21T18:20Z (2026-11-22 00:05 NPT) — worker: main session, generation 1
- R1 verified: pytest 48→52 incl. models==migrations, idempotent, legacy stamp keeps data, forward-only.
- R2 verified: shared-limit, window rollover, outage fallback tests (pytest 52 passed).
- R3+R4 verified on Windows 11 (elevated test): service Running/auto/LocalSystem, failure actions 5s/5s/30s, API 200 w/ token, 401 without; ACL dir SYSTEM+Admins, token +INTERACTIVE:R; DPAPI round trip + plaintext upgrade (cargo test agent 8 passed); clippy -D warnings clean; uninstall clean, test state removed. Linux token path: unit-tested (group lookup, 0600 secrets) — not run on Linux here (CI runs it).
- R5: pip-audit clean; npm prod clean; web dev deps upgraded vite 5→8, vitest 2→5, plugin-react 4→6 (0 vulnerabilities, tests 5/5, build OK); cargo audit running.
- R6 done: versions set (pyproject/__version__ 0.0.0.1, extension 0.0.0.1, Android name 0.0.0.1, Cargo/npm 0.0.0+1, iOS 0.0.0 build 1).
- Added: .github/workflows/release.yml (owner asked: release assets via GitHub Actions), docs/releases/v0.0.0.1.md.
- Next safe action: cargo audit result → commit → push → CI green → merge PR #5 → tag v0.0.0.1 (workflow publishes) → verify release → delete branches.
- Completion: 5/8 tasks verified (R1–R6 minus R5 pending cargo) → 62% (unknown for R5 until cargo audit).

### 2026-11-21T17:33Z (23:18 NPT) — worker: main session, generation 1
- State: R1–R8 todo. Branch beyond-v2 @ 0f9809a (= origin). CI on 0f9809a: green (7 jobs).
- Baseline: control-plane pytest 44 passed; cargo test 52 passed; e2e passed (2026-11-21).
- Next safe action: implement R1.
