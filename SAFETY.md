> Current recorded-scope note: execution occurred after this source-design document was authored. Any NOT_RUN or pending statement in that historical design refers to source-generation time. Current verified observations are in RESULTS.json and traces/; broader capabilities remain unverified.

# SAFETY.md

## Status

All source here is NOT_RUN. Static admission is pending. The contract reviewer reservation is recorded as satisfied by `ownerapproval115` (per the task statement); that does not substitute for exact-source independent admission. Synthetic tests are authored, not run, and are `synthetic_test_double` evidence. Real runtime evidence does not exist yet.

## Kill switch

Pass `--kill-switch PATH`; if that file exists, or SIGINT/SIGTERM is received, the supervisor aborts. It is checked before the provider, continuously during the provider wait (SIGTERM then SIGKILL to the provider's own process group only), after validation, during worker start/prepare, and again after PREPARED immediately before `COMMIT` is sent. An abort at any of those points leaves the target file unchanged (the result reports `files_unchanged`; leftover temp files are removed).

Limits of that claim: a signal arriving after `COMMIT` has been sent cannot be guaranteed to prevent the write. The result then carries `no_write_guaranteed=false` and reports what was observed: `aborted` if the file is unchanged, `committed_abort_race` (exit code 5) if it changed. A signal that arrives strictly after the worker finished is not an abort. A tiny race also exists between the final check and sending `COMMIT`. Synthetic tests inject kill points through test-only hooks (not exposed on the CLI); real provider-wait abort evidence is still required later.

## Watcher

The adapter ships its own minimal stdlib watcher (`adapter.py watcher`). It is not a copy of any private or prestart infrastructure. It starts in its own session, completes a READY handshake before any model or worker payload, exchanges heartbeats (0.5 s period, 3 s timeout), and receives `REG`/`UNREG` for owned process-group leaders. On parent death (parent pid change or stdin EOF), heartbeat loss or protocol error it SIGTERMs then SIGKILLs only registered groups (never its own or the parent's group) and exits. On loss of the watcher the parent aborts and stops its own groups. On normal exits and aborts each group is SIGKILLed after the leader exits (to reap stragglers), unregistered, readers are joined with timeouts, and the watcher is told to `QUIT`.

Residual risks: if the parent and the watcher are both SIGKILLed at once, nothing cleans up; a child that escapes its group by calling setsid is not covered; registration happens just after spawn, so a child spawned in the instant before registration is covered only by its stdin reaching EOF (the provider and worker both exit on EOF without a payload); process-group id reuse after a group has fully exited is theoretically possible but very unlikely within the short windows involved. The watcher trusts registrations from its parent pipe, bounded to group leaders other than its own and the parent's group.

## Boundaries

- Provider parent uses the CLI's existing login via the normal HOME/PATH; it does not extract, log or forward credentials. API keys, provider routing/selector variables and secret-like variable names are not copied. The provider is not sandboxed by this adapter; it relies on tools/MCP being empty (verified from the actual init event) and on the CLI's own protections.
- The worker runs under a profile derived from the pinned base profile (SHA-256 `71999f33...171854`): the exact process-fork allow line removed, old workspace replaced by the fresh workspace, one read-only subpath for the exact candidate code directory added. Wrong SHA or unexpected text refuses the run. The effective guarantee is only as good as the pinned base profile and the OS sandbox. The adapter changes no UID, VM, resolver or system setting.
- Candidate code directory, its ancestors and the two source files are checked for ownership and group/other write bits. Output and workspace directories are fresh, 0700, disjoint and not inside the code directory.
- Worker resource limits: CPU 3 s, FSIZE 1 MiB, NOFILE 64, CORE 0 are applied by the worker at start and verified by the parent from its READY line before any payload is sent (self-applied and parent-verified, not applied by the parent before exec). Wall 4 s and RSS 96 MiB are enforced by the parent. RSS is sampled with `ps` roughly every 0.2 s, so a short spike can be missed: it is sampled RSS, not a hard RAM cap. Three consecutive failed samples abort the worker. The provider has a separate wall limit of at most 120 s and no resource limits.
- Capture: combined stdout/stderr is stored up to a cap (provider 2 MiB, worker 64 KiB) as private files; observed byte counts and a truncation flag are recorded; exceeding the cap stops the owning process group and the run fails with traces retained. Reader threads are bounded (two per process plus a short-lived writer).
- Writes happen only inside the freshly created synthetic workspace: lstat walk rejects symlinks, wrong file types and traversal; prestate SHA is checked at prepare and again before the atomic replace; no proposal text is ever executed by a shell.
- Logs are redacted and carry synthetic content only. The raw private stdout/stderr files are not redacted (they may contain whatever the CLI printed, for example the init event) and must not be published.
- Untrusted artifacts reach Guardian only as evidence and are wrapped as untrusted data in the prompt.

## Limitations

- Planner role is narrow: it echoes an operator-approved edit, so the demo shows the gated pipeline, not general agent autonomy.
- Guardian is a heuristic rule engine; its limitations apply.
- CLI flag names, settings keys and the init event schema may differ across versions; mismatches fail closed. Whether `managed-only` instruction-file policy is honoured is not verified.
- Hash pinning covers `guardian.py` and the base profile; `adapter.py` itself needs independent admission.
- Unit tests use a synthetic fake CLI and no sandbox; they are not evidence of real runtime behaviour.

Trap artifacts: Agentware 2026 Trap Pack, Hackathon Raptors (CC BY 4.0).

## Actual evidence and remaining limits

The recorded Kill Switch stopped the real provider wait before any commit; files remained unchanged and observed PIDs were absent. Separate synthetic tests cover precommit cancellation and watcher loss. Do not infer post-commit rollback or arbitrary secret handling. The OS preflight kept setuid ps denied inside restrictions and sampled owned worker memory from the trusted supervisor outside. No security or account configuration was changed. Public trace copies omit private metadata; original private RAW is retained locally with hashes.
