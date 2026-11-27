> Current recorded-scope note: execution occurred after this source-design document was authored. Any NOT_RUN or pending statement in that historical design refers to source-generation time. Current verified observations are in RESULTS.json and traces/; broader capabilities remain unverified.

# AGENT.md - AI path, state and permission model

## AI path

The only AI component is the planner: the official Claude CLI, model alias `haiku`, invoked by the provider parent as a subprocess (`-p`, stream-json). It receives the operator intent plus untrusted artifact text and must return one JSON object `{op, path, old, new}`. Its output is data, never authority.

## Permission model

- Immutable operator intent (frozen dataclass): path (must be `docs/setup.md`), old line, new line, prestate SHA-256, allowed hosts. Set before the model call.
- Model output cannot add operations, paths, URLs or hosts. Any difference from the intent is rejected. No model-directed permissions exist.
- Provider: `--tools ''`, `--strict-mcp-config` with an empty MCP config file, `--disable-slash-commands`, `--no-chrome`, `--no-session-persistence`, no bare/safe/restricted mode, no permission bypass, hooks and security plugins untouched (no `enabledPlugins` override), fresh empty cwd. `--settings` sets `autoMemoryEnabled=false`, `pluginConfigs` `cc-plugin-agents-md@builtin` `options.instructionFiles=managed-only` and `claudeMdExcludes` for CLAUDE.md, CLAUDE.local.md, AGENTS.md and `.claude/rules`. Environment keeps normal HOME/PATH/login; `ANTHROPIC_`, `OPENAI_`, `AWS_`, `SSH_`, `CLAUDE_CODE_` and key/token/secret-like variables are removed before only `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` is set. Flag names and settings keys reflect the author's understanding and are unverified against the installed CLI; an unsupported flag makes the provider fail closed.
- The stream is trusted only if it has exactly one `init` (tools[] and MCP[] empty, Haiku, no bypass), exactly one successful `result`, no tool use and only JSON lines.
- Worker: offline, deterministic, no network, no subprocess, no shell, clean env (no HOME, no credentials), runs under a profile derived from the pinned base profile with no process-fork. It receives only the job JSON on stdin, after a READY line that reports its applied resource limits.
- Watcher: own minimal stdlib process; ready handshake before any model or worker payload; it kills only registered owned process groups on parent death or heartbeat loss; the parent aborts if the watcher is lost.

## State machine

`watcher_ready -> provider_process -> provider_init -> proposal -> validation (rejected | validated) -> worker ready (limits checked) -> PREPARED -> committed | aborted -> verification -> result`

Kill-switch/watcher-loss checks: before provider, during provider wait, after validation, during worker start and prepare, and immediately before the `COMMIT` signal. After `COMMIT` is sent the outcome is reported from observed file state with `no_write_guaranteed=false` (state `aborted` if unchanged, `committed_abort_race` if the file changed). Every stage runs without owner prompts.

## Logging

JSONL with UTC timestamps: input and intent SHA, proposal excerpt (redacted), validation outcome, pre/post file SHA, actual pids/pgids, return codes, observed byte counts, truncation flags and redacted bounded excerpts. Each record carries `evidence` (`actual_cli` for demo runs, `synthetic_test_double` for unit tests). Environment and credentials are never logged. Full bounded raw provider/worker output lives only in private 0600 files.

## Verified recorded scope

The actual run used Claude Haiku 5.5 with tools[]/MCP[], then the frozen Guardian gate and one offline atomic line replacement. See RESULTS.json and public traces for observed state transitions. The shipped public template was the actual worker profile, not just a proposal. Initial author NOT_RUN statements describe source-generation time. The final independent evidence gate is recorded separately; no broad autonomy or all-Trap-Pack claim is made.
