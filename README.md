# GUARDIAN — bounded AI documentation maintainer

A narrow Developer Workflow agent. It reads a maintenance issue, gets a real AI proposal, checks immutable operator permissions with a deterministic guard, applies exactly one authorized documentation line, and verifies the resulting file hash. No human acts between these stages.

## Recorded result

The included traces record a real Claude Haiku run, not a mocked planner or replay fallback: tools and MCP lists were empty, the guard accepted the proposed edit, the offline worker changed one line in docs/setup.md, and the parent verified the change. A separate automatically triggered Kill Switch stopped another actual provider run without changing files. See RESULTS.json and traces/. The demo video is explicitly labelled playback of recorded evidence; timing is edited.

The 37 new targeted tests passed with synthetic providers. They do not substitute for the real-model evidence. The finite OS prerequisite check passed positive I/O, helpers, limits and cleanup, and negative network/outside-path/process controls. The frozen guardian.py engine was not changed or repeatedly retested during adapter work.

## Setup (macOS; measured fresh-project trial below 15 minutes)

See [JURY_SETUP.md](JURY_SETUP.md) and [INSTALLATION_CHECK.json](INSTALLATION_CHECK.json) for the measured fresh-project installation trial, exact prerequisite scope and required in-project venv placement. Use Python 3.9+ and the existing sandbox-exec utility. No Python package installation is needed. The live planner uses an already-authorized official Claude Code subscription login. No credentials are included, and no pay-as-you-go API path was used in the recorded runs. Before a live run, verify claude auth status reports claude.ai/firstParty and that existing settings do not route through an API key helper, Bedrock, Vertex or paid API endpoint. Do not copy our credentials. Recorded evidence and synthetic tests can be inspected without any login.

Put the files in a directory owned by you, not writable by other users. Its ancestors must also be protected (a sticky temporary-directory ancestor is supported). Choose fresh absolute output and workspace paths whose parents exist. Both paths must be outside the code directory and must not exist yet.

```sh
python3 adapter.py demo --input /absolute/path/to/demo_input.json \
  --base-profile /absolute/path/to/worker_base.sb --base-old-workspace /unused \
  --claude-cli /absolute/path/to/claude \
  --out-dir /private/tmp/guardian-demo-out --workspace /private/tmp/guardian-demo-ws \
  --kill-switch /private/tmp/guardian-demo-kill
```

The shipped pinned public profile is used in the recorded run. It denies network and fork in the executor, substitutes only exact workspace/code/Python executable paths, and contains a specific Python.app launcher allowance for framework-based macOS Python. Other unsupported interpreter layouts fail closed. The credentialed provider stays outside the offline worker.

The input file contains a synthetic repository, an immutable operator edit and an official maintenance issue as untrusted context. Never use production files or real secrets for this demonstration.

## Tests and stopping

```sh
python3 -B -m unittest test_adapter
```

These tests use synthetic providers, run their workers without the production sandbox, and test gate/capture/watcher logic only. Actual offline isolation was checked separately. To stop a live run, create the configured kill-switch file or send SIGINT/SIGTERM to the adapter. A precommit stop prevents the target edit. A signal after COMMIT may race with a completed edit; the observed state is reported and rollback is not claimed.

Private raw provider/worker output is written to the selected output directory. It can contain account or host metadata; review and redact it before sharing. The public traces here omit private paths/arguments and raw provider streams. Their original byte counts and hashes are listed separately. They are not claimed to be full unredacted RAW.

## Scope and honest limits

This agent performs one operator-authorized line replacement. It does not select arbitrary repository changes, repair CI, handle credentials, deploy or make payments. The model cannot expand allowed paths, hosts or operations. All-20 Trap Pack scoring and the organizer answer key were not used. See tests/trap-pack/RESULTS.md.

Worker limits: CPU 3 seconds, file size 1 MiB, 64 file descriptors, no core dumps; 4-second wall limit and sampled RSS 96 MiB (not a hard memory limit). The AI provider has a separate 120-second wall limit and bounded capture. A heartbeat watcher covers registered provider and worker process groups. This is a bounded single-run agent; a long-running daemon lifecycle has not been validated. Python emitted ResourceWarning for a few stream/test-file objects during the passing test suite; all observed owned processes were absent afterward.

Code was authored after the competition kickoff. Claude Sonnet authored the adapter; the coordinator made small profile, capture, cleanup and packaging corrections, independently admitted before execution. Engine, adapter and test hashes are in RESULTS.json. Local factory infrastructure, credentials, organizer answers and private WERYFI code are excluded.

## License and credits

Project: MIT. Trap artifacts: Agentware 2026 Trap Pack, Hackathon Raptors, CC BY 4.0. The owner authorized publication of this contest project and accepted film. The public repository is https://github.com/hotelkrynicabiuro-ux/weryfi-guardian-agentware-2026. The competition form remains prepared and NOT_SUBMITTED pending the owner's latest final-approval instruction.


## Final release media and license boundary

See RELEASE_NOTES.md for the owner-approved110-second PREMIUM film and measured evidence scope. Root MIT LICENSE covers project code; official fixture and rendered brand/media have separate notices in THIRD_PARTY_NOTICES.md. A fresh project/venv installation plus a real jury command was subsequently measured below15minutes, with prerequisite scope and original failure preserved in INSTALLATION_CHECK.json. This is coordinator-observed, not a new independent Codex assessment. Public repository: https://github.com/hotelkrynicabiuro-ux/weryfi-guardian-agentware-2026. Submission: NOT_SENT pending final owner approval.
