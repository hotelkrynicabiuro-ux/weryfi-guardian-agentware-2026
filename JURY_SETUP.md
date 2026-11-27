# Fresh setup for judges (macOS)

Measured installation trial: **3minutes11seconds including a failed first placement and its diagnosis**. The corrected fresh project/venv itself was ready and completed the real AI task in about69seconds, including coordinator checks. See INSTALLATION_CHECK.json. The actual final command completed in5.74seconds. No product code, accepted video or policy privileges were changed. This does not include installing macOS, obtaining a provider account, or installing prerequisite tools.

## Existing prerequisites
Supported macOS, Python3.9+ in a supported layout, /usr/bin/sandbox-exec, and the official ClaudeCLI already signed into an authorized subscription/test environment. The measured host was Intel/macOS with Python3.9.6. Never copy the owner's credentials. No pip dependencies or paidAPIkey are required. Auth must be claude.ai/firstParty; an APIkey/helper/third-party route is outside this demonstration. A live run consumes existing subscription allowance; a judge without such access can inspect actual recorded traces without login, or run synthetic tests without a model.

## Extract and create a clean environment
Download this release's public source ZIP or clone this repository. Enter the directory containing adapter.py and README.md. Keep it owned by you and not writable by other users.

```sh
python3 -m venv --without-pip .venv
.venv/bin/python3 -I -B adapter.py --help
```

Place `.venv` **inside the project directory**, as above. An external venv has a configuration file outside the worker's allowed read root and correctly fails closed. Do not relax the profile to fix that. No package installation is needed.

## Run one authorized synthetic-repository task with real AI
Find the absolute path of your existing authorized CLI with `command -v claude`. Confirm `claude auth status` reports subscription authentication rather than an API-key/helper/third-party route. Use that absolute path below.

```sh
trial_root="$(mktemp -d /private/tmp/guardian-jury-XXXXXX)"
claude_cli="$(command -v claude)"
.venv/bin/python3 -I -B adapter.py demo   --input "$PWD/demo_input.json"   --base-profile "$PWD/worker_base.sb"   --base-old-workspace /unused   --claude-cli "$claude_cli"   --out-dir "$trial_root/out"   --workspace "$trial_root/workspace"   --kill-switch "$trial_root/kill"   --provider-timeout 120
```

The out/workspace paths must not exist before the command. The parent temporary directory does exist. The expected result is `committed_verified`: exactly one line in the synthetic docs/setup.md changes to the approved example staging-access URL; the sibling README remains unchanged. The provider has tools[]/MCP[]; it cannot authorize extra paths or operations. The actual executor remains offline and NOFORK.

Private capture files are produced under your chosen output directory and may contain local/account metadata. Keep them private. Published traces are deliberately redacted projections. Stopping/cancellation limitations and the distinct existing synthetic test suites remain as documented in README.md and SAFETY.md.
