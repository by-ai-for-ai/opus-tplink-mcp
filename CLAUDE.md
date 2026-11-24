# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **This file is published with the repository for public review.** Keep it up to date when the
> architecture, commands or release flow change, and keep it free of anything private (addresses,
> MACs, names, passwords, hostnames of real networks).

MCP server (stdio) for TP-Link Archer BE routers and RE range extenders, published on PyPI as
`opus-tplink-mcp` (import package `mcp_tplink_router`). It drives the devices through the same
LuCI form requests their web UI sends, behind a dry-run / confirm-token / journal / undo pipeline.

## Commands

```bash
venv/bin/pytest -q                                   # full suite, offline
venv/bin/pytest -q tests/test_extender.py::test_hardened_login_and_signed_requests   # one test
venv/bin/ruff check .
venv/bin/bandit -r src/ -ll                          # CI also runs pip-audit
venv/bin/pip install build && venv/bin/python -m build && venv/bin/twine check dist/*
```

CI (`.github/workflows/ci.yml`) runs ruff + pytest on Python 3.10–3.12, then bandit and pip-audit.
`publish.yml` runs on a published GitHub release: it checks that the tag `vX.Y.Z` matches
`pyproject.toml`'s version, tests, builds, and uploads via PyPI Trusted Publishing (no token).

Tests must never touch the network: `tests/conftest.py` makes any socket/requests use fail. Router
behaviour is simulated by `tests/fake_router.py` (an in-memory BE9300 seeded from
`tests/fixtures/shapes.json`, live field *shapes* with fake values; it can fail a call before or
after applying it to simulate lost replies). Extender protocols are simulated in
`tests/test_extender.py` by fakes that verify the real signatures/encryption.

## Architecture

Request flow: `server.py` (MCP glue, one lock per call) → `tools.run_tool` → feature handler
`(Ctx) -> result | Plan` → `safety.finalize` → transport.

- **`config.py`** — `load_routers()` builds `RouterConfig`s from env. `TPLINK_HOST`/`TPLINK_PASSWORD`
  is router `main`; `TPLINK_ROUTERS=a,b` adds `TPLINK_<NAME>_HOST/_PASSWORD_FILE/_PROTOCOL/_KIND`.
  Protocols: `plain`, `encrypted`, `extender`, `encrypted-v2`. Kinds: `router`, `extender`.
- **Transports** (all expose `login / call(path, op, fields) / logout`, used via
  `transport.session()` which always logs out — devices allow ONE admin session):
  - `transport.RouterTransport` — `plain` (BE9300-style RSA login, form POSTs).
  - `transport.EncryptedRouterTransport` — `encrypted` (BE4800/BE3600). Uses `tplinkrouterc6u` only
    for login + AES; `_form_request` deliberately bypasses the library's JSON adapter (it collapses
    repeated keys and drops blanks) and fails closed if the library layout changes.
  - `extender_transport.ExtenderTransport` — `extender` (X-series RE: RSA-1024 PKCS#1 login).
  - `extender_transport.HardenedTransport` — `encrypted-v2` (e.g. RE3200BE fw 1.5: SHA-256 hash,
    RSA-OAEP login signature, HMAC-SHA256 + per-request ciphertext hash). The scheme is chosen by
    config, not detected. A refused login raises `LoginRefused` (`no_retry`) and is never retried —
    devices lock the account after failed logins.
- **`tools.py`** — `ToolDef` registry (`register(...)`), JSON schemas (every write tool gets
  `apply`, `confirm_token`, `reveal`, `router`), dispatch, retry rules (reads/planning retried once on
  ambiguous errors; writes are never resent — after a lost reply the server re-reads and reports).
  `ToolDef.kinds` gates tools by device kind. `tests/test_core.py` enforces a tool-count budget;
  prefer adding an `action` to an existing tool over adding a tool.
- **`features/`** — one module per area; handlers read args via `Ctx.arg/need/obj` and return data
  (reads) or a `safety.Plan` (writes). `features/__init__.settings_change()` is the standard
  read-merge-write helper for a single form. `features/extender.py` holds the extender form map
  (`EXTENDER_FORMS`) and the `extender` / `extender_set` tools.
- **`catalog.py` + `_endpoints.py`** — every form path the web UI references, its ops, write-field
  allowlist, risk tier (`read < normal < critical < forbidden`, per router profile), secret fields,
  and provenance (`verified`: `live` / `ui` / `none`). `LIVE_VERIFIED` lists ops exercised against
  real hardware. `forms.endpoint(path)` is how features look these up.
- **`forms.py`** — form/table primitives: read-merge-write, row-by-key table edits with collateral
  checks (whole table compared before/after).
- **`safety.py`** — `Plan`/steps, diff, risk, confirm tokens (HMAC over the exact requests + current
  state, 5 min), `gate`, `apply_plan`, verification (`applied` / `mismatch` / `no_effect`),
  pre-change auto-backup, Wi-Fi health probe, `plan_undo`, and `redact` (secrets masked unless
  `reveal`). `Plan.reboots` marks changes after which the device reboots (skip post-checks).
- **`journal.py`** — append-only JSONL journal (before-state fsynced before the first request); the
  basis of `router_undo`. Device-state sections (`requests`/`before`/`after`/`wire`/`detail`) are
  AES-256-GCM encrypted at rest (per-install key, `TPLINK_JOURNAL_KEY`); `entries()` decrypts, unreadable
  entries carry `unreadable` and `plan_undo` refuses them. Never print a raw journal file; read it via
  `router_journal` (redacted).
- **`validate.py` / `netcalc.py`** — subnet, pool, reservation and MAC checks.
- **`events.py`** — local event log (`events.jsonl`, 0600, redacted, rotated) written by `tools.run_tool`
  for every reply worth a look, plus the firmware/mode watcher (`note_firmware`: model, hardware, firmware
  and `system?form=sysmode` mode, read on a device's first use per process and every 6 h;
  `firmware_changed` / `mode_changed`). Never raises. Followed by `watch.py` (terminal) and `viewer.py`
  (PySide6 window, optional `gui` extra) - subcommands of the console script, which still runs the MCP
  server when called with no argument.
- **`capabilities.py`** — what a router does NOT support, learned live from "no such callback" / HTTP 404,
  keyed on model + hardware + firmware + operation mode + the form selector (e.g. `band=6g`, never user
  values), TTL 1 h, reset on a firmware/mode change and on a mode switch made through the tool. Refusals
  say "not supported by this tool on <model>", never "the router lacks it".
- **`reporting.py`** — optional field reports, OFF until a person chooses in an interactive `setup` or the
  viewer (the env var can only force OFF; no MCP tool can change it). Payloads come only from `build()`
  (fixed codes, categories, versions, validated model/fw); never from the event log. `server/report_server.py`
  is the stdlib receiver: allowlisted fields, no stored IPs, per-day salted source ids, public totals only
  for >= 5 distinct sources; reports never set "verified" (maintainer-written `verified.json` only).

Reference data: `docs/router/endpoints.txt` (every form the UI references) and
`tests/fixtures/shapes.json` (catalog write fields are checked against it).

## Model tiers, memory and the local-model bench

- `safety.model_tier()` reads `TPLINK_MODEL_TIER` (`large` default, `small` for local models). The small
  tier is shaped around how small models were seen to fail (`docs/local-model-bench.md`): compact tool set
  (`tools.CORE_TOOLS`), short replies (`tools.shorten`), repeat-confirm only as the very next call within
  60 s (`safety.CALL_SEQ`, `REPEAT_WINDOW`), `recent_changes`, id-less `router_undo` within 10 minutes, and
  the **task memory** (`tools.TASK_MEMORY`, `memory` block first in every reply). Safety is identical in
  both tiers; never relax it per tier.
- Previews go through `safety._preview` (status `PREVIEW_ONLY` / `ALREADY_PREVIEWED` / `REFUSED_NOTHING_CHANGED`,
  `tell_user`, exact `next_call`); results carry `verified` + `tell_user` + `undo_call` (`safety.verdict`).
  `safety.PENDING` remembers previewed-but-unapplied changes (shown only on calls to the same tool).
- `bench/` runs local models (OpenAI-compatible server, e.g. LM Studio) against ONE test router
  (`BENCH_HOST`, `BENCH_PASSWORD_FILE`, `BENCH_PROTOCOL`; `BENCH_TIER`, `BENCH_TOOLSET`, `BENCH_PREVIEW`,
  `BENCH_PRESERVE_THINKING`). `python bench.py perfect` must score 7/7 before trusting a model result;
  `report.py` re-scores saved summaries with the current checks and builds the color-coded table, with
  plain-words reasons from `bench/failure-notes.json`. Fix the TOOL when a model fails, not the prompt;
  fix the bench only when it scores a correct answer wrongly, and record that in the report.

## Conventions

- New write ops: add/adjust the catalog entry (fields, risk, secrets) first, build a `Plan`, and add
  a fake-router test. Only mark an op `live` in `LIVE_VERIFIED` after exercising it on real hardware
  (apply → verify → undo).
- Wire formats come from the device's own web UI (captured requests / UI JS), not guesses.
- Never put real addresses, MACs, names or passwords in code, tests or docs: this repo is exported
  as-is to the public repository. Tests use documentation ranges (`192.0.2.x`, `00-00-5E-00-53-xx`,
  locally administered `02-...` MACs).
- Release: bump `pyproject.toml` version and `CHANGELOG.md`; publishing happens from a GitHub
  release tag `vX.Y.Z` on the public repo.
- Changes for local-model results go through four gates before a bench batch: a test replaying the
  failing call plus its passing neighbours, the full suite + ruff, the perfect agent 7/7 on every bench
  device, and a canary of a model that previously PASSED the touched scenarios.
