# Changelog

## 1.2.0 (2026-11-24)

**Tested with local models, on routers and range extenders.** Four local models were run against a real
router and two range extenders (63 trials each), and the tools were changed wherever a failure showed a
weakness: Gemma 4 12B and a 1-bit Bonsai 27B are perfect on all three devices, Nemotron 3 Nano 4B scores
62/63 and Gemma 4 E4B 60/63 - all four with zero false claims. Full report: `docs/local-model-bench.md`;
harness: `bench/`.

### Security
- Requires `mcp>=1.30.0` (older 1.x releases have CVE-2026-59951 and CVE-2026-116685).

### Watch it work
- **Local event log** (`events.jsonl` next to the journal, 0600, secrets masked, rotated): errors,
  refusals, not-done, recoveries after a model mistake, unknown devices, unsupported features, unreachable
  devices, failed logins, verified changes, Wi-Fi restarts, and the model / hardware / firmware / operation
  mode each device reports - with **firmware and mode changes flagged**.
- `opus-tplink-mcp viewer` (live window, `pip install 'opus-tplink-mcp[gui]'`) and `opus-tplink-mcp watch`
  (terminal). Both read-only.
- **Optional field reports, OFF until a person chooses** (`opus-tplink-mcp setup` or the viewer's first-run
  notice). Fixed codes, feature categories and router model / firmware only - never addresses, names,
  Wi-Fi names, requests or messages; no install ID. `report --dry-run` shows exactly what would be sent.
  Public totals at by-ai-for-ai.com need 5 different sources, and reports never mark a router supported.

### Knows what each router supports
- A feature whose form a router's firmware lacks answers `NOT_SUPPORTED` ("not supported by this tool on
  <model> (hardware, firmware); nothing was changed; it may still exist in the router's own web page"),
  remembered for that exact model, firmware and operation mode for an hour and refused up front; a firmware
  or mode change resets it. `router_status capabilities=true` lists it.
- Never writes a field a router's form does not have (a form that reads fine on another model is not proof
  its fields mean the same).
- A combined read survives one missing form (an Archer AX3000 has no 6 GHz guest network).

### Traffic monitor
- `clients action=traffic` (name, IP or MAC; optional `history=minute|hour|day`): per-device usage from the
  router's own statistics, with where the numbers came from. Verified live on an Archer AX3000 and AXE5400.
  Wiping the statistics (`reset_all`) is critical and no action sends it.

### From the extender round of the local-model bench
- Previews and results **name the actual change** ("change 5g Wi-Fi (enable: on -> off)").
- Every write-tool error reads NOT DONE - NOTHING CHANGED (NOT CONFIRMED when it failed mid-apply); read
  errors never do.
- Device names: `router` is "router OR extender"; `device` is accepted as the same argument; "the
  extender" / "my router" mean the only device of that kind; small-tier reads say which device they are
  about; unknown names get `NO_SUCH_DEVICE` with a sentence for the user.
- A confirm call that dropped arguments, or garbled the token's timestamp, gets the previewed call back
  (applying still needs the exact token).
- MLO: the read gives the exact call to change it; `settings.enable` is accepted; the preview warns that
  the extender's Wi-Fi restarts, and the tool waits and reports what came back (also after undo).
- LED night mode: `enable` alone uses the saved times.

### Security: the journal is encrypted at rest
Older versions kept the full device state in the change journal as plain text (mode 0600), which
included Wi-Fi passwords, because undo needs them. Every section that holds device state is now
encrypted with AES-256-GCM under a random per-install key (`~/.config/opus-tplink-mcp/journal.key`,
0600; `TPLINK_JOURNAL_KEY`). Existing journals are encrypted the first time the server starts. Writes
and that migration take a lock file, so two server instances can't lose each other's records. Without
the key, `router_undo` refuses and names the reason (key missing, a different key, or a damaged
record) and sends nothing. Tool replies are redacted unless you pass `reveal=true`; tests (on the
simulated router) check that the journal file never holds a password, and that `router_journal` and the
undo preview don't show one. Change summaries stay readable and can name devices, MACs and file names.

### Extender MLO
- **`extender_set action=mlo`** (Wi-Fi 7 extenders, e.g. RE3200BE): read the MLO network, turn it on/off and
  choose its bands (`bands=["2g","5g"]`, at least two, only bands the unit supports). Sent as the extender's
  own web UI does (the full `extend?form=settings` payload); verified live (off, read back, undo).

### Fixed
- `next_call` on a router other than `main` now includes `router`, so it can be sent exactly as given (it
  used to target `main` and be refused).

### Extenders over HTTPS
- `encrypted-v2` (e.g. RE3200BE) over **HTTPS** logs in and talks with plain forms, as its web UI does there
  (it wraps requests in AES + signatures only over plain HTTP); the old wrapped login got "no such callback".
- Extender sessions accept the older RSA-only TLS some X-series units offer (e.g. RE1750X: AES128-GCM-SHA256),
  which current Python/OpenSSL defaults refuse with a handshake failure.

### Configuration
- **Settings come from a `.env` file** the server actually finds: `TPLINK_ENV_FILE`, then
  `~/.config/opus-tplink-mcp/.env`, then `./.env` (a bare `load_dotenv()` searched the installed package's
  folder, so a user's file was never found after `pip`/`uvx` installs). The MCP client's own `env` still
  wins. `.env.example` is now a complete annotated template, including the model tier.
- The main router accepts `TPLINK_PASSWORD_FILE`, `TPLINK_PROTOCOL` and `TPLINK_KIND`.

### Changed (found by testing with a 1-bit local model, Bonsai 27B)
- **Every change now needs a dry run first**, not only critical ones: `apply=true` without the
  `confirm_token` of a dry run is refused. The refusal itself is the dry run (plan, diff and a fresh
  token), so the next call can apply exactly what was shown. The model skipped previews whenever the
  tool allowed it.
- A call that asks to change something but only reads (e.g. `apply=true` without `action=set` or
  settings) now says **"NOTHING WAS CHANGED"** with a hint, instead of returning the current values.
  The model had reported "5 GHz has been turned off" after such a call.
- **Every change result states the truth in plain words**: `verified` = `yes` (reading the device back
  confirms it) / `no` / `unknown` (sent, cannot be read back) / `after_restart`, plus a `tell_user`
  sentence ("DONE AND VERIFIED", "NOT DONE: ...", "SENT BUT NOT CONFIRMED"). A re-read that disagrees is
  now status `mismatch` (it was `applied` with a warning), and custom-op writes (e.g. MLO) are read
  back when their form is readable.
- A dry run is spelled out as **step 1 of 2**: `status: PREVIEW_ONLY` first, a `tell_user` that says
  nothing has changed yet and step 2 is required, and **`next_call`** with the exact step-2 arguments
  (including `apply=true` and the confirm token), ready to send. A model took repeated previews for the
  change and reported it done.
- The everyday tools' descriptions end with **ready-to-copy example calls**, and every write tool states
  the two-call rule (preview, then `next_call`). Examples show only the change itself, never a sample name
  or password; a test runs every literal example. Models' reasoning showed they needed a correct command
  to copy.
- **The tool's memory (small tier):** every reply starts with `memory`: what the model was asked to do,
  what actually happened, and `is_it_done` YES/NO. Write tools take an optional `intent` (the user's request
  in the model's words), remembered for the task. A model reasoned only on its first turn, then wrote its
  answer from its own plan without reading the reply.
- A refused apply (bad or fake confirm token) now has its own status, **`REFUSED_NOTHING_CHANGED`**, with
  `tell_user` "NOT DONE - NOTHING CHANGED"; it no longer looks like step 1 of a preview. A model sent a
  fake token, got `PREVIEW_ONLY` back and told the user the change was made.
- **`TPLINK_MODEL_TIER=large|small`**, chosen by the user for the model driving the server. `small`: compact
  tool set, short replies, and an identical repeat of a just-previewed request confirms it - only as the very next
  call and within a minute, so a declined preview is never revived later (a model reasoned only on its
  first turn, then re-sent its own last call unchanged). `router_status` reports the tier.
  Small-tier replies also state `recent_changes` (what this server actually changed in the last 10
  minutes, or "none": models claimed changes they never made after only reading), and `router_undo`
  without an id undoes the most recent change from the last 10 minutes, previewed first (models could
  not find the journal id; an older change, e.g. from another conversation, still needs its id).
  Safety does not change with the tier.
- **The server remembers unfinished changes.** While a previewed change is not applied, calls to the same
  tool carry a `pending` block with its `next_call` (never unrelated calls: that could nudge a model into a
  change the current request did not ask for); previewing the same change again
  returns `ALREADY_PREVIEWED` ("send next_call now"). A model planned "dry run, then apply", lost the
  plan between turns (clients do not send a model's reasoning back) and previewed the same change five
  times. Entries expire after 5 minutes.
- **Every applied change returns its `undo_call`** (`router_undo` with that change's id), and `tell_user`
  says how to reverse it.
- `TPLINK_PREVIEW=critical` (opt-in): normal changes apply on the first call, critical changes are still
  previewed. Default `always`.
- `TPLINK_TOOLSET=core`: an opt-in compact set of the 13 everyday tools (about 3.7k tokens instead of
  10.5k) for small local models; it also hides the raw escape hatch. Default: every tool.
- `wifi_set action=set` takes a top-level `enable` as the band on/off, and its "what to change" error no
  longer shows an SSID/password example: a model sent `enable=false`, was told settings were required
  "e.g. ssid/password", and filled in `ssid`/`password` "dummy" (stopped only by the password length
  check).
- `router_status` no longer passes on empty firmware details as `null`s: the BE3600 sometimes answers the
  firmware read with nothing while busy; it now asks once more and otherwise says "unavailable".
- "true"/"false" sent as text on an on/off field are understood (they were misreported as a mismatch).
- Made-up settings are rejected by name; the raw and catalog tools point to the dedicated tool; an
  unknown router name tells the model to say it does not exist.
- `router_raw_write` is described as experts-only and not a way around a refusal (the model reached for
  it after a dry-run refusal).

### Fixed
- The main router can now use any protocol (`TPLINK_PROTOCOL`, `TPLINK_KIND`). It was always `plain`, so
  a single encrypted-firmware router or an extender could only be added under another name.

## 1.1.0 (2026-11-19)

### Added
- **TP-Link RE range extenders** (experimental): two new login generations taken from the extenders'
  own web pages - `extender` (X-series: RSA-1024 login, `Referer` on every request) and
  `encrypted-v2` (the hardened generation: SHA-256 login hash, RSA-OAEP login signature, HMAC-SHA256
  signature over each request's ciphertext). Tested live on RE2700X, RE1750X, RE1500X and RE3200BE in
  repeater mode.
- Tools `extender` (status, uplink, extended and guest networks, mesh, network, clients, advanced Wi-Fi,
  system, logs) and `extender_set` (LEDs, LED night mode, power schedule, reboot), each change applied,
  verified and undone live on all four (reboot on the RE1500X).
- Device kinds (`TPLINK_<NAME>_KIND=router|extender`): router-only tools answer "not supported" on an
  extender with the list of tools that work there.
- **Operation mode switched live** (Archer BE3600: router -> AP -> router, both directions, with the
  tool). The dry run explains how the device will be reached afterwards. Leaving router mode makes the
  firmware turn remote management off; `keep_access=true` turns it on before switching back to router
  mode (opt-in: it exposes the admin page on the WAN side).

### Fixed
- A mode switch was reported as `no_effect`: the device accepts it, still reads the old mode, and
  switches about 15 s later. The operation-mode form (and an undo of it) now reports `verify_deferred`;
  every other write keeps the strict check.
- An unreachable device (restarting, or a changed address) no longer gets the misleading "one admin
  login at a time" hint; the hint now says it did not answer at its configured address.
- A refused extender login is never retried (the devices lock the account after failures).

## 1.0.2 (2026-11-18)

### Added
- **Archer BE3600 v2 (fw 1.0.4)** tested live: the full runbook (22 change types, each undone and
  verified), MLO on/off, USB sharing and partitions, HTTPS remote management, reboot, and all reads.
- **Published on PyPI** (`pip install opus-tplink-mcp`, `uvx opus-tplink-mcp`) through a GitHub
  workflow with Trusted Publishing (no stored token). An `opus-tplink-mcp` command was added next to
  `mcp-tplink-router`.
- MLO on models that reboot after an MLO change (the router's `mloNetwork.reboot` flag): the dry
  run says so, and the result reports `router_rebooting` instead of running the Wi-Fi health check
  against a router that is going down.

### Fixed
- `clients action=list` was empty on encrypted-protocol firmware (BE4800, BE3600). It now falls back
  to the web UI's `smart_network?form=game_accelerator` `loadDevice` source.

## 1.0.1 (2026-11-18)

### Fixed
- **Encrypted protocol (e.g. Archer BE4800 1.0.x): requests are now sent exactly as the web UI sends
  them.** Earlier versions went through `tplinkrouterc6u`'s JSON adapter (written for the BE805). That
  adapter rebuilds the body with `dict(parse_qsl(...))`, which:
  - collapsed repeated keys to their last value, so list fields such as MLO `selected_bands` reached
    the router as a single band;
  - dropped blank values, so clearing a field (e.g. the DMZ address) was silently ignored;
  - copied every field into the URL query string, **including secrets such as Wi-Fi passwords**.
    HTTPS still encrypted them on the wire, but they could appear in router or proxy URL logs.

  The library is now used only for login and AES. The body goes out as the form string with
  `Content-Type: application/x-www-form-urlencoded`. A regression test drives the real library class.
- **MLO on a BE4800 can now be switched on from off.** The router refused it because the adapter
  above cut `selected_bands` down to one band. The MLO recipe now sends exactly the web UI's 7
  fields (taken from a capture of the BE4800 web page's own requests). `band_select` is no longer
  sent, because it is read-only and the UI never writes it. MLO also requires at least two bands.
- The DMZ "router keeps the address when cleared" quirk was an artifact of the same adapter, and
  has been removed.

### Changed
- `tplinkrouterc6u` is pinned to `>=5.23,<6`, since the fix depends on its class layout.

### Verified live
- BE4800: MLO switched off and on twice through the tool. The Wi-Fi health check passed, per-band
  `disabled_by` was intact, and the wireless-config diff was empty.
- BE4800: every write type previously verified on it was re-run (apply, verify, undo, verify
  restored): 21 runbook operations plus advanced radio settings. The one exception is access
  control, which is off-limits on that router. All 131 `router_get` sections and every tool's read
  actions were swept. The only failures were 2 forms this model doesn't have (`afc`, `eco_mode`;
  it uses `eco_mode_v2`), and those fail identically on the old path.
- The transport fails closed: if a future `tplinkrouterc6u` changes its class layout, requests stop
  with an error instead of falling back to the JSON adapter.
- The BE9300 uses the plain protocol and is not affected.

## 1.0.0 (2026-11-18)
- First public release.
