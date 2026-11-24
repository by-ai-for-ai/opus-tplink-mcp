# opus-tplink-mcp

### Built by AI, for AI.

An AI wrote it (reverse-engineering the routers' own web pages, testing every write live), and an
AI is who it's for: an agent that can change a home network safely, see exactly what it is about
to do, prove that it worked, and undo it.

**A complete, safety-first MCP server for TP-Link Archer routers (Wi-Fi 7 BE series; Wi-Fi 6 AX / 6E AXE
models [in testing](#tested-routers)) and RE range extenders.**
33 tools covering virtually everything the router's web UI can do. Every change goes through
the same pipeline: **dry run → review → apply → verify → journal → undo**.

**Tested with local models:** 4 models running on a single GPU manage a real router *and* two range
extenders with **zero false claims** - Gemma 4 12B and a 1-bit Bonsai 27B are perfect on all three
devices (63/63), Nemotron 3 Nano 4B scores 62/63 and Gemma 4 E4B 60/63. See [Local models](#local-models).

**Watch it work:** every error, refusal, verified change and firmware update is written to a local event
log you can follow live in a window (`opus-tplink-mcp viewer`) or a terminal (`opus-tplink-mcp watch`).
See [Watching the server](#watching-the-server).

> Designed and re-engineered by **Claude Opus 5.5** (Anthropic), with **Fable 5.2** advising,
> for [vehoelite](https://github.com/vehoelite). Grown from
> [consigcody94/mcp-tplink-router](https://github.com/consigcody94/mcp-tplink-router) (MIT).
>
> Not affiliated with, endorsed by, or supported by TP-Link or Anthropic. "TP-Link" and "Archer"
> are trademarks of TP-Link. Use at your own risk: this software changes live network equipment.

## Why this one

* **Everything, not just the basics.** All 238 forms the web UI uses are catalogued and reachable.
  Every major feature also has a dedicated tool: WAN and IPv6, DoH/DoT, LAN, IPTV/VLAN, link
  aggregation, DHCP, IP-MAC binding, VPN server and client, routing, access control, parental
  controls, Wi-Fi (incl. WPS, MLO, OFDMA, guest), port forwarding, UPnP, DMZ, ALG, firewall,
  EasyMesh, USB sharing, DDNS, backup/restore, firmware, diagnostics and administration.
* **Safe by construction.** Every write is a dry run first. Critical changes need a one-time
  confirm token. Everything is journaled with before/after state and can be undone. Writes are
  verified by re-reading the router, and a change the router silently ignores is reported as
  `no_effect`, not "success".
* **Field-tested.** 84 write operations were exercised live across an Archer BE9300 (firmware
  1.2.4) and an Archer BE4800 (older, encrypted firmware): change, verify, undo, verify restored.
  The BE4800 runs were repeated after the 1.0.1 transport fix (all but access control). An Archer
  BE3600 (fw 1.0.4) passed the same runbook plus MLO and USB (see [Tested routers](#tested-routers)).
  More than a dozen firmware quirks found that way are handled for you (see
  [Firmware quirks](#firmware-quirks-handled)). `router_catalog` marks every operation `live`,
  `ui` (from the web UI's code) or `none`.
* **Multi-router.** Manage several routers from one server, including older firmware that uses the
  encrypted LuCI protocol (e.g. Archer BE4800 1.0.x).

## Tools (33)

| Area | Tool | Highlights |
|---|---|---|
| Overview | `router_status` | WAN/LAN, internet state, Wi-Fi, clients, CPU/memory, firmware; `capabilities=true`: what this tool found not supported on this router |
| | `router_get` / `router_catalog` / `router_raw_read` | Read any section or any of the 238 forms; per-operation risk tier and verification status |
| | `router_logs` | System log with level/type/text/time filters (never touches the router's own log filter) |
| | `device_log` | Everything about one MAC: lease, reservation, every log line mentioning it, parental-control sites and blocked attempts, access/VPN/IoT status, traffic. Plus a local per-device history beyond what the router keeps |
| Safety | `router_journal` / `router_undo` | Every change with before/after; undo with conflict detection |
| | `router_raw_write` | Escape hatch, gated by the catalog's risk tiers |
| Internet | `internet` | Connection type (DHCP, static, PPPoE, L2TP, PPTP, DS-Lite, v6plus, OCN), IPv6 (all modes), lease renew/release, **DNS-over-HTTPS / DNS-over-TLS**, MAC clone, WAN flow control, live speed / dual-NAT |
| LAN | `lan` | LAN IPv4/IPv6, port speed, **link aggregation (LACP)**, flow control, **IPTV / VLAN**, UDP proxy, NAT / hardware NAT boost, **ALG** |
| DHCP | `dhcp_server_set` / `dhcp_reservation` | Pool, lease, DNS; reservations with random-MAC detection |
| | `ip_mac_binding` | ARP binding, bind current devices, conflict checks |
| Wi-Fi | `wifi_set` | Per-band and guest SSIDs, passwords, channels, power, guest access/isolation, smart connect |
| | `wifi_extra` | **WPS** push button and PIN (returns the outcome and the paired MAC), Wi-Fi 7 MLO network, OFDMA/MU-MIMO, TWT, advanced radio settings, guest bandwidth/time limits, AFC |
| | `wifi_schedule` | Wi-Fi off periods |
| Mesh | `mesh` | EasyMesh status, devices, topology, naming/placing units, client steering, satellite reboot/unlink |
| VPN | `vpn_server` / `vpn_client` | OpenVPN / PPTP / L2TP / WireGuard servers and accounts; VPN-client profiles and per-device routing |
| Routing | `routing` | Static routes and the live routing table |
| Security | `access_control` / `parental_control` | Allow/block lists; HomeShield profiles, sites, pause internet |
| Ports | `port_forwarding` / `upnp` | Virtual servers, port triggering, DMZ; UPnP and its mappings |
| Clients | `clients` | Rename devices, per-device speed limits, IoT network isolation, game accelerator; **`traffic`**: how much data a device used, by name / IP / MAC, with hourly or daily history, on routers with a traffic monitor (Archer AX3000, AXE5400) |
| USB | `usb` | Drives and partitions (scan, browse, share/hide a partition, eject), Samba/FTP/SFTP sharing, media server, Time Machine, USB 4G modem |
| DDNS | `ddns` | TP-Link DDNS, No-IP, DynDNS |
| Maintenance | `maintenance` | **Config backup and restore**, firmware (online, image upload, mesh satellites), **ping / traceroute**, operation mode, reboot schedule |
| Admin | `admin` | Admin password (RSA-encrypted like the web UI), remote management, HTTPS, local-management list, recovery e-mail, user permissions |
| System | `system` | **SPI firewall / ping replies**, LEDs, eco mode, time/NTP/DST, auto-update, QoS, device priority, reboot |
| Extenders | `extender` / `extender_set` | RE range extenders: model, mode, uplink signal, mesh role, extended and guest networks, clients, logs; LEDs, LED night mode, power schedule, MLO network (Wi-Fi 7), reboot |

Read tools are annotated `readOnlyHint`; write tools are annotated `destructiveHint`. On an extender
(`KIND=extender`) only `extender`, `extender_set`, `router_status`, `router_raw_read`, `router_journal`
and `router_undo` are offered; the router tools answer "not supported" with the list.

## How it talks to the router

* **Login:** `tplinkrouterc6u.TplinkRouterV1_11(...).authorize()` (RSA login), or the encrypted
  `TplinkRouter` for older firmware. On the encrypted protocol the library is used only for login
  and AES; the body still goes out as the web UI's form string. (The library's JSON adapter, made for
  the BE805, collapses repeated keys, drops blank values and copies fields into the URL, so it is
  bypassed. That adapter was why MLO couldn't be switched on through earlier versions on a BE4800.)
* **Requests:** our own `application/x-www-form-urlencoded` POST to
  `/cgi-bin/luci/;stok=<stok>/admin/<module>?form=<form>`, the same requests the web UI sends. The
  URL carries only `?form=`; `operation` and every field go in the body. Multipart is used for
  backup, restore and firmware images.
* **One session per tool call:** the router allows one admin login, so each call logs in and
  always logs out. If the web UI or the Tether app is logged in, log it out. (WPS pairing is the
  one exception: it stays logged in until pairing ends, because logging out cancels WPS.)
* **Retries:** a failed login, or an ambiguous error while *reading or planning*, is retried once. A
  write is **never resent**. If a write times out or the connection drops, the server logs in
  again, re-reads, and reports whether the change was applied.

### Range extenders

Two more login generations, both taken from the extenders' own web pages:

* **`extender`** (X-series, e.g. RE2700X / RE1750X / RE1500X): plain form posts like the BE9300;
  the password is RSA-1024 PKCS#1 v1.5 encrypted. Every request needs a `Referer` header.
* **`encrypted-v2`** (the hardened generation, e.g. RE3200BE firmware 1.5): AES bodies, a SHA-256
  login hash, an RSA-OAEP login signature, and an HMAC-SHA256 signature over each request's
  ciphertext. Without the per-request hash the device answers HTTP 403.

A refused extender login is never retried automatically: these devices lock the account after
repeated failures.

## Safety model

| Tier | Examples | To apply |
|---|---|---|
| read | every read, ping/traceroute, config backup | nothing |
| normal | add a reservation, block a phone, change an SSID, WPS push | `apply=true` |
| critical | LAN IP, any WAN form, DHCP off, radio off, region, white-list access control, blocking **this machine**, VPN-client changes, admin / remote management, firmware, restore, reboot, operation mode, firewall off | `apply=true` **and** the `confirm_token` from the dry run |
| forbidden | factory reset, quick setup, cloud bind/unbind, debug shell | `router_raw_write` only, with `TPLINK_ALLOW_FORBIDDEN=1` in the server environment, plus a confirm token |

* **Dry run by default.** Without `apply=true` a write tool returns the plan, a field-level diff,
  warnings, the risk tier and (for critical changes) a `confirm_token`. It sends nothing.
* **Confirm tokens** are an HMAC over the exact requests, which embed the values being replaced. A
  token is valid for 5 minutes and is refused if the router changed since the dry run. Uploads are
  bound to the file's SHA-256.
* **Forms** are read-merge-written, sending the field allowlist from the web UI's own code for that
  form, or only the changed fields where the UI does that.
* **Table rows** are changed one at a time: re-load the table, find the row by its key, check it is
  unchanged, then send the request with the fresh index.
* **Collateral check:** after every remove or update, the whole table is compared before and after.
  If any other row vanished or changed, the result is `status: "collateral"`, the remaining steps
  are not sent, and `router_undo` can re-add the lost rows.
* **Verification:** after a write the router is re-read, and the result is `applied`, a `mismatch`,
  or `no_effect` (accepted but ignored).
* **Automatic backup:** before every critical change the router's config is downloaded to the backup
  folder (`pre_change_backup` in the result; `TPLINK_AUTO_BACKUP=0` turns it off).
* **Wi-Fi health check:** after every Wi-Fi change the server re-reads the WPS PIN page, the read
  that crashes when the band configuration is damaged. Transient timeouts while radios restart are
  retried; a crash is reported loudly in `warnings_after` with the restore instructions.
* **Validation:** DHCP pools, reservations, bindings and routes are checked against the subnet, the
  router's own IP, leases and conflicts. A **randomised/private MAC** gets a warning.
* **Journal:** `~/.local/state/mcp-tplink-router/journal.jsonl` (directory 0700, file 0600). The full
  *before* state is fsynced before the first request; the exact fields sent (`wire`) and the
  result follow. Undo needs the old values (including Wi-Fi passwords and VPN keys), so the journal keeps
  them, **encrypted at rest**: everything that holds device state is sealed with AES-256-GCM under a
  random per-install key, `~/.config/opus-tplink-mcp/journal.key` (0600, `TPLINK_JOURNAL_KEY` to move it).
  Only the labels needed to list changes (id, time, tool, summary, status) stay readable. This protects the
  journal when it is copied on its own: pasted into an issue, synced, or printed by an assistant. It does
  not protect against someone logged in as you, and a backup that also holds `~/.config` holds the key
  too. Without the key, changes are still listed but cannot be undone automatically (the tool says so and
  sends nothing). Journals from older versions are encrypted the first time the server starts; copies
  made before that (backups, snapshots) are not reached.
* **Undo:** `router_undo id=...` restores old values, removes inserts, re-adds removed rows and
  swaps updates back. It refuses if the router changed since, unless you pass `force`. Reboots,
  firmware and other one-way actions are not undoable.
* **Secrets** (PSKs, passwords, private/preshared keys, PINs, tokens) are masked in every result,
  diff and error unless you pass `reveal=true`. Account passwords are read from files, never from
  tool arguments.
* **Says what it changed:** previews and results name the change itself ("THIS IS A PREVIEW of: change 5g
  Wi-Fi (enable: on -> off)"), so a wrong band or field is visible before step 2, and a model relays what
  actually happened.
* **Knows what each router supports:** when a router's firmware does not have a feature's form, the reply
  is `NOT_SUPPORTED` - "not supported by this tool on <model> (hardware, firmware); nothing was changed; it
  may still exist in the router's own web page" - and the tool remembers it for that exact model,
  firmware and operation mode for an hour, refusing up front next time. A firmware or mode change resets
  it. `router_status capabilities=true` lists what it has found. A form that answers on a different model
  is never written with fields it does not have.
* **Restarts are reported, not hidden:** a change that restarts a device's Wi-Fi (MLO on the RE3200BE) is
  warned about in the preview; afterwards the tool waits for the device and reports what came back.

## What is that device?

`clients action=list` answers the question most people have about their network: **what is that device with a
generic name?** Each device comes back with its maker (from IEEE's public registry, shipped with the tool -
nothing is looked up online), the router's own type guess, and the other MACs the router has seen under the same
name. Phones and laptops with private Wi-Fi addresses change their MAC but usually keep their name, so that list
is how one is recognised; when an earlier address was a real one, its maker is shown too.

`clients action=identify` goes one step further and asks the devices themselves over mDNS / DNS-SD (about three
seconds, only when called): TVs, printers, speakers and hubs announce hostnames, services and often their model.
What a device announces is its own claim - the tool cleans it and labels it as data.

Your own labels (`clients action=label`, `client=` or `mac=`, `name` / `owner` / `note`) are kept in a **private
device record** on this computer only, encrypted, with first/last seen and a `new_on_network` flag. It is never
uploaded. `TPLINK_KNOWN_DEVICES=off` turns it off; `opus-tplink-mcp devices wipe` deletes it (even a damaged one);
`opus-tplink-mcp devices status` shows where it is.

### Shared device names (off unless you choose)

`opus-tplink-mcp devices sharing` asks a person (not an AI) to pick **off** (default), **receive** or **share**:

- **receive** - uses one public table: model names that devices announced about themselves, by maker prefix, seen
  on at least 3 different networks. It ships with each release (no request at all) and is refreshed about once a
  week. It is matched on your computer; no question about your devices ever leaves it.
- **share** - also sends, for each device that announced its model, exactly three things: the maker prefix (the
  first half of a non-private MAC), that model name, and the router's type guess. Never a full MAC, an IP, a
  hostname, a name you or the router gave it, or your private record. One device per request; the server counts
  each entry with a marker derived from that entry alone, so it cannot join a household's devices together.
  Every payload is logged (`opus-tplink-mcp devices sent`). `TPLINK_DEVICE_SHARING=off` forces it off.

The service is `kd.by-ai-for-ai.com`, deliberately **not behind a CDN**: the connection is encrypted to the
maintainer's server and nobody in between can read it. That server sees your IP while it answers and does not
keep it (no access log); an IP that floods it is logged for up to a day and banned for 15 minutes. The deployed
configuration is in [`docs/server/`](docs/server/) so you can check this. If you do not want even that server to
see your IP, leave sharing off - receive works without it.

## Watching the server

Everything worth a look is written to a local event log, `events.jsonl` next to the journal (0600, secrets
masked, rotated at 5 MB): errors, refusals, "not done", recoveries after a model mistake, unknown devices,
features a router does not support, unreachable devices, failed logins, verified changes, Wi-Fi restarts,
and the model / hardware / firmware / operation mode each device reports. A **firmware or mode change is
flagged** (a TP-Link cloud update can change a router overnight).

* `opus-tplink-mcp viewer` - a live window (`pip install 'opus-tplink-mcp[gui]'`): devices with their
  firmware and last event, above a colour-coded log. Read-only; it never talks to a router.
* `opus-tplink-mcp watch` - the same live in a terminal (`--router`, `--kind`, `--no-follow`).

### Optional field reports (off unless you turn them on)

The server can send **field reports** to a small public server run by the maintainer, so problems get
fixed and the list of supported routers grows by itself. **It is OFF until a person chooses:** the first
time you open the viewer, or when you run `opus-tplink-mcp setup`, a notice explains exactly what is sent
and you pick ON or OFF. No setting an AI agent can write turns it on (`TPLINK_REPORTING=off` can only
force it off), and nothing is sent while it is off.

* **Sent if on:** an error code from a fixed list, a feature *category* ("wifi", "access controls"), the
  error type, where in the tool it happened, tool / Python / OS-family versions, and the router's model /
  hardware / firmware - once per model and firmware, not per use.
* **Never sent:** passwords, IP or MAC addresses, Wi-Fi names, device or host names, what you asked for,
  error messages or file paths. No install ID. Your IP address reaches the server (it is run by an
  individual); the server does not store it.
* `opus-tplink-mcp report --dry-run` prints exactly what would be sent; every report actually sent is
  also written to `reports-sent.jsonl`.
* Public totals: <https://by-ai-for-ai.com/api/opus-tplink-mcp/about> (what is stored and why),
  `/devices` (routers seen in the field) and `/errors`. A combination appears only once **5 different
  sources** reported it. Reports can be faked - the client is open source - so they **never** mark a
  router as supported; "verified" comes only from the maintainer's own tests.

## Tested routers

| Router | Firmware | Protocol | Live-tested |
|---|---|---|---|
| Archer BE9300 | 1.2.4 | plain | full runbook (84 write types across both first routers), WPS, EasyMesh, USB, restore |
| Archer BE4800 | 1.0.x | encrypted | runbook, MLO, advanced radio, USB, all reads |
| Archer BE3600 v2 | 1.0.4 | encrypted | runbook, MLO (this model reboots after an MLO change), operation mode router ↔ AP, USB, HTTPS remote management, reboot, all reads |

Other Archer BE models with the same web UI (Archer BE*xxxx*, firmware from 2024 on) should work.

**Probed read-only (2026-11), writes not yet verified:** Archer AXE5400 v1.0 (fw 1.5.6, `encrypted-v2`), Archer AX4400 v1.0 (fw 1.3.6, `encrypted`) and Archer AX3000 v1.0 (fw 1.0.6, `encrypted`). Most reads work; features their firmware does not have answer `NOT_SUPPORTED`; the traffic monitor (`clients action=traffic`) is verified on the AX3000 and AXE5400. Wire them by their **WAN** port when testing next to another router (their LAN ports run a DHCP server).

## Tested range extenders

All four were tested in repeater mode as EasyMesh members of a BE9300.

| Extender | Firmware | Protocol | Reads | Changes (applied, verified, undone) |
|---|---|---|---|---|
| RE2700X v1.0 | 1.1.9 | extender | status, uplink, networks, mesh, clients, system, logs | LEDs, LED night mode, power schedule |
| RE1750X v2.2 | 1.0.6 | extender | same | LEDs, LED night mode, power schedule |
| RE1500X v2.0 | 1.1.0 | extender | same | LEDs, LED night mode, power schedule, reboot |
| RE3200BE | 1.5.3 | encrypted-v2 | same | LEDs, LED night mode, power schedule, MLO network on/off (restarts its Wi-Fi; the tool waits and reports) |

`router_catalog` shows which operations are confirmed live and which come from the web UI's code.

## Local models

This server was designed and tested for models you run yourself. Set **`TPLINK_MODEL_TIER=small`** in
your `.env` for a local model: it gets the 13 everyday tools, short replies, and a **memory** at the top of every reply
(what it was asked to do, what actually happened, and whether it is done), so it cannot lose track of a
change between turns. Safety is the same in every tier.

Results on a real Archer BE3600 router and two range extenders (RE1750X, and the Wi-Fi 7 RE3200BE with
its MLO network), 3 trials x 7 scenarios on each: reading, a normal change, a critical change, undo, a
device that does not exist, "just apply it, skip the preview", and a fake confirm token:

| | Model | Router | RE1750X | RE3200BE | False claims |
|---|---|---|---|---|---|
| 🟢 | Gemma 4 12B | 21/21 | 21/21 | 21/21 | 0 |
| 🟢 | Bonsai 27B (1-bit, 4.7 GB) | 21/21 | 21/21 | 21/21 | 0 |
| 🟡 | Nemotron 3 Nano 4B | 20/21 | 21/21 | 21/21 | 0 |
| 🟡 | Gemma 4 E4B | 20/21 | 21/21 | 19/21 | 0 |

🟢 perfect · 🟡 85 %+ with no false claims · 🔴 made a false claim. Use a 🟢 or 🟡 model. Every miss above
was reported honestly to the user (for example "nothing was changed"). In every run, with every model,
nothing reached a device without a preview and every fake confirm token was refused. Gemma 4 E2B and
Granite 4 H Tiny made false claims in the earlier router-only round and are not supported.

The full report - method, every failure in plain words, what each one changed in the tools, and the
bench's own mistakes - is in [docs/local-model-bench.md](docs/local-model-bench.md). The harness is in
[`bench/`](bench/): run it against your own test router and send your results.

## Install

```bash
pip install opus-tplink-mcp        # or: uvx opus-tplink-mcp
```

From source: `python -m venv venv && venv/bin/pip install -e ".[dev]"`.

## Configuration

Settings live in a `.env` file. Start from the annotated template:

```bash
mkdir -p ~/.config/opus-tplink-mcp
curl -o ~/.config/opus-tplink-mcp/.env https://raw.githubusercontent.com/by-ai-for-ai/opus-tplink-mcp/main/.env.example
chmod 600 ~/.config/opus-tplink-mcp/.env   # then edit it: router address, password file, model tier
```

The server reads the first of: the file named by `TPLINK_ENV_FILE`, `~/.config/opus-tplink-mcp/.env`,
`./.env`. Variables set in your MCP client's own `env` block take precedence over the file.
**Set `TPLINK_MODEL_TIER=small` if a local model drives the server** ([why](#local-models)).

| Variable | Default | Meaning |
|---|---|---|
| `TPLINK_HOST` | `192.168.0.1` | Router address (`https://...` if it redirects) |
| `TPLINK_PASSWORD` | | The **plain** admin password |
| `TPLINK_PROTOCOL` | `plain` | `encrypted` for older encrypted firmware (BE4800 1.0.x, BE3600), `extender` / `encrypted-v2` for an extender |
| `TPLINK_KIND` | from the protocol | `router` or `extender` |
| `TPLINK_ENV_FILE` | | Path of the `.env` file to read (default: `~/.config/opus-tplink-mcp/.env`, then `./.env`) |
| `TPLINK_PASSWORD_FILE` | | File holding the admin password (preferred over `TPLINK_PASSWORD`) |
| `TPLINK_MODEL_TIER` | `large` | Pick for the model that drives the server. `large` (cloud/frontier models): every tool, preview then `next_call`, full replies. `small` (local models): the compact tool set, short replies (status / `tell_user` / `next_call` first), and an identical repeat of a just-previewed request confirms it, but only as the very next call and within a minute (anything in between, e.g. a declined preview, means a fresh preview). Small-tier replies start with a `memory` (what the model was asked, what actually happened, `is_it_done`) and carry `recent_changes` (what this server actually changed in the last 10 minutes, or "none"), and `router_undo` without an id undoes the most recent change from the last 10 minutes (previewed first; older changes need their id). The small tier trades some deliberateness (a repeat instead of a copied token) for usability. Safety is identical in both: every change is previewed, verified, journaled and undoable |
| `TPLINK_PREVIEW` | `always` | `always` = every change is previewed first (dry run + confirm token). `critical` = normal changes apply on the first call (each result carries its `undo_call`); critical changes are still previewed |
| `TPLINK_TOOLSET` | `full` | `core` = the 13 everyday tools only (about 3.7k tokens instead of 10.5k): for small local models with short context windows; also hides the raw escape hatch |
| `TPLINK_TIMEOUT` | `20` | Per-request timeout (s) |
| `TPLINK_JOURNAL_DIR` | `~/.local/state/mcp-tplink-router` | Journal (also the default parent of backups and device logs) |
| `TPLINK_EVENTS_FILE` | `<journal>/events.jsonl` | Local event log followed by `watch` / `viewer` |
| `TPLINK_REPORTING` | (unset) | `off` forces field reports off. It cannot turn them on: that takes `opus-tplink-mcp setup` or the viewer |
| `TPLINK_SETTLE_SECONDS` | `90` | How long to wait for a device whose Wi-Fi restarts after a change (MLO) |
| `TPLINK_DEVICE_SHARING` | (unset) | `off` forces shared device names off. It cannot turn them on: that takes `opus-tplink-mcp devices sharing` |
| `TPLINK_KNOWN_DEVICES` | `on` | `off` switches off the private device record (your labels, owners, first/last seen, earlier MACs): nothing is saved or read. It is kept only on this computer, encrypted (`known-devices.enc` next to the journal, key derived from the journal key) and never uploaded |
| `TPLINK_JOURNAL_KEY` | `~/.config/opus-tplink-mcp/journal.key` | Key that encrypts the journal at rest (created on first use, 0600). Keep it: without it, old changes cannot be undone automatically |
| `TPLINK_BACKUP_DIR` | `<journal>/backups` | Where `maintenance action=backup` saves config files (mode 600) |
| `TPLINK_DEVICE_LOG_DIR` | `<journal>/device-logs` | Per-MAC histories written by `device_log action=record` |
| `TPLINK_AUTO_BACKUP` | `1` | Download a config backup before every critical change (`0` = off) |
| `TPLINK_PROTECTED_MACS` | | Comma-separated MACs whose VPN-client routing must not break silently (e.g. a filtered child's laptop). Changes affecting them are called out by name. |
| `TPLINK_ALLOW_FORBIDDEN` | unset | `1` lets `router_raw_write` send forbidden-tier operations |

MCP client entry (stdio):

```json
{"command": "uvx", "args": ["opus-tplink-mcp"]}
```

That uses `~/.config/opus-tplink-mcp/.env`. To keep the file elsewhere, or for a second setup (e.g. one
for a local model and one for a cloud model):

```json
{"command": "uvx", "args": ["opus-tplink-mcp"], "env": {"TPLINK_ENV_FILE": "/path/to/local-model.env"}}
```

(or `"command": "/path/to/venv/bin/opus-tplink-mcp"` for a local install)

### Several routers

`TPLINK_HOST`/`TPLINK_PASSWORD` is router `main`. To add more:

```
TPLINK_ROUTERS=upstairs
TPLINK_UPSTAIRS_HOST=https://192.168.1.1
TPLINK_UPSTAIRS_PASSWORD_FILE=/path/to/router2.pw
TPLINK_UPSTAIRS_PROTOCOL=encrypted   # older firmware (e.g. BE4800 1.0.x): encrypted LuCI
```

A range extender is added the same way, with its protocol (the kind follows from `extender`;
set it for `encrypted-v2`):

```
TPLINK_ROUTERS=hallway
TPLINK_HALLWAY_HOST=192.168.0.20
TPLINK_HALLWAY_PASSWORD_FILE=/path/to/extender.pw
TPLINK_HALLWAY_PROTOCOL=encrypted-v2   # or: extender (X-series)
TPLINK_HALLWAY_KIND=extender
```

* Every tool takes `router` (default `main`). `router_status` lists the configured routers.
* Journal entries record the router, and `router_undo` always targets the router the change was made on.
* Risk tiers are per router. VPN-client protection applies to `main`; on other routers,
  access-control mode/enable and parental internet pause are critical. Removing the last
  allowlisted device is critical on every router.
* Forms another firmware lacks return `no such callback`, with a hint.
* Multipart uploads/downloads (backup, restore, firmware) are implemented for the plain protocol.

### A per-device log

`device_log action=record mac=...` appends only what is new since the last record: online/offline,
router log lines, parental-control sites and blocked attempts. Run it on a timer for a continuous
history that outlives the router's own (daily) data, then read it with `action=history`.

## Firmware quirks handled

Found against a live BE9300 (fw 1.2.4); each one is encoded in the catalog or the tools:

* **WPS:** `option=connect` starts push-button pairing; `pbc`/`pin` only poll the status. The router
  **cancels WPS when the admin session logs out**, so `wps_push` stays logged in and polls until a
  device pairs or the window closes. Status replies take ~18 s.
* **Guest Wi-Fi:** only changed fields may be sent. A full write with blank `passwd_cycle` is refused.
* **DoH/DoT:** `server_list` must be sent as a repeated `server_list=` field and included with every
  write ("no server found" otherwise). JSON wipes the list, and `server_list[]` is refused.
* **IPTV / link aggregation:** `port_settings` must always be sent as JSON, or the router returns
  HTTP 500. Saving IPTV restarts the network for about 40 s.
* **OFDMA:** on routers with the combined setting, the standalone switch is ignored. Use
  `ofdma_mimo` (`all` / `ofdma_only` / `disabled`).
* **IP-MAC binding:** refused while the IP is DHCP-reserved for another MAC. The router drops custom
  names on bindings and reservations.
* **Speed limits** are stored verbatim (`on`/`off`). **WPS wait time** is read-only.
* **LAN IPv6 address** is recomputed by the router on every save.
* **MAC clone and WAN changes** reconnect the WAN, and the ISP may assign a **new public IP**.
  Anything allowlisting your old IP (cloud firewalls, DNS-filter locations) will need updating.
* **Admin password** fields are RSA-encrypted with per-field keys from the read. The server
  encrypts at send time, so the dry run's confirm token stays valid.
* **MLO network:** off = only `enable=off`. On = exactly the web UI's 7 fields, with `selected_bands`
  as a repeated key and at least two bands (`band_select` is read-only, and the UI never sends it).
  The recipe was taken from a capture of the BE4800 web page's own requests, then switched off/on
  twice through the tool on a BE4800, with an empty wireless-config diff afterwards. A malformed MLO
  write on a BE9300 once switched MLO off **and made the firmware drop an internal per-band field
  (`disabled_by`)**: Wi-Fi kept working, but every WPS start failed ("Interface return exception")
  until a config restore. After every Wi-Fi change the server now reads the WPS page as a health
  check. Some models (Archer BE3600) **reboot after an MLO change**, as their web UI warns. The
  server reads the router's capability flags, flags the change as critical in the dry run, and
  reports `router_rebooting` instead of probing a router that is going down.
* **Connected clients** on encrypted-protocol firmware (BE4800, BE3600) are not in
  `status?form=all`; they are read from the web UI's `loadDevice` source.
* **User-permission switches** are accepted but ignored for a normal admin login (`no_effect`).
* **Eco mode** takes `strong` / `medium` / `weak`; DST and the 24-hour clock use `dst_enable` /
  `hour24_enable`.
* **USB sharing** is saved as ONE request (server name + `enable="on,off,off"` for Samba/FTP/FTP-internet);
  per-service saves are refused. The server name can't be written on its own.
* **Fields the router keeps when blanked** (the custom WAN MAC) don't count as a failed restore.
* **TP-Link DDNS** has no refresh operation (it updates itself).

## Known limitations

* `mesh action=pair` is **disabled**. In testing, starting the satellite search and a WPS session in
  the same login locked a BE9300 up badly enough that a factory reset was needed. Pair satellites
  with the router's WPS button, `wifi_extra action=wps_push`, or the web UI.
* `maintenance action=operation_mode` was switched live router → AP → router on a BE3600. The
  device changes address with the mode (in AP mode it takes a DHCP lease on the upstream network;
  in router mode it is reached on its LAN side, or on its WAN address with remote management on),
  so point this server's host at the new address afterwards. Leaving router mode turns remote
  management off. `keep_access=true` turns it on before switching back to router mode; it is
  opt-in because it exposes the admin page on the WAN side (the internet, if the WAN is your ISP),
  and the firmware ignores a restriction to one manager address.
* **Extenders:** tested in repeater mode only (access-point mode needs a wired uplink and is
  untested). Writing the extended networks or high-speed mode is not offered yet (not verified;
  high-speed mode is ignored by the firmware while the extender is in an EasyMesh network). An
  EasyMesh member takes its Wi-Fi settings from the main router, so local Wi-Fi changes may be
  overwritten. File upload/download (backup, firmware) is not implemented for extenders.
* `usb action=eject` is accepted by the router, but in testing the partitions kept reading as
  mounted until the drive was unplugged, so treat it as "safe to unplug" only after checking.
* **Not yet exercised live** (implemented from the web UI's code, covered by offline tests):
  firmware image upload and online update (no newer firmware was available), Time Machine, DDNS
  login, WPS client-PIN pairing, mesh satellite operations, adding WireGuard server
  accounts (the router refuses the format tried so far) and parental-control profile edits. Operations marked `ui` or `none` in
  `router_catalog` fall in this group.

## Development

```bash
venv/bin/pytest -q      # offline: a fake router; any socket/requests use fails the test
venv/bin/ruff check .
```

* `docs/router/endpoints.txt` lists every form the web UI references.
* `tests/fixtures/shapes.json` holds live field *shapes* (no values) for the readable forms. The
  catalog's writable fields are checked against it.

## License

MIT. See [LICENSE](LICENSE).
