# opus-tplink-mcp

**A complete, safety-first MCP server for TP-Link Archer routers (Wi-Fi 7 / BE series).**
31 tools covering virtually everything the router's web UI can do. Every change goes through
the same pipeline: **dry run → review → apply → verify → journal → undo**.

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
  More than a dozen firmware quirks found that way are handled for you (see
  [Firmware quirks](#firmware-quirks-handled)). `router_catalog` marks every operation `live`,
  `ui` (from the web UI's code) or `none`.
* **Multi-router.** Manage several routers from one server, including older firmware that uses the
  encrypted LuCI protocol (e.g. Archer BE4800 1.0.x).

## Tools (31)

| Area | Tool | Highlights |
|---|---|---|
| Overview | `router_status` | WAN/LAN, internet state, Wi-Fi, clients, CPU/memory, firmware |
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
| Clients | `clients` | Rename devices, per-device speed limits, IoT network isolation, game accelerator |
| USB | `usb` | Drives and partitions (scan, browse, share/hide a partition, eject), Samba/FTP/SFTP sharing, media server, Time Machine, USB 4G modem |
| DDNS | `ddns` | TP-Link DDNS, No-IP, DynDNS |
| Maintenance | `maintenance` | **Config backup and restore**, firmware (online, image upload, mesh satellites), **ping / traceroute**, operation mode, reboot schedule |
| Admin | `admin` | Admin password (RSA-encrypted like the web UI), remote management, HTTPS, local-management list, recovery e-mail, user permissions |
| System | `system` | **SPI firewall / ping replies**, LEDs, eco mode, time/NTP/DST, auto-update, QoS, device priority, reboot |

Read tools are annotated `readOnlyHint`; write tools are annotated `destructiveHint`.

## How it talks to the router

* **Login:** `tplinkrouterc6u.TplinkRouterV1_11(...).authorize()` (RSA login), or the encrypted
  `TplinkRouter` for older firmware.
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
  result follow. The journal keeps secrets so undo can restore them.
* **Undo:** `router_undo id=...` restores old values, removes inserts, re-adds removed rows and
  swaps updates back. It refuses if the router changed since, unless you pass `force`. Reboots,
  firmware and other one-way actions are not undoable.
* **Secrets** (PSKs, passwords, private/preshared keys, PINs, tokens) are masked in every result,
  diff and error unless you pass `reveal=true`. Account passwords are read from files, never from
  tool arguments.

## Configuration

```bash
python -m venv venv && venv/bin/pip install -e ".[dev]"
cp .env.example .env   # or pass the variables from your MCP client config
```

| Variable | Default | Meaning |
|---|---|---|
| `TPLINK_HOST` | `192.168.0.1` | Router address (`https://...` if it redirects) |
| `TPLINK_PASSWORD` | | The **plain** admin password |
| `TPLINK_TIMEOUT` | `20` | Per-request timeout (s) |
| `TPLINK_JOURNAL_DIR` | `~/.local/state/mcp-tplink-router` | Journal (also the default parent of backups and device logs) |
| `TPLINK_BACKUP_DIR` | `<journal>/backups` | Where `maintenance action=backup` saves config files (mode 600) |
| `TPLINK_DEVICE_LOG_DIR` | `<journal>/device-logs` | Per-MAC histories written by `device_log action=record` |
| `TPLINK_AUTO_BACKUP` | `1` | Download a config backup before every critical change (`0` = off) |
| `TPLINK_PROTECTED_MACS` | | Comma-separated MACs whose VPN-client routing must not break silently (e.g. a filtered child's laptop). Changes affecting them are called out by name. |
| `TPLINK_ALLOW_FORBIDDEN` | unset | `1` lets `router_raw_write` send forbidden-tier operations |

MCP client entry (stdio):

```json
{"command": "/path/to/venv/bin/mcp-tplink-router", "env": {"TPLINK_HOST": "192.168.0.1", "TPLINK_PASSWORD": "..."}}
```

### Several routers

`TPLINK_HOST`/`TPLINK_PASSWORD` is router `main`. To add more:

```
TPLINK_ROUTERS=upstairs
TPLINK_UPSTAIRS_HOST=https://192.168.1.1
TPLINK_UPSTAIRS_PASSWORD_FILE=/path/to/router2.pw
TPLINK_UPSTAIRS_PROTOCOL=encrypted   # older firmware (e.g. BE4800 1.0.x): encrypted LuCI
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
* **MLO network:** off = only `enable=off`. On = the web UI's fields plus `selected_bands` (repeated)
  and `band_select=on`. A malformed MLO write switched MLO off **and made the firmware drop an
  internal per-band field (`disabled_by`)**: Wi-Fi kept working, but every WPS start failed
  ("Interface return exception") until a config restore. Turning MLO back on from off worked on a
  BE9300 but not on a BE4800 (use the web page there).
* **User-permission switches** are accepted but ignored for a normal admin login (`no_effect`).
* **Eco mode** takes `strong` / `medium` / `weak`; DST and the 24-hour clock use `dst_enable` /
  `hour24_enable`.
* **USB sharing** is saved as ONE request (server name + `enable="on,off,off"` for Samba/FTP/FTP-internet);
  per-service saves are refused. The server name can't be written on its own.
* **Fields the router keeps when blanked** (the DMZ address, the custom WAN MAC) don't count as a
  failed restore.
* **TP-Link DDNS** has no refresh operation (it updates itself).

## Known limitations

* `mesh action=pair` is **disabled**. In testing, starting the satellite search and a WPS session in
  the same login locked a BE9300 up badly enough that a factory reset was needed. Pair satellites
  with the router's WPS button, `wifi_extra action=wps_push`, or the web UI.
* `maintenance action=operation_mode` (router ↔ AP/repeater) is implemented but was not switched
  live. With the router connected straight to an ISP box, AP mode can leave it unreachable.
* `usb action=eject` is accepted by the router, but in testing the partitions kept reading as
  mounted until the drive was unplugged, so treat it as "safe to unplug" only after checking.
* **Not yet exercised live** (implemented from the web UI's code, covered by offline tests):
  firmware image upload and online update (no newer firmware was available), Time Machine, DDNS
  login, WPS client-PIN pairing, mesh satellite operations, adding WireGuard server
  accounts (the router refuses the format tried so far), parental-control profile edits and
  operation mode. Operations marked `ui` or `none` in
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
