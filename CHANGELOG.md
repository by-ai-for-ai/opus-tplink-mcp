# Changelog

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
