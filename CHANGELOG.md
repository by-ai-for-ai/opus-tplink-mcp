# Changelog

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
