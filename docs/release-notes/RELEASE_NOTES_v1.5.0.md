# NetScout v1.5.0 — Reporting, Accountability & Scale

This release makes NetScout feel built for a team running a real, multi-VLAN network: an **emailable weekly
health report**, a complete **action audit log**, **multi-subnet scanning with saved profiles**, and
**sharper device identification**. Two new tools bring the count to **36**.

## New — Weekly Health Report (emailable, schedulable)
A branded, one-look summary of the network's health:

- **How many devices**, by type, and an overall **A–F grade** (worst-risk-wins — one critical device is an F).
- The **risks worst-first**, each with its reason.
- **What changed since last week** — new and gone devices, matched by MAC so a device that just changed IP
  isn't counted as both.

Press RUN to build it, **SAVE HTML** to keep it, or **EMAIL IT NOW** to send it with your Guardian email
settings. **SCHEDULE WEEKLY** prints the one command that makes this PC email it every week on its own — the
built app now accepts `wreport` on the command line and runs headless, so **NetScout doesn't need to be
open** for the weekly report to go out.

## New — Action Log (accountability trail)
A defensive tool that can shut machines down, cut switch ports, push power policies and block hosts should
keep a record of it. **ACTION LOG** is an append-only trail of **every state-changing action** NetScout
sends — **who** ran it, **when**, the **exact command**, and **whether it worked**. It records what NetScout
*did*, never what it merely read, pairs naturally with v1.4.0's "exact command before it runs" previews, and
**EXPORT** saves a copy for your records.

## New — Scan your whole site, not just one LAN
- **Multi-subnet scanning** — the DEVICE SCAN tool gains a **SITES** field: list several networks
  (`10.0.1.0/24, 10.0.2.0/24, …`) and NetScout sweeps them all in one run, merged into one table with a new
  **SITE** column tagging each device with the network it was found on.
- **Saved scan profiles** — save a set of networks (plus the SHOW filter) as a named **profile** —
  "Server VLAN", "Guest WiFi" — and pick it with LOAD instead of retyping ranges.

## Improved — sharper device identification (fewer "Unknown" rows)
The MAC-vendor lookup now understands IEEE's **shared small blocks**. A prefix that resolves only to the
generic *"IEEE Registration Authority"* holder (the owner of a sub-divided MA-M/MA-S block, not the device
maker) is no longer shown as a misleading vendor — so other signals (mDNS, hostname, ports) identify the
device instead, and more rows get a real name. The lookup also prefers a more-specific 28-bit/36-bit match
when the data has one. All six places NetScout resolved a vendor now go through one hardened function.

## Under the hood
- New engine: `health_report` / `health_report_lines` / `health_report_html` (pure; reuse the branded report
  renderer), `send_report_email` (HTML + attachment, sharing one SMTP layer with the Guardian's alert mail),
  `weekly_schedule_command`; `audit_log` / `audit_entries` / `audit_log_lines` wired into every action
  (`remote_power`, `apply_power_policy`, `firewall_block_host`, `set_device_port`, `switch_lockdown`);
  `scan_sites` / `parse_networks` and a `profiles_*` store; `vendor_of`. A new `wreport` CLI subcommand, and
  the GUI binary now forwards CLI subcommands so the built app is dual GUI/CLI.
- **Faster where it counts:** reverse-DNS is now cached for the session (carried over from the v1.4.x polish),
  so Live Monitor / Background Watch stop re-querying the resolver every cycle.
- **36 tools** now (HEALTH REPORT + ACTION LOG); the window's tool count is computed live.
- The reaper reacts to the two new tools as well (calm "watching" motion for the report/log views).
- **Bug sweep:** the full suite (now **67 test files**) and the undefined-reference check are green, and a
  sweep for the usual defect patterns (bare excepts, mutable default arguments, identity-vs-equality mix-ups,
  `shell=True`, unbounded subprocess timeouts) came back clean.
- **Still defensive-only, still credentialed, still reversible.** The audit log and the reports only make the
  existing, consented actions more transparent.

## Still open source
NetScout remains free and open source under the **GNU AGPL v3** — see `LICENSE`.

## Downloads
| Platform | File |
|---|---|
| Windows | `Windows - NetScout Build v1.5.0.zip` (build with `build_windows.bat` + Inno Setup) |
| macOS | `macOS - NetScout Build v1.5.0.zip` (build with `build_macos.sh`) |
| Linux | `Linux - NetScout Build v1.5.0.zip` — includes the ready-to-install `netscout_1.5.0_all.deb` |
