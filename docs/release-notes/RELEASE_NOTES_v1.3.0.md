# NetScout v1.3.0 — Switch X-ray

This release is for anyone running a real network with managed switches: NetScout can now **see inside
your switch** — not just whether a cable is healthy, but **which device is plugged into every port**.

## New — Switch X-ray
The old **CABLE TEST** grows up into **SWITCH X-RAY**. Point it at a managed switch (the **SWITCH** box,
or leave it blank to use your gateway) and one read-only SNMP read gives you the whole switch:

- **Cable health** — every port judged from the counters the switch keeps anyway, flagging the gigabit
  port quietly linking at 100 Mbit because a pair is broken, frames corrupted in transit (FCS errors),
  and ports worth a re-seat. (This is the old CABLE TEST, unchanged.)
- **A port map** — **which device is on each port**, resolved to a name from your current scan (so you
  read *"Leon-ThinkPad on Gi1/0/3"*, not a bare port number), with its **VLAN**, and its MAC vendor when
  the device wasn't in the scan. Trunk/uplink ports — the ones that have learned the whole network beyond
  them — are detected and flagged so they don't drown the endpoints.

It's built on the forwarding table the switch already keeps (dot1q, VLAN-aware, with the classic dot1d
table as a fallback), it's **read-only** — NetScout only asks the switch, never changes it — and it needs
no admin rights, no packet capture, and works identically on Windows, macOS and Linux.

## Fixed
- **The reaper's left hand** no longer hangs crooked — it's been redrawn to fall naturally from the
  sleeve, matching the scythe hand's style, everywhere the mascot appears (the app and the PDFs).

## Under the hood
- New engine: `switch_portmap` (the port map), `portmap_lines` (its readable form), `_fdb_entries`
  (decodes MAC + VLAN out of the forwarding-table OIDs) — all read-only, all offline-tested.
- The port map reuses CABLE TEST's interface read instead of walking the switch twice.
- **Bug audit:** the full suite (now **59 test files**) and the undefined-reference check are green, and a
  sweep for the usual defect patterns (bare excepts, mutable default arguments, identity-vs-equality
  mix-ups) came back clean.
- A quick note on **power control:** it's already comprehensive and stays as-is — per-device switch-port
  cutoff (DISCONNECT), whole-switch emergency lockdown, local-firewall blocking, and credentialed power
  (Windows/WinRM/SSH/IPMI + Wake-on-LAN). NetScout still never force-powers-off a device it has no rights
  over; containment is done through gear you control, reversibly.

## Still open source
NetScout remains free and open source under the **GNU AGPL v3** — see `LICENSE`.

## Downloads
| Platform | File |
|---|---|
| Windows | `Windows - NetScout Build v1.3.0.zip` (build with `build_windows.bat` + Inno Setup) |
| macOS | `macOS - NetScout Build v1.3.0.zip` (build with `build_macos.sh`) |
| Linux | `Linux - NetScout Build v1.3.0.zip` — includes the ready-to-install `netscout_1.3.0_all.deb` |
