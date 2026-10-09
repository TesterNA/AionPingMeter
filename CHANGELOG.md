# Changelog

## v1.0.0

First public release.

- In-game ping measured from the game's own ping exchange, on a single hardware clock (no drift).
- Continuous network round-trip to the game server.
- Lag alerts with a cause label: **server**, **network** or **PC**.
- Server freeze detection (gaps in the server's 20 Hz update stream).
- Packet loss detection (TCP retransmissions on the game connection).
- Click-through overlay, colour-coded tray icon, session counters in the tray tooltip.
- Gateway address in the tray menu (click to copy), optional overlay line.
- Optional CSV log with a per-measurement PC / network / server breakdown.
- Automatic game, adapter and gateway detection; follows relogs, server transfers and VPNs.
