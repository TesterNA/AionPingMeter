# Changelog

## v1.0.2

- New overlay look: a compact rounded capsule with signal bars, ping, NET and MAX.
- Alerts now appear as a separate pill under the overlay (red at first, then orange), and the cause reads `ping 1200 server` instead of `ping 1200 (server)`.
- Real per-pixel transparency and smooth rounded corners; the overlay uses the Bahnschrift font built into Windows.

## v1.0.1

- Two downloads: **standalone** (everything built in, nothing to install except Npcap) and **light** (tiny, needs the .NET 8 Desktop Runtime).
- Both are now a single `AionPingMeter.exe` instead of several files.
- Release notes and README explain which one to pick, in English, Ukrainian and Russian.

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
