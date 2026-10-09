// AionPingMeter — a lightweight ping meter for Aion 2 (Global).
//
// How ping is measured:
//   The game client sends the server a ping carrying its own timestamp = QPC in ms + 16 777 216 000,
//   and the server echoes it back in a packet with opcode 0x0336. We capture that reply via Npcap
//   and compute   ping = QPC_at_packet_arrival − QPC_from_packet.
//   Both values come from the same hardware timer (QueryPerformanceCounter); the Windows
//   system clock is never used, so clock corrections cannot introduce an offset.
//
// The program only reads AION2.exe traffic and never sends anything anywhere.

using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace AionPingMeter;

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        string npcapDir = Path.Combine(Environment.SystemDirectory, "Npcap");
        if (Directory.Exists(npcapDir))
            Native.SetDllDirectory(npcapDir);

        if (args.Length > 0 && args[0] == "--gaps")
            return Probe.Gaps(args.Length > 1 ? int.Parse(args[1]) : 60);

        if (args.Length > 0 && args[0] == "--probe")
            return Probe.Run(args.Length > 1 ? int.Parse(args[1]) : 20);

        using var mutex = new Mutex(true, "AionPingMeter.Aion2.SingleInstance", out bool first);
        if (!first) return 0;

        ApplicationConfiguration.Initialize();
        var stats = new PingStats();
        using var captures = new CaptureManager(stats);
        Application.Run(new OverlayForm(stats));
        return 0;
    }
}

// ───────────────────────────── statistics ─────────────────────────────

sealed class PingStats
{
    // The game sends a ping every ~10 s.
    public const int WindowMs = 60_000;   // window for the in-game ping median/max
    public const int StaleMs = 25_000;    // no new samples for longer than this — show "—"

    readonly object _lock = new();
    readonly Queue<(long At, double Rtt)> _samples = new();
    (long At, double Rtt) _last = (long.MinValue, 0);
    StreamWriter? _log;

    public long Packets;
    public long Pings;
    public volatile string Status = "starting…";
    /// <summary>The connection the game's ping was found on (server ip/port).</summary>
    public (uint Ip, int Port)? GameEndpoint
    {
        get => _gameEndpoint;
        set
        {
            // Count how many times pings started arriving from a different gateway (the first one after start is not a change).
            if (value is { } v)
            {
                if (_lastGateway is { } last && last != v) Interlocked.Increment(ref GatewayChanges);
                _lastGateway = v;
            }
            _gameEndpoint = value;
        }
    }
    (uint Ip, int Port)? _gameEndpoint, _lastGateway;
    public long GatewayChanges;

    /// <summary>Address of the game gateway the client is connected to, e.g. "203.0.113.42:12000".</summary>
    public string? GameEndpointText =>
        GameEndpoint is { } e ? $"{new IPAddress(e.Ip)}:{e.Port}" : null;

    public long MsSinceLastPing
    {
        get { lock (_lock) return _last.At == long.MinValue ? long.MaxValue : Environment.TickCount64 - _last.At; }
    }
    public volatile string Debug = "";

    /// <param name="pcMs">How long the request sat on the PC before being sent (if it could be determined).</param>
    public void Add(double rtt, double? pcMs)
    {
        long now = Environment.TickCount64;
        lock (_lock)
        {
            Trim(now);
            // Breakdown: PC (before sending) + network (current TCP RTT) + server (the rest).
            double pc = pcMs ?? 0;
            double net = _tcp.Count > 0 ? _tcp.Min(t => t.Rtt) : 0;
            double server = Math.Max(0, rtt - pc - net);
            string cause = pc >= net && pc >= server ? "PC" : net >= server ? "network" : "server";
            DetectGameSpike(now, rtt, cause);
            _last = (now, rtt);
            _samples.Enqueue(_last);
            Trim(now);
            _log?.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff},{rtt:F1},{(pcMs is double p ? p.ToString("F1") : "")},{net:F1},{server:F1},{GameEndpointText}");
        }
        Interlocked.Increment(ref Pings);
    }

    // ── continuous TCP RTT (network round-trip) ──
    readonly Queue<(long At, double Rtt)> _tcp = new();
    public long TcpSamples;

    public void AddTcp(double rtt)
    {
        long now = Environment.TickCount64;
        lock (_lock)
        {
            DetectNetworkSpike(now, rtt);
            _tcp.Enqueue((now, rtt));
            while (_tcp.Count > 0 && now - _tcp.Peek().At > 2000) _tcp.Dequeue();
        }
        Interlocked.Increment(ref TcpSamples);
    }

    // ── spikes ──
    public const int SpikeShowMs = 60_000;    // how long a spike stays on screen
    public const int SpikeFlashMs = 10_000;   // how long it is highlighted in red
    const double JumpRatio = 1.6, JumpMinMs = 40;

    public volatile int ThresholdMs = 100;
    readonly List<Spike> _spikes = new();
    readonly Queue<double> _netSecondMins = new();   // min RTT for each second, last 60
    long _netSecond = -1;
    double _netSecondMin;

    public enum SpikeKind { Game, Network, Loss, Freeze }
    public readonly record struct Spike(long At, double Value, SpikeKind Kind, string? Cause = null);

    /// <summary>Problems in the last minute: the worst of each kind and ms since the most recent one.</summary>
    public readonly record struct SpikeSummary(double? GameMax, string? GameCause, double? NetworkMax, int Losses, double? FreezeMax, long SinceLastMs);

    public long Losses;

    /// <summary>Diagnostics: timestamps of data packets on the game connection (--gaps mode only).</summary>
    public System.Collections.Concurrent.ConcurrentQueue<(double At, bool Inbound, int Len)>? Trace;

    /// <summary>A retransmission on the game connection = a lost packet.</summary>
    public long Freezes;

    /// <summary>
    /// The server sends data every 50 ms (20 Hz tick). A gap longer than FreezeMs with no data at all is a freeze
    /// (the server stalled, even if the network is fine).
    /// </summary>
    public const double FreezeMs = 200;

    public void AddFreeze(double gapMs)
    {
        long now = Environment.TickCount64;
        lock (_lock)
        {
            _spikes.Add(new Spike(now, gapMs, SpikeKind.Freeze));
            _log?.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff},freeze,{gapMs:F0},,,,{GameEndpointText}");
        }
        Interlocked.Increment(ref Freezes);
    }

    public void AddLoss()
    {
        long now = Environment.TickCount64;
        lock (_lock) _spikes.Add(new Spike(now, 0, SpikeKind.Loss));
        Interlocked.Increment(ref Losses);
    }

    /// <summary>In-game ping above the threshold or sharply above normal (median of the last minute).</summary>
    void DetectGameSpike(long now, double rtt, string cause)
    {
        double baseline = 0;
        if (_samples.Count >= 3)
        {
            var a = _samples.Select(x => x.Rtt).Order().ToArray();
            baseline = a[a.Length / 2];
        }
        bool jump = baseline > 0 && rtt >= baseline * JumpRatio && rtt - baseline >= JumpMinMs;
        if (rtt >= ThresholdMs || jump)
            _spikes.Add(new Spike(now, rtt, SpikeKind.Game, cause));
    }

    /// <summary>
    /// Network: take the min RTT of each second (it is unaffected by delayed ACKs).
    /// If a second ended noticeably above the usual minimum, that is a network spike.
    /// </summary>
    void DetectNetworkSpike(long now, double rtt)
    {
        long sec = now / 1000;
        if (sec == _netSecond)
        {
            if (rtt < _netSecondMin) _netSecondMin = rtt;
            return;
        }
        if (_netSecond >= 0)
        {
            double done = _netSecondMin;
            if (_netSecondMins.Count >= 5)
            {
                double baseline = _netSecondMins.Min();
                if (done - baseline >= JumpMinMs || done >= ThresholdMs)
                    _spikes.Add(new Spike(now, done, SpikeKind.Network));
            }
            _netSecondMins.Enqueue(done);
            if (_netSecondMins.Count > 60) _netSecondMins.Dequeue();
        }
        _netSecond = sec;
        _netSecondMin = rtt;
    }

    public SpikeSummary? SpikeSnapshot()
    {
        long now = Environment.TickCount64;
        lock (_lock)
        {
            _spikes.RemoveAll(x => now - x.At > SpikeShowMs);
            if (_spikes.Count == 0) return null;
            double? Max(SpikeKind k) => _spikes.Any(x => x.Kind == k) ? _spikes.Where(x => x.Kind == k).Max(x => x.Value) : null;
            var worstGame = _spikes.Where(x => x.Kind == SpikeKind.Game).OrderByDescending(x => x.Value).FirstOrDefault();
            return new SpikeSummary(Max(SpikeKind.Game), worstGame.Cause, Max(SpikeKind.Network),
                _spikes.Count(x => x.Kind == SpikeKind.Loss), Max(SpikeKind.Freeze), now - _spikes[^1].At);
        }
    }

    /// <summary>Min and median TCP RTT over the last 2 seconds.</summary>
    public (double? Min, double? Median) TcpSnapshot()
    {
        long now = Environment.TickCount64;
        lock (_lock)
        {
            while (_tcp.Count > 0 && now - _tcp.Peek().At > 2000) _tcp.Dequeue();
            if (_tcp.Count == 0) return (null, null);
            var a = _tcp.Select(t => t.Rtt).Order().ToArray();
            return (a[0], a[a.Length / 2]);
        }
    }

    public (double? Current, double Median, double Max) Snapshot()
    {
        long now = Environment.TickCount64;
        lock (_lock)
        {
            Trim(now);
            if (_samples.Count == 0 || now - _last.At > StaleMs)
                return (null, 0, 0);
            var sorted = new double[_samples.Count];
            int i = 0;
            foreach (var s in _samples) sorted[i++] = s.Rtt;
            Array.Sort(sorted);
            return (_last.Rtt, sorted[sorted.Length / 2], sorted[^1]);
        }
    }

    public string? SetLogging(bool enabled)
    {
        lock (_lock)
        {
            _log?.Dispose();
            _log = null;
            if (!enabled) return null;
            string path = Path.Combine(Settings.Dir, "ping-log.csv");
            bool fresh = !File.Exists(path) || new FileInfo(path).Length == 0;
            _log = new StreamWriter(path, append: true, Encoding.UTF8) { AutoFlush = true };
            if (fresh) _log.WriteLine("time,ping_ms,pc_ms,network_ms,server_ms,gateway");
            return path;
        }
    }

    void Trim(long now)
    {
        while (_samples.Count > 0 && now - _samples.Peek().At > WindowMs)
            _samples.Dequeue();
    }
}

// ───────────────────────────── packet parsing ─────────────────────────────

static class PingParser
{
    // Client clock on Global: QPC in ms + 2^24 s.
    public const long ClientClockBase = 16_777_216_000L;
    const long ClientClockLimit = 62_135_596_800_000L;   // above this it is UTC (KR/TW), not our format
    const double MaxRttMs = 3000;

    static ReadOnlySpan<byte> Signature => [0x03, 0x36, 0x00, 0x00];   // opcode 822 + 00 00

    /// <summary>
    /// Looks for ping replies in a TCP payload; calls onPing(sent_at_ms, rtt) for each new one.
    /// Returns true if at least one was found.
    /// </summary>
    public static bool Scan(ReadOnlySpan<byte> payload, double arrivalQpcMs, RecentSet seen, Action<double, double> onPing)
    {
        bool found = false;
        int pos = 0;
        while (true)
        {
            int idx = payload[pos..].IndexOf(Signature);
            if (idx < 0) return found;
            int at = pos + idx;
            pos = at + 1;
            if (at + 12 > payload.Length) return found;

            long stamp = BinaryPrimitives.ReadInt64LittleEndian(payload.Slice(at + 4, 8));
            if (stamp < ClientClockBase || stamp >= ClientClockLimit) continue;

            double rtt = arrivalQpcMs + ClientClockBase - stamp;
            if (rtt < 0 || rtt > MaxRttMs) continue;
            found = true;
            if (!seen.Add(stamp)) continue;   // TCP retransmission of the same reply

            onPing(stamp - ClientClockBase, rtt);
        }
    }

    /// <summary>Parses a TCP segment in a frame (Ethernet / loopback / raw IP).</summary>
    public static bool TryParseTcp(ReadOnlySpan<byte> frame, int linkType, out TcpSegment seg)
    {
        seg = default;
        int ip;
        switch (linkType)
        {
            case 1: // Ethernet
                if (frame.Length < 14) return false;
                ip = 14;
                int etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(12, 2));
                if (etherType == 0x8100 && frame.Length >= 18)
                {
                    etherType = BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(16, 2));
                    ip = 18;
                }
                if (etherType != 0x0800 && etherType != 0x86DD) return false;
                break;
            case 0: // Npcap loopback (BSD null)
                ip = 4;
                break;
            case 12: case 14: case 101: // raw IP (some VPN adapters)
                ip = 0;
                break;
            default:
                return false;
        }
        if (frame.Length < ip + 20) return false;

        int version = frame[ip] >> 4;
        int tcp, ipEnd;
        uint src = 0, dst = 0;
        if (version == 4)
        {
            int ihl = (frame[ip] & 0x0F) * 4;
            if (frame[ip + 9] != 6 || ihl < 20) return false;
            ipEnd = ip + BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ip + 2, 2));
            tcp = ip + ihl;
            src = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(ip + 12, 4));   // same byte order as IPAddress.GetAddressBytes()
            dst = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(ip + 16, 4));
        }
        else if (version == 6)
        {
            if (frame.Length < ip + 40 || frame[ip + 6] != 6) return false;
            ipEnd = ip + 40 + BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(ip + 4, 2));
            tcp = ip + 40;
        }
        else return false;

        // Frames with hardware segment coalescing (LSO/RSC) may have total length = 0.
        if (ipEnd <= tcp || ipEnd > frame.Length) ipEnd = frame.Length;
        if (tcp + 20 > ipEnd) return false;

        int payload = tcp + (frame[tcp + 12] >> 4) * 4;
        seg = new TcpSegment(
            src, dst,
            BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(tcp, 2)),
            BinaryPrimitives.ReadUInt16BigEndian(frame.Slice(tcp + 2, 2)),
            BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(tcp + 4, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(frame.Slice(tcp + 8, 4)),
            (frame[tcp + 13] & 0x10) != 0,
            payload,
            Math.Max(0, ipEnd - payload));
        return true;
    }
}

readonly record struct TcpSegment(uint SrcIp, uint DstIp, int SrcPort, int DstPort, uint Seq, uint Ack, bool HasAck, int PayloadOffset, int PayloadLength);

/// <summary>
/// Continuous RTT of the game connection: time from our data segment to the server ACK
/// that covers it (both timestamps from the same driver). Retransmissions are skipped (Karn's algorithm).
/// </summary>
sealed class TcpRttTracker
{
    readonly Queue<(uint SeqEnd, double SentMs)> _inFlight = new();
    uint _highestSent, _highestReceived;
    bool _sentStarted, _receivedStarted;

    /// <returns>true if this is a retransmission (our data was lost).</returns>
    public bool OnOutbound(in TcpSegment s, double atMs)
    {
        if (s.PayloadLength == 0) return false;
        uint end = s.Seq + (uint)s.PayloadLength;
        if (_sentStarted && (int)(end - _highestSent) <= 0)
        {
            _inFlight.Clear();   // retransmission — this data no longer gives an honest sample
            return s.PayloadLength > 1;   // 0–1 bytes is a keep-alive, not a loss
        }
        _sentStarted = true;
        _highestSent = end;
        if (_inFlight.Count < 512) _inFlight.Enqueue((end, atMs));
        return false;
    }

    /// <returns>true if the server re-sent data we already had (its packet or our ACK was lost).</returns>
    public bool IsInboundRetransmit(in TcpSegment s)
    {
        if (s.PayloadLength <= 1) return false;
        uint end = s.Seq + (uint)s.PayloadLength;
        if (_receivedStarted && (int)(end - _highestReceived) <= 0) return true;
        _receivedStarted = true;
        _highestReceived = end;
        return false;
    }

    /// <returns>RTT in ms, or null if this ACK acknowledged nothing new.</returns>
    public double? OnInbound(in TcpSegment s, double atMs)
    {
        if (!s.HasAck) return null;
        double? sent = null;
        while (_inFlight.Count > 0 && (int)(s.Ack - _inFlight.Peek().SeqEnd) >= 0)
            sent = _inFlight.Dequeue().SentMs;   // newest acknowledged segment — least affected by delayed ACK
        return sent is double t ? atMs - t : null;
    }
}

/// <summary>The last few timestamps, so TCP retransmissions are not counted twice.</summary>
sealed class RecentSet(int capacity)
{
    readonly long[] _ring = new long[capacity];
    readonly HashSet<long> _set = new(capacity);
    int _next;

    public bool Add(long value)
    {
        if (!_set.Add(value)) return false;
        if (_set.Count > capacity) _set.Remove(_ring[_next]);
        _ring[_next] = value;
        _next = (_next + 1) % capacity;
        return true;
    }
}

/// <summary>
/// Converts an Npcap timestamp to the QPC timescale.
/// The offset between them = min(QPC_received − Npcap_timestamp) over the last 5 seconds:
/// the minimum corresponds to packets delivered without delay, so the driver timestamp
/// precision is kept, and the sliding window prevents drift or a stale offset from building up.
/// </summary>
sealed class ClockCalibrator
{
    const int Buckets = 5;
    readonly double[] _min = new double[Buckets];
    readonly long[] _second = Enumerable.Repeat(-1000L, Buckets).ToArray();

    public double ToQpcMs(double npcapMs, double receivedQpcMs)
    {
        double delta = receivedQpcMs - npcapMs;
        long sec = (long)(receivedQpcMs / 1000);
        int i = (int)(sec % Buckets);
        if (_second[i] != sec) { _second[i] = sec; _min[i] = delta; }
        else if (delta < _min[i]) _min[i] = delta;

        double offset = double.MaxValue;
        for (int k = 0; k < Buckets; k++)
            if (sec - _second[k] < Buckets && _min[k] < offset) offset = _min[k];
        return npcapMs + offset;
    }
}

// ───────────────────────────── capture ─────────────────────────────

readonly record struct GameConnection(IPAddress Local, IPAddress Remote, int RemotePort);

/// <summary>Every few seconds finds AION2.exe connections and keeps capture limited to them.</summary>
sealed class CaptureManager : IDisposable
{
    const int RefreshMs = 4000;

    readonly PingStats _stats;
    readonly Dictionary<string, DeviceCapture> _captures = new();
    readonly System.Threading.Timer _timer;
    readonly object _gate = new();
    string _lastSignature = "";

    public CaptureManager(PingStats stats)
    {
        _stats = stats;
        _timer = new System.Threading.Timer(_ => Refresh(), null, 0, RefreshMs);
    }

    void Refresh()
    {
        if (!Monitor.TryEnter(_gate)) return;
        try
        {
            var conns = GameConnections.Find();
            if (conns.Count == 0)
            {
                StopAll();
                _lastSignature = "";
                _stats.Status = "game not found";
                return;
            }

            // Once we know which connection carries the game's ping, listen to that one only.
            // If there has been no ping on it for a while (the game moved to another server but kept the old connection),
            // forget it and listen to all game connections again.
            if (_stats.GameEndpoint != null && _stats.MsSinceLastPing > PingStats.StaleMs)
                _stats.GameEndpoint = null;
            var game = _stats.GameEndpoint;
            if (game is { } g && conns.Any(c => IsEndpoint(c, g)))
                conns = conns.Where(c => IsEndpoint(c, g)).ToList();

            string signature = string.Join(";", conns.Select(c => $"{c.Local}>{c.Remote}:{c.RemotePort}").Order());
            bool allAlive = _captures.Count > 0 && _captures.Values.All(c => c.Alive);
            if (signature == _lastSignature && allAlive) return;
            _lastSignature = signature;

            var devices = Pcap.ListDevices();
            var wanted = new Dictionary<string, List<GameConnection>>();
            foreach (var c in conns)
            {
                string? device = IPAddress.IsLoopback(c.Remote)
                    ? devices.Keys.FirstOrDefault(n => n.Contains("Loopback", StringComparison.OrdinalIgnoreCase))
                    : devices.FirstOrDefault(d => d.Value.Contains(c.Local)).Key;
                if (device == null) continue;
                if (!wanted.TryGetValue(device, out var list)) wanted[device] = list = new();
                list.Add(c);
            }

            foreach (var name in _captures.Keys.Except(wanted.Keys).ToList())
            {
                _captures[name].Stop();
                _captures.Remove(name);
            }

            if (wanted.Count == 0)
            {
                _stats.Status = "adapter not found";
                _lastSignature = "";
                return;
            }

            foreach (var (device, list) in wanted)
            {
                // Only game connection traffic — the driver drops everything else.
                string filter = "tcp and (" + string.Join(" or ",
                    list.Select(c => $"(host {c.Remote} and port {c.RemotePort})").Distinct()) + ")";
                var remotes = list.Select(c => (Ip: Pcap.ToRaw(c.Remote), Port: c.RemotePort)).ToHashSet();
                if (_captures.TryGetValue(device, out var cap) && cap.Alive)
                    cap.SetTarget(filter, remotes);
                else
                    _captures[device] = new DeviceCapture(device, filter, remotes, _stats);
            }
            _stats.Status = "waiting for ping…";
        }
        catch (Exception ex)
        {
            _stats.Status = "error: " + ex.Message;
        }
        finally
        {
            Monitor.Exit(_gate);
        }
    }

    static bool IsEndpoint(GameConnection c, (uint Ip, int Port) e) => Pcap.ToRaw(c.Remote) == e.Ip && c.RemotePort == e.Port;

    void StopAll()
    {
        foreach (var c in _captures.Values) c.Stop();
        _captures.Clear();
    }

    public void Dispose()
    {
        _timer.Dispose();
        lock (_gate) StopAll();
    }
}

sealed class DeviceCapture
{
    static readonly double MsPerTick = 1000.0 / Stopwatch.Frequency;

    readonly string _device;
    readonly PingStats _stats;
    readonly Thread _thread;
    volatile Target _target;
    volatile bool _stop;

    sealed record Target(string Filter, HashSet<(uint Ip, int Port)> Remotes);

    public DeviceCapture(string device, string filter, HashSet<(uint Ip, int Port)> remotes, PingStats stats)
    {
        _device = device;
        _target = new Target(filter, remotes);
        _stats = stats;
        _thread = new Thread(Run) { IsBackground = true, Name = "capture", Priority = ThreadPriority.AboveNormal };
        _thread.Start();
    }

    public bool Alive => _thread.IsAlive;
    public void SetTarget(string filter, HashSet<(uint Ip, int Port)> remotes) => _target = new Target(filter, remotes);

    public void Stop()
    {
        _stop = true;
        _thread.Join(1000);
    }

    void Run()
    {
        var err = new StringBuilder(512);
        IntPtr p = Pcap.pcap_create(_device, err);
        if (p == IntPtr.Zero) { _stats.Status = "Npcap: " + err; return; }
        try
        {
            Pcap.pcap_set_snaplen(p, 65535);
            Pcap.pcap_set_promisc(p, 0);
            Pcap.pcap_set_timeout(p, 250);
            Pcap.pcap_set_immediate_mode(p, 1);          // no buffering — packets are delivered immediately
            Pcap.pcap_set_buffer_size(p, 1 << 20);
            Pcap.pcap_set_tstamp_type(p, Pcap.TstampHostHiprecUnsynced); // QPC timestamps, if the driver supports them
            if (Pcap.pcap_activate(p) < 0) { _stats.Status = "Npcap: " + Pcap.Error(p); return; }

            int linkType = Pcap.pcap_datalink(p);
            var clock = new ClockCalibrator();
            var seen = new RecentSet(256);
            var buffer = new byte[65536];
            var trackers = new Dictionary<(uint, int), TcpRttTracker>();
            double lastServerData = 0;   // when data last arrived from the game server
            var outTimes = new double[256];
            int outIdx = 0;

            // How long the request sat on your PC: from the game's timestamp to our first packet on the wire after it.
            Action<double, double> onPing = (sentStampMs, rtt) =>
            {
                double best = double.MaxValue;
                foreach (var t in outTimes)
                    if (t >= sentStampMs - 2 && t - sentStampMs < best) best = t - sentStampMs;
                double? pc = best <= rtt ? Math.Max(0, best) : null;
                _stats.Add(rtt, pc);
                _stats.Debug = pc is double d ? $"pc={d:F2}ms" : "pc=?";
            };
            Target? applied = null;

            while (!_stop)
            {
                var target = _target;
                if (target != applied)
                {
                    if (!Pcap.SetFilter(p, target.Filter)) { _stats.Status = "filter: " + Pcap.Error(p); return; }
                    applied = target;
                    trackers.Clear();
                    lastServerData = 0;
                }

                int rc = Pcap.pcap_next_ex(p, out IntPtr header, out IntPtr data);
                if (rc == 0) continue;     // timeout — just re-check _stop/_filter
                if (rc < 0) { _stats.Status = "Npcap: " + Pcap.Error(p); return; }

                double receivedMs = Stopwatch.GetTimestamp() * MsPerTick;
                uint sec = (uint)Marshal.ReadInt32(header, 0);
                uint usec = (uint)Marshal.ReadInt32(header, 4);
                int caplen = Math.Min(Marshal.ReadInt32(header, 8), buffer.Length);
                Marshal.Copy(data, buffer, 0, caplen);
                Interlocked.Increment(ref _stats.Packets);

                double arrivalMs = clock.ToQpcMs(sec * 1000.0 + usec / 1000.0, receivedMs);
                var frame = buffer.AsSpan(0, caplen);
                if (!PingParser.TryParseTcp(frame, linkType, out var seg)) continue;

                bool inbound = target.Remotes.Contains((seg.SrcIp, seg.SrcPort));
                var key = inbound ? (seg.SrcIp, seg.SrcPort) : (seg.DstIp, seg.DstPort);
                if (!trackers.TryGetValue(key, out var tracker)) trackers[key] = tracker = new TcpRttTracker();

                if (_stats.Trace is { } trace && seg.PayloadLength > 0 && _stats.GameEndpoint == key)
                    trace.Enqueue((arrivalMs, inbound, seg.PayloadLength));

                if (!inbound)
                {
                    if (seg.PayloadLength > 0) { outTimes[outIdx] = arrivalMs; outIdx = (outIdx + 1) % outTimes.Length; }
                    if (tracker.OnOutbound(seg, arrivalMs) && _stats.GameEndpoint == key)
                        _stats.AddLoss();
                    continue;
                }
                if (seg.PayloadLength > 0 &&
                    PingParser.Scan(frame.Slice(seg.PayloadOffset, seg.PayloadLength), arrivalMs, seen, onPing))
                    _stats.GameEndpoint = (seg.SrcIp, seg.SrcPort);

                if (seg.PayloadLength > 0 && _stats.GameEndpoint == key)
                {
                    if (lastServerData > 0 && arrivalMs - lastServerData > PingStats.FreezeMs)
                        _stats.AddFreeze(arrivalMs - lastServerData);
                    lastServerData = Math.Max(lastServerData, arrivalMs);
                }

                if (tracker.IsInboundRetransmit(seg) && _stats.GameEndpoint == key)
                    _stats.AddLoss();

                double? tcpRtt = tracker.OnInbound(seg, arrivalMs);
                if (tcpRtt is double r && _stats.GameEndpoint == (seg.SrcIp, seg.SrcPort))
                    _stats.AddTcp(r);
            }
        }
        catch (Exception ex)
        {
            _stats.Status = "error: " + ex.Message;
        }
        finally
        {
            Pcap.pcap_close(p);
        }
    }
}

static class GameConnections
{
    public static List<GameConnection> Find()
    {
        var pids = new HashSet<uint>();
        foreach (var proc in Process.GetProcessesByName("AION2"))
        {
            pids.Add((uint)proc.Id);
            proc.Dispose();
        }
        var result = new List<GameConnection>();
        if (pids.Count == 0) return result;

        int size = 0;
        Native.GetExtendedTcpTable(IntPtr.Zero, ref size, false, (int)AddressFamily.InterNetwork, 4, 0);
        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            if (Native.GetExtendedTcpTable(buf, ref size, false, (int)AddressFamily.InterNetwork, 4, 0) != 0)
                return result;
            int count = Marshal.ReadInt32(buf);
            for (int i = 0; i < count; i++)
            {
                IntPtr row = buf + 4 + i * 24;   // MIB_TCPROW_OWNER_PID
                if (Marshal.ReadInt32(row, 0) != 5) continue;              // ESTABLISHED
                if (!pids.Contains((uint)Marshal.ReadInt32(row, 20))) continue;
                var local = new IPAddress((uint)Marshal.ReadInt32(row, 4));
                var remote = new IPAddress((uint)Marshal.ReadInt32(row, 12));
                int rawPort = Marshal.ReadInt32(row, 16);
                int port = ((rawPort & 0xFF) << 8) | ((rawPort >> 8) & 0xFF);
                result.Add(new GameConnection(local, remote, port));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
        return result;
    }
}

// ───────────────────────────── native calls ─────────────────────────────

static class Pcap
{
    const string Dll = "wpcap.dll";
    public const int TstampHostHiprecUnsynced = 5;

    [DllImport(Dll, CharSet = CharSet.Ansi)] public static extern IntPtr pcap_create(string source, StringBuilder errbuf);
    [DllImport(Dll)] public static extern int pcap_set_snaplen(IntPtr p, int snaplen);
    [DllImport(Dll)] public static extern int pcap_set_promisc(IntPtr p, int promisc);
    [DllImport(Dll)] public static extern int pcap_set_timeout(IntPtr p, int ms);
    [DllImport(Dll)] public static extern int pcap_set_immediate_mode(IntPtr p, int on);
    [DllImport(Dll)] public static extern int pcap_set_buffer_size(IntPtr p, int size);
    [DllImport(Dll)] public static extern int pcap_set_tstamp_type(IntPtr p, int type);
    [DllImport(Dll)] public static extern int pcap_activate(IntPtr p);
    [DllImport(Dll)] public static extern int pcap_datalink(IntPtr p);
    [DllImport(Dll)] public static extern int pcap_next_ex(IntPtr p, out IntPtr header, out IntPtr data);
    [DllImport(Dll)] public static extern void pcap_close(IntPtr p);
    [DllImport(Dll)] static extern IntPtr pcap_geterr(IntPtr p);
    [DllImport(Dll, CharSet = CharSet.Ansi)] static extern int pcap_compile(IntPtr p, IntPtr program, string filter, int optimize, uint netmask);
    [DllImport(Dll)] static extern int pcap_setfilter(IntPtr p, IntPtr program);
    [DllImport(Dll)] static extern void pcap_freecode(IntPtr program);
    [DllImport(Dll)] static extern int pcap_findalldevs(out IntPtr devs, StringBuilder errbuf);
    [DllImport(Dll)] static extern void pcap_freealldevs(IntPtr devs);

    public static uint ToRaw(IPAddress a) => BitConverter.ToUInt32(a.GetAddressBytes(), 0);

    public static string Error(IntPtr p) => Marshal.PtrToStringAnsi(pcap_geterr(p)) ?? "?";

    public static bool SetFilter(IntPtr p, string filter)
    {
        IntPtr program = Marshal.AllocHGlobal(16);   // struct bpf_program
        try
        {
            if (pcap_compile(p, program, filter, 1, 0xFFFFFFFF) != 0) return false;
            int rc = pcap_setfilter(p, program);
            pcap_freecode(program);
            return rc == 0;
        }
        finally
        {
            Marshal.FreeHGlobal(program);
        }
    }

    /// <summary>Npcap adapter names and their IPv4 addresses.</summary>
    public static Dictionary<string, List<IPAddress>> ListDevices()
    {
        var result = new Dictionary<string, List<IPAddress>>();
        var err = new StringBuilder(512);
        if (pcap_findalldevs(out IntPtr devs, err) != 0)
            throw new InvalidOperationException("Npcap unavailable: " + err);
        try
        {
            for (IntPtr d = devs; d != IntPtr.Zero; d = Marshal.ReadIntPtr(d, 0))
            {
                string name = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(d, 8)) ?? "";
                var addrs = new List<IPAddress>();
                for (IntPtr a = Marshal.ReadIntPtr(d, 24); a != IntPtr.Zero; a = Marshal.ReadIntPtr(a, 0))
                {
                    IntPtr sa = Marshal.ReadIntPtr(a, 8);
                    if (sa != IntPtr.Zero && Marshal.ReadInt16(sa, 0) == 2)   // AF_INET
                        addrs.Add(new IPAddress((uint)Marshal.ReadInt32(sa, 4)));
                }
                result[name] = addrs;
            }
        }
        finally
        {
            pcap_freealldevs(devs);
        }
        return result;
    }
}

static class Native
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern bool SetDllDirectory(string path);
    [DllImport("iphlpapi.dll")] public static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);
    [DllImport("user32.dll")] public static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int index);
    [DllImport("user32.dll")] public static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int index, IntPtr value);
    [DllImport("user32.dll")] public static extern bool ReleaseCapture();
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
}

// ───────────────────────────── diagnostics ─────────────────────────────

/// <summary>AionPingMeter.exe --probe [seconds]: no window, writes progress to probe.txt next to the settings.</summary>
static partial class Probe
{
    public static int Run(int seconds)
    {
        string path = Path.Combine(Settings.Dir, "probe.txt");
        using var w = new StreamWriter(path, false, Encoding.UTF8) { AutoFlush = true };
        var stats = new PingStats();
        using (new CaptureManager(stats))
        {
            for (int i = 0; i < seconds; i++)
            {
                Thread.Sleep(1000);
                var (cur, med, max) = stats.Snapshot();
                var (tmin, tmed) = stats.TcpSnapshot();
                w.WriteLine($"{i + 1,3}s  packets={Interlocked.Read(ref stats.Packets),6}  pings={Interlocked.Read(ref stats.Pings),4}  " +
                            $"game={cur?.ToString("F1") ?? "-"}  tcpMin2s={tmin?.ToString("F1") ?? "-"}  tcpMed2s={tmed?.ToString("F1") ?? "-"}  tcpN={Interlocked.Read(ref stats.TcpSamples)}  losses={Interlocked.Read(ref stats.Losses)}  freezes={Interlocked.Read(ref stats.Freezes)}  {stats.Debug}");
            }
        }
        foreach (var c in GameConnections.Find()) w.WriteLine($"conn {c.Local} -> {c.Remote}:{c.RemotePort}");
        return 0;
    }
}

static partial class Probe
{
    /// <summary>AionPingMeter.exe --gaps [seconds]: gaps between data packets on the game connection → gaps.txt.</summary>
    public static int Gaps(int seconds)
    {
        var stats = new PingStats { Trace = new() };
        using (new CaptureManager(stats))
            Thread.Sleep(seconds * 1000);

        var all = stats.Trace!.ToArray();
        using var w = new StreamWriter(Path.Combine(Settings.Dir, "gaps.txt"), false, Encoding.UTF8);
        w.WriteLine($"server={stats.GameEndpointText} packets={all.Length} seconds={seconds}");
        foreach (bool inbound in new[] { true, false })
        {
            var t = all.Where(x => x.Inbound == inbound).Select(x => x.At).ToArray();
            if (t.Length < 2) { w.WriteLine($"{(inbound ? "IN" : "OUT")}: too few packets"); continue; }
            var gaps = t.Zip(t.Skip(1), (a, b) => (Gap: b - a, At: a)).ToArray();
            var sorted = gaps.Select(g => g.Gap).Order().ToArray();
            double P(double q) => sorted[(int)(q * (sorted.Length - 1))];
            w.WriteLine($"{(inbound ? "IN  (server->you)" : "OUT (you->server)")}: n={t.Length} rate={t.Length / (double)seconds:F1}/s  " +
                        $"p50={P(0.5):F1} p90={P(0.9):F1} p99={P(0.99):F1} max={sorted[^1]:F1} ms  " +
                        $">150:{sorted.Count(g => g > 150)} >250:{sorted.Count(g => g > 250)} >500:{sorted.Count(g => g > 500)} >1000:{sorted.Count(g => g > 1000)}");
            foreach (var g in gaps.OrderByDescending(g => g.Gap).Take(8))
            {
                int burst = t.Count(x => x > g.At + g.Gap && x <= g.At + g.Gap + 30);
                w.WriteLine($"    gap {g.Gap,7:F1} ms at +{(g.At - t[0]) / 1000,6:F1}s, then {burst + 1} packets within 30 ms");
            }
        }
        return 0;
    }
}

static class Settings
{
    public static readonly string Dir = Init();

    static string Init()
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string dir = Path.Combine(appData, "AionPingMeter");
        // Migrate settings from early builds that were simply called PingMeter.
        string legacy = Path.Combine(appData, "PingMeter");
        if (!Directory.Exists(dir) && Directory.Exists(legacy))
            try { Directory.Move(legacy, dir); } catch { }
        return Directory.CreateDirectory(dir).FullName;
    }

    static string PosFile => Path.Combine(Dir, "position.txt");

    public static Point? LoadPosition()
    {
        try
        {
            var parts = File.ReadAllText(PosFile).Split(',');
            var pt = new Point(int.Parse(parts[0]), int.Parse(parts[1]));
            return Screen.AllScreens.Any(s => s.WorkingArea.Contains(pt)) ? pt : null;
        }
        catch { return null; }
    }

    static string ThresholdFile => Path.Combine(Dir, "threshold.txt");

    public static int LoadThreshold()
    {
        try { return int.Parse(File.ReadAllText(ThresholdFile)); } catch { return 100; }
    }

    static string ShowServerFile => Path.Combine(Dir, "show-server.txt");

    public static bool LoadShowServer() => File.Exists(ShowServerFile);

    public static void SaveShowServer(bool show)
    {
        try { if (show) File.WriteAllText(ShowServerFile, "1"); else File.Delete(ShowServerFile); } catch { }
    }

    public static void SaveThreshold(int ms)
    {
        try { File.WriteAllText(ThresholdFile, ms.ToString()); } catch { }
    }

    public static void SavePosition(Point p)
    {
        try { File.WriteAllText(PosFile, $"{p.X},{p.Y}"); } catch { }
    }
}

// ───────────────────────────── overlay ─────────────────────────────

/// <summary>Tray icon — signal bars in the colour of the current ping. Each colour is drawn once.</summary>
static class TrayIcons
{
    static readonly Dictionary<Color, Icon> Cache = new();

    public static Icon For(Color color)
    {
        if (Cache.TryGetValue(color, out var icon)) return icon;
        int size = SystemInformation.SmallIconSize.Width;
        using var bmp = new Bitmap(size, size);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            float w = size * 0.17f, gap = size * 0.07f, left = (size - (4 * w + 3 * gap)) / 2, bottom = size * 0.92f;
            float[] heights = [0.30f, 0.50f, 0.70f, 0.90f];
            using var brush = new SolidBrush(color);
            for (int i = 0; i < 4; i++)
                g.FillRectangle(brush, left + i * (w + gap), bottom - size * heights[i], w, size * heights[i]);
        }
        return Cache[color] = Icon.FromHandle(bmp.GetHicon());
    }
}

sealed class OverlayForm : Form
{
    const int GwlExStyle = -20, WsExTransparent = 0x20, WsExLayered = 0x80000,
              WsExToolWindow = 0x80, WsExNoActivate = 0x08000000, WsExTopmost = 0x8,
              WmNcLButtonDown = 0xA1, HtCaption = 2;

    readonly PingStats _stats;
    readonly NotifyIcon _tray;
    readonly ToolStripMenuItem _moveItem, _logItem, _serverItem;
    readonly System.Windows.Forms.Timer _timer;
    readonly Font _bigFont = new("Segoe UI Semibold", 13f);
    readonly Font _smallFont = new("Segoe UI", 7.5f);
    bool _locked = true;
    string _big = "", _small = "", _max = "", _warn = "", _serverLine = "", _tip = "";
    bool _showServer = Settings.LoadShowServer();
    Color _color = Color.Gray, _warnColor = Color.Gray;
    bool _flash;
    static readonly Color SmallText = Color.FromArgb(170, 176, 186);
    static readonly Color WarnText = Color.FromArgb(255, 170, 60);
    static readonly Color AlarmRed = Color.FromArgb(255, 80, 70);
    int _tick;

    public OverlayForm(PingStats stats)
    {
        _stats = stats;
        _stats.ThresholdMs = Settings.LoadThreshold();
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.Manual;
        BackColor = Color.FromArgb(18, 20, 24);
        Opacity = 0.82;
        DoubleBuffered = true;
        float s = DeviceDpi / 96f;
        ClientSize = new Size((int)(128 * s), (int)(38 * s));
        Location = Settings.LoadPosition() ?? DefaultLocation;

        _serverItem = new ToolStripMenuItem("Server: —") { Enabled = false };
        _serverItem.Click += (_, _) =>
        {
            if (_stats.GameEndpointText is string t)
            {
                Clipboard.SetText(t);
                _tray?.ShowBalloonTip(2000, "AionPingMeter", "Copied: " + t, ToolTipIcon.Info);
            }
        };
        _moveItem = new ToolStripMenuItem("Move", null, (_, _) => SetLocked(!_locked));
        _logItem = new ToolStripMenuItem("Write log", null, (_, _) => ToggleLog());
        var menu = new ContextMenuStrip();
        var version = typeof(OverlayForm).Assembly.GetName().Version;
        menu.Items.Add(new ToolStripMenuItem($"AionPingMeter v{version?.ToString(3)}") { Enabled = false });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_serverItem);
        var showServerItem = new ToolStripMenuItem("Show server in overlay") { Checked = _showServer };
        showServerItem.Click += (_, _) =>
        {
            _showServer = showServerItem.Checked = !_showServer;
            Settings.SaveShowServer(_showServer);
            UpdateView();
        };
        menu.Items.Add(showServerItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_moveItem);
        menu.Items.Add("Reset position", null, (_, _) =>
        {
            Location = DefaultLocation;
            Settings.SavePosition(Location);
        });
        menu.Items.Add(_logItem);
        menu.Items.Add(BuildThresholdMenu());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => Close());
        _tray = new NotifyIcon { Icon = TrayIcons.For(Color.FromArgb(140, 146, 156)), Text = "AionPingMeter", ContextMenuStrip = menu, Visible = true };

        _timer = new System.Windows.Forms.Timer { Interval = 250 };
        _timer.Tick += (_, _) => UpdateView();
        _timer.Start();
        UpdateView();
    }

    /// <summary>Top-left corner of the primary monitor.</summary>
    static Point DefaultLocation => new(Screen.PrimaryScreen!.WorkingArea.Left + 24, Screen.PrimaryScreen.WorkingArea.Top + 24);

    protected override bool ShowWithoutActivation => true;

    protected override CreateParams CreateParams
    {
        get
        {
            var cp = base.CreateParams;
            cp.ExStyle |= WsExToolWindow | WsExNoActivate | WsExTopmost | WsExLayered | WsExTransparent;
            return cp;
        }
    }

    void SetLocked(bool locked)
    {
        _locked = locked;
        long ex = Native.GetWindowLongPtr(Handle, GwlExStyle).ToInt64();
        ex = locked ? ex | WsExTransparent : ex & ~WsExTransparent;
        Native.SetWindowLongPtr(Handle, GwlExStyle, new IntPtr(ex));
        _moveItem.Text = locked ? "Move" : "Lock position";
        if (locked) Settings.SavePosition(Location);
        Invalidate();
    }

    ToolStripMenuItem BuildThresholdMenu()
    {
        var root = new ToolStripMenuItem("Alert threshold");
        foreach (int ms in new[] { 80, 100, 150, 200, 300 })
        {
            var item = new ToolStripMenuItem($"{ms} ms") { Checked = _stats.ThresholdMs == ms };
            item.Click += (_, _) =>
            {
                _stats.ThresholdMs = ms;
                Settings.SaveThreshold(ms);
                foreach (ToolStripMenuItem i in root.DropDownItems) i.Checked = i == item;
            };
            root.DropDownItems.Add(item);
        }
        return root;
    }

    void ToggleLog()
    {
        string? path = _stats.SetLogging(!_logItem.Checked);
        _logItem.Checked = path != null;
        if (path != null)
            _tray.ShowBalloonTip(3000, "AionPingMeter", "Log: " + path, ToolTipIcon.Info);
    }

    void UpdateView()
    {
        var (cur, med, max) = _stats.Snapshot();
        string big, small, maxText = "";
        Color color;
        var (net, _) = _stats.TcpSnapshot();
        if (cur is double c)
        {
            big = $"{c:0} ms";
            maxText = $"max {max:0}";
            small = net is double n ? $"network {n:0}" : "network —";
            color = c < 60 ? Color.FromArgb(110, 220, 130) : c < 120 ? Color.FromArgb(240, 200, 90) : Color.FromArgb(255, 110, 100);
        }
        else
        {
            big = "— ms";
            small = _stats.Status;
            color = Color.FromArgb(140, 146, 156);
        }
        // Third line — problems in the last minute: red for the first 10 s (plus a frame), then orange.
        string warn = "";
        Color warnColor = WarnText;
        bool flash = false;
        if (_stats.SpikeSnapshot() is { } sp)
        {
            flash = sp.SinceLastMs < PingStats.SpikeFlashMs;
            var parts = new List<string>(3);
            if (sp.GameMax is double gm) parts.Add(sp.GameCause is string gc ? $"ping {gm:0} ({gc})" : $"ping {gm:0}");
            if (sp.NetworkMax is double nm) parts.Add($"network {nm:0}");
            if (sp.FreezeMax is double fm) parts.Add($"freeze {fm:0}");
            if (sp.Losses > 0) parts.Add($"loss ×{sp.Losses}");
            parts.Add(sp.SinceLastMs < 1000 ? "just now" : $"{sp.SinceLastMs / 1000}s ago");
            warn = "⚠ " + string.Join(" · ", parts);
            warnColor = flash ? AlarmRed : WarnText;
        }

        string serverLine = _showServer ? _stats.GameEndpointText ?? "server —" : "";

        if (big != _big || small != _small || maxText != _max || warn != _warn || serverLine != _serverLine ||
            color != _color || warnColor != _warnColor || flash != _flash)
        {
            if (color != _color || flash != _flash)
                _tray.Icon = TrayIcons.For(flash ? AlarmRed : color);
            bool relayout = small != _small || warn != _warn || serverLine != _serverLine;
            (_big, _small, _max, _warn, _serverLine, _color, _warnColor, _flash) = (big, small, maxText, warn, serverLine, color, warnColor, flash);
            if (relayout) Relayout();
            Invalidate();
        }

        if (++_tick % 4 == 0)
        {
            string? server = _stats.GameEndpointText;
            string tip = (server != null ? $"AionPingMeter · {server}" : "AionPingMeter") +
                $"\npings {Interlocked.Read(ref _stats.Pings)} · loss {Interlocked.Read(ref _stats.Losses)} · freeze {Interlocked.Read(ref _stats.Freezes)}" +
                $"\ngateway changes {Interlocked.Read(ref _stats.GatewayChanges)}";
            string serverText = server != null ? $"Server: {server}  (click to copy)" : "Server: —";
            if (_serverItem.Text != serverText) { _serverItem.Text = serverText; _serverItem.Enabled = server != null; }
            if (tip.Length > 127) tip = tip[..127];   // Windows tray tooltip limit
            if (tip != _tip) _tray.Text = _tip = tip;
        }
    }

    /// <summary>Small lines under the ping: network, (gateway), (alerts).</summary>
    IEnumerable<(string Text, Color Color)> SmallLines()
    {
        yield return (_small, SmallText);
        if (_serverLine.Length > 0) yield return (_serverLine, SmallText);
        if (_warn.Length > 0) yield return (_warn, _warnColor);
    }

    /// <summary>Height fits the number of lines, width fits the longest one.</summary>
    void Relayout()
    {
        float s = DeviceDpi / 96f;
        int width = (int)(128 * s), lines = 0;
        foreach (var (text, _) in SmallLines())
        {
            width = Math.Max(width, TextRenderer.MeasureText(text, _smallFont).Width + (int)(16 * s));
            lines++;
        }
        var size = new Size(width, (int)((24 + 14 * lines) * s));
        if (ClientSize != size) ClientSize = size;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        float s = DeviceDpi / 96f;
        using (var b = new SolidBrush(_color))
            g.DrawString(_big, _bigFont, b, 6 * s, 0);
        if (_max.Length > 0)
            using (var b = new SolidBrush(SmallText))
            using (var fmt = new StringFormat { Alignment = StringAlignment.Far })
                g.DrawString(_max, _smallFont, b, new RectangleF(0, 6 * s, ClientSize.Width - 6 * s, 16 * s), fmt);
        float y = 23 * s;
        foreach (var (text, color) in SmallLines())
        {
            using var b = new SolidBrush(color);
            g.DrawString(text, _smallFont, b, 8 * s, y);
            y += 14 * s;
        }
        if (_flash)
            using (var pen = new Pen(AlarmRed, 2 * s) { Alignment = System.Drawing.Drawing2D.PenAlignment.Inset })
                g.DrawRectangle(pen, 0, 0, ClientSize.Width, ClientSize.Height);
        else if (!_locked)
            using (var pen = new Pen(Color.FromArgb(120, 170, 255)))
                g.DrawRectangle(pen, 0, 0, ClientSize.Width - 1, ClientSize.Height - 1);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (_locked || e.Button != MouseButtons.Left) return;
        Native.ReleaseCapture();
        Native.SendMessage(Handle, WmNcLButtonDown, HtCaption, IntPtr.Zero);
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _timer.Dispose();
        _stats.SetLogging(false);
        _tray.Visible = false;
        _tray.Dispose();
        base.OnFormClosed(e);
    }
}
