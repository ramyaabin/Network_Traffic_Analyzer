import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk
import datetime

from backend        import MON
from theme          import BG
from header         import Header
from tabbar         import TabBar
from page_dashboard import DashPage
from page_packets   import PacketPage
from page_charts    import ChartsPage
from page_alerts    import AlertsPage
from page_summary   import SummaryPage

# Jasmine's analysis/anomaly-detection engine. Imported here (the integration
# layer) rather than in backend.py, since analyzer.py already imports MON
# from backend — importing it back into backend.py would create a circular
# import. main.py already depends on both modules, so this is the natural
# place to connect them.
import analyzer

class App(tk.Tk):
    REFRESH_MS = 1000

    def __init__(self):
        super().__init__()
        self.title("Network Traffic Analyzer  · v4.0")
        self.geometry("1440x880")
        self.minsize(1100, 700)
        self.configure(bg=BG)

        # Pages list must exist before TabBar fires its first callback
        self._pages = []
        # Dedup set so the anomaly bridge below doesn't re-log the same
        # finding (e.g. the same high-traffic IP) on every refresh tick.
        self._seen_alert_keys = set()
        self._tick = 0
        self._build()
        MON.on_packet(self._on_pkt)
        self._schedule()

    def _build(self):
        # Header
        self._hdr = Header(self,
            on_start=MON.start,
            on_stop=MON.stop,
            on_clear=self._clear)
        self._hdr.pack(fill="x", side="top")

        # Tab bar
        self._tabs = TabBar(self, on_select=self._nav)
        self._tabs.pack(fill="x", side="top")

        # Content stack
        self._stack = tk.Frame(self, bg=BG)
        self._stack.pack(fill="both", expand=True)

        # Instantiate all pages
        self._dash   = DashPage(self._stack);    self._pages.append(self._dash)
        self._pkts   = PacketPage(self._stack);  self._pages.append(self._pkts)
        self._charts = ChartsPage(self._stack);  self._pages.append(self._charts)
        self._alrts  = AlertsPage(self._stack);  self._pages.append(self._alrts)
        self._summ   = SummaryPage(self._stack); self._pages.append(self._summ)

        self._show(0)

    # ── Navigation ────────────────────────────────────────────────────────────
    def _nav(self, idx):
        self._show(idx)

    def _show(self, idx):
        if not self._pages:
            return
        for p in self._pages:
            p.pack_forget()
        self._pages[idx].pack(fill="both", expand=True)

    # ── Packet callback (from background thread) ──────────────────────────────
    def _on_pkt(self, pkt):
        self._pkts.add(pkt)
        self._dash.add_mini(pkt)

    # ── Periodic refresh ──────────────────────────────────────────────────────
    def _schedule(self):
        self._refresh()
        self._tick += 1
        if self._tick % 3 == 0:        # run the analysis engine every ~3s
            self._run_anomaly_scan()
        self.after(self.REFRESH_MS, self._schedule)

    def _refresh(self):
        s   = MON.summary()
        ps  = MON.proto_stats()
        pps = MON.pps_hist()
        bps = MON.bps_hist()

        self._dash.refresh(s, ps, pps, bps)
        self._charts.update_charts(ps)
        self._charts.update_throughput(pps, bps)
        self._alrts.refresh(MON.alerts)
        self._summ.refresh(s, ps, MON.packets)
        self._tabs.update_pps(s.get("pps", 0))
        self._hdr.update_count(s.get("total", 0))

    # ── Clear ─────────────────────────────────────────────────────────────────
    def _clear(self):
        MON.reset()
        self._seen_alert_keys.clear()
        self._tick = 0
        self._pkts.clear()
        self._charts.update_charts({})
        self._charts.update_throughput([], [])
        self._dash.refresh(MON.summary(), {}, [], [])

    # ── Analysis-engine bridge ──────────────────────────────────────────────────
    # Connects Jasmine's anomaly-detection logic (analyzer.py) into the live
    # Alerts feed. Previously backend.py never set a packet's "threat" field
    # to anything but "Normal" during live capture, so MON.alerts (and the
    # Alerts page / dashboard alert count) stayed empty no matter what
    # traffic occurred — the analysis module ran completely disconnected
    # from the GUI. This method is the fix: it calls into analyzer.py on a
    # timer and folds genuinely new findings into MON.alerts.
    def _run_anomaly_scan(self):
        now = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # High-traffic sources (possible DoS attempt / aggressive scanner).
        # Alert once per source per session rather than once per tick.
        for ip, count in analyzer.detect_high_traffic_sources():
            key = ("HIGH_TRAFFIC", ip)
            if key in self._seen_alert_keys:
                continue
            self._seen_alert_keys.add(key)
            MON.alerts.append({
                "time": now, "threat": "DDoS", "src": ip,
                "details": f"High traffic: {ip} sent {count} packets "
                           f"(threshold {analyzer.HIGH_TRAFFIC_THRESHOLD})",
            })

        # ICMP flood sources (possible ping-flood DoS).
        for ip, count in analyzer.detect_icmp_flood():
            key = ("ICMP_FLOOD", ip)
            if key in self._seen_alert_keys:
                continue
            self._seen_alert_keys.add(key)
            MON.alerts.append({
                "time": now, "threat": "DDoS", "src": ip,
                "details": f"Possible ICMP flood from {ip} "
                           f"({count} ICMP packets)",
            })

        # Packets aimed at known suspicious ports (22, 3389, 4444, 31337…).
        # These map to real packets, so tag the packet dict itself too —
        # that makes the live Packet table / dashboard mini-table colour
        # the row immediately, instead of only showing up in the Alerts log.
        for pkt in analyzer.detect_suspicious_ports():
            key = ("SUSPICIOUS_PORT", pkt["timestamp"], pkt["src_ip"], pkt["dst_port"])
            if key in self._seen_alert_keys:
                continue
            self._seen_alert_keys.add(key)
            if pkt.get("threat", "Normal") == "Normal":
                pkt["threat"] = "Port Scan"
            MON.alerts.append({
                "time": pkt["timestamp"], "threat": "Port Scan", "src": pkt["src_ip"],
                "details": f"{pkt['src_ip']} \u2192 {pkt['dst_ip']}:{pkt['dst_port']} "
                           f"({pkt['protocol']}) \u2014 suspicious destination port",
            })


if __name__ == "__main__":
    app = App()
    app.mainloop()