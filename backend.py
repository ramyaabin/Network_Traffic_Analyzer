# backend.py — Real packet capture (Scapy)
import time, threading, datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "DNS", "HTTPS"]


class Monitor:
    def __init__(self):
        self._running    = False
        self._callbacks  = []
        self.packets     = []
        self.stats       = {p: 0 for p in PROTOCOLS}
        self.total_bytes = 0
        self.alerts      = []
        self._pps_hist   = []
        self._bps_hist   = []
        self._last_n     = 0
        self._last_b     = 0

    def on_packet(self, fn):
        self._callbacks.append(fn)

    def start(self):
        if self._running:
            return
        self._running = True
        threading.Thread(target=self._capture_loop, daemon=True).start()
        threading.Thread(target=self._ticker,       daemon=True).start()

    def stop(self):
        self._running = False

    def reset(self):
        self.stop()
        self.packets.clear()
        self.alerts.clear()
        self.stats       = {p: 0 for p in PROTOCOLS}
        self.total_bytes = 0
        self._pps_hist.clear()
        self._bps_hist.clear()
        self._last_n = 0
        self._last_b = 0

    def proto_stats(self):
        return dict(self.stats)

    def pps_hist(self):
        return list(self._pps_hist[-60:])

    def bps_hist(self):
        return list(self._bps_hist[-60:])

    def summary(self):
        total = sum(self.stats.values())
        return {
            "total":   total,
            "bytes":   self.total_bytes,
            "protos":  len([p for p, c in self.stats.items() if c > 0]),
            "top":     max(self.stats, key=self.stats.get) if total else "—",
            "alerts":  len(self.alerts),
            "pps":     self._pps_hist[-1] if self._pps_hist else 0,
        }

    def _ticker(self):
        while self._running:
            time.sleep(1)
            total = sum(self.stats.values())
            self._pps_hist.append(total - self._last_n)
            self._bps_hist.append(self.total_bytes - self._last_b)
            if len(self._pps_hist) > 120: self._pps_hist.pop(0)
            if len(self._bps_hist) > 120: self._bps_hist.pop(0)
            self._last_n = total
            self._last_b = self.total_bytes


    def _record(self, pkt):
        self.packets.append(pkt)
        # Guard: only count protocols the stats dict knows about
        if pkt["protocol"] in self.stats:
            self.stats[pkt["protocol"]] += 1
        else:
            self.stats[pkt["protocol"]] = 1
        self.total_bytes += pkt["size"]
        if pkt.get("threat", "Normal") != "Normal":
            self.alerts.append({
                "time":    pkt["timestamp"],
                "threat":  pkt["threat"],
                "src":     pkt["src_ip"],
                "details": f'{pkt["protocol"]} from {pkt["src_ip"]}:{pkt["src_port"]}',
            })
        for cb in self._callbacks:
            cb(pkt)


    def _parse(self, packet):
        """Converting a scapy packet into the dictionary"""
        if IP not in packet:
            return None

        ip_layer = packet[IP]
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if 443 in (src_port, dst_port):
                protocol = "HTTPS"
            elif 80 in (src_port, dst_port):
                protocol = "HTTP"
            else:
                protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if 53 in (src_port, dst_port):
                protocol = "DNS"
            else:
                protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
            src_port = None
            dst_port = None
        else:
            protocol = "OTHER"
            src_port = None
            dst_port = None

        return {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip":    ip_layer.src,
            "dst_ip":    ip_layer.dst,
            "protocol":  protocol,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "size":      len(packet),
            "flags":     str(packet[TCP].flags) if TCP in packet else "—",
            "ttl":       ip_layer.ttl,
            "threat":    "Normal",
        }

    def _capture_loop(self):
        def handle(packet):
            pkt = self._parse(packet)
            if pkt:
                self._record(pkt)
        # stop_filter is checked after each packet; stop when not running.
        sniff(prn=handle, store=False,
              stop_filter=lambda p: not self._running)



MON = Monitor()