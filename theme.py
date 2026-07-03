# theme.py — All colours, fonts, and style tokens
BG     = "#07111f"
PANEL  = "#0b1a2e"
CARD   = "#0f2040"
RAISED = "#132848"
BRD    = "#1a3558"
BRD2   = "#2a5080"
ACCENT = "#00d4ff"
ACC2   = "#006688"
GREEN  = "#00e676"
YELLOW = "#ffd740"
RED    = "#ff4444"
ORANGE = "#ff9800"
PURPLE = "#ce93d8"
TEXT   = "#ddeeff"
TEXT2  = "#5a8aaf"
MUTED  = "#1e3f60"

PROTO_C = {
    "TCP":   "#388bfd",
    "UDP":   "#00e676",
    "ICMP":  "#ffd740",
    "HTTP":  "#ce93d8",
    "DNS":   "#ff7043",
    "HTTPS": "#56d364",
}
THREAT_C = {
    "Normal":    "#ddeeff",
    "Port Scan": "#ffd740",
    "DDoS":      "#ff4444",
    "ARP Spoof": "#ff9800",
    "DNS Flood": "#ce93d8",
    "SYN Flood": "#ff4444",
}

FM  = ("Consolas", 9)
FMB = ("Consolas", 9,  "bold")
FMS = ("Consolas", 8)
FMH = ("Consolas", 11, "bold")
FMT = ("Consolas", 20, "bold")

def fmt_bytes(b):
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.0f} {u}"
        b /= 1024
    return f"{b:.1f} TB"