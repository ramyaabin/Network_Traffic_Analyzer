# page_dashboard.py — Dashboard: stat cards + pie + bar + throughput + mini table
import tkinter as tk
from tkinter import ttk
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from theme   import *
from widgets import StatCard

class DashPage(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._cards = {}
        self._build()

    def _build(self):
        # ── Row 1: 6 stat cards ──────────────────────────────────────────────
        row1 = tk.Frame(self, bg=BG)
        row1.pack(fill="x", padx=8, pady=(8, 4))
        defs = [
            ("Packets",    "📡", ACCENT),
            ("Pkt / sec",  "⚡", GREEN),
            ("Data",       "💾", PURPLE),
            ("Protocols",  "🔀", YELLOW),
            ("Alerts",     "⚠",  RED),
            ("Top Proto",  "🏆", ORANGE),
        ]
        for i, (lbl, icon, clr) in enumerate(defs):
            row1.columnconfigure(i, weight=1, uniform="c")
            card = StatCard(row1, lbl, icon, clr)
            card.grid(row=0, column=i, padx=4, sticky="nsew")
            self._cards[lbl] = card

        # ── Row 2: Pie | Bar | Throughput ────────────────────────────────────
        row2 = tk.Frame(self, bg=BG)
        row2.pack(fill="both", expand=True, padx=8, pady=4)
        row2.columnconfigure(0, weight=1)
        row2.columnconfigure(1, weight=1)
        row2.columnconfigure(2, weight=1)
        row2.rowconfigure(0, weight=1)

        # Pie chart
        pf = self._chart_card(row2, "  PROTOCOL DISTRIBUTION  —  Pie Chart", 0)
        self._pie_fig, self._ax_pie = plt.subplots(figsize=(4, 3.4), facecolor=CARD)
        self._pie_fig.subplots_adjust(left=0.02, right=0.98, top=0.97, bottom=0.02)
        self._ax_pie.set_facecolor(CARD)
        self._pie_cv = FigureCanvasTkAgg(self._pie_fig, master=pf)
        self._pie_cv.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

        # Bar chart
        bf = self._chart_card(row2, "  PACKETS PER PROTOCOL  —  Bar Chart", 1)
        self._bar_fig, self._ax_bar = plt.subplots(figsize=(4, 3.4), facecolor=CARD)
        self._bar_fig.subplots_adjust(left=0.12, right=0.97, top=0.93, bottom=0.18)
        self._ax_bar.set_facecolor(RAISED)
        self._bar_cv = FigureCanvasTkAgg(self._bar_fig, master=bf)
        self._bar_cv.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

        # Throughput lines
        tf2 = self._chart_card(row2, "  LIVE THROUGHPUT", 2)
        self._thr_fig, (self._ax_pps, self._ax_bps) = plt.subplots(
            2, 1, figsize=(4, 3.4), facecolor=CARD)
        self._thr_fig.subplots_adjust(left=0.14, right=0.97, top=0.93,
                                       bottom=0.12, hspace=0.55)
        for ax in (self._ax_pps, self._ax_bps):
            ax.set_facecolor(RAISED)
        self._thr_cv = FigureCanvasTkAgg(self._thr_fig, master=tf2)
        self._thr_cv.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

        # ── Row 3: Recent packets mini-table ─────────────────────────────────
        row3 = tk.Frame(self, bg=CARD,
                        highlightthickness=1, highlightbackground=BRD)
        row3.pack(fill="x", padx=8, pady=(4, 8))
        tk.Label(row3, text="  RECENT PACKETS",
                 font=FMB, bg=CARD, fg=TEXT2, pady=5).pack(fill="x")
        tk.Frame(row3, bg=BRD, height=1).pack(fill="x")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("MINI.Treeview", background=CARD, foreground=TEXT,
            fieldbackground=CARD, rowheight=20, font=FMS, borderwidth=0)
        style.configure("MINI.Treeview.Heading", background=RAISED,
            foreground=TEXT2, relief="flat", font=FMS)
        style.map("MINI.Treeview",
            background=[("selected", RAISED)],
            foreground=[("selected", ACCENT)])

        cols = ("time","src","dst","proto","size","threat")
        hdrs = ("Time","Source IP","Dest IP","Protocol","Bytes","Threat")
        wids = [90, 120, 120, 70, 65, 100]
        self._mini = ttk.Treeview(row3, columns=cols,
                                   show="headings", style="MINI.Treeview", height=5)
        for col, hdr, w in zip(cols, hdrs, wids):
            self._mini.heading(col, text=hdr)
            self._mini.column(col, width=w, anchor="center", stretch=False)
        for p, c in PROTO_C.items():
            self._mini.tag_configure(p, foreground=c)
        for t, c in THREAT_C.items():
            if t != "Normal":
                self._mini.tag_configure(f"T_{t}", foreground=c)
        self._mini.pack(fill="x", padx=4, pady=4)

        # Initial empty render
        self._render_charts({})
        self._render_throughput([], [])

    # ── helpers ───────────────────────────────────────────────────────────────
    def _chart_card(self, parent, title, col):
        f = tk.Frame(parent, bg=CARD,
                     highlightthickness=1, highlightbackground=BRD)
        f.grid(row=0, column=col, sticky="nsew",
               padx=(0,4) if col<2 else (4,0) if col==2 else 4)
        tk.Label(f, text=title, font=FMB, bg=CARD, fg=TEXT2, pady=6).pack(fill="x")
        tk.Frame(f, bg=BRD, height=1).pack(fill="x")
        return f

    def _sax(self, ax, title="", tiny=False):
        ax.set_facecolor(RAISED)
        if title:
            ax.set_title(title, color=TEXT2,
                         fontsize=6.5 if tiny else 7.5,
                         pad=3, fontfamily="Consolas", loc="left")
        ax.spines[:].set_color(BRD)
        ax.tick_params(colors=MUTED, labelsize=6)
        ax.yaxis.grid(True, color=BRD, linewidth=0.4, linestyle="--")
        ax.set_axisbelow(True)

    # ── public API ────────────────────────────────────────────────────────────
    def refresh(self, summary, proto_stats, pps_hist, bps_hist):
        s   = summary
        pps = s.get("pps", 0)
        tb  = s.get("bytes", 0)
        tp  = s.get("total", 0)
        self._cards["Packets"].set(f"{tp:,}", tp)
        self._cards["Pkt / sec"].set(str(pps), pps)
        self._cards["Data"].set(fmt_bytes(tb), tb)
        self._cards["Protocols"].set(str(s.get("protos", 0)))
        self._cards["Alerts"].set(str(s.get("alerts", 0)), s.get("alerts", 0))
        self._cards["Top Proto"].set(s.get("top", "—"), 0)
        self.after(0, self._render_charts, proto_stats)
        self.after(0, self._render_throughput, pps_hist, bps_hist)

    def add_mini(self, pkt):
        self.after(0, self._add_mini, pkt)

    def _add_mini(self, pkt):
        proto  = pkt.get("protocol", "TCP")
        threat = pkt.get("threat", "Normal")
        tags   = [proto] + ([] if threat == "Normal" else [f"T_{threat}"])
        self._mini.insert("", "0",
            values=(pkt["timestamp"], pkt["src_ip"], pkt["dst_ip"],
                    proto, pkt["size"], threat),
            tags=tuple(tags))
        kids = self._mini.get_children()
        if len(kids) > 8:
            self._mini.delete(kids[-1])

    def _render_charts(self, stats):
        protos = list(PROTO_C.keys())
        counts = [stats.get(p, 0) for p in protos]
        colors = list(PROTO_C.values())
        total  = sum(counts)

        # Pie
        ax = self._ax_pie; ax.clear(); ax.set_facecolor(CARD)
        if total:
            nzv = [c for c in counts if c > 0]
            nzc = [colors[i] for i, c in enumerate(counts) if c > 0]
            nzl = [protos[i] for i, c in enumerate(counts) if c > 0]
            _, _, autos = ax.pie(nzv, colors=nzc, autopct="%1.0f%%",
                startangle=140, pctdistance=0.75,
                wedgeprops={"linewidth": 1.5, "edgecolor": CARD})
            for a in autos:
                a.set_color(CARD); a.set_fontsize(7); a.set_fontfamily("Consolas")
            patches = [mpatches.Patch(color=c, label=l) for c, l in zip(nzc, nzl)]
            ax.legend(handles=patches, loc="lower left", fontsize=6.5,
                      framealpha=0.1, labelcolor=TEXT,
                      facecolor=CARD, edgecolor=BRD)
        else:
            ax.text(0, 0, "No data yet", ha="center", va="center",
                    color=MUTED, fontsize=9, fontfamily="Consolas")
        self._pie_cv.draw_idle()

        # Bar
        ax = self._ax_bar; ax.clear(); self._sax(ax)
        mx   = max(counts) if counts else 1
        bars = ax.bar(protos, counts, color=colors, edgecolor=CARD, width=0.55)
        for bar, cnt in zip(bars, counts):
            if cnt:
                ax.text(bar.get_x() + bar.get_width()/2,
                        bar.get_height() + mx * 0.03, str(cnt),
                        ha="center", va="bottom", color=TEXT2,
                        fontsize=6.5, fontfamily="Consolas")
        ax.set_xticks(range(len(protos)))
        ax.set_xticklabels(protos, color=TEXT2, fontsize=7, fontfamily="Consolas")
        ax.set_ylim(0, mx * 1.25 if mx else 10)
        ax.tick_params(axis="y", colors=MUTED, labelsize=6)
        self._bar_cv.draw_idle()

    def _render_throughput(self, pps, bps):
        pps_d = (pps + [0]*60)[-60:]
        bps_d = (bps + [0]*60)[-60:]
        xs    = list(range(60))
        for ax, data, color, title in [
            (self._ax_pps, pps_d, ACCENT, "PKT/S"),
            (self._ax_bps, bps_d, GREEN,  "B/S"),
        ]:
            ax.clear(); self._sax(ax, title, tiny=True)
            ax.fill_between(xs, data, alpha=0.18, color=color)
            ax.plot(xs, data, color=color, linewidth=1.5)
            ax.set_xlim(0, 59)
            mx = max(data) if data else 1
            ax.set_ylim(0, mx * 1.3 if mx else 10)
            ax.tick_params(axis="x", colors=MUTED, labelsize=5.5)
            ax.tick_params(axis="y", colors=MUTED, labelsize=5.5)
        self._thr_cv.draw_idle()