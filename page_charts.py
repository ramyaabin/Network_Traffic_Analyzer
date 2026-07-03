# page_charts.py — Full-size pie chart, bar chart, and two live line graphs
import tkinter as tk
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from theme import *

class ChartsPage(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._pp = [0]*60
        self._bp = [0]*60
        self._build()

    def _build(self):
        # ── Top: Pie + Bar ────────────────────────────────────────────────────
        top = tk.Frame(self, bg=BG)
        top.pack(fill="both", expand=True, padx=8, pady=(8,4))
        top.columnconfigure(0, weight=1); top.columnconfigure(1, weight=1)
        top.rowconfigure(0, weight=1)

        # Pie card
        pf = self._card(top, "  PROTOCOL DISTRIBUTION  —  Pie Chart", 0)
        self._pfig, self._axp = plt.subplots(figsize=(5.5, 3.8), facecolor=CARD)
        self._pfig.subplots_adjust(left=0.03, right=0.97, top=0.97, bottom=0.03)
        self._axp.set_facecolor(CARD)
        self._pcv = FigureCanvasTkAgg(self._pfig, master=pf)
        self._pcv.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

        # Bar card
        bf = self._card(top, "  PACKETS PER PROTOCOL  —  Bar Chart", 1)
        self._bfig, self._axb = plt.subplots(figsize=(5.5, 3.8), facecolor=CARD)
        self._bfig.subplots_adjust(left=0.1, right=0.97, top=0.93, bottom=0.16)
        self._axb.set_facecolor(RAISED)
        self._bcv = FigureCanvasTkAgg(self._bfig, master=bf)
        self._bcv.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

        # ── Bottom: PPS line + BPS line ───────────────────────────────────────
        bot = tk.Frame(self, bg=BG)
        bot.pack(fill="both", expand=True, padx=8, pady=(4,8))
        bot.columnconfigure(0, weight=1); bot.columnconfigure(1, weight=1)
        bot.rowconfigure(0, weight=1)

        lf1 = self._card(bot, "  PACKETS / SECOND  —  Live Throughput", 0)
        self._pfig2, self._axpps = plt.subplots(figsize=(5.5, 2.6), facecolor=CARD)
        self._pfig2.subplots_adjust(left=0.09, right=0.97, top=0.88, bottom=0.2)
        self._axpps.set_facecolor(RAISED)
        self._ppscv = FigureCanvasTkAgg(self._pfig2, master=lf1)
        self._ppscv.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

        lf2 = self._card(bot, "  BYTES / SECOND  —  Live Throughput", 1)
        self._pfig3, self._axbps = plt.subplots(figsize=(5.5, 2.6), facecolor=CARD)
        self._pfig3.subplots_adjust(left=0.09, right=0.97, top=0.88, bottom=0.2)
        self._axbps.set_facecolor(RAISED)
        self._bpscv = FigureCanvasTkAgg(self._pfig3, master=lf2)
        self._bpscv.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

        self._render_proto({})
        self._render_lines()

    def _card(self, parent, title, col):
        f = tk.Frame(parent, bg=CARD,
                     highlightthickness=1, highlightbackground=BRD)
        f.grid(row=0, column=col, sticky="nsew",
               padx=(0,4) if col==0 else (4,0))
        tk.Label(f, text=title, font=FMB, bg=CARD, fg=TEXT2, pady=7).pack(fill="x")
        tk.Frame(f, bg=BRD, height=1).pack(fill="x")
        return f

    def _sax(self, ax):
        ax.set_facecolor(RAISED)
        ax.spines[:].set_color(BRD)
        ax.tick_params(colors=MUTED, labelsize=7)
        ax.yaxis.grid(True, color=BRD, linewidth=0.4, linestyle="--")
        ax.set_axisbelow(True)

    # ── public ────────────────────────────────────────────────────────────────
    def update_charts(self, stats):
        self.after(0, self._render_proto, stats)

    def update_throughput(self, pps, bps):
        self._pp = (pps + [0]*60)[-60:]
        self._bp = (bps + [0]*60)[-60:]
        self.after(0, self._render_lines)

    # ── render ────────────────────────────────────────────────────────────────
    def _render_proto(self, stats):
        protos = list(PROTO_C.keys())
        counts = [stats.get(p, 0) for p in protos]
        colors = list(PROTO_C.values())
        total  = sum(counts)

        # Pie
        ax = self._axp; ax.clear(); ax.set_facecolor(CARD)
        if total:
            nzv = [c for c in counts if c > 0]
            nzc = [colors[i] for i,c in enumerate(counts) if c > 0]
            nzl = [protos[i] for i,c in enumerate(counts) if c > 0]
            _, _, autos = ax.pie(nzv, colors=nzc, autopct="%1.1f%%",
                startangle=140, pctdistance=0.76,
                wedgeprops={"linewidth":1.5,"edgecolor":CARD})
            for a in autos:
                a.set_color(CARD); a.set_fontsize(8); a.set_fontfamily("Consolas")
            patches = [mpatches.Patch(color=c, label=f"{l}  ({v})")
                       for c,l,v in zip(nzc, nzl, nzv)]
            ax.legend(handles=patches, loc="lower left", fontsize=8,
                      framealpha=0.12, labelcolor=TEXT,
                      facecolor=CARD, edgecolor=BRD)
        else:
            ax.text(0, 0, "Waiting for capture data…", ha="center", va="center",
                    color=MUTED, fontsize=10, fontfamily="Consolas")
        self._pcv.draw_idle()

        # Bar
        ax = self._axb; ax.clear(); self._sax(ax)
        mx   = max(counts) if counts else 1
        bars = ax.bar(protos, counts, color=colors, edgecolor=CARD, width=0.6)
        for bar, cnt in zip(bars, counts):
            if cnt:
                ax.text(bar.get_x()+bar.get_width()/2,
                        bar.get_height()+mx*0.025, str(cnt),
                        ha="center", va="bottom", color=TEXT2,
                        fontsize=8, fontfamily="Consolas")
        ax.set_xticks(range(len(protos)))
        ax.set_xticklabels(protos, color=TEXT2, fontsize=9, fontfamily="Consolas")
        ax.set_ylim(0, mx*1.2 if mx else 10)
        ax.tick_params(axis="y", colors=MUTED, labelsize=7)
        self._bcv.draw_idle()

    def _render_lines(self):
        xs = list(range(60))
        for ax, cv, data, color in [
            (self._axpps, self._ppscv, self._pp, ACCENT),
            (self._axbps, self._bpscv, self._bp, GREEN),
        ]:
            ax.clear(); self._sax(ax)
            ax.fill_between(xs, data, alpha=0.15, color=color)
            ax.plot(xs, data, color=color, linewidth=1.8)
            ax.set_xlim(0, 59)
            mx = max(data) if data else 1
            ax.set_ylim(0, mx*1.2 if mx else 10)
            ax.tick_params(axis="x", colors=MUTED, labelsize=6)
            ax.tick_params(axis="y", colors=MUTED, labelsize=6)
            cv.draw_idle()