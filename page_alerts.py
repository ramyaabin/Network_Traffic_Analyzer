# page_alerts.py — Threat alert log
import tkinter as tk
from tkinter import ttk
from theme import *

class AlertsPage(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=PANEL,
                       highlightthickness=1, highlightbackground=BRD)
        hdr.pack(fill="x")
        tk.Label(hdr, text="  ⚑  THREAT ALERT LOG", font=FMH,
                 bg=PANEL, fg=RED, pady=10).pack(side="left")
        self._cnt = tk.Label(hdr, text="0 alerts", font=FM, bg=PANEL, fg=TEXT2)
        self._cnt.pack(side="right", padx=12)

        style = ttk.Style()
        style.configure("ALT.Treeview",
            background=BG, foreground=TEXT, fieldbackground=BG,
            rowheight=24, font=FM, borderwidth=0)
        style.configure("ALT.Treeview.Heading",
            background=PANEL, foreground=TEXT2, relief="flat", font=FMB)
        style.map("ALT.Treeview",
            background=[("selected", RAISED)],
            foreground=[("selected", ACCENT)])

        cols = ("no","time","threat","src","details")
        hdrs = ("#","Time","Threat","Source IP","Details")
        wids = [42, 90, 110, 130, 500]

        fr = tk.Frame(self, bg=BG)
        fr.pack(fill="both", expand=True, padx=4, pady=4)
        self._tree = ttk.Treeview(fr, columns=cols,
                                   show="headings", style="ALT.Treeview")
        for col, hdr, w in zip(cols, hdrs, wids):
            self._tree.heading(col, text=hdr)
            self._tree.column(col, width=w,
                              anchor="w" if col=="details" else "center")
        for t, c in THREAT_C.items():
            if t != "Normal":
                self._tree.tag_configure(t, foreground=c)

        vs = ttk.Scrollbar(fr, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vs.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

    def refresh(self, alerts):
        self.after(0, self._ref, alerts)

    def _ref(self, alerts):
        existing = len(self._tree.get_children())
        for i, a in enumerate(alerts[existing:], start=existing+1):
            self._tree.insert("", "end",
                values=(i, a["time"], a["threat"], a["src"], a["details"]),
                tags=(a["threat"],))
        self._cnt.config(text=f"{len(alerts)} alerts")
        kids = self._tree.get_children()
        if kids:
            self._tree.see(kids[-1])