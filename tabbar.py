# tabbar.py — Horizontal tab navigation bar
import tkinter as tk
from theme import PANEL, RAISED, BRD, ACCENT, TEXT2, FMS

TABS = [
    ("⬡  Dashboard",   "Dashboard"),
    ("≋  Packets",     "Live Packets"),
    ("◑  Charts",      "Charts"),
    ("⚑  Alerts",      "Alerts"),
    ("⊞  Summary",     "Summary"),
]

class TabBar(tk.Frame):
    def __init__(self, parent, on_select, **kw):
        super().__init__(parent, bg=PANEL, height=36,
                         highlightthickness=1, highlightbackground=BRD, **kw)
        self.pack_propagate(False)
        self._on_sel = on_select
        self._sel    = 0
        self._btns   = []
        self._build()

    def _build(self):
        for i, (icon, label) in enumerate(TABS):
            b = tk.Button(self, text=f"  {icon}  ", font=FMS,
                          bg=PANEL, fg=TEXT2, relief="flat",
                          cursor="hand2", bd=0, padx=8, pady=0,
                          activebackground=RAISED, activeforeground=ACCENT,
                          command=lambda idx=i: self._select(idx))
            b.pack(side="left", fill="y")
            self._btns.append(b)

        self._pps_lbl = tk.Label(self, text="0 pps", font=FMS,
                                  bg=PANEL, fg=TEXT2)
        self._pps_lbl.pack(side="right", padx=14)
        self._select(0)

    def _select(self, idx):
        for i, b in enumerate(self._btns):
            b.config(bg=RAISED if i == idx else PANEL,
                     fg=ACCENT if i == idx else TEXT2)
        self._sel = idx
        self._on_sel(idx)

    def update_pps(self, v):
        self._pps_lbl.config(text=f"{v} pps")