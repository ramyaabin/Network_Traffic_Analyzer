"""
sidebar.py — Animated left sidebar with nav icons and live mini-stats.
"""

import tkinter as tk
from theme import *

NAV_ITEMS = [
    ("⬡", "Dashboard"),
    ("≋", "Live Packets"),
    ("◑", "Charts"),
    ("⚑", "Alerts"),
    ("⊞", "Summary"),
]

class Sidebar(tk.Frame):
    def __init__(self, parent, on_select=None, **kw):
        super().__init__(parent, bg=BG_PANEL, width=62,
                         highlightthickness=1, highlightbackground=BORDER, **kw)
        self.pack_propagate(False)
        self._on_select = on_select or (lambda i: None)
        self._selected  = 0
        self._btns      = []
        self._build()

    def _build(self):
        # Logo strip
        logo = tk.Label(self, text="NT\nA", font=mono(8,"bold"),
                        bg=ACCENT_DIM, fg=ACCENT, width=4, pady=10)
        logo.pack(fill="x")

        # Separator
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # Nav buttons
        for i, (icon, label) in enumerate(NAV_ITEMS):
            btn = tk.Label(self, text=icon, font=(FONT_MONO, 18),
                           bg=BG_PANEL, fg=TEXT_MUTED,
                           cursor="hand2", pady=14)
            btn.pack(fill="x")
            btn.bind("<Button-1>", lambda e, idx=i: self._select(idx))
            btn.bind("<Enter>",    lambda e, b=btn, idx=i: self._hover(b, idx, True))
            btn.bind("<Leave>",    lambda e, b=btn, idx=i: self._hover(b, idx, False))
            self._btns.append(btn)

        self._select(0)

        # Bottom: separator + pps label
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", side="bottom", pady=(0,0))
        self._pps_var = tk.StringVar(value="0\npps")
        tk.Label(self, textvariable=self._pps_var, font=mono(7),
                 bg=BG_PANEL, fg=TEXT_MUTED, pady=10).pack(side="bottom", fill="x")

    def _select(self, idx):
        for i, btn in enumerate(self._btns):
            if i == idx:
                btn.config(fg=ACCENT, bg=BG_RAISED)
            else:
                btn.config(fg=TEXT_MUTED, bg=BG_PANEL)
        self._selected = idx
        self._on_select(idx)

    def _hover(self, btn, idx, entering):
        if idx != self._selected:
            btn.config(bg=BG_HOVER if entering else BG_PANEL,
                       fg=TEXT_SEC if entering else TEXT_MUTED)

    def update_pps(self, pps):
        self._pps_var.set(f"{pps}\npps")