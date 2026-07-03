# header.py — Top header bar with Start/Stop/Clear buttons and live clock
import tkinter as tk
import time
from theme import PANEL, BRD, ACC2, ACCENT, GREEN, RED, YELLOW, RAISED, BRD2, MUTED, TEXT2, FMB, FM

class Header(tk.Frame):
    def __init__(self, parent, on_start, on_stop, on_clear, **kw):
        super().__init__(parent, bg=PANEL, height=50,
                         highlightthickness=1, highlightbackground=BRD, **kw)
        self.pack_propagate(False)
        self._on_start = on_start
        self._on_stop  = on_stop
        self._on_clear = on_clear
        self._running  = False
        self._build()

    def _build(self):
        # Coloured left bar
        tk.Frame(self, bg=ACC2, width=5).pack(side="left", fill="y")

        # Title
        tk.Label(self, text="  NTA ", font=("Consolas", 12, "bold"),
                 bg=PANEL, fg=ACCENT).pack(side="left")
        tk.Label(self, text="Network Traffic Analyzer",
                 font=FM, bg=PANEL, fg=TEXT2).pack(side="left")
        tk.Frame(self, bg=BRD, width=1).pack(side="left", fill="y", padx=10)

        # Status dot + label
        self._dot    = tk.Label(self, text="⬤", font=("Consolas", 11),
                                bg=PANEL, fg=MUTED)
        self._stlbl  = tk.Label(self, text=" IDLE", font=FMB,
                                bg=PANEL, fg=MUTED)
        self._dot.pack(side="left")
        self._stlbl.pack(side="left")

        # Right side: clock, packet count, buttons
        self._clk    = tk.Label(self, font=FM, bg=PANEL, fg=TEXT2)
        self._clk.pack(side="right", padx=14)

        self._pktlbl = tk.Label(self, text="0 packets", font=FM,
                                bg=PANEL, fg=TEXT2)
        self._pktlbl.pack(side="right", padx=12)

        self._bclear = self._btn("⟳  CLEAR",  RAISED,    YELLOW, self._do_clear)
        self._bstop  = self._btn("■  STOP",   "#2a0808", RED,    self._do_stop,  "disabled")
        self._bstart = self._btn("▶  START",  "#08280e", GREEN,  self._do_start)
        for b in (self._bclear, self._bstop, self._bstart):
            b.pack(side="right", padx=4, pady=8)

        self._tick()

    def _btn(self, text, bg, fg, cmd, state="normal"):
        return tk.Button(self, text=text, command=cmd,
                         bg=bg, fg=fg, activebackground=BRD2,
                         activeforeground=fg, relief="flat",
                         font=FMB, cursor="hand2",
                         padx=12, pady=2, bd=0, state=state,
                         disabledforeground=MUTED)

    def _do_start(self):
        self._running = True
        self._bstart.config(state="disabled")
        self._bstop.config(state="normal")
        self._dot.config(fg=GREEN)
        self._stlbl.config(text=" CAPTURING", fg=GREEN)
        self._on_start()

    def _do_stop(self):
        self._running = False
        self._bstart.config(state="normal")
        self._bstop.config(state="disabled")
        self._dot.config(fg=RED)
        self._stlbl.config(text=" STOPPED", fg=RED)
        self._on_stop()

    def _do_clear(self):
        if self._running:
            self._do_stop()
        self._dot.config(fg=MUTED)
        self._stlbl.config(text=" IDLE", fg=MUTED)
        self._pktlbl.config(text="0 packets")
        self._on_clear()

    def update_count(self, n):
        self._pktlbl.config(text=f"{n:,} packets")

    def _tick(self):
        self._clk.config(text=time.strftime("  %d %b %Y  %H:%M:%S  "))
        self.after(1000, self._tick)