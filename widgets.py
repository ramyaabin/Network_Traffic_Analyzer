# widgets.py — Reusable small widgets: Sparkline, StatCard
import tkinter as tk
from theme import CARD, BRD, TEXT2, FMT, FMS

class Spark(tk.Canvas):
    """Tiny animated line graph embedded in a stat card."""
    def __init__(self, parent, color, **kw):
        super().__init__(parent, bg=CARD, height=28, highlightthickness=0, **kw)
        self._color = color
        self._data  = []
        self.bind("<Configure>", lambda e: self._draw())

    def push(self, v):
        self._data.append(float(v))
        if len(self._data) > 50:
            self._data.pop(0)
        self._draw()

    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 4 or len(self._data) < 2:
            return
        mn, mx = min(self._data), max(self._data)
        rng  = mx - mn or 1
        step = w / max(len(self._data) - 1, 1)
        pts  = []
        for i, v in enumerate(self._data):
            pts += [i * step, h - 3 - int((v - mn) / rng * (h - 6))]
        self.create_line(*pts, fill=self._color, width=1.5, smooth=True)
        lx, ly = pts[-2], pts[-1]
        self.create_oval(lx-3, ly-3, lx+3, ly+3, fill=self._color, outline="")


class StatCard(tk.Frame):
    """Coloured card: icon + label + big value + sparkline."""
    def __init__(self, parent, label, icon, color, **kw):
        super().__init__(parent, bg=CARD,
                         highlightthickness=1, highlightbackground=BRD, **kw)
        self._color = color

        top = tk.Frame(self, bg=CARD)
        top.pack(fill="x", padx=10, pady=(8, 0))
        tk.Label(top, text=icon, font=("Segoe UI Emoji", 13),
                 bg=CARD, fg=color).pack(side="left")
        tk.Label(top, text=f"  {label.upper()}", font=FMS,
                 bg=CARD, fg=TEXT2).pack(side="left")

        self._var = tk.StringVar(value="0")
        tk.Label(self, textvariable=self._var, font=FMT,
                 bg=CARD, fg=color).pack(anchor="w", padx=12)

        self._spark = Spark(self, color)
        self._spark.pack(fill="x", padx=8, pady=(2, 8))

    def set(self, value, raw=0):
        self._var.set(str(value))
        self._spark.push(raw)