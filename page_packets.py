# page_packets.py — Live packet table with filter, search, sort, detail pane
import tkinter as tk
from tkinter import ttk
from theme import *

MAX_ROWS = 1000

class PacketPage(tk.Frame):
    COLS = ("no","time","src_ip","dst_ip","proto","sport","dport","size","flags","ttl","threat")
    HDRS = ("#","Time","Source IP","Dest IP","Proto","SPort","DPort","Bytes","Flags","TTL","Threat")
    WIDS = [42, 90, 120, 120, 65, 62, 62, 62, 52, 42, 90]

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._n   = 0
        self._all = []
        self._fp  = "ALL"
        self._sv  = tk.StringVar()
        self._build()

    def _build(self):
        from backend import PROTOCOLS

        # ── Filter bar ────────────────────────────────────────────────────────
        bar = tk.Frame(self, bg=PANEL,
                       highlightthickness=1, highlightbackground=BRD)
        bar.pack(fill="x")

        tk.Label(bar, text="  FILTER:", font=FMB,
                 bg=PANEL, fg=TEXT2).pack(side="left", pady=7)
        for p in ["ALL"] + PROTOCOLS:
            clr = PROTO_C.get(p, ACCENT)
            tk.Button(bar, text=p, font=("Consolas",7,"bold"),
                      bg=RAISED, fg=clr, relief="flat", cursor="hand2",
                      padx=7, pady=1, bd=0,
                      command=lambda x=p: self._fp_set(x)).pack(side="left", padx=2, pady=6)

        tk.Label(bar, text="  SEARCH:", font=FMB,
                 bg=PANEL, fg=TEXT2).pack(side="left", padx=(16,4))
        tk.Entry(bar, textvariable=self._sv,
                 bg=RAISED, fg=TEXT, insertbackground=ACCENT,
                 relief="flat", font=FM, width=20,
                 highlightthickness=1, highlightcolor=ACCENT,
                 highlightbackground=BRD).pack(side="left", pady=6)
        self._sv.trace_add("write", lambda *_: self._filter())

        self._cnt = tk.Label(bar, text="0 packets", font=FM, bg=PANEL, fg=TEXT2)
        self._cnt.pack(side="right", padx=12)

        # ── PanedWindow: table | detail ───────────────────────────────────────
        pw = tk.PanedWindow(self, orient="horizontal",
                            bg=BG, sashwidth=5, sashrelief="flat", sashpad=0)
        pw.pack(fill="both", expand=True)

        # Table frame
        tf = tk.Frame(pw, bg=BG)
        pw.add(tf, minsize=500, stretch="always")

        style = ttk.Style()
        style.configure("PKT.Treeview",
            background=BG, foreground=TEXT, fieldbackground=BG,
            rowheight=23, font=FM, borderwidth=0)
        style.configure("PKT.Treeview.Heading",
            background=PANEL, foreground=TEXT2, relief="flat",
            font=FMB, borderwidth=0)
        style.map("PKT.Treeview",
            background=[("selected", RAISED)],
            foreground=[("selected", ACCENT)])

        self._tree = ttk.Treeview(tf, columns=self.COLS,
                                   show="headings", style="PKT.Treeview")
        for col, hdr, w in zip(self.COLS, self.HDRS, self.WIDS):
            self._tree.heading(col, text=hdr,
                               command=lambda c=col: self._sort(c))
            self._tree.column(col, width=w, anchor="center", stretch=False)

        for p, c in PROTO_C.items():
            self._tree.tag_configure(p, foreground=c)
        for t, c in THREAT_C.items():
            if t != "Normal":
                self._tree.tag_configure(f"T_{t}", foreground=c)
        self._tree.tag_configure("alt", background=CARD)

        vs = ttk.Scrollbar(tf, orient="vertical",   command=self._tree.yview)
        hs = ttk.Scrollbar(tf, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        tf.rowconfigure(0, weight=1); tf.columnconfigure(0, weight=1)
        self._tree.bind("<<TreeviewSelect>>", self._on_sel)

        # Detail pane
        df = tk.Frame(pw, bg=PANEL,
                      highlightthickness=1, highlightbackground=BRD)
        pw.add(df, minsize=200, stretch="never")
        tk.Label(df, text="PACKET DETAILS", font=FMB,
                 bg=PANEL, fg=TEXT2, pady=8).pack(fill="x", padx=10)
        tk.Frame(df, bg=BRD, height=1).pack(fill="x")
        self._det = tk.Text(df, bg=PANEL, fg=TEXT, font=FM, relief="flat",
                            padx=10, pady=8, wrap="word", state="disabled",
                            highlightthickness=0)
        self._det.pack(fill="both", expand=True)
        self._det.tag_config("key",   foreground=ACCENT)
        self._det.tag_config("val",   foreground=TEXT)
        self._det.tag_config("alert", foreground=RED)
        self._det.tag_config("hd",    foreground=TEXT2)

    # ── public ────────────────────────────────────────────────────────────────
    def add(self, pkt):
        self.after(0, self._ins, pkt)

    def clear(self):
        self._tree.delete(*self._tree.get_children())
        self._all.clear(); self._n = 0
        self._cnt.config(text="0 packets")

    # ── internal ──────────────────────────────────────────────────────────────
    def _ins(self, pkt):
        self._n += 1
        proto  = pkt.get("protocol", "TCP")
        threat = pkt.get("threat", "Normal")
        tags   = [proto] + ([] if threat == "Normal" else [f"T_{threat}"])
        if self._n % 2 == 0: tags.append("alt")

        vals = (self._n, pkt["timestamp"], pkt["src_ip"], pkt["dst_ip"],
                proto, pkt["src_port"], pkt["dst_port"], pkt["size"],
                pkt["flags"], pkt.get("ttl","—"), threat)
        iid  = self._tree.insert("", "end", values=vals, tags=tuple(tags))
        self._all.append((iid, pkt, vals))
        self._tree.see(iid)

        kids = self._tree.get_children()
        if len(kids) > MAX_ROWS:
            old = kids[0]; self._tree.delete(old)
            self._all = [x for x in self._all if x[0] != old]
        self._filter()

    def _fp_set(self, p):
        self._fp = p; self._filter()

    def _filter(self):
        srch = self._sv.get().lower(); vis = 0
        for iid, pkt, vals in self._all:
            ok = (self._fp == "ALL" or pkt.get("protocol") == self._fp) and \
                 (not srch or any(srch in str(v).lower() for v in vals))
            try:
                if ok: self._tree.reattach(iid, "", "end"); vis += 1
                else:  self._tree.detach(iid)
            except: pass
        self._cnt.config(text=f"{vis} packets")

    def _on_sel(self, _):
        sel = self._tree.selection()
        if not sel: return
        vals = self._tree.item(sel[0], "values")
        if not vals: return
        self._det.config(state="normal"); self._det.delete("1.0","end")
        self._det.insert("end", "━  Packet Info  ━\n\n", "hd")
        for k, v in zip(self.HDRS, vals):
            self._det.insert("end", f"  {k:<12}", "key")
            tag = "alert" if k=="Threat" and v not in ("Normal","—") else "val"
            self._det.insert("end", f"{v}\n", tag)
        self._det.config(state="disabled")

    def _sort(self, col):
        data = [(self._tree.set(i,col),i) for i in self._tree.get_children()]
        try:    data.sort(key=lambda x: int(x[0]))
        except: data.sort()
        for i, (_, iid) in enumerate(data): self._tree.move(iid,"",i)