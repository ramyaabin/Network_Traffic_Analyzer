"""
packet_table.py — Advanced live packet table with detail pane, search filter,
                  and colour-coded threat/protocol rows.
"""

import tkinter as tk
from tkinter import ttk
from theme import *

MAX_ROWS = 1000

THREAT_TAG_COLOR = {
    "Normal":    TEXT_PRI,
    "Port Scan": YELLOW,
    "DDoS":      RED,
    "ARP Spoof": ORANGE,
    "DNS Flood": PURPLE,
    "SYN Flood": RED,
}

class PacketTable(tk.Frame):
    COLS = ("no","time","src_ip","dst_ip","protocol","src_port","dst_port","size","flags","ttl","threat")
    HDRS = ("#","Time","Src IP","Dst IP","Protocol","S.Port","D.Port","Bytes","Flags","TTL","Threat")
    WIDS = [45,90,120,120,75,65,65,65,55,45,90]

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG_DEEP, **kw)
        self._row_count = 0
        self._all_items = []   # (iid, pkt) for filter
        self._filter_proto = "ALL"
        self._search_var   = tk.StringVar()
        self._build()

    def _build(self):
        # ── Filter bar ────────────────────────────────────────────────────────
        bar = tk.Frame(self, bg=BG_PANEL,
                       highlightthickness=1, highlightbackground=BORDER)
        bar.pack(fill="x", padx=0, pady=(0,2))

        tk.Label(bar, text="FILTER:", font=mono(8,"bold"),
                 bg=BG_PANEL, fg=TEXT_MUTED).pack(side="left", padx=8, pady=6)

        for proto in ["ALL","TCP","UDP","ICMP","HTTP","DNS","HTTPS"]:
            color = PROTO.get(proto, ACCENT) if proto != "ALL" else TEXT_SEC
            btn = tk.Button(bar, text=proto, font=mono(7,"bold"),
                            bg=BG_RAISED, fg=color, relief="flat",
                            cursor="hand2", padx=8, pady=2, bd=0,
                            command=lambda p=proto: self._set_filter(p))
            btn.pack(side="left", padx=2, pady=5)

        # Search box
        tk.Label(bar, text="SEARCH:", font=mono(8,"bold"),
                 bg=BG_PANEL, fg=TEXT_MUTED).pack(side="left", padx=(20,4))
        entry = tk.Entry(bar, textvariable=self._search_var,
                         bg=BG_RAISED, fg=TEXT_PRI, insertbackground=ACCENT,
                         relief="flat", font=mono(9), width=18,
                         highlightthickness=1, highlightcolor=ACCENT,
                         highlightbackground=BORDER)
        entry.pack(side="left", pady=6)
        self._search_var.trace_add("write", lambda *_: self._apply_filter())

        # Row count
        self._count_var = tk.StringVar(value="0 packets")
        tk.Label(bar, textvariable=self._count_var, font=mono(8),
                 bg=BG_PANEL, fg=TEXT_MUTED).pack(side="right", padx=12)

        # ── Paned: table | detail ─────────────────────────────────────────────
        paned = tk.PanedWindow(self, orient="horizontal",
                               bg=BG_DEEP, sashwidth=4, sashrelief="flat",
                               sashpad=0)
        paned.pack(fill="both", expand=True)

        # Table side
        table_frame = tk.Frame(paned, bg=BG_DEEP)
        paned.add(table_frame, minsize=500, stretch="always")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Adv.Treeview",
            background=BG_DEEP, foreground=TEXT_PRI,
            fieldbackground=BG_DEEP, rowheight=22,
            font=mono(8), borderwidth=0)
        style.configure("Adv.Treeview.Heading",
            background=BG_PANEL, foreground=TEXT_SEC,
            relief="flat", font=mono(8,"bold"), borderwidth=0)
        style.map("Adv.Treeview",
            background=[("selected", BG_RAISED)],
            foreground=[("selected", ACCENT)])

        self._tree = ttk.Treeview(table_frame, columns=self.COLS,
                                   show="headings", style="Adv.Treeview",
                                   selectmode="browse")
        for col, hdr, w in zip(self.COLS, self.HDRS, self.WIDS):
            self._tree.heading(col, text=hdr,
                               command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=w, anchor="center", stretch=False)

        # Tags
        for proto, clr in PROTO.items():
            self._tree.tag_configure(proto, foreground=clr)
        for threat, clr in THREAT_TAG_COLOR.items():
            if threat != "Normal":
                self._tree.tag_configure(f"T_{threat}", foreground=clr)
        self._tree.tag_configure("alt", background=BG_RAISED)

        vsb = ttk.Scrollbar(table_frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        # Detail pane
        detail_frame = tk.Frame(paned, bg=BG_PANEL,
                                highlightthickness=1, highlightbackground=BORDER)
        paned.add(detail_frame, minsize=200, stretch="never")
        tk.Label(detail_frame, text="PACKET DETAIL", font=mono(8,"bold"),
                 bg=BG_PANEL, fg=TEXT_MUTED, pady=8).pack(fill="x", padx=10)
        tk.Frame(detail_frame, bg=BORDER, height=1).pack(fill="x")
        self._detail_text = tk.Text(detail_frame, bg=BG_PANEL, fg=TEXT_PRI,
                                    font=mono(8), relief="flat", padx=10, pady=8,
                                    wrap="word", state="disabled",
                                    highlightthickness=0, insertbackground=ACCENT)
        self._detail_text.pack(fill="both", expand=True)
        self._detail_text.tag_config("key",   foreground=ACCENT)
        self._detail_text.tag_config("val",   foreground=TEXT_PRI)
        self._detail_text.tag_config("warn",  foreground=YELLOW)
        self._detail_text.tag_config("alert", foreground=RED)

    # ── public ───────────────────────────────────────────────────────────────
    def add_packet(self, pkt: dict):
        self.after(0, self._insert, pkt)

    def clear(self):
        self._tree.delete(*self._tree.get_children())
        self._all_items.clear()
        self._row_count = 0
        self._count_var.set("0 packets")

    # ── internal ─────────────────────────────────────────────────────────────
    def _insert(self, pkt: dict):
        self._row_count += 1
        proto  = pkt.get("protocol","TCP")
        threat = pkt.get("threat","Normal")

        tags = [proto]
        if threat != "Normal": tags.append(f"T_{threat}")
        if self._row_count % 2 == 0: tags.append("alt")

        values = (
            self._row_count, pkt["timestamp"],
            pkt["src_ip"],   pkt["dst_ip"],
            proto,           pkt["src_port"],
            pkt["dst_port"], pkt["size"],
            pkt["flags"],    pkt.get("ttl","—"),
            threat,
        )
        iid = self._tree.insert("", "end", values=values, tags=tuple(tags))
        self._all_items.append((iid, pkt, values))
        self._tree.see(iid)

        # prune
        if len(self._tree.get_children()) > MAX_ROWS:
            old = self._tree.get_children()[0]
            self._tree.delete(old)
            self._all_items = [(i,p,v) for i,p,v in self._all_items if i != old]

        self._apply_filter()

    def _set_filter(self, proto):
        self._filter_proto = proto
        self._apply_filter()

    def _apply_filter(self):
        search = self._search_var.get().lower()
        visible = 0
        for iid, pkt, values in self._all_items:
            proto  = pkt.get("protocol","")
            match_proto  = (self._filter_proto == "ALL" or proto == self._filter_proto)
            match_search = (not search or
                            any(search in str(v).lower() for v in values))
            try:
                if match_proto and match_search:
                    self._tree.reattach(iid, "", "end")
                    visible += 1
                else:
                    self._tree.detach(iid)
            except Exception:
                pass
        self._count_var.set(f"{visible} packets")

    def _on_select(self, _event):
        sel = self._tree.selection()
        if not sel: return
        vals = self._tree.item(sel[0], "values")
        if not vals: return
        keys = self.HDRS
        self._detail_text.config(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("end", "── Packet Info ──\n\n", "key")
        for k, v in zip(keys, vals):
            self._detail_text.insert("end", f"  {k:<10}: ", "key")
            tag = "alert" if k=="Threat" and v!="Normal" else "val"
            self._detail_text.insert("end", f"{v}\n", tag)
        self._detail_text.config(state="disabled")

    def _sort_by(self, col):
        data = [(self._tree.set(i, col), i) for i in self._tree.get_children()]
        try:    data.sort(key=lambda x: int(x[0]))
        except: data.sort()
        for idx, (_, iid) in enumerate(data):
            self._tree.move(iid, "", idx)