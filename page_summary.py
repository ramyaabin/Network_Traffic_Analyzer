# page_summary.py — Session summary table + CSV export
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv, datetime, os
from theme import *
import analyzer   # Jasmine's analysis & report-generation engine

class SummaryPage(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=PANEL,
                       highlightthickness=1, highlightbackground=BRD)
        hdr.pack(fill="x")
        tk.Label(hdr, text="  ⊞  SESSION SUMMARY", font=FMH,
                 bg=PANEL, fg=ACCENT, pady=10).pack(side="left")
        tk.Button(hdr, text="⬇  EXPORT CSV", font=FMB,
                  bg=RAISED, fg=GREEN, relief="flat",
                  cursor="hand2", padx=14, bd=0,
                  command=self._export).pack(side="right", padx=12, pady=8)
        tk.Button(hdr, text="📊  FULL REPORT (CSV+JSON)", font=FMB,
                  bg=RAISED, fg=ACCENT, relief="flat",
                  cursor="hand2", padx=14, bd=0,
                  command=self._export_full_report).pack(side="right", padx=4, pady=8)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=8, pady=8)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)

        # Left: key-value stats
        left = tk.Frame(body, bg=PANEL,
                        highlightthickness=1, highlightbackground=BRD)
        left.grid(row=0, column=0, sticky="nsew", padx=(0,4))
        tk.Label(left, text="SESSION STATS", font=FMB,
                 bg=PANEL, fg=TEXT2, pady=8).pack(fill="x", padx=12)
        tk.Frame(left, bg=BRD, height=1).pack(fill="x")
        self._kv = tk.Frame(left, bg=PANEL)
        self._kv.pack(fill="both", expand=True, padx=8, pady=8)

        # Right: protocol breakdown table
        right = tk.Frame(body, bg=PANEL,
                         highlightthickness=1, highlightbackground=BRD)
        right.grid(row=0, column=1, sticky="nsew", padx=(4,0))
        tk.Label(right, text="PROTOCOL BREAKDOWN", font=FMB,
                 bg=PANEL, fg=TEXT2, pady=8).pack(fill="x", padx=12)
        tk.Frame(right, bg=BRD, height=1).pack(fill="x")

        style = ttk.Style()
        style.configure("SUM.Treeview",
            background=PANEL, foreground=TEXT,
            fieldbackground=PANEL, rowheight=26, font=FM)
        style.configure("SUM.Treeview.Heading",
            background=RAISED, foreground=TEXT2, relief="flat", font=FMB)

        cols = ("proto","count","bytes","pct","avg")
        hdrs = ("Protocol","Packets","Total Bytes","%","Avg Size")
        wids = [90, 90, 110, 65, 90]
        tf = tk.Frame(right, bg=PANEL)
        tf.pack(fill="both", expand=True, padx=4, pady=4)
        self._stree = ttk.Treeview(tf, columns=cols,
                                    show="headings", style="SUM.Treeview", height=8)
        for col, hdr, w in zip(cols, hdrs, wids):
            self._stree.heading(col, text=hdr)
            self._stree.column(col, width=w, anchor="center")
        for p, c in PROTO_C.items():
            self._stree.tag_configure(p, foreground=c)
        vs = ttk.Scrollbar(tf, orient="vertical", command=self._stree.yview)
        self._stree.configure(yscrollcommand=vs.set)
        self._stree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

    def refresh(self, summary, proto_stats, packets):
        self.after(0, self._ref, summary, proto_stats, packets)

    def _ref(self, s, ps, pkts):
        for w in self._kv.winfo_children():
            w.destroy()
        tp = s.get("total", 0)
        tb = s.get("bytes", 0)
        rows = [
            ("Total Packets",    f"{tp:,}",                 ACCENT),
            ("Total Bytes",      fmt_bytes(tb),              PURPLE),
            ("Active Protocols", str(s.get("protos", 0)),   YELLOW),
            ("Top Protocol",     s.get("top", "—"),         ORANGE),
            ("Threat Alerts",    str(s.get("alerts", 0)),   RED),
            ("Capture Rate",     f"{s.get('pps',0)} pkt/s", GREEN),
        ]
        for i, (k, v, vc) in enumerate(rows):
            r = tk.Frame(self._kv, bg=PANEL if i%2==0 else RAISED)
            r.pack(fill="x", pady=1)
            tk.Label(r, text=f"  {k}", font=FM, bg=r["bg"],
                     fg=TEXT2, width=22, anchor="w").pack(side="left", pady=5)
            tk.Label(r, text=v, font=FMB, bg=r["bg"], fg=vc).pack(side="left")

        self._stree.delete(*self._stree.get_children())
        for proto in PROTO_C:
            cnt = ps.get(proto, 0)
            bts = sum(p["size"] for p in pkts if p.get("protocol") == proto)
            pct = f"{100*cnt/max(tp,1):.1f}%"
            avg = f"{bts//max(cnt,1)} B"
            self._stree.insert("", "end",
                values=(proto, cnt, fmt_bytes(bts), pct, avg),
                tags=(proto,))

    def _export(self):
        from backend import MON
        pkts = MON.packets
        if not pkts:
            messagebox.showinfo("Export", "No packets captured yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not path:
            return
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(pkts[0].keys()))
            w.writeheader(); w.writerows(pkts)
        messagebox.showinfo("Done", f"Saved {len(pkts):,} packets →\n{path}")

    def _export_full_report(self):
        """
        Generate the full traffic-analysis + anomaly report using Jasmine's
        analyzer.py engine (traffic_summary + run_anomaly_detection), instead
        of just dumping raw packets. This is the GUI's connection point into
        the analysis/report-generation module.
        """
        from backend import MON
        if not MON.packets:
            messagebox.showinfo("Full Report", "No packets captured yet.")
            return
        folder = filedialog.askdirectory(title="Choose folder to save the report")
        if not folder:
            return
        stamp     = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path  = os.path.join(folder, f"traffic_analysis_{stamp}.csv")
        json_path = os.path.join(folder, f"traffic_summary_{stamp}.json")
        try:
            analyzer.export_summary_to_csv(csv_path)
            analyzer.export_summary_to_json(json_path)
        except Exception as exc:
            messagebox.showerror("Report Failed", f"Could not generate report:\n{exc}")
            return
        report = analyzer.run_anomaly_detection()
        messagebox.showinfo(
            "Report Generated",
            f"Saved:\n{csv_path}\n{json_path}\n\n"
            f"{report['total_alerts']} anomaly alert(s) included in the JSON report."
        )