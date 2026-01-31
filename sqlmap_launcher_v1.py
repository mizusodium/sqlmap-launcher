import sys
from pathlib import Path
import shlex
import re
import queue
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional

APP_TITLE = "SQLMap GUI Launcher"


TECHNIQUE_ORDER = "BEUSTQ"  # Boolean-based, Error-based, UNION, Stacked, Time-based, Inline

# Default to sqlmap.py in the same folder as this launcher (absolute path)
LAUNCHER_DIR = Path(__file__).resolve().parent
DEFAULT_SQLMAP_PATH = LAUNCHER_DIR / "sqlmap.py"


class SqlmapLauncher(tk.Tk):
    def _norm_win_path(self, p: str) -> str:
        p = (p or "").strip().strip('"')
        if not p:
            return p
        return str(Path(p))

    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x800")

        self.proc = None
        self.q = queue.Queue()

        # Track last ERROR/CRITICAL message (for popup)
        self.last_critical: Optional[str] = None
        self.last_error: Optional[str] = None
        self.severity_popup_shown = False
# ---------- Variables ----------
        self.sqlmap_path = tk.StringVar(value=str(DEFAULT_SQLMAP_PATH))  # or sqlmap.exe

        self.use_request_file = tk.BooleanVar(value=False)
        self.request_file = tk.StringVar(value="")
        self.url = tk.StringVar(value="")

        self.method = tk.StringVar(value="GET")
        self.data = tk.StringVar(value="")
        self.cookie = tk.StringVar(value="")

        self.level = tk.IntVar(value=1)
        self.risk = tk.IntVar(value=1)
        self.threads = tk.IntVar(value=10)
        self.timeout = tk.IntVar(value=30)
        self.retries = tk.IntVar(value=3)
        self.verbose = tk.IntVar(value=1)

        self.random_agent = tk.BooleanVar(value=True)
        self.flush_session = tk.BooleanVar(value=False)

        self.proxy = tk.StringVar(value="")
        self.output_dir = tk.StringVar(value="")

        self.tech_B = tk.BooleanVar(value=False)
        self.tech_E = tk.BooleanVar(value=False)
        self.tech_U = tk.BooleanVar(value=False)
        self.tech_S = tk.BooleanVar(value=False)
        self.tech_T = tk.BooleanVar(value=False)
        self.tech_Q = tk.BooleanVar(value=False)  # --technique checkboxes

        self.action = tk.StringVar(value="dbs")  # dbs/tables/columns/dump/custom
        self.db = tk.StringVar(value="")
        self.table = tk.StringVar(value="")
        self.columns = tk.StringVar(value="")  # comma-separated
        self.custom_args = tk.StringVar(value="")  # advanced

        # ---------- UI ----------
        self._build_ui()
        self._refresh_command_preview()
        self._poll_queue()

    # ---------------- UI Building ----------------
    def _build_ui(self):
        # ===== Root split: left controls / right (command preview + log) =====
        paned = ttk.Panedwindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=10, pady=8)

        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=3)
        paned.add(right, weight=2)

        # ---------------- Left: controls ----------------
        # Top: paths
        frm_paths = ttk.LabelFrame(left, text="Paths")
        frm_paths.pack(fill="x", pady=(0, 8))
        ttk.Label(frm_paths, text="sqlmap:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        ttk.Entry(frm_paths, textvariable=self.sqlmap_path, width=60).grid(row=0, column=1, sticky="we", padx=6, pady=6)
        ttk.Button(frm_paths, text="Browse", command=self._pick_sqlmap).grid(row=0, column=2, padx=6, pady=6)

        frm_paths.columnconfigure(1, weight=1)

        # Target
        frm_target = ttk.LabelFrame(left, text="Target")
        frm_target.pack(fill="x", pady=(0, 8))

        ttk.Checkbutton(
            frm_target,
            text="Use request file (-r)",
            variable=self.use_request_file,
            command=self._toggle_target_mode,
        ).grid(row=0, column=0, sticky="w", padx=6, pady=6)

        ttk.Label(frm_target, text="Request file:").grid(row=1, column=0, sticky="w", padx=6, pady=6)
        self.ent_request_file = ttk.Entry(frm_target, textvariable=self.request_file, width=70)
        self.ent_request_file.grid(row=1, column=1, sticky="we", padx=6, pady=6)
        self.btn_request_browse = ttk.Button(frm_target, text="Browse", command=self._pick_request)
        self.btn_request_browse.grid(row=1, column=2, padx=6, pady=6)

        ttk.Label(frm_target, text="URL:").grid(row=2, column=0, sticky="w", padx=6, pady=6)
        self.ent_url = ttk.Entry(frm_target, textvariable=self.url, width=70)
        self.ent_url.grid(row=2, column=1, sticky="we", padx=6, pady=6)

        ttk.Label(frm_target, text="Method:").grid(row=3, column=0, sticky="w", padx=6, pady=6)
        self.cmb_method = ttk.Combobox(
            frm_target,
            textvariable=self.method,
            values=["GET", "POST"],
            width=10,
            state="readonly",
        )
        self.cmb_method.grid(row=3, column=1, sticky="w", padx=6, pady=6)

        ttk.Label(frm_target, text="Data (POST):").grid(row=4, column=0, sticky="nw", padx=6, pady=6)
        self.txt_data = tk.Text(frm_target, height=4)
        self.txt_data.grid(row=4, column=1, sticky="we", padx=6, pady=6)
        self.txt_data.bind("<<Modified>>", lambda e: self._sync_text_to_var(self.txt_data, self.data))

        ttk.Label(frm_target, text="Cookie:").grid(row=5, column=0, sticky="w", padx=6, pady=6)
        ttk.Entry(frm_target, textvariable=self.cookie, width=70).grid(row=5, column=1, sticky="we", padx=6, pady=6)

        frm_target.columnconfigure(1, weight=1)

        # Options
        frm_opts = ttk.LabelFrame(left, text="Common Options")
        frm_opts.pack(fill="x", pady=(0, 8))

        row = 0
        ttk.Label(frm_opts, text="--level").grid(row=row, column=0, padx=6, pady=6, sticky="w")
        ttk.Spinbox(
            frm_opts, from_=1, to=5, textvariable=self.level, width=6, command=self._refresh_command_preview
        ).grid(row=row, column=1, padx=6, pady=6)

        ttk.Label(frm_opts, text="--risk").grid(row=row, column=2, padx=6, pady=6, sticky="w")
        ttk.Spinbox(
            frm_opts, from_=1, to=3, textvariable=self.risk, width=6, command=self._refresh_command_preview
        ).grid(row=row, column=3, padx=6, pady=6)

        ttk.Label(frm_opts, text="--threads").grid(row=row, column=4, padx=6, pady=6, sticky="w")
        ttk.Spinbox(
            frm_opts, from_=1, to=10, textvariable=self.threads, width=6, command=self._refresh_command_preview
        ).grid(row=row, column=5, padx=6, pady=6)

        row += 1
        ttk.Label(frm_opts, text="--timeout").grid(row=row, column=0, padx=6, pady=6, sticky="w")
        ttk.Spinbox(
            frm_opts, from_=5, to=300, textvariable=self.timeout, width=6, command=self._refresh_command_preview
        ).grid(row=row, column=1, padx=6, pady=6)

        ttk.Label(frm_opts, text="--retries").grid(row=row, column=2, padx=6, pady=6, sticky="w")
        ttk.Spinbox(
            frm_opts, from_=0, to=10, textvariable=self.retries, width=6, command=self._refresh_command_preview
        ).grid(row=row, column=3, padx=6, pady=6)

        ttk.Label(frm_opts, text="-v").grid(row=row, column=4, padx=6, pady=6, sticky="w")
        ttk.Spinbox(
            frm_opts, from_=0, to=6, textvariable=self.verbose, width=6, command=self._refresh_command_preview
        ).grid(row=row, column=5, padx=6, pady=6)

        row += 1
        ttk.Checkbutton(frm_opts, text="--random-agent", variable=self.random_agent, command=self._refresh_command_preview).grid(
            row=row, column=0, padx=6, pady=6, sticky="w"
        )
        ttk.Checkbutton(frm_opts, text="--flush-session", variable=self.flush_session, command=self._refresh_command_preview).grid(
            row=row, column=2, padx=6, pady=6, sticky="w"
        )

        ttk.Label(frm_opts, text="--proxy").grid(row=row, column=3, padx=6, pady=6, sticky="w")
        ttk.Entry(frm_opts, textvariable=self.proxy, width=28).grid(row=row, column=4, padx=6, pady=6, sticky="we")

        # technique (multi-select checkboxes)
        row += 1
        ttk.Label(frm_opts, text="--technique").grid(row=row, column=0, padx=6, pady=6, sticky="w")

        tech_frame = ttk.Frame(frm_opts)
        tech_frame.grid(row=row, column=1, columnspan=5, padx=6, pady=6, sticky="w")

        ttk.Checkbutton(tech_frame, text="B", variable=self.tech_B, command=self._refresh_command_preview).pack(side="left")
        ttk.Checkbutton(tech_frame, text="E", variable=self.tech_E, command=self._refresh_command_preview).pack(side="left", padx=(6,0))
        ttk.Checkbutton(tech_frame, text="U", variable=self.tech_U, command=self._refresh_command_preview).pack(side="left", padx=(6,0))
        ttk.Checkbutton(tech_frame, text="S", variable=self.tech_S, command=self._refresh_command_preview).pack(side="left", padx=(6,0))
        ttk.Checkbutton(tech_frame, text="T", variable=self.tech_T, command=self._refresh_command_preview).pack(side="left", padx=(6,0))
        ttk.Checkbutton(tech_frame, text="Q", variable=self.tech_Q, command=self._refresh_command_preview).pack(side="left", padx=(6,0))
        row += 1
        ttk.Label(frm_opts, text="--output-dir").grid(row=row, column=0, padx=6, pady=6, sticky="w")
        ttk.Entry(frm_opts, textvariable=self.output_dir, width=60).grid(row=row, column=1, columnspan=4, padx=6, pady=6, sticky="we")
        ttk.Button(frm_opts, text="Browse", command=self._pick_output_dir).grid(row=row, column=5, padx=6, pady=6)

        frm_opts.columnconfigure(4, weight=1)

        # Actions
        frm_action = ttk.LabelFrame(left, text="Action")
        frm_action.pack(fill="x", pady=(0, 8))

        ttk.Radiobutton(frm_action, text="--dbs", variable=self.action, value="dbs", command=self._refresh_command_preview).grid(
            row=0, column=0, padx=6, pady=6, sticky="w"
        )
        ttk.Radiobutton(frm_action, text="--tables (-D)", variable=self.action, value="tables", command=self._refresh_command_preview).grid(
            row=0, column=1, padx=6, pady=6, sticky="w"
        )
        ttk.Radiobutton(frm_action, text="--columns (-D -T)", variable=self.action, value="columns", command=self._refresh_command_preview).grid(
            row=0, column=2, padx=6, pady=6, sticky="w"
        )
        ttk.Radiobutton(frm_action, text="--dump (-D -T [-C])", variable=self.action, value="dump", command=self._refresh_command_preview).grid(
            row=0, column=3, padx=6, pady=6, sticky="w"
        )
        ttk.Radiobutton(frm_action, text="Custom args", variable=self.action, value="custom", command=self._refresh_command_preview).grid(
            row=0, column=4, padx=6, pady=6, sticky="w"
        )

        ttk.Label(frm_action, text="DB (-D):").grid(row=1, column=0, padx=6, pady=6, sticky="w")
        ttk.Entry(frm_action, textvariable=self.db, width=22).grid(row=1, column=1, padx=6, pady=6, sticky="w")
        ttk.Label(frm_action, text="Table (-T):").grid(row=1, column=2, padx=6, pady=6, sticky="w")
        ttk.Entry(frm_action, textvariable=self.table, width=22).grid(row=1, column=3, padx=6, pady=6, sticky="w")
        ttk.Label(frm_action, text="Columns (-C):").grid(row=2, column=0, padx=6, pady=6, sticky="w")
        ttk.Entry(frm_action, textvariable=self.columns, width=60).grid(
            row=2, column=1, columnspan=3, padx=6, pady=6, sticky="we"
        )

        ttk.Label(frm_action, text="Custom:").grid(row=3, column=0, padx=6, pady=6, sticky="w")
        ttk.Entry(frm_action, textvariable=self.custom_args, width=80).grid(
            row=3, column=1, columnspan=4, padx=6, pady=6, sticky="we"
        )

        frm_action.columnconfigure(3, weight=1)

        # Run controls (buttons only)

        # ---------------- Right: command preview + log ----------------
        frm_cmd = ttk.LabelFrame(right, text="Command preview")
        frm_cmd.pack(fill="x")

        self.cmd_preview = tk.Text(frm_cmd, height=5)
        self.cmd_preview.pack(fill="x", padx=6, pady=(6, 4))
        self.cmd_preview.configure(state="disabled")

        cmd_btns = ttk.Frame(frm_cmd)
        cmd_btns.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(cmd_btns, text="Run", command=self._run).pack(side="left", padx=(0, 8))
        ttk.Button(cmd_btns, text="Stop", command=self._stop).pack(side="left")

        frm_log = ttk.LabelFrame(right, text="Log")
        frm_log.pack(fill="both", expand=True)

        # Text + scrollbar live in their own frame so the scrollbar doesn't extend into the button bar.
        log_text_frame = ttk.Frame(frm_log)
        log_text_frame.pack(fill="both", expand=True, padx=6, pady=6)

        log_scroll = ttk.Scrollbar(log_text_frame, orient="vertical")
        log_scroll.pack(side="right", fill="y")

        self.output = tk.Text(log_text_frame, yscrollcommand=log_scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        log_scroll.config(command=self.output.yview)

        # Bottom-right actions
        log_btns = ttk.Frame(frm_log)
        log_btns.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(log_btns, text="Clear log", command=self._clear_log).pack(side="right")

        # Bind refresh on variable changes
        for v in [
            self.sqlmap_path,
            self.use_request_file,
            self.request_file,
            self.url,
            self.method,
            self.cookie,
            self.proxy,
            self.output_dir,
            self.db,
            self.table,
            self.columns,
            self.custom_args,
        ]:
            v.trace_add("write", lambda *args: self._refresh_command_preview())

        self.level.trace_add("write", lambda *args: self._refresh_command_preview())
        self.risk.trace_add("write", lambda *args: self._refresh_command_preview())
        self.threads.trace_add("write", lambda *args: self._refresh_command_preview())
        self.timeout.trace_add("write", lambda *args: self._refresh_command_preview())
        self.retries.trace_add("write", lambda *args: self._refresh_command_preview())
        self.verbose.trace_add("write", lambda *args: self._refresh_command_preview())
        self.random_agent.trace_add("write", lambda *args: self._refresh_command_preview())
        self.flush_session.trace_add("write", lambda *args: self._refresh_command_preview())
        self.action.trace_add("write", lambda *args: self._refresh_command_preview())

        self._toggle_target_mode()

    # ---------------- Helpers ----------------
    def _sync_text_to_var(self, txt: tk.Text, var: tk.StringVar):
        if txt.edit_modified():
            var.set(txt.get("1.0", "end").strip())
            txt.edit_modified(False)

    def _toggle_target_mode(self):
        use_r = self.use_request_file.get()

        # Request file controls
        if hasattr(self, "ent_request_file") and hasattr(self, "btn_request_browse"):
            self.ent_request_file.configure(state="normal" if use_r else "disabled")
            self.btn_request_browse.configure(state="normal" if use_r else "disabled")

        # URL & method controls
        if hasattr(self, "ent_url"):
            self.ent_url.configure(state="disabled" if use_r else "normal")
        if hasattr(self, "cmb_method"):
            self.cmb_method.configure(state="disabled" if use_r else "readonly")

        # POST data textbox enabled only when needed
        if self.method.get() == "POST" and not use_r:
            self.txt_data.configure(state="normal")
        else:
            self.txt_data.configure(state="disabled")

    def _pick_sqlmap(self):
        path = filedialog.askopenfilename(title="Select sqlmap.py or sqlmap executable")
        if path:
            self.sqlmap_path.set(self._norm_win_path(path))

    def _pick_request(self):
        path = filedialog.askopenfilename(title="Select request file", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            self.request_file.set(self._norm_win_path(path))

    def _pick_output_dir(self):
        path = filedialog.askdirectory(title="Select output dir")
        if path:
            self.output_dir.set(self._norm_win_path(path))

    def _is_sqlmap_py(self):
        return self.sqlmap_path.get().lower().endswith(".py")

    def build_command_list(self, show_popup: bool = False):
        # basic validation
        use_r = self.use_request_file.get()
        if use_r:
            if not self._norm_win_path(self.request_file.get()):
                raise ValueError("You selected request file mode (-r), but no file is chosen.")
        else:
            if not self.url.get().strip():
                raise ValueError("Please input a target URL (or switch to request file mode).")

        cmd = []

        # hard limits / sanity checks (pop up only on explicit actions)
        self._enforce_limits(show_popup=show_popup)
        sqlmap = self._norm_win_path(self.sqlmap_path.get())

        if self._is_sqlmap_py():
            cmd += ["python", sqlmap]
        else:
            cmd += [sqlmap]

        # target
        if use_r:
            cmd += ["-r", self._norm_win_path(self.request_file.get())]
        else:
            cmd += ["-u", self.url.get().strip()]
            if self.method.get() == "POST":
                data = self.data.get().strip()
                if data:
                    cmd += ["--data", data]

        ck = self.cookie.get().strip()
        if ck:
            cmd += ["--cookie", ck]

        # common options (values already clamped by _enforce_limits)
        cmd += ["--level", str(int(self.level.get()))]
        cmd += ["--risk", str(int(self.risk.get()))]
        cmd += ["--threads", str(int(self.threads.get()))]
        cmd += ["--timeout", str(int(self.timeout.get()))]
        cmd += ["--retries", str(int(self.retries.get()))]
        cmd += ["-v", str(int(self.verbose.get()))]

        if self.random_agent.get():
            cmd += ["--random-agent"]
        cmd += ["--batch"]
        if self.flush_session.get():
            cmd += ["--flush-session"]

        proxy = self.proxy.get().strip()
        if proxy:
            cmd += ["--proxy", proxy]

        outdir = self._norm_win_path(self.output_dir.get())
        if outdir:
            cmd += ["--output-dir", outdir]

        tech_letters = []
        if self.tech_B.get(): tech_letters.append("B")
        if self.tech_E.get(): tech_letters.append("E")
        if self.tech_U.get(): tech_letters.append("U")
        if self.tech_S.get(): tech_letters.append("S")
        if self.tech_T.get(): tech_letters.append("T")
        if self.tech_Q.get(): tech_letters.append("Q")
        tech = "".join(tech_letters)
        if tech:
            cmd += ["--technique", tech]

        # action
        act = self.action.get()
        if act == "dbs":
            cmd += ["--dbs"]
        elif act == "tables":
            if self.db.get().strip():
                cmd += ["-D", self.db.get().strip(), "--tables"]
            else:
                cmd += ["--tables"]
        elif act == "columns":
            if self.db.get().strip():
                cmd += ["-D", self.db.get().strip()]
            if self.table.get().strip():
                cmd += ["-T", self.table.get().strip()]
            cmd += ["--columns"]
        elif act == "dump":
            if self.db.get().strip():
                cmd += ["-D", self.db.get().strip()]
            if self.table.get().strip():
                cmd += ["-T", self.table.get().strip()]
            cols = self.columns.get().strip()
            if cols:
                cmd += ["-C", cols]
            cmd += ["--dump"]
        elif act == "custom":
            extra = self.custom_args.get().strip()
            if extra:
                try:
                    # Support quoted args (Windows-friendly)
                    posix = not sys.platform.startswith("win")
                    cmd += shlex.split(extra, posix=posix)
                except ValueError as e:
                    raise ValueError(f"Custom args parse error: {e}")

        return cmd

    def _refresh_command_preview(self, show_popup: bool = False):
        try:
            self._toggle_target_mode()
            cmd = self.build_command_list(show_popup=show_popup)
            preview = " ".join(self._quote_if_needed(x) for x in cmd)
        except Exception as e:
            preview = f"(Command not ready) {e}"

        self.cmd_preview.configure(state="normal")
        self.cmd_preview.delete("1.0", "end")
        self.cmd_preview.insert("1.0", preview)
        self.cmd_preview.configure(state="disabled")

    def _quote_if_needed(self, s: str) -> str:
        if not s:
            return '""'
        if any(c.isspace() for c in s) or any(c in s for c in ['"', "'"]):
            return '"' + s.replace('"', '\\"') + '"'
        return s

    
    def _clamp_int_var(self, label: str, var: tk.Variable, min_v: int, max_v: int, changed: list):
        """Clamp an IntVar-like variable to [min_v, max_v]. Record any adjustment in changed."""
        try:
            val = int(var.get())
        except Exception:
            val = min_v
            changed.append(f"{label}: invalid -> {val}")
            var.set(val)
            return
        clamped = max(min_v, min(max_v, val))
        if clamped != val:
            changed.append(f"{label}: {val} -> {clamped}")
            var.set(clamped)

    def _enforce_limits(self, show_popup: bool = False):
        """Apply hard limits to parameters. Optionally pop up a warning if any adjustments were made."""
        changed = []

        # numeric ranges
        self._clamp_int_var("--level", self.level, 1, 5, changed)
        self._clamp_int_var("--risk", self.risk, 1, 3, changed)
        self._clamp_int_var("--threads", self.threads, 1, 10, changed)
        self._clamp_int_var("--timeout", self.timeout, 5, 300, changed)
        self._clamp_int_var("--retries", self.retries, 0, 10, changed)
        self._clamp_int_var("-v", self.verbose, 0, 6, changed)

        # enum-like safety (rare, but keeps things consistent if the var got corrupted)
        if self.method.get() not in ("GET", "POST"):
            old = self.method.get()
            self.method.set("GET")
            changed.append(f"Method: {old} -> GET")
        if self.action.get() not in ("dbs", "tables", "columns", "dump", "custom"):
            old = self.action.get()
            self.action.set("dbs")
            changed.append(f"Action: {old} -> dbs")

        if show_popup and changed:
            messagebox.showwarning(
                "Parameters adjusted",
                "Some parameters were out of allowed range and were adjusted automatically:\n\n"
                + "\n".join(f"- {x}" for x in changed),
            )

        return changed
# ---------------- Run/Stop ----------------
    def _run(self):
        if self.proc and self.proc.poll() is None:
            messagebox.showwarning("Running", "A process is already running.")
            return

        # Reset per-run state
        self.last_critical = None
        self.last_error = None
        self.severity_popup_shown = False

        try:
            cmd = self.build_command_list(show_popup=True)
        except Exception as e:
            messagebox.showerror("Invalid", str(e))
            return

        self.output.insert("end", "\n[RUN] " + " ".join(self._quote_if_needed(x) for x in cmd) + "\n")
        self.output.see("end")

        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                shell=False
            )
        except Exception as e:
            messagebox.showerror("Failed to start", str(e))
            return

        t = threading.Thread(target=self._reader_thread, daemon=True)
        t.start()

    def _reader_thread(self):
        try:
            # Defensive guard: in rare cases stdout can be None (or proc not fully initialized)
            stream = getattr(self.proc, "stdout", None)
            if not stream:
                self.q.put("[Reader error] No stdout stream available.\n")
                return

            for line in stream:
                self.q.put(line)

                # Capture last CRITICAL/ERROR line for popup (CRITICAL has priority)
                if "[CRITICAL]" in line:
                    # Ignore retry-related CRITICAL that is informational and would be noisy in a popup
                    if "sqlmap is going to retry the request(s)" in line.lower():
                        continue
                    msg = line.strip()
                    # Strip leading timestamp like "[23:38:38] " for popup clarity
                    msg = re.sub(r"^\[\d{2}:\d{2}:\d{2}\]\s*", "", msg)
                    self.last_critical = msg
                elif "[ERROR]" in line:
                    msg = line.strip()
                    msg = re.sub(r"^\[\d{2}:\d{2}:\d{2}\]\s*", "", msg)
                    # Only record ERROR if we haven't seen a CRITICAL (CRITICAL is more important)
                    if not self.last_critical:
                        self.last_error = msg
        except Exception as e:
            self.q.put(f"[Reader error] {e}\n")
        finally:
            code = self.proc.poll()
            self.q.put(f"\n[EXIT] code={code}\n")

            # Show popup only if ERROR/CRITICAL occurred
            if (self.last_critical or self.last_error) and not self.severity_popup_shown:
                self.after(0, self._show_severity_popup)

    def _show_severity_popup(self):
        """Show a single popup for ERROR/CRITICAL messages (once per run)."""
        if self.severity_popup_shown:
            return

        msg = self.last_critical or self.last_error
        if not msg:
            return

        title = "sqlmap CRITICAL" if self.last_critical else "sqlmap ERROR"
        messagebox.showerror(title, msg)
        self.severity_popup_shown = True

    def _clear_log(self):
        """Clear the log output panel."""
        try:
            self.output.delete("1.0", "end")
        except Exception:
            pass

    def _stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.output.insert("end", "\n[STOP] terminate() sent.\n")
                self.output.see("end")
            except Exception as e:
                messagebox.showerror("Stop failed", str(e))

    def _poll_queue(self):
        try:
            while True:
                line = self.q.get_nowait()
                self.output.insert("end", line)
                self.output.see("end")
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

if __name__ == "__main__":
    app = SqlmapLauncher()
    app.mainloop()
