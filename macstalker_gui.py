#!/usr/bin/env python3
"""macstalker GUI — a minimal Tkinter wrapper around macstalker.sh.

The GUI does not reimplement the scanner: it runs macstalker.sh as a
subprocess, answers its two stdin prompts (max MACs, workers), and displays
the scanner's event lines (PROGRESS| / FOUND| / SUMMARY|) in a log.

Note on the proxy file: macstalker.sh generates and tests MACs directly and
does not itself use a proxy list. The .txt file is selected here (and passed
to the script as $2, which only verifies it is readable) so the file is
recorded with the scan.

Fedora: dnf install -y python3-tk bash curl jq
Run:    python3 macstalker_gui.py
"""

import os
import queue
import re
import signal
import subprocess
import threading
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "macstalker.sh")

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text):
    return ANSI_RE.sub("", text)


class MacstalkerApp:
    def __init__(self, root):
        self.root = root
        self.queue = queue.Queue()
        self.proc = None
        self.proxy_file = None
        self.scanning = False
        self.mac_count = 0
        self._closing = False
        self._destroyed = False

        root.title("macstalker — Stalker Portal MAC scanner")
        root.geometry("820x560")
        root.minsize(640, 420)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_ui()
        self.root.after(100, self.poll_queue)

    # ---------- UI construction ----------

    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}

        # Row 1: proxy .txt file selection
        file_frame = ttk.Frame(self.root)
        file_frame.pack(fill="x")
        file_frame.pack_configure(**pad)
        ttk.Label(file_frame, text="Proxy .txt file:").pack(side="left")
        self.file_button = ttk.Button(file_frame, text="Choose file…", command=self.on_choose_file)
        self.file_button.pack(side="left", padx=(6, 0))
        self.file_label = ttk.Label(file_frame, text="(none selected)", foreground="#555")
        self.file_label.pack(side="left", padx=(6, 0))
        ttk.Label(
            file_frame,
            text="  — the scanner itself tests MACs directly and does not use proxies; "
                 "the file is only verified to be readable",
            foreground="#555",
        ).pack(side="left")

        # Row 2: scan parameters (same prompts macstalker.sh asks on stdin)
        params = ttk.Frame(self.root)
        params.pack(fill="x")
        params.pack_configure(**pad)
        ttk.Label(params, text="Portal URL:").pack(side="left")
        self.url_entry = ttk.Entry(params)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(6, 12))
        ttk.Label(params, text="MACs to find:").pack(side="left")
        self.max_entry = ttk.Entry(params, width=8)
        self.max_entry.insert(0, "1")
        self.max_entry.pack(side="left", padx=(6, 12))
        ttk.Label(params, text="Workers:").pack(side="left")
        self.workers_entry = ttk.Entry(params, width=5)
        self.workers_entry.insert(0, "10")
        self.workers_entry.pack(side="left", padx=6)

        # Row 3: Start / Stop
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill="x")
        btn_frame.pack_configure(**pad)
        self.start_button = ttk.Button(btn_frame, text="Start scan", command=self.on_start)
        self.start_button.pack(side="left")
        self.start_button.config(state="disabled")
        self.stop_button = ttk.Button(btn_frame, text="Stop", command=self.on_stop, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.status_label = ttk.Label(btn_frame, text="Ready")
        self.status_label.pack(side="left", padx=(12, 0))

        # Row 4: activity indicator
        self.activity_bar = ttk.Progressbar(self.root, maximum=100)
        self.activity_bar.pack(fill="x", padx=8)

        # Row 5: log
        log_frame = ttk.Frame(self.root)
        log_frame.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        self.log = tk.Text(log_frame, state="disabled", wrap="word", height=14,
                           background="#101418", foreground="#d8dee9")
        self.log.tag_config("found", foreground="#a7e08f")
        self.log.tag_config("summary", foreground="#81c7ff")
        self.log.tag_config("error", foreground="#e06c75")
        self.log.tag_config("info", foreground="#7f8896")
        self.log.pack(fill="both", expand=True)

        self._update_start_state()

    # ---------- helpers ----------

    def log_line(self, text, tag=None):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")
        self.log.config(state="disabled")

    def set_scanning(self, active):
        self.scanning = active
        self.start_button.config(state="disabled" if active else "normal")
        self.stop_button.config(state="normal" if active else "disabled")
        self.file_button.config(state="disabled" if active else "normal")
        if active:
            self.activity_bar.config(mode="indeterminate")
            self.activity_bar.start()
        else:
            self.activity_bar.config(mode="determinate")
            self.activity_bar.stop()
        self._update_start_state()

    def _update_start_state(self):
        # Start is available only when a file is selected and no scan runs;
        # URL validity is checked (with an error message) in on_start().
        valid = bool(self.proxy_file) and not self.scanning
        self.start_button.config(state="normal" if valid else "disabled")

    def on_close(self):
        if self._closing:
            return
        if self.scanning:
            self._closing = True
            self.log_line("Closing: stopping scan…", "info")
            self._kill_proc()
        self._destroy_window()

    def _destroy_window(self):
        self._destroyed = True
        self.root.destroy()

    def _kill_proc(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    # ---------- file selection ----------

    def on_choose_file(self):
        path = filedialog.askopenfilename(
            title="Choose the .txt proxy list",
            filetypes=[("Text files", "*.txt"), ("All files", "*")],
        )
        if not path:
            return
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            self._set_proxy_file(None)
            self.log_line(f"Cannot read file: {exc}", "error")
            return
        if size == 0:
            self._set_proxy_file(None)
            self.log_line("File is empty — please choose a file that contains proxy lines.", "error")
            return
        self._set_proxy_file(path)
        self.log_line(f"Loaded {os.path.basename(path)} ({size} bytes).", "info")

    def _set_proxy_file(self, path):
        self.proxy_file = path
        self.file_label.config(
            text=os.path.basename(path) if path else "(none selected)",
            foreground="" if path else "#555",
        )
        self._update_start_state()

    # ---------- scan ----------

    def on_start(self):
        if self.scanning:
            return
        url = self.url_entry.get().strip()
        if not url.startswith(("http://", "https://")) or len(url) <= 8:
            self.log_line("Enter a complete portal URL, e.g. http://1.2.3.4:8080", "error")
            return
        try:
            max_success = int(self.max_entry.get().strip())
            if max_success < 1:
                raise ValueError
            workers = int(self.workers_entry.get().strip())
            if workers < 1:
                raise ValueError
        except ValueError:
            self.log_line('"MACs to find" and "Workers" must be positive integers.', "error")
            return

        self.mac_count = 0
        self.log_line(f"--- Scan started: {url} (stop after {max_success} MAC, {workers} workers) ---", "info")
        self.set_scanning(True)
        threading.Thread(target=self._scan_worker,
                          args=(url, self.proxy_file, max_success, workers), daemon=True).start()

    def _scan_worker(self, url, proxy_file, max_success, workers):
        def put(item):
            if not self._destroyed:
                self.queue.put(item)

        try:
            proc = subprocess.Popen(
                ["bash", SCRIPT, url, proxy_file],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            self.queue.put(("error", f"Could not start macstalker.sh: {exc}"))
            return
        self.proc = proc
        try:
            # The two lines answer macstalker.sh's stdin prompts
            # ("How many MACs do you want to find?" / "Parallel workers?").
            proc.stdin.write(f"{max_success}\n{workers}\n")
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass

        for line in proc.stdout:
            line = line.rstrip("\r\n")
            line = strip_ansi(line)
            if not line or line == "\x1b[2K":
                continue
            if line.startswith("PROGRESS|"):
                self._handle_progress(line[len("PROGRESS|"):])
            elif line.startswith("FOUND|"):
                put(("found", line[len("FOUND|"):]))
            elif line.startswith("SUMMARY|"):
                put(("summary", line[len("SUMMARY|"):]))
            elif "Proxy file" in line or line.startswith("Usage:"):
                put(("error", line))
            else:
                # Prompts, "Target reached", scanner stderr output, …
                put(("info", line))
        code = proc.wait()
        put(("done", code))

    def _handle_progress(self, text):
        # "found: <mac> [phone]  Live:.. VOD:.. Series:.." or
        # "scanning: <mac> [reason]" — one line per attempted MAC.
        if text.startswith("found: "):
            self.mac_count += 1
        self.queue.put(("progress", text))

    def on_stop(self):
        if self.scanning:
            self.log_line("Stopping: Ctrl-C sent to scanner…", "info")
            # Interrupts the workers so macstalker.sh prints its summary.
            if self.proc and self.proc.poll() is None:
                try:
                    self.proc.send_signal(signal.SIGINT)
                except OSError:
                    self._kill_proc()
            else:
                self._kill_proc()

    # ---------- main loop plumbing ----------

    def poll_queue(self):
        try:
            for _ in range(100):
                item = self.queue.get_nowait()
                if item[0] == "done":
                    self._on_scan_done(item[1])
                else:
                    self._handle_event(item)
        except queue.Empty:
            pass
        if not self._destroyed:
            self.root.after(100, self.poll_queue)

    def _handle_event(self, item):
        kind, text = item
        if kind == "progress":
            self.status_label.config(text=f"{self.mac_count} found — {text}")
        else:
            self.log_line(text, kind)
            if kind == "found":
                self.status_label.config(text=f"{self.mac_count} found")

    def _on_scan_done(self, code):
        self.set_scanning(False)
        if code == 0:
            self.log_line("Scan finished.", "info")
            self.status_label.config(text=f"Done — {self.mac_count} found")
        elif code in (1, 130, 137, 143):
            self.log_line("Scan stopped.", "info")
            self.status_label.config(text=f"Stopped — {self.mac_count} found")
        else:
            self.log_line(f"Scanner exited with code {code}.", "error")
            self.status_label.config(text="Error")


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass
    MacstalkerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
