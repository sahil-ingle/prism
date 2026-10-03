from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from pathlib import Path
from typing import Any

from . import __version__
from .config import load_settings
from .core.engine import IOCEngine
from .detector import detect_ioc
from .models import IOCType, Investigation, ProviderResult
from .providers.registry import build_providers


BG = "#0b0d10"
SURFACE = "#11151a"
SURFACE_2 = "#171c22"
BORDER = "#252c34"
TEXT = "#f2f5f7"
MUTED = "#89939e"
ACCENT = "#64d8a5"
ACCENT_DARK = "#163b2d"
RED = "#ff6b7a"
YELLOW = "#f3c969"
BLUE = "#73a7ff"


class PrismApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("PRISM — IOC Intelligence")
        self.geometry("1120x760")
        self.minsize(900, 620)
        self.configure(bg=BG)

        self._queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._busy = False
        self._last_investigation: Investigation | None = None
        self._provider_widgets: dict[str, tk.Frame] = {}
        self._provider_states: dict[str, str] = {}
        self._expected_providers: list[str] = []
        self._completed_providers: set[str] = set()
        self._skeleton_phase = 0
        self._skeleton_after: str | None = None

        self._configure_styles()
        self._build_ui()
        self.after(80, self._process_queue)
        self.bind("<Return>", lambda _event: self.start_lookup())
        self.bind("<Escape>", lambda _event: self.clear())

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Root.TFrame", background=BG)
        style.configure("Surface.TFrame", background=SURFACE)
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 26, "bold"))
        style.configure("Subtitle.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 10))
        style.configure("Section.TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 12, "bold"))
        style.configure("Card.TFrame", background=SURFACE)
        style.configure("CardTitle.TLabel", background=SURFACE, foreground=TEXT, font=("Segoe UI", 11, "bold"))
        style.configure("CardMeta.TLabel", background=SURFACE, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Body.TLabel", background=SURFACE, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=SURFACE, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Accent.TButton", background=ACCENT, foreground="#08100c", borderwidth=0, padding=(20, 10), font=("Segoe UI", 10, "bold"))
        style.map("Accent.TButton", background=[("active", "#7be2b5"), ("disabled", "#315c49")])
        style.configure("Ghost.TButton", background=SURFACE_2, foreground=TEXT, borderwidth=0, padding=(14, 9), font=("Segoe UI", 9, "bold"))
        style.map("Ghost.TButton", background=[("active", "#202832")])
        style.configure("Status.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("TScrollbar", troughcolor=BG, background=BORDER, bordercolor=BG, arrowcolor=MUTED)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, style="Root.TFrame", padding=(34, 28, 34, 20))
        root.pack(fill="both", expand=True)

        header = ttk.Frame(root, style="Root.TFrame")
        header.pack(fill="x")
        title_row = ttk.Frame(header, style="Root.TFrame")
        title_row.pack(fill="x")
        ttk.Label(title_row, text="PRISM", style="Title.TLabel").pack(side="left")
        ttk.Label(title_row, text=f"  v{__version__}", style="Subtitle.TLabel").pack(side="left", pady=(10, 0))
        ttk.Label(title_row, text="IOC INTELLIGENCE", style="Subtitle.TLabel").pack(side="right", pady=(10, 0))
        ttk.Label(header, text="Search an IP, domain, URL or file hash across your configured threat-intelligence sources.", style="Subtitle.TLabel").pack(anchor="w", pady=(3, 20))

        search = tk.Frame(root, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        search.pack(fill="x", pady=(0, 20))
        self.ioc_var = tk.StringVar()
        self.entry = tk.Entry(search, textvariable=self.ioc_var, bg=SURFACE, fg=TEXT, insertbackground=ACCENT, relief="flat", bd=0, font=("Segoe UI", 13), selectbackground=ACCENT_DARK)
        self.entry.pack(side="left", fill="x", expand=True, padx=(18, 8), pady=14)
        self.entry.insert(0, "")
        self.search_button = ttk.Button(search, text="Investigate", command=self.start_lookup, style="Accent.TButton")
        self.search_button.pack(side="right", padx=8, pady=8)
        self.clear_button = ttk.Button(search, text="Clear", command=self.clear, style="Ghost.TButton")
        self.clear_button.pack(side="right", padx=(0, 0), pady=8)

        toolbar = ttk.Frame(root, style="Root.TFrame")
        toolbar.pack(fill="x", pady=(0, 10))
        self.summary_var = tk.StringVar(value="Ready")
        ttk.Label(toolbar, textvariable=self.summary_var, style="Status.TLabel").pack(side="left")
        self.copy_button = ttk.Button(toolbar, text="Copy JSON", command=self.copy_json, style="Ghost.TButton", state="disabled")
        self.copy_button.pack(side="right")

        container = ttk.Frame(root, style="Root.TFrame")
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(container, bg=BG, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        self.results_frame = ttk.Frame(self.canvas, style="Root.TFrame")
        self.canvas_window = self.canvas.create_window((0, 0), window=self.results_frame, anchor="nw")
        self.results_frame.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self._resize_canvas_window)
        self.canvas.bind_all("<MouseWheel>", self._mousewheel)
        self._show_empty_state()

        ttk.Label(root, text="PRISM  •  Local desktop interface  •  ESC clears  •  ENTER investigates", style="Status.TLabel").pack(anchor="w", pady=(12, 0))
        self.entry.focus_set()

    def _resize_canvas_window(self, event: tk.Event) -> None:
        self.canvas.itemconfigure(self.canvas_window, width=event.width)

    def _mousewheel(self, event: tk.Event) -> None:
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _clear_results_frame(self) -> None:
        for child in self.results_frame.winfo_children():
            child.destroy()

    def _show_empty_state(self) -> None:
        self._clear_results_frame()
        frame = ttk.Frame(self.results_frame, style="Root.TFrame", padding=(12, 70))
        frame.pack(fill="both", expand=True)
        tk.Label(frame, text="◈", bg=BG, fg=ACCENT, font=("Segoe UI Symbol", 34)).pack()
        ttk.Label(frame, text="Enter an IOC to begin", style="Section.TLabel").pack(pady=(12, 4))
        ttk.Label(frame, text="Example: 8.8.8.8  •  google.com  •  https://example.com/path  •  SHA256", style="Subtitle.TLabel").pack()

    def clear(self) -> None:
        if self._busy:
            return
        self.ioc_var.set("")
        self.summary_var.set("Ready")
        self.copy_button.configure(state="disabled")
        self._last_investigation = None
        self._show_empty_state()
        self.entry.focus_set()

    def start_lookup(self) -> None:
        if self._busy:
            return
        value = self.ioc_var.get().strip()
        if not value:
            messagebox.showinfo("PRISM", "Enter an IOC to investigate.", parent=self)
            self.entry.focus_set()
            return

        try:
            detected = detect_ioc(value)
        except ValueError as exc:
            messagebox.showerror("Invalid IOC", str(exc), parent=self)
            return

        self._busy = True
        self.search_button.configure(state="disabled", text="Investigating…")
        self.clear_button.configure(state="disabled")
        self.copy_button.configure(state="disabled")
        self.summary_var.set(f"Investigating {detected.type.value.upper()}…")
        self._begin_investigation_view(detected.value, detected.type.value)

        threading.Thread(target=self._investigate_worker, args=(detected,), daemon=True).start()

    def _investigate_worker(self, ioc) -> None:
        try:
            settings = load_settings()
            engine = IOCEngine(build_providers(settings))
            investigation = engine.investigate(
                ioc,
                on_result=lambda result: self._queue.put(("result", result)),
            )
            self._queue.put(("done", investigation))
        except Exception as exc:
            self._queue.put(("error", exc))

    def _process_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "result":
                    self._display_provider_result(payload)
                elif kind == "done":
                    self._finish_investigation(payload)
                else:
                    self._display_error(payload)
        except queue.Empty:
            pass
        self.after(80, self._process_queue)

    def _show_loading(self, value: str, ioc_type: str) -> None:
        self._clear_results_frame()
        card = tk.Frame(self.results_frame, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", padx=2, pady=2)
        tk.Label(card, text="ANALYSIS", bg=SURFACE, fg=ACCENT, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=22, pady=(20, 4))
        tk.Label(card, text=value, bg=SURFACE, fg=TEXT, font=("Segoe UI", 14, "bold"), wraplength=900, justify="left").pack(anchor="w", padx=22)
        tk.Label(card, text=f"Detected as {ioc_type.upper()}  •  querying configured providers…", bg=SURFACE, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=22, pady=(5, 20))

    def _display_error(self, exc: Exception) -> None:
        self._busy = False
        self.search_button.configure(state="normal", text="Investigate")
        self.clear_button.configure(state="normal")
        self.summary_var.set("Investigation failed")
        self._clear_results_frame()
        tk.Label(self.results_frame, text=f"{type(exc).__name__}: {exc}", bg=SURFACE, fg=RED, font=("Segoe UI", 10), wraplength=900, justify="left", padx=22, pady=22).pack(fill="x", padx=2, pady=2)
        messagebox.showerror("PRISM error", str(exc), parent=self)

    def _display_results(self, investigation: Investigation) -> None:
        # Kept as a compatibility wrapper for callers that may still use the
        # old method. The live GUI uses _display_provider_result +
        # _finish_investigation so results appear independently.
        self._begin_investigation_view(investigation.ioc.value, investigation.ioc.type.value)
        for result in investigation.results:
            self._display_provider_result(result)
        self._finish_investigation(investigation)

    def _begin_investigation_view(self, value: str, ioc_type: str) -> None:
        self._clear_results_frame()
        self._provider_widgets.clear()
        self._provider_states.clear()
        self._completed_providers.clear()
        self._expected_providers.clear()
        if self._skeleton_after is not None:
            try:
                self.after_cancel(self._skeleton_after)
            except Exception:
                pass
            self._skeleton_after = None

        hero = tk.Frame(self.results_frame, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        hero.pack(fill="x", padx=2, pady=(2, 12))
        tk.Label(hero, text="IOC", bg=SURFACE, fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=22, pady=(17, 3))
        tk.Label(hero, text=value, bg=SURFACE, fg=TEXT, font=("Segoe UI", 16, "bold"), wraplength=950, justify="left").pack(anchor="w", padx=22)
        tk.Label(hero, text=ioc_type.upper(), bg=SURFACE, fg=ACCENT, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=22, pady=(4, 17))

        # Build the provider list immediately so every provider gets a live
        # skeleton. Each result card is then replaced independently as soon as
        # that provider finishes; a slow sandbox scan never hides fast results.
        try:
            settings = load_settings()
            providers = build_providers(settings)
            detected_type = next((item for item in IOCType if item.value == ioc_type), None)
            if detected_type is not None:
                self._expected_providers = [p.name for p in providers if p.supports(detected_type)]
        except Exception:
            # The worker will report the actual configuration error. Keep the
            # GUI useful by showing a generic preparation state meanwhile.
            self._expected_providers = []

        self.live_label = tk.Label(
            self.results_frame,
            text=self._progress_text(),
            bg=BG, fg=MUTED, font=("Segoe UI", 9),
        )
        self.live_label.pack(anchor="w", padx=4, pady=(0, 8))

        for provider_name in self._expected_providers:
            self._add_skeleton_card(provider_name)

        if self._expected_providers:
            self._skeleton_phase = 0
            self._animate_skeletons()
        else:
            self._show_preparing_card()

    def _progress_text(self) -> str:
        total = len(self._expected_providers)
        done = len(self._completed_providers)
        if total:
            return f"Working in parallel  •  {done}/{total} providers completed  •  live results appear below"
        return "Preparing configured providers…"

    def _show_preparing_card(self) -> None:
        card = tk.Frame(self.results_frame, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", padx=2, pady=5)
        tk.Label(card, text="PREPARING", bg=SURFACE, fg=ACCENT, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=20, pady=(16, 4))
        tk.Label(card, text="Loading configured threat-intelligence providers…", bg=SURFACE, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=20, pady=(0, 16))

    def _add_skeleton_card(self, provider_name: str) -> None:
        card = tk.Frame(self.results_frame, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", padx=2, pady=5)
        self._provider_widgets[provider_name] = card
        self._provider_states[provider_name] = "processing"

        top = tk.Frame(card, bg=SURFACE)
        top.pack(fill="x", padx=20, pady=(15, 8))
        tk.Label(top, text=provider_name, bg=SURFACE, fg=TEXT, font=("Segoe UI", 11, "bold")).pack(side="left")
        tk.Label(top, text="SCANNING", bg=SURFACE, fg=YELLOW, font=("Segoe UI", 8, "bold")).pack(side="right")

        body = tk.Frame(card, bg=SURFACE)
        body.pack(fill="x", padx=20, pady=(0, 16))
        skeletons = []
        for width in (0.82, 0.58, 0.70):
            bar = tk.Frame(body, bg="#20262d", height=10)
            bar.pack(fill="x", pady=4)
            bar.pack_propagate(False)
            # Keep a short inner segment so the loading state looks alive.
            inner = tk.Frame(bar, bg="#2c353e", width=280, height=10)
            inner.place(relx=0.0, rely=0, relheight=1.0, relwidth=0.24)
            skeletons.append(inner)
        card._skeleton_bars = skeletons  # type: ignore[attr-defined]

    def _animate_skeletons(self) -> None:
        if not self._busy:
            self._skeleton_after = None
            return
        self._skeleton_phase = (self._skeleton_phase + 1) % 24
        phase = self._skeleton_phase / 24.0
        for provider_name, card in list(self._provider_widgets.items()):
            if self._provider_states.get(provider_name) != "processing" or not card.winfo_exists():
                continue
            bars = getattr(card, "_skeleton_bars", [])
            for index, bar in enumerate(bars):
                if not bar.winfo_exists():
                    continue
                offset = (phase + index * 0.18) % 1.0
                bar.place(relx=offset * 0.76, rely=0, relheight=1.0, relwidth=0.24)
        self._skeleton_after = self.after(70, self._animate_skeletons)

    def _display_provider_result(self, result: ProviderResult) -> None:
        # Replace only this provider's skeleton. Other providers continue to
        # animate until their own callbacks arrive.
        self._completed_providers.add(result.provider)
        self._provider_states[result.provider] = result.status
        self._add_or_update_provider_card(result)
        completed = len(self._completed_providers)
        total = len(self._expected_providers) or completed
        self.summary_var.set(f"Live results  •  {completed}/{total} providers completed")
        if hasattr(self, "live_label") and self.live_label.winfo_exists():
            self.live_label.configure(text=self._progress_text())

    def _finish_investigation(self, investigation: Investigation) -> None:
        self._busy = False
        if self._skeleton_after is not None:
            try:
                self.after_cancel(self._skeleton_after)
            except Exception:
                pass
            self._skeleton_after = None
        self._last_investigation = investigation
        self.search_button.configure(state="normal", text="Investigate")
        self.clear_button.configure(state="normal")
        self.copy_button.configure(state="normal")

        completed = len(investigation.results)
        ok = sum(result.status == "success" for result in investigation.results)
        self.summary_var.set(
            f"{investigation.ioc.type.value.upper()}  •  {ok}/{completed} providers returned data"
        )
        if hasattr(self, "live_label") and self.live_label.winfo_exists():
            self.live_label.configure(
                text="Investigation complete • all configured providers have finished"
            )

    def _add_or_update_provider_card(self, result: ProviderResult) -> None:
        old_card = self._provider_widgets.get(result.provider)
        if old_card is None or not old_card.winfo_exists():
            card = tk.Frame(self.results_frame, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
            card.pack(fill="x", padx=2, pady=5)
            self._provider_widgets[result.provider] = card
        else:
            card = old_card
            for child in card.winfo_children():
                child.destroy()

        self._render_provider_card(card, result)

    def _add_provider_card(self, result: ProviderResult) -> None:
        card = tk.Frame(self.results_frame, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", padx=2, pady=5)
        self._render_provider_card(card, result)

    def _render_provider_card(self, card: tk.Frame, result: ProviderResult) -> None:
        top = tk.Frame(card, bg=SURFACE)
        top.pack(fill="x", padx=20, pady=(15, 5))
        tk.Label(top, text=result.provider, bg=SURFACE, fg=TEXT, font=("Segoe UI", 11, "bold")).pack(side="left")
        status = result.status.upper().replace("_", " ")
        status_color = ACCENT if result.status == "success" else YELLOW if result.status in {"not_found", "skipped", "processing"} else RED
        tk.Label(top, text=status, bg=SURFACE, fg=status_color, font=("Segoe UI", 8, "bold")).pack(side="right")

        if result.error:
            tk.Label(card, text=result.error, bg=SURFACE, fg=MUTED, font=("Segoe UI", 9), wraplength=920, justify="left").pack(anchor="w", padx=20, pady=(0, 15))

        if result.status in {"success", "processing", "not_found", "skipped"} and result.data:
            body = tk.Frame(card, bg=SURFACE)
            body.pack(fill="x", padx=20, pady=(0, 16))
            rows = self._flatten_for_display(result.data)
            for index, (key, value) in enumerate(rows):
                bg = SURFACE_2 if index % 2 == 0 else SURFACE
                row = tk.Frame(body, bg=bg)
                row.pack(fill="x")
                tk.Label(row, text=key, bg=bg, fg=MUTED, font=("Segoe UI", 9), anchor="w", width=24).pack(side="left", padx=10, pady=6)
                tk.Label(row, text=value, bg=bg, fg=TEXT, font=("Segoe UI", 9), anchor="w", justify="left", wraplength=680).pack(side="left", fill="x", expand=True, padx=(0, 10), pady=6)

    def _flatten_for_display(self, data: dict[str, Any]) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        for key, value in data.items():
            if value is None or value == "":
                continue
            label = str(key).replace("_", " ").title()
            if isinstance(value, (dict, list)):
                rendered = json.dumps(value, ensure_ascii=False, default=str)
                if len(rendered) > 1200:
                    rendered = rendered[:1197] + "…"
            else:
                rendered = str(value)
            rows.append((label, rendered))
        return rows or [("Result", "No displayable fields returned.")]

    def copy_json(self) -> None:
        if not self._last_investigation:
            return
        payload = {
            "ioc": self._last_investigation.ioc.value,
            "type": self._last_investigation.ioc.type.value,
            "providers": [
                {"provider": r.provider, "status": r.status, "data": r.data, "error": r.error}
                for r in self._last_investigation.results
            ],
        }
        self.clipboard_clear()
        self.clipboard_append(json.dumps(payload, indent=2, default=str))
        self.update()
        self.summary_var.set("JSON copied to clipboard")


def main() -> None:
    app = PrismApp()
    app.mainloop()


if __name__ == "__main__":
    main()
