from __future__ import annotations

import json
import queue
import re
import threading
import tkinter as tk
from datetime import datetime, timezone
from tkinter import font as tkfont
from tkinter import messagebox, ttk
from typing import Any

from . import __version__
from .config import load_settings
from .core.engine import IOCEngine
from .detector import detect_ioc
from .models import IOCType, Investigation, ProviderResult
from .providers.registry import build_providers

UI_FONT = "Segoe UI"
ICON_FONT = "Segoe UI Symbol"

# Title of the key-facts card at the top of the Overview tab.
SUMMARY_TITLE = "Analyst Details"

# (label, candidate keys, glyph). The first four that exist in the provider
# data are shown in the summary card, so file hashes show file facts, IPs show
# reputation / network facts, and so on.
SUMMARY_FIELDS: list[tuple[str, tuple[str, ...], str]] = [
    ("Last Analysis Date", ("last_analysis_date",), "▦"),
    ("Meaningful Name", ("meaningful_name",), "▤"),
    ("Size", ("size",), "☰"),
    ("Type Description", ("type_description",), "◇"),
    ("Malicious", ("malicious",), "☠"),
    ("Verdict", ("verdict",), "⚑"),
    ("Abuse Confidence", ("abuse_confidence_score",), "⚠"),
    ("Reputation", ("reputation",), "★"),
    ("Country", ("country", "country_code"), "⊕"),
    ("ISP / AS Owner", ("isp", "as_owner"), "⌂"),
    ("Registrar", ("registrar",), "✎"),
]

PROVIDER_GLYPHS = {
    "urlscan": "⊕",
    "urlquery": "∞",
    "virustotal": "◈",
    "abuseipdb": "⚑",
}


# ----------------------------------------------------------------------
# Small custom widgets (Tkinter has no rounded corners, so we draw them)
# ----------------------------------------------------------------------
def _rr_points(x1: float, y1: float, x2: float, y2: float, r: float) -> list[float]:
    r = max(0.0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    return [
        x1 + r, y1, x1 + r, y1, x2 - r, y1, x2 - r, y1,
        x2, y1, x2, y1 + r, x2, y1 + r, x2, y2 - r,
        x2, y2 - r, x2, y2, x2 - r, y2, x2 - r, y2,
        x1 + r, y2, x1 + r, y2, x1, y2, x1, y2 - r,
        x1, y2 - r, x1, y1 + r, x1, y1 + r, x1, y1,
    ]


class RoundedCard(tk.Canvas):
    """A rounded, optionally outlined container. Put children in ``.inner``."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        parent_bg: str,
        fill: str,
        outline: str | None = None,
        radius: int = 14,
        pad: int = 0,
        fit_height: bool = True,
        bleed_bottom: bool = False,
    ) -> None:
        super().__init__(master, bg=parent_bg, highlightthickness=0, bd=0, height=48)
        self._fill = fill
        self._outline = outline
        self._radius = radius
        self._pad = pad
        self._fit_height = fit_height
        self._bleed = bleed_bottom
        self.inner = tk.Frame(self, bg=fill)
        self._win = self.create_window(pad, pad, window=self.inner, anchor="nw")
        self.bind("<Configure>", self._on_canvas, add="+")
        self.inner.bind("<Configure>", self._on_inner, add="+")
        if fit_height:
            # A canvas never maps a window that lies outside its visible area,
            # so the inner <Configure> event alone cannot grow a tiny canvas.
            # Measure explicitly once geometry has settled.
            self.after_idle(self._sync_height)

    def _sync_height(self) -> None:
        try:
            if not self._fit_height or not self.winfo_exists():
                return
            self.inner.update_idletasks()
            need = self.inner.winfo_reqheight() + 2 * self._pad
            if int(self.cget("height")) != need:
                self.configure(height=need)
        except tk.TclError:
            pass

    def _on_canvas(self, event: tk.Event) -> None:
        w, h = event.width, event.height
        self.itemconfigure(self._win, width=max(1, w - 2 * self._pad))
        if not self._fit_height:
            self.itemconfigure(self._win, height=max(1, h - 2 * self._pad))
        self._redraw(w, h)

    def _on_inner(self, _event: tk.Event) -> None:
        if not self._fit_height:
            return
        need = self.inner.winfo_reqheight() + 2 * self._pad
        if int(self.cget("height")) != need:
            self.configure(height=need)

    def _redraw(self, w: int, h: int) -> None:
        self.delete("bg")
        y2 = h - 1 + (self._radius * 2 if self._bleed else 0)
        self.create_polygon(
            _rr_points(1, 1, w - 1, y2, self._radius),
            smooth=True, fill=self._fill,
            outline=self._outline or self._fill, width=1, tags="bg",
        )
        self.tag_lower("bg")

    def set_outline(self, color: str) -> None:
        self._outline = color
        self.itemconfigure("bg", outline=color)


class RoundButton(tk.Canvas):
    """Rounded button / pill. Set ``interactive=False`` for static pills."""

    def __init__(
        self,
        master: tk.Misc,
        text: str = "",
        command=None,
        *,
        style: dict[str, str],
        parent_bg: str,
        icon: str = "",
        font: tuple = (UI_FONT, 10, "bold"),
        icon_font: tuple = (ICON_FONT, 11),
        padx: int = 16,
        pady: int = 9,
        radius: int | None = None,
        interactive: bool = True,
        state: str = "normal",
    ) -> None:
        super().__init__(master, bg=parent_bg, highlightthickness=0, bd=0)
        self._style = style
        self._btn_text = text
        self._icon = icon
        self._command = command
        self._font = font
        self._icon_font = icon_font
        self._tf = tkfont.Font(root=self, font=font)
        self._icf = tkfont.Font(root=self, font=icon_font)
        self._padx = padx
        self._pady = pady
        self._radius = radius
        self._interactive = interactive
        self._btn_state = state
        self._hover = False
        if interactive:
            self.bind("<Enter>", self._on_enter)
            self.bind("<Leave>", self._on_leave)
            self.bind("<ButtonRelease-1>", self._on_release)
        self._paint()

    def configure(self, cnf=None, **kw):  # type: ignore[override]
        repaint = False
        if "state" in kw:
            self._btn_state = kw.pop("state")
            self._hover = False
            repaint = True
        if "text" in kw:
            self._btn_text = kw.pop("text")
            repaint = True
        result = None
        if cnf or kw:
            result = super().configure(cnf, **kw)
        elif not repaint:
            return super().configure()
        if repaint:
            self._paint()
        return result

    def _on_enter(self, _e: tk.Event) -> None:
        if self._btn_state == "normal":
            self._hover = True
            self._paint()

    def _on_leave(self, _e: tk.Event) -> None:
        self._hover = False
        self._paint()

    def _on_release(self, _e: tk.Event) -> None:
        if self._btn_state == "normal" and self._command:
            self._command()

    def _paint(self) -> None:
        st = self._style
        disabled = self._interactive and self._btn_state == "disabled"
        if disabled:
            fill = st.get("disabled_bg", st["bg"])
            fg = st.get("disabled_fg", st["fg"])
            outline = fill
        else:
            fill = st["hover"] if (self._hover and self._interactive) else st["bg"]
            fg = st["fg"]
            outline = st.get("border") or fill

        text_w = self._tf.measure(self._btn_text) if self._btn_text else 0
        icon_w = self._icf.measure(self._icon) if self._icon else 0
        gap = 8 if (self._icon and self._btn_text) else 0
        w = int(self._padx * 2 + icon_w + gap + text_w)
        h = int(max(self._tf.metrics("linespace"), self._icf.metrics("linespace"))
                + self._pady * 2)
        tk.Canvas.configure(
            self, width=w, height=h,
            cursor="hand2" if (self._interactive and not disabled) else "",
        )
        self.delete("all")
        r = h / 2 if self._radius is None else self._radius
        self.create_polygon(
            _rr_points(1, 1, w - 1, h - 1, r), smooth=True,
            fill=fill, outline=outline, width=1,
        )
        x = self._padx
        cy = h / 2
        if self._icon:
            self.create_text(x, cy, text=self._icon, fill=fg,
                             font=self._icon_font, anchor="w")
            x += icon_w + gap
        if self._btn_text:
            self.create_text(x, cy, text=self._btn_text, fill=fg,
                             font=self._font, anchor="w")


class IconBadge(tk.Canvas):
    """A square-rounded or circular badge with a glyph in the middle."""

    def __init__(
        self,
        master: tk.Misc,
        glyph: str,
        *,
        size: int = 36,
        fill: str,
        fg: str,
        parent_bg: str,
        outline: str | None = None,
        circle: bool = False,
        font: tuple = (ICON_FONT, 13),
    ) -> None:
        super().__init__(master, width=size, height=size, bg=parent_bg,
                         highlightthickness=0, bd=0)
        edge = outline or fill
        if circle:
            self.create_oval(1, 1, size - 2, size - 2, fill=fill, outline=edge)
        else:
            self.create_polygon(
                _rr_points(1, 1, size - 1, size - 1, size * 0.28),
                smooth=True, fill=fill, outline=edge,
            )
        self.create_text(size / 2, size / 2, text=glyph, fill=fg, font=font)


# ----------------------------------------------------------------------
# Main application
# ----------------------------------------------------------------------
class PrismApp(tk.Tk):
    """PRISM desktop UI.

    Native Tkinter only, so the same code works on Linux and Windows 11.
    Rounded corners, pills and badges are drawn on canvases. Provider work
    stays in background threads and each result renders as it arrives.
    """

    THEMES = {
        # Fully dark: every surface, card, entry and scrollbar.
        "dark": {
            "bg": "#101219", "header_text": "#f5f3fa", "header_muted": "#9a9db3",
            "pill": "#1e2130", "pill_hover": "#2a2e44",
            "panel": "#171a24", "card": "#1f2331", "card_alt": "#262b3d",
            "border": "#2e3347", "text": "#eceef7", "muted": "#9096ad",
            "accent": "#8b79f0", "accent_hover": "#a091f5", "accent_text": "#14101f",
            "accent_soft": "#2e2a55",
            "danger": "#f08a8e", "danger_bg": "#3a2228", "danger_hover": "#4a2a31",
            "danger_border": "#6b3a42",
            "success": "#5fd391", "success_bg": "#1f3a2e",
            "warning": "#e5c77d", "warning_bg": "#3a3220",
            "chip": "#2b3044", "chip_hover": "#2b3044",
            "disabled_bg": "#262a3a", "disabled_fg": "#5f647a",
            "skeleton": "#262a3b", "skeleton_hi": "#363b55",
            "scroll": "#343a52", "scroll_hover": "#454c6b",
        },
        # Fully light variant.
        "light": {
            "bg": "#eceef6", "header_text": "#1b1e2e", "header_muted": "#6b7088",
            "pill": "#dde0ee", "pill_hover": "#d0d4e6",
            "panel": "#ffffff", "card": "#ffffff", "card_alt": "#f5f6fa",
            "border": "#e1e4ee", "text": "#1b1e2e", "muted": "#6b7088",
            "accent": "#5b46d9", "accent_hover": "#6d5ae3", "accent_text": "#ffffff",
            "accent_soft": "#ebe8fc",
            "danger": "#e5484d", "danger_bg": "#fdecec", "danger_hover": "#fbd9d9",
            "danger_border": "#f3a9ab",
            "success": "#1f8f55", "success_bg": "#dcf5e5",
            "warning": "#b7791f", "warning_bg": "#fdf1d6",
            "chip": "#eceef4", "chip_hover": "#eceef4",
            "disabled_bg": "#e3e5ee", "disabled_fg": "#9a9db3",
            "skeleton": "#eceef4", "skeleton_hi": "#d9d4f6",
            "scroll": "#d5d8e4", "scroll_hover": "#bfc3d4",
        },
    }

    def __init__(self) -> None:
        super().__init__()
        self.title("PRISM — IOC Intelligence")
        self.geometry("1180x820")
        self.minsize(860, 600)
        self.resizable(True, True)

        self._queue: queue.Queue[tuple[str, int, Any]] = queue.Queue()
        self._busy = False
        self._cancel_event: threading.Event | None = None
        self._run_id = 0
        self._last_investigation: Investigation | None = None
        self._provider_widgets: dict[str, RoundedCard] = {}
        self._raw_provider_widgets: dict[str, RoundedCard] = {}
        self._provider_states: dict[str, str] = {}
        self._expected_providers: list[str] = []
        self._completed_providers: set[str] = set()
        self._results_by_provider: dict[str, ProviderResult] = {}
        self._current_ioc: tuple[str, str] | None = None
        self._current_type: str | None = None
        self._status_text = "Ready"
        self._active_tab = 0
        self._skeleton_phase = 0
        self._skeleton_after: str | None = None
        self._theme_name = "dark"
        self._theme = self.THEMES[self._theme_name]

        self.ioc_var = tk.StringVar()
        self.summary_var = tk.StringVar(value="Ready")

        self._configure_styles()
        self._apply_theme()
        self._build_ui()
        self._bind_mousewheel()
        self.bind("<Configure>", self._on_window_resize, add="+")
        self.after(80, self._process_queue)
        self.after(150, self._apply_native_titlebar)
        self.bind("<Return>", lambda _event: self.start_lookup())
        self.bind("<Escape>", lambda _event: self.stop_lookup() if self._busy else self.clear())

    def _on_window_resize(self, event: tk.Event) -> None:
        if event.widget is not self:
            return
        try:
            for canvas in (self.canvas, self.details_canvas):
                canvas.configure(scrollregion=canvas.bbox("all"))
        except (AttributeError, tk.TclError):
            pass

    # ------------------------------------------------------------------
    # Theme / styling
    # ------------------------------------------------------------------
    def _configure_styles(self) -> None:
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

    def _apply_theme(self) -> None:
        c = self._theme
        self.configure(bg=c["bg"])
        s = self.style
        s.configure(
            "Panel.Vertical.TScrollbar",
            troughcolor=c["panel"], background=c["scroll"], bordercolor=c["panel"],
            lightcolor=c["scroll"], darkcolor=c["scroll"], arrowcolor=c["panel"],
            relief="flat", arrowsize=6, gripcount=0,
        )
        s.map("Panel.Vertical.TScrollbar",
              background=[("active", c["scroll_hover"])])
        s.configure(
            "PRISM.Horizontal.TProgressbar",
            troughcolor=c["chip"], background=c["accent"], bordercolor=c["chip"],
            lightcolor=c["accent"], darkcolor=c["accent"], thickness=6,
        )
        self._apply_native_titlebar()

    def _btn_style(self, kind: str) -> dict[str, str]:
        c = self._theme
        base = {"disabled_bg": c["disabled_bg"], "disabled_fg": c["disabled_fg"]}
        styles = {
            "primary": dict(bg=c["accent"], fg=c["accent_text"], hover=c["accent_hover"]),
            "danger": dict(bg=c["danger_bg"], fg=c["danger"], hover=c["danger_hover"],
                           border=c["danger_border"]),
            "ghost": dict(bg=c["card"], fg=c["text"], hover=c["card_alt"],
                          border=c["border"]),
            "header": dict(bg=c["pill"], fg=c["header_text"], hover=c["pill_hover"]),
            "tag": dict(bg=c["pill"], fg=c["header_muted"], hover=c["pill"]),
            "accent": dict(bg=c["accent_soft"], fg=c["accent"], hover=c["accent_soft"]),
            "chip": dict(bg=c["chip"], fg=c["text"], hover=c["chip"]),
            "muted": dict(bg=c["chip"], fg=c["muted"], hover=c["chip"]),
            "success": dict(bg=c["success_bg"], fg=c["success"], hover=c["success_bg"]),
            "warning": dict(bg=c["warning_bg"], fg=c["warning"], hover=c["warning_bg"]),
            "error": dict(bg=c["danger_bg"], fg=c["danger"], hover=c["danger_bg"]),
        }
        return {**base, **styles[kind]}

    def _apply_native_titlebar(self) -> None:
        """Tint the native Windows 10/11 caption bar to match PRISM."""
        try:
            import ctypes
            import sys

            if sys.platform != "win32":
                return

            self.update_idletasks()
            child = self.winfo_id()
            hwnd = ctypes.windll.user32.GetParent(child) or child
            dark_mode = ctypes.c_int(1 if self._theme_name == "dark" else 0)

            def colorref(hex_color: str) -> ctypes.c_uint32:
                h = hex_color.lstrip("#")
                r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
                return ctypes.c_uint32(r | (g << 8) | (b << 16))  # 0x00BBGGRR

            caption = colorref(self._theme["bg"])
            caption_text = colorref(self._theme["header_text"])
            dwmapi = ctypes.windll.dwmapi
            # 20 = IMMERSIVE_DARK_MODE, 34 = CAPTION_COLOR, 36 = TEXT_COLOR
            for attr, value in ((20, dark_mode), (34, caption), (36, caption_text)):
                dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)
                )
        except Exception:
            pass

    def toggle_theme(self) -> None:
        if self._busy:
            return
        self._theme_name = "light" if self._theme_name == "dark" else "dark"
        self._theme = self.THEMES[self._theme_name]
        self._apply_theme()
        self.root_frame.destroy()
        self._build_ui()

    def _theme_button_label(self) -> str:
        return "Light  ⌄" if self._theme_name == "dark" else "Dark  ⌄"

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        c = self._theme
        root = tk.Frame(self, bg=c["bg"])
        root.pack(fill="both", expand=True)
        self.root_frame = root

        # ---- Header -------------------------------------------------
        header = tk.Frame(root, bg=c["bg"])
        header.pack(fill="x", padx=40, pady=(22, 18))

        title_row = tk.Frame(header, bg=c["bg"])
        title_row.pack(fill="x")
        left = tk.Frame(title_row, bg=c["bg"])
        left.pack(side="left")
        tk.Label(left, text="PRISM", bg=c["bg"], fg=c["header_text"],
                 font=(UI_FONT, 26, "bold")).pack(side="left")
        RoundButton(
            left, f"v{__version__}", style=self._btn_style("tag"), parent_bg=c["bg"],
            font=(UI_FONT, 10), padx=13, pady=4, interactive=False,
        ).pack(side="left", padx=(14, 0), pady=(6, 0))

        right = tk.Frame(title_row, bg=c["bg"])
        right.pack(side="right")
        tk.Label(right, text="IOC INTELLIGENCE", bg=c["bg"], fg=c["header_muted"],
                 font=(UI_FONT, 10)).pack(side="left", padx=(0, 18))
        self.theme_button = RoundButton(
            right, self._theme_button_label(), self.toggle_theme, icon="☀",
            style=self._btn_style("header"), parent_bg=c["bg"],
            font=(UI_FONT, 10, "bold"), padx=14, pady=7,
        )
        self.theme_button.pack(side="left")

        tk.Label(
            header, text="A calm workspace for checking IPs, domains, URLs and file hashes.",
            bg=c["bg"], fg=c["header_muted"], font=(UI_FONT, 10),
        ).pack(anchor="w", pady=(2, 0))

        # ---- Main rounded panel -------------------------------------
        panel = RoundedCard(
            root, parent_bg=c["bg"], fill=c["panel"], radius=22, pad=24,
            fit_height=False, bleed_bottom=True,
        )
        panel.pack(fill="both", expand=True, padx=16)
        body = panel.inner

        # Search surface
        self.search = RoundedCard(
            body, parent_bg=c["panel"], fill=c["card"], outline=c["border"],
            radius=14, pad=8,
        )
        self.search.pack(fill="x", pady=(0, 14))
        s = self.search.inner
        IconBadge(s, "◉", size=40, fill=c["accent_soft"], fg=c["accent"],
                  parent_bg=c["card"], font=(ICON_FONT, 14)).pack(side="left", padx=(2, 12))

        self.clear_button = RoundButton(
            s, "Clear", self.clear, icon="✕", style=self._btn_style("ghost"),
            parent_bg=c["card"], padx=18, pady=10,
        )
        self.clear_button.pack(side="right", padx=(8, 2))
        self.stop_button = RoundButton(
            s, "Stop", self.stop_lookup, icon="■", style=self._btn_style("danger"),
            parent_bg=c["card"], padx=18, pady=10, state="disabled",
        )
        self.stop_button.pack(side="right", padx=(8, 0))
        self.search_button = RoundButton(
            s, "Investigate", self.start_lookup, icon="⌕", style=self._btn_style("primary"),
            parent_bg=c["card"], padx=20, pady=10,
        )
        self.search_button.pack(side="right", padx=(8, 0))

        self.entry = tk.Entry(
            s, textvariable=self.ioc_var, bg=c["card"], fg=c["text"],
            insertbackground=c["accent"], relief="flat", bd=0, highlightthickness=0,
            font=(UI_FONT, 12), selectbackground=c["accent_soft"],
            selectforeground=c["text"],
        )
        self.entry.pack(side="left", fill="x", expand=True, ipady=8)
        self.entry.bind("<FocusIn>", lambda _e: self.search.set_outline(c["accent"]), add="+")
        self.entry.bind("<FocusOut>", lambda _e: self.search.set_outline(c["border"]), add="+")

        # Status row: type pill, summary, copy button
        toolbar = tk.Frame(body, bg=c["panel"])
        toolbar.pack(fill="x", pady=(0, 12))
        status_left = tk.Frame(toolbar, bg=c["panel"])
        status_left.pack(side="left")
        self.type_holder = tk.Frame(status_left, bg=c["panel"])
        self.type_holder.pack(side="left")
        tk.Label(status_left, textvariable=self.summary_var, bg=c["panel"],
                 fg=c["muted"], font=(UI_FONT, 10)).pack(side="left", padx=(10, 0))
        self.copy_button = RoundButton(
            toolbar, "Copy JSON", self.copy_json, icon="⧉",
            style=self._btn_style("ghost"), parent_bg=c["panel"],
            padx=16, pady=8, state="disabled",
        )
        self.copy_button.pack(side="right")

        # Tabs
        tabbar = tk.Frame(body, bg=c["panel"])
        tabbar.pack(fill="x")
        self._tab_labels: list[tk.Label] = []
        self._tab_lines: list[tk.Frame] = []
        for index, name in enumerate(("Overview", "Analyst Details")):
            tab = tk.Frame(tabbar, bg=c["panel"], cursor="hand2")
            tab.pack(side="left", padx=(12 if index == 0 else 6, 6))
            label = tk.Label(tab, text=name, bg=c["panel"], fg=c["muted"],
                             font=(UI_FONT, 11, "bold"), cursor="hand2", padx=8, pady=11)
            label.pack()
            line = tk.Frame(tab, height=3, bg=c["panel"])
            line.pack(fill="x")
            for widget in (tab, label, line):
                widget.bind("<Button-1>", lambda _e, i=index: self._select_tab(i))
            self._tab_labels.append(label)
            self._tab_lines.append(line)
        tk.Frame(body, height=1, bg=c["border"]).pack(fill="x")

        # Footer is packed before the result stack so it never gets pushed out.
        footer = tk.Frame(body, bg=c["panel"])
        footer.pack(side="bottom", fill="x", pady=(10, 0))
        tk.Label(footer, text="PRISM  •  ESC stops / clears  •  ENTER investigates",
                 bg=c["panel"], fg=c["muted"], font=(UI_FONT, 9)).pack(side="left")
        tk.Label(footer, text="Created by Sahil", bg=c["panel"], fg=c["muted"],
                 font=(UI_FONT, 9)).pack(side="right")

        # Result stack (Overview / Analyst Details)
        stack = tk.Frame(body, bg=c["panel"])
        stack.pack(fill="both", expand=True, pady=(12, 0))
        overview_tab = tk.Frame(stack, bg=c["panel"])
        details_tab = tk.Frame(stack, bg=c["panel"])
        self._tab_frames = [overview_tab, details_tab]
        self.canvas, self.results_frame = self._create_scroll_view(overview_tab)
        self.details_canvas, self.details_frame = self._create_scroll_view(details_tab)

        self._select_tab(self._active_tab)
        self._restore_view()
        self.entry.focus_set()

    def _select_tab(self, index: int) -> None:
        c = self._theme
        self._active_tab = index
        for i, frame in enumerate(self._tab_frames):
            if i == index:
                frame.pack(fill="both", expand=True)
            else:
                frame.pack_forget()
            self._tab_labels[i].configure(fg=c["accent"] if i == index else c["muted"])
            self._tab_lines[i].configure(bg=c["accent"] if i == index else c["panel"])
        self.after_idle(self._on_tab_changed)

    def _on_tab_changed(self) -> None:
        try:
            canvas = self.details_canvas if self._active_tab == 1 else self.canvas
            canvas.update_idletasks()
            canvas.configure(scrollregion=canvas.bbox("all"))
        except (tk.TclError, AttributeError):
            pass

    def _create_scroll_view(self, parent: tk.Frame) -> tuple[tk.Canvas, tk.Frame]:
        c = self._theme
        wrapper = tk.Frame(parent, bg=c["panel"])
        wrapper.pack(fill="both", expand=True)

        canvas = tk.Canvas(wrapper, bg=c["panel"], highlightthickness=0, bd=0,
                           relief="flat", yscrollincrement=24)
        scrollbar = ttk.Scrollbar(wrapper, orient="vertical", command=canvas.yview,
                                  style="Panel.Vertical.TScrollbar")
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        frame = tk.Frame(canvas, bg=c["panel"])
        window = canvas.create_window((0, 0), window=frame, anchor="nw")

        def update_scrollregion(_event=None) -> None:
            try:
                canvas.configure(scrollregion=canvas.bbox("all"))
            except tk.TclError:
                pass

        def update_width(event: tk.Event) -> None:
            try:
                canvas.itemconfigure(window, width=max(1, event.width))
                update_scrollregion()
            except tk.TclError:
                pass

        frame.bind("<Configure>", update_scrollregion, add="+")
        canvas.bind("<Configure>", update_width, add="+")
        return canvas, frame

    # ------------------------------------------------------------------
    # Mouse wheel
    # ------------------------------------------------------------------
    def _bind_mousewheel(self) -> None:
        self.bind_all("<MouseWheel>", self._global_mousewheel, add="+")
        self.bind_all("<Button-4>", self._global_mousewheel_linux_up, add="+")
        self.bind_all("<Button-5>", self._global_mousewheel_linux_down, add="+")

    def _canvas_from_widget(self, widget: tk.Misc | None) -> tk.Canvas | None:
        current = widget
        while current is not None:
            if current is self.canvas:
                return self.canvas
            if current is self.details_canvas:
                return self.details_canvas
            try:
                parent = current.master
            except (AttributeError, tk.TclError):
                break
            if parent is current:
                break
            current = parent
        try:
            return self.details_canvas if self._active_tab == 1 else self.canvas
        except (tk.TclError, AttributeError):
            return None

    def _scroll_canvas(self, canvas: tk.Canvas, units: int) -> None:
        try:
            first, last = canvas.yview()
            if first == 0.0 and last == 1.0:
                return
            canvas.yview_scroll(units, "units")
        except tk.TclError:
            pass

    def _global_mousewheel(self, event: tk.Event) -> str:
        canvas = self._canvas_from_widget(event.widget)
        if canvas is None:
            return "break"
        delta = int(getattr(event, "delta", 0))
        if delta == 0:
            return "break"
        if abs(delta) >= 120:
            units = -int(delta / 120) * 3
        else:
            units = -1 if delta > 0 else 1
        self._scroll_canvas(canvas, units)
        return "break"

    def _global_mousewheel_linux_up(self, event: tk.Event) -> str:
        canvas = self._canvas_from_widget(event.widget)
        if canvas is not None:
            self._scroll_canvas(canvas, -3)
        return "break"

    def _global_mousewheel_linux_down(self, event: tk.Event) -> str:
        canvas = self._canvas_from_widget(event.widget)
        if canvas is not None:
            self._scroll_canvas(canvas, 3)
        return "break"

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------
    def _set_status(self, text: str) -> None:
        self._status_text = text
        prefix = "•  " if self._current_type else ""
        self.summary_var.set(prefix + text)

    def _set_type_pill(self, ioc_type: str | None) -> None:
        self._current_type = ioc_type
        holder = getattr(self, "type_holder", None)
        if holder is not None and holder.winfo_exists():
            for child in holder.winfo_children():
                child.destroy()
            if ioc_type:
                RoundButton(
                    holder, ioc_type.upper(), style=self._btn_style("accent"),
                    parent_bg=self._theme["panel"], icon="◉",
                    font=(UI_FONT, 9, "bold"), icon_font=(ICON_FONT, 10),
                    padx=13, pady=6, interactive=False,
                ).pack()
        self._set_status(self._status_text)

    def _restore_view(self) -> None:
        """Re-render whatever state exists (used after building / theme change)."""
        self._set_type_pill(self._current_type)
        self.copy_button.configure(
            state="normal" if self._last_investigation is not None else "disabled"
        )
        if self._busy:
            self.search_button.configure(state="disabled", text="Investigating…")
            self.stop_button.configure(state="normal")
            self.clear_button.configure(state="disabled")
        if self._current_ioc is None:
            self._show_empty_state()
            return
        self._prepare_result_views()
        for result in self._results_by_provider.values():
            self._add_or_update_provider_card(result)
            self._add_or_update_raw_card(result)
        self._refresh_summary_card()

    # ------------------------------------------------------------------
    # Search lifecycle / cancellation
    # ------------------------------------------------------------------
    def _is_current(self, run_id: int) -> bool:
        return run_id == self._run_id

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

        self._run_id += 1
        run_id = self._run_id
        self._cancel_event = threading.Event()
        self._busy = True
        self._last_investigation = None
        self._results_by_provider.clear()
        self._current_ioc = (detected.value, detected.type.value)

        self.search_button.configure(state="disabled", text="Investigating…")
        self.stop_button.configure(state="normal")
        self.clear_button.configure(state="disabled")
        self.copy_button.configure(state="disabled")
        self.theme_button.configure(state="disabled")
        self._set_type_pill(detected.type.value)
        self._set_status("Investigating…")
        self._begin_investigation_view(detected.value, detected.type.value)

        threading.Thread(
            target=self._investigate_worker,
            args=(detected, run_id, self._cancel_event),
            daemon=True,
        ).start()

    def stop_lookup(self) -> None:
        if not self._busy:
            return

        # Render provider results already produced but still waiting in the
        # UI queue, so Stop never throws away a successful result.
        current_run = self._run_id
        pending: list[tuple[str, int, Any]] = []
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            kind, run_id, payload = item
            if run_id == current_run and kind == "result":
                self._display_provider_result(payload)
            else:
                pending.append(item)
        for item in pending:
            self._queue.put(item)

        self._run_id += 1
        if self._cancel_event is not None:
            self._cancel_event.set()

        self._busy = False
        self._cancel_skeleton()

        self.search_button.configure(state="normal", text="Investigate")
        self.stop_button.configure(state="disabled")
        self.clear_button.configure(state="normal")
        self.theme_button.configure(state="normal")
        self.copy_button.configure(state="disabled")
        self._set_status("Stopped — completed results kept")

        self._mark_unfinished_as_stopped()
        if hasattr(self, "live_label") and self.live_label.winfo_exists():
            completed = len(self._completed_providers)
            total = len(self._expected_providers) or completed
            self.live_label.configure(
                text=f"Stopped  •  {completed}/{total} providers completed  •  completed results preserved"
            )
        self.entry.focus_set()

    def _cancel_skeleton(self) -> None:
        if self._skeleton_after is not None:
            try:
                self.after_cancel(self._skeleton_after)
            except Exception:
                pass
            self._skeleton_after = None

    def _mark_unfinished_as_stopped(self) -> None:
        c = self._theme
        for provider_name, card in list(self._provider_widgets.items()):
            if self._provider_states.get(provider_name) != "processing":
                continue
            if not card.winfo_exists():
                continue
            self._provider_states[provider_name] = "stopped"
            for child in card.inner.winfo_children():
                child.destroy()
            self._provider_header(card.inner, provider_name, "stopped")
            tk.Label(
                card.inner, text="No result returned before the search was stopped.",
                bg=c["card"], fg=c["muted"], font=(UI_FONT, 10),
            ).pack(anchor="w", padx=18, pady=(0, 16))

    def clear(self) -> None:
        if self._busy:
            self.stop_lookup()
        self.ioc_var.set("")
        self._last_investigation = None
        self._results_by_provider.clear()
        self._current_ioc = None
        self._set_type_pill(None)
        self._set_status("Ready")
        self.copy_button.configure(state="disabled")
        self._show_empty_state()
        self.entry.focus_set()

    def _investigate_worker(self, ioc, run_id: int, cancel_event: threading.Event) -> None:
        try:
            settings = load_settings()
            if cancel_event.is_set():
                return
            engine = IOCEngine(build_providers(settings))
            investigation = engine.investigate(
                ioc,
                on_result=lambda result: self._queue.put(("result", run_id, result))
                if not cancel_event.is_set() else None,
            )
            if not cancel_event.is_set():
                self._queue.put(("done", run_id, investigation))
        except Exception as exc:
            if not cancel_event.is_set():
                self._queue.put(("error", run_id, exc))

    def _process_queue(self) -> None:
        try:
            while True:
                kind, run_id, payload = self._queue.get_nowait()
                if not self._is_current(run_id):
                    continue
                if kind == "result":
                    self._display_provider_result(payload)
                elif kind == "done":
                    self._finish_investigation(payload)
                else:
                    self._display_error(payload)
        except queue.Empty:
            pass
        self.after(80, self._process_queue)

    # ------------------------------------------------------------------
    # Result views
    # ------------------------------------------------------------------
    def _clear_results_frame(self) -> None:
        for child in self.results_frame.winfo_children():
            child.destroy()
        for child in self.details_frame.winfo_children():
            child.destroy()
        self._provider_widgets.clear()
        self._raw_provider_widgets.clear()

    def _new_card(self, parent: tk.Misc) -> RoundedCard:
        c = self._theme
        card = RoundedCard(parent, parent_bg=c["panel"], fill=c["card"],
                           outline=c["border"], radius=14, pad=1)
        card.pack(fill="x", padx=2, pady=6)
        return card

    def _show_empty_state(self) -> None:
        self._clear_results_frame()
        c = self._theme
        entries = (
            (self.results_frame, "Search an IOC",
             "Try 8.8.8.8  •  google.com  •  https://example.com/path  •  SHA256"),
            (self.details_frame, "Analyst Details",
             "Relevant investigation data, grouped for quick triage — without raw API noise or repeated fields."),
        )
        for parent, title, subtitle in entries:
            frame = tk.Frame(parent, bg=c["panel"])
            frame.pack(fill="both", expand=True, padx=12, pady=60)
            IconBadge(frame, "⌕", size=64, fill=c["accent_soft"], fg=c["accent"],
                      parent_bg=c["panel"], circle=True,
                      font=(ICON_FONT, 24)).pack()
            tk.Label(frame, text=title, bg=c["panel"], fg=c["text"],
                     font=(UI_FONT, 15, "bold")).pack(pady=(14, 5))
            tk.Label(frame, text=subtitle, bg=c["panel"], fg=c["muted"],
                     font=(UI_FONT, 10)).pack()

    def _prepare_result_views(self) -> None:
        """Reset both tabs and create the fixed top sections."""
        self._clear_results_frame()
        c = self._theme
        self.summary_holder = tk.Frame(self.results_frame, bg=c["panel"])
        self.summary_holder.pack(fill="x")
        self.progress_holder = tk.Frame(self.results_frame, bg=c["panel"])
        self.progress_holder.pack(fill="x")

        intro = RoundedCard(self.details_frame, parent_bg=c["panel"], fill=c["card_alt"],
                            outline=c["border"], radius=14, pad=1)
        intro.pack(fill="x", padx=2, pady=(2, 10))
        tk.Label(intro.inner, text="ANALYST DETAILS", bg=c["card_alt"], fg=c["accent"],
                 font=(UI_FONT, 8, "bold")).pack(anchor="w", padx=20, pady=(15, 3))
        tk.Label(intro.inner,
                 text="Curated provider findings grouped by what matters during IOC triage.",
                 bg=c["card_alt"], fg=c["text"], font=(UI_FONT, 11)).pack(
                     anchor="w", padx=20, pady=(0, 4))
        tk.Label(intro.inner,
                 text="Repeated query/source metadata and low-value API fields are intentionally omitted.",
                 bg=c["card_alt"], fg=c["muted"], font=(UI_FONT, 9)).pack(
                     anchor="w", padx=20, pady=(0, 15))

    def _begin_investigation_view(self, value: str, ioc_type: str) -> None:
        self._provider_states.clear()
        self._completed_providers.clear()
        self._expected_providers.clear()
        self._cancel_skeleton()
        self._prepare_result_views()

        try:
            settings = load_settings()
            providers = build_providers(settings)
            detected_type = next((item for item in IOCType if item.value == ioc_type), None)
            if detected_type is not None:
                self._expected_providers = [
                    p.name for p in providers if p.supports(detected_type)
                ]
        except Exception:
            self._expected_providers = []

        c = self._theme
        self.live_label = tk.Label(
            self.progress_holder, text=self._progress_text(),
            bg=c["panel"], fg=c["muted"], font=(UI_FONT, 9)
        )
        self.live_label.pack(anchor="w", padx=4, pady=(0, 6))
        self.progress_bar = ttk.Progressbar(
            self.progress_holder, mode="determinate",
            style="PRISM.Horizontal.TProgressbar",
            maximum=max(1, len(self._expected_providers)), value=0,
        )
        self.progress_bar.pack(fill="x", padx=2, pady=(0, 10))

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
            return f"Working in parallel  •  {done}/{total} complete"
        return "Preparing configured providers…"

    def _show_preparing_card(self) -> None:
        c = self._theme
        card = RoundedCard(self.progress_holder, parent_bg=c["panel"], fill=c["card"],
                           outline=c["border"], radius=14, pad=1)
        card.pack(fill="x", padx=2, pady=5)
        tk.Label(card.inner, text="PREPARING", bg=c["card"], fg=c["accent"],
                 font=(UI_FONT, 9, "bold")).pack(anchor="w", padx=20, pady=(16, 4))
        tk.Label(card.inner, text="Loading configured providers…", bg=c["card"],
                 fg=c["muted"], font=(UI_FONT, 10)).pack(anchor="w", padx=20, pady=(0, 16))

    def _add_skeleton_card(self, provider_name: str) -> None:
        c = self._theme
        card = self._new_card(self.results_frame)
        self._provider_widgets[provider_name] = card
        self._provider_states[provider_name] = "processing"

        self._provider_header(card.inner, provider_name, "processing", label="SCANNING")

        body = tk.Frame(card.inner, bg=c["card"])
        body.pack(fill="x", padx=18, pady=(0, 16))
        skeletons = []
        for _ in range(3):
            bar = tk.Frame(body, bg=c["skeleton"], height=10)
            bar.pack(fill="x", pady=4)
            bar.pack_propagate(False)
            inner = tk.Frame(bar, bg=c["skeleton_hi"], height=10)
            inner.place(relx=0, rely=0, relheight=1, relwidth=.24)
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
            for index, bar in enumerate(getattr(card, "_skeleton_bars", [])):
                try:
                    if not bar.winfo_exists():
                        continue
                    offset = (phase + index * .18) % 1.0
                    bar.place(relx=offset * .76, rely=0, relheight=1, relwidth=.24)
                except tk.TclError:
                    pass
        self._skeleton_after = self.after(70, self._animate_skeletons)

    def _display_provider_result(self, result: ProviderResult) -> None:
        if not self._busy:
            return
        self._results_by_provider[result.provider] = result
        self._completed_providers.add(result.provider)
        self._provider_states[result.provider] = result.status
        self._add_or_update_provider_card(result)
        self._add_or_update_raw_card(result)
        self._refresh_summary_card()
        completed = len(self._completed_providers)
        total = len(self._expected_providers) or completed
        self._set_status(f"Live results  •  {completed}/{total} providers complete")
        if hasattr(self, "live_label") and self.live_label.winfo_exists():
            self.live_label.configure(text=self._progress_text())
        if hasattr(self, "progress_bar") and self.progress_bar.winfo_exists():
            self.progress_bar.configure(maximum=max(1, total), value=completed)

    def _finish_investigation(self, investigation: Investigation) -> None:
        self._busy = False
        self._cancel_event = None
        self._cancel_skeleton()

        self._last_investigation = investigation
        self.search_button.configure(state="normal", text="Investigate")
        self.stop_button.configure(state="disabled")
        self.clear_button.configure(state="normal")
        self.copy_button.configure(state="normal")
        self.theme_button.configure(state="normal")

        if hasattr(self, "progress_holder") and self.progress_holder.winfo_exists():
            for child in self.progress_holder.winfo_children():
                child.destroy()

        completed = len(investigation.results)
        ok = sum(result.status == "success" for result in investigation.results)
        self._set_status(f"{ok}/{completed} providers returned data")

    def _display_error(self, exc: Exception) -> None:
        self._busy = False
        self._cancel_event = None
        self._cancel_skeleton()
        self.search_button.configure(state="normal", text="Investigate")
        self.stop_button.configure(state="disabled")
        self.clear_button.configure(state="normal")
        self.theme_button.configure(state="normal")
        self._set_status("Investigation failed")
        c = self._theme
        self._clear_results_frame()
        card = self._new_card(self.results_frame)
        tk.Label(
            card.inner, text=f"{type(exc).__name__}: {exc}",
            bg=c["card"], fg=c["danger"], font=(UI_FONT, 10),
            wraplength=900, justify="left", padx=22, pady=22,
        ).pack(fill="x")
        messagebox.showerror("PRISM error", str(exc), parent=self)

    # ------------------------------------------------------------------
    # Cards
    # ------------------------------------------------------------------
    def _provider_glyph(self, name: str) -> str:
        lowered = name.lower()
        for key, glyph in PROVIDER_GLYPHS.items():
            if key in lowered:
                return glyph
        return "◆"

    def _status_pill(self, parent: tk.Misc, status: str, parent_bg: str,
                     label: str | None = None) -> RoundButton:
        if status == "success":
            kind, icon = "success", "✓"
        elif status in {"not_found", "skipped", "processing"}:
            kind, icon = "warning", "◌" if status == "processing" else "!"
        elif status == "stopped":
            kind, icon = "muted", "■"
        else:
            kind, icon = "error", "✕"
        return RoundButton(
            parent, label or status.upper().replace("_", " "),
            style=self._btn_style(kind), parent_bg=parent_bg, icon=icon,
            font=(UI_FONT, 8, "bold"), icon_font=(ICON_FONT, 9, "bold"),
            padx=12, pady=5, interactive=False,
        )

    def _provider_header(self, inner: tk.Frame, name: str, status: str,
                         label: str | None = None) -> tuple[tk.Frame, tk.Label]:
        c = self._theme
        header = tk.Frame(inner, bg=c["card"])
        header.pack(fill="x", padx=16, pady=(14, 10))
        IconBadge(header, self._provider_glyph(name), size=34, fill=c["accent_soft"],
                  fg=c["accent"], parent_bg=c["card"], circle=True,
                  font=(ICON_FONT, 12)).pack(side="left")
        tk.Label(header, text=name, bg=c["card"], fg=c["text"],
                 font=(UI_FONT, 12, "bold")).pack(side="left", padx=(12, 0))
        chevron = tk.Label(header, text="⌄", bg=c["card"], fg=c["muted"],
                           font=(ICON_FONT, 13))
        chevron.pack(side="right", padx=(14, 0))
        self._status_pill(header, status, c["card"], label).pack(side="right")
        return header, chevron

    def _make_collapsible(self, header: tk.Frame, chevron: tk.Label, body: tk.Frame) -> None:
        expanded = {"open": True}

        def toggle(_event=None) -> None:
            if expanded["open"]:
                body.pack_forget()
                chevron.configure(text="⌃")
            else:
                body.pack(fill="x", padx=18, pady=(0, 16))
                chevron.configure(text="⌄")
            expanded["open"] = not expanded["open"]

        header.configure(cursor="hand2")
        for widget in (header, *header.winfo_children()):
            widget.bind("<Button-1>", toggle, add="+")

    def _wrap_width(self) -> int:
        return max(380, self.winfo_width() - 420)

    @staticmethod
    def _is_chip(value: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z][A-Za-z_\-]{0,23}", value))

    def _chip(self, parent: tk.Misc, text: str, parent_bg: str) -> RoundButton:
        return RoundButton(
            parent, text, style=self._btn_style("chip"), parent_bg=parent_bg,
            font=(UI_FONT, 9), padx=10, pady=3, radius=7, interactive=False,
        )

    def _rows_table(self, parent: tk.Misc, rows: list[tuple[str, str]]) -> tk.Frame:
        c = self._theme
        table = tk.Frame(parent, bg=c["card"], highlightbackground=c["border"],
                         highlightthickness=1)
        wrap = self._wrap_width()
        for index, (key, value) in enumerate(rows):
            row_bg = c["card_alt"] if index % 2 == 0 else c["card"]
            row = tk.Frame(table, bg=row_bg)
            row.pack(fill="x")
            row.grid_columnconfigure(0, minsize=190)
            row.grid_columnconfigure(1, weight=1)
            tk.Label(row, text=key, bg=row_bg, fg=c["muted"], font=(UI_FONT, 10),
                     anchor="nw", justify="left").grid(
                         row=0, column=0, sticky="nw", padx=(14, 8), pady=8)
            if self._is_chip(value):
                self._chip(row, value, row_bg).grid(row=0, column=1, sticky="w", pady=5)
            else:
                tk.Label(row, text=value, bg=row_bg, fg=c["text"], font=(UI_FONT, 10),
                         anchor="nw", justify="left", wraplength=wrap).grid(
                             row=0, column=1, sticky="nw", padx=(0, 14), pady=8)
        return table

    def _add_or_update_provider_card(self, result: ProviderResult) -> None:
        old_card = self._provider_widgets.get(result.provider)
        if old_card is None or not old_card.winfo_exists():
            card = self._new_card(self.results_frame)
            self._provider_widgets[result.provider] = card
        else:
            card = old_card
            for child in card.inner.winfo_children():
                child.destroy()
        self._render_provider_card(card, result)

    def _render_provider_card(self, card: RoundedCard, result: ProviderResult) -> None:
        c = self._theme
        header, chevron = self._provider_header(card.inner, result.provider, result.status)
        body = tk.Frame(card.inner, bg=c["card"])
        body.pack(fill="x", padx=18, pady=(0, 16))
        self._make_collapsible(header, chevron, body)

        if result.error:
            tk.Label(body, text=result.error, bg=c["card"], fg=c["muted"],
                     font=(UI_FONT, 10), wraplength=self._wrap_width() + 160,
                     justify="left").pack(anchor="w", pady=(0, 4))

        if result.status in {"success", "processing", "not_found", "skipped"} and result.data:
            self._rows_table(body, self._flatten_for_display(result.data)).pack(fill="x")
        elif not result.error:
            tk.Label(body, text="No fields returned.", bg=c["card"], fg=c["muted"],
                     font=(UI_FONT, 10)).pack(anchor="w")

    def _add_or_update_raw_card(self, result: ProviderResult) -> None:
        """Curated analyst view instead of dumping raw API JSON."""
        old_card = self._raw_provider_widgets.get(result.provider)
        if old_card is None or not old_card.winfo_exists():
            card = self._new_card(self.details_frame)
            self._raw_provider_widgets[result.provider] = card
        else:
            card = old_card
            for child in card.inner.winfo_children():
                child.destroy()

        c = self._theme
        header, chevron = self._provider_header(card.inner, result.provider, result.status)
        body = tk.Frame(card.inner, bg=c["card"])
        body.pack(fill="x", padx=18, pady=(0, 16))
        self._make_collapsible(header, chevron, body)

        if result.error:
            tk.Label(body, text=result.error, bg=c["card"], fg=c["danger"],
                     font=(UI_FONT, 10), wraplength=self._wrap_width() + 160,
                     justify="left").pack(anchor="w", pady=(0, 8))

        sections = self._build_analyst_sections(result) if result.data else []
        if not sections:
            tk.Label(body, text="No additional analyst details returned.",
                     bg=c["card"], fg=c["muted"], font=(UI_FONT, 10)).pack(anchor="w")
            return

        for title, rows in sections:
            if not rows:
                continue
            tk.Label(body, text=title.upper(), bg=c["card"], fg=c["accent"],
                     font=(UI_FONT, 8, "bold")).pack(anchor="w", pady=(8, 5))
            self._rows_table(body, rows).pack(fill="x")

        reference = (result.data or {}).get("result_url")
        if reference:
            footer = tk.Frame(body, bg=c["card"])
            footer.pack(fill="x", pady=(12, 0))
            tk.Label(footer, text="Provider report", bg=c["card"], fg=c["muted"],
                     font=(UI_FONT, 9)).pack(side="left")
            tk.Label(footer, text=str(reference), bg=c["card"], fg=c["accent"],
                     font=(UI_FONT, 9), anchor="w").pack(side="left", padx=(10, 0))

    # ------------------------------------------------------------------
    # Overview summary card
    # ------------------------------------------------------------------
    @staticmethod
    def _lookup(data: Any, keys: tuple[str, ...]) -> Any:
        if not isinstance(data, dict):
            return None
        for key in keys:
            for source in (data, data.get("analysis"), data.get("page")):
                if isinstance(source, dict):
                    value = source.get(key)
                    if value not in (None, "", [], {}):
                        return value
        return None

    @staticmethod
    def _format_summary_value(label: str, value: Any) -> str:
        if "date" in label.lower():
            try:
                number = float(value)
                if number > 1e8:
                    return datetime.fromtimestamp(number, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M UTC"
                    )
            except (TypeError, ValueError, OverflowError, OSError):
                pass
        return str(value)

    def _collect_summary(self) -> list[tuple[str, str, str]]:
        results = list(self._results_by_provider.values())
        stats: list[tuple[str, str, str]] = []
        for label, keys, glyph in SUMMARY_FIELDS:
            for result in results:
                value = self._lookup(result.data, keys)
                if value is not None:
                    stats.append((label, self._format_summary_value(label, value), glyph))
                    break
            if len(stats) == 4:
                break
        return stats

    def _refresh_summary_card(self) -> None:
        holder = getattr(self, "summary_holder", None)
        if holder is None or not holder.winfo_exists():
            return
        for child in holder.winfo_children():
            child.destroy()
        stats = self._collect_summary()
        if not stats:
            return

        c = self._theme
        card = RoundedCard(holder, parent_bg=c["panel"], fill=c["card_alt"],
                           outline=c["border"], radius=16, pad=1)
        card.pack(fill="x", padx=2, pady=(2, 10))
        inner = card.inner

        head = tk.Frame(inner, bg=c["card_alt"])
        head.pack(fill="x", padx=18, pady=(14, 8))
        IconBadge(head, "▤", size=34, fill=c["accent_soft"], fg=c["accent"],
                  parent_bg=c["card_alt"], font=(ICON_FONT, 12)).pack(side="left")
        tk.Label(head, text=SUMMARY_TITLE, bg=c["card_alt"], fg=c["text"],
                 font=(UI_FONT, 12, "bold")).pack(side="left", padx=(12, 0))

        grid = tk.Frame(inner, bg=c["card_alt"])
        grid.pack(fill="x", padx=18, pady=(0, 16))
        column = 0
        for index, (label, value, glyph) in enumerate(stats):
            if index:
                tk.Frame(grid, bg=c["border"], width=1).grid(
                    row=0, column=column, sticky="ns", padx=14)
                column += 1
            cell = tk.Frame(grid, bg=c["card_alt"])
            cell.grid(row=0, column=column, sticky="nsew")
            grid.grid_columnconfigure(column, weight=1, uniform="stat")
            column += 1
            IconBadge(cell, glyph, size=34, fill=c["card"], fg=c["muted"],
                      outline=c["border"], parent_bg=c["card_alt"],
                      font=(ICON_FONT, 12)).pack(side="left", anchor="n")
            text_col = tk.Frame(cell, bg=c["card_alt"])
            text_col.pack(side="left", padx=(12, 0), anchor="n")
            tk.Label(text_col, text=label, bg=c["card_alt"], fg=c["muted"],
                     font=(UI_FONT, 9)).pack(anchor="w")
            tk.Label(text_col, text=value, bg=c["card_alt"], fg=c["text"],
                     font=(UI_FONT, 11, "bold"), wraplength=190,
                     justify="left").pack(anchor="w", pady=(2, 0))

    # ------------------------------------------------------------------
    # Data shaping (unchanged behaviour)
    # ------------------------------------------------------------------
    def _build_analyst_sections(
        self, result: ProviderResult
    ) -> list[tuple[str, list[tuple[str, str]]]]:
        """Return only investigation-useful fields, grouped and de-duplicated."""
        data = result.data or {}
        provider = result.provider.lower()
        sections: list[tuple[str, list[tuple[str, str]]]] = []

        def add_section(title: str, pairs: list[tuple[str, Any]]) -> None:
            seen: set[str] = set()
            rows: list[tuple[str, str]] = []
            for key, value in pairs:
                if value is None or value == "" or value == [] or value == {}:
                    continue
                label = str(key)
                normalized = label.lower().strip()
                if normalized in seen:
                    continue
                seen.add(normalized)
                if isinstance(value, (dict, list)):
                    if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
                        rendered_items = []
                        for item in value:
                            compact = []
                            for k, v in item.items():
                                if v not in (None, "", [], {}):
                                    compact.append(f"{str(k).replace('_', ' ').title()}: {v}")
                            if compact:
                                rendered_items.append(" • ".join(compact))
                        rendered = "\n".join(rendered_items)
                    else:
                        rendered = json.dumps(value, ensure_ascii=False, default=str)
                else:
                    rendered = str(value)
                if rendered.strip():
                    rows.append((label, rendered))
            if rows:
                sections.append((title, rows))

        if "virustotal" in provider:
            analysis = data.get("analysis") or {}
            add_section("Detection & Reputation", [
                ("Reputation", data.get("reputation")),
                ("Malicious detections", analysis.get("malicious")),
                ("Suspicious detections", analysis.get("suspicious")),
                ("Harmless detections", analysis.get("harmless")),
                ("Undetected", analysis.get("undetected")),
                ("Timeouts", analysis.get("timeout")),
            ])
            add_section("Infrastructure", [
                ("Country", data.get("country")),
                ("ASN", data.get("asn")),
                ("AS owner", data.get("as_owner")),
                ("Network", data.get("network")),
                ("Registrar", data.get("registrar")),
            ])
            add_section("File / Object", [
                ("Meaningful name", data.get("meaningful_name")),
                ("File type", data.get("type_description")),
                ("Size", data.get("size")),
            ])
            add_section("Timeline", [
                ("Created", data.get("creation_date")),
                ("Last modified", data.get("last_modification_date")),
                ("Last analysis", data.get("last_analysis_date")),
            ])

        elif "abuseipdb" in provider:
            add_section("Abuse Assessment", [
                ("Abuse confidence", data.get("abuse_confidence_score")),
                ("Total reports", data.get("total_reports")),
                ("Distinct reporters", data.get("num_distinct_users")),
                ("Last reported", data.get("last_reported_at")),
                ("TOR", data.get("is_tor")),
            ])
            add_section("Network Identity", [
                ("ISP", data.get("isp")),
                ("Usage type", data.get("usage_type")),
                ("Country", data.get("country_code")),
                ("Domain", data.get("domain")),
                ("Hostnames", data.get("hostnames")),
            ])

        elif "urlscan" in provider:
            page = data.get("page") or {}
            stats = data.get("stats") or {}
            tls = data.get("tls") or {}
            add_section("Web Identity", [
                ("URL", page.get("url")),
                ("Domain", page.get("domain")),
                ("IP address", page.get("ip")),
                ("Page title", page.get("title")),
                ("HTTP status", page.get("status")),
                ("Country", page.get("country")),
                ("ASN", page.get("asn")),
                ("AS name", page.get("asnname")),
            ])
            add_section("Scan Activity", [
                ("Requests", stats.get("requests")),
                ("Unique IPs", stats.get("ips")),
                ("Unique countries", stats.get("countries")),
                ("Unique domains", stats.get("domains")),
                ("Scan time", data.get("scan_time")),
            ])
            add_section("TLS", [
                ("Issuer", tls.get("issuer")),
                ("Certificate age", tls.get("age_days")),
                ("Valid for", tls.get("valid_days")),
                ("Valid from", tls.get("valid_from")),
            ])
            add_section("Observed Infrastructure", [
                ("IPs", data.get("lists", {}).get("ips")),
                ("Domains", data.get("lists", {}).get("domains")),
                ("Countries", data.get("lists", {}).get("countries")),
            ])

        elif "urlquery" in provider:
            add_section("Verdict & Findings", [
                ("Verdict", data.get("verdict")),
                ("Status", data.get("status")),
                ("Alert count", data.get("alert_count")),
                ("Alerts", data.get("alerts")),
            ])
            add_section("Web Identity", [
                ("Submitted URL", data.get("submitted_url")),
                ("Final URL", data.get("final_url")),
                ("Final title", data.get("final_title")),
                ("Domain", data.get("domain")),
                ("FQDN", data.get("fqdn")),
                ("IP address", data.get("ip")),
            ])
            add_section("Analysis Reference", [
                ("Report ID", data.get("report_id")),
                ("Analysis date", data.get("date")),
            ])

        else:
            ignored = {
                "query", "source", "found", "type", "result_url", "raw_data",
                "error", "status", "queue_id", "scan_id",
            }
            pairs = [(str(k).replace("_", " ").title(), v)
                     for k, v in data.items() if k not in ignored]
            add_section("Analyst Findings", pairs)

        return sections

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
                {
                    "provider": r.provider,
                    "status": r.status,
                    "data": r.data,
                    "raw_data": r.raw_data,
                    "error": r.error,
                }
                for r in self._last_investigation.results
            ],
        }
        self.clipboard_clear()
        self.clipboard_append(json.dumps(payload, indent=2, default=str))
        self.update()
        self._set_status("JSON copied to clipboard")


def main() -> None:
    app = PrismApp()
    app.mainloop()


if __name__ == "__main__":
    main()