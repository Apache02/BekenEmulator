"""Tkinter front-end for the BK7231 emulator: two UART consoles you can type into.

Run it with no arguments (or point it straight at a dump):

    python tools/sim_ui.py
    python tools/sim_ui.py firmwares/OpenBK7231T_QIO_1.18.300_mathDemo_obkStartupCommand_uartConsole.bin

Pick any Beken flash dump, press Run, and watch UART1 and UART2 in their own
panes, with a third column decoding the GPIO and PWM registers as the firmware
configures them. Anything typed in the send bar goes into UART1's receive FIFO
through BekenEmulator.feed_uart1(), i.e. the same RX interrupt path --uart1-rx
and the simulated TuyaMCU peer use - the firmware cannot tell the difference.

Two things are worth knowing before the first run:

  * Typing only DOES anything if the firmware is listening on UART1. For
    OpenBeken that means config flag 31 (OBK_FLAG_CMD_ACCEPT_UART_COMMANDS),
    which turns UART1 into a command console at boot; the bundled
    ..._obkStartupCommand_uartConsole.bin image has it set, and
    tools/make_obk_config.py --flag 31 sets it on any other image. Without it
    the bytes are delivered and the firmware simply drops them.
  * OpenBeken does not echo, and command OUTPUT goes to the UART2 debug log.
    So you type into UART1 and read the result in UART2. That is how the real
    hardware behaves; the UI echoes your own line locally so the pane still
    reads like a session.

Threading: Tk owns the main thread and every widget. The emulation runs on a
worker thread and only ever touches a lock-guarded output buffer, so no Tk call
is ever made from it. The UI polls that buffer on a timer.
"""
import os
import sys
import re
import struct
import tempfile
import threading
import time
import traceback

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT_DIR)

from src import netstack
from src.crypto import KNOWN_KEYS, parse_key
from src.emulator import CHIP_FAMILIES, CONSOLE_RX_HOLDOFF_INSNS, SLOW_TICK_INSNS, SLOW_TICK_MS
from src.main import build_emulator, parse_hex_blobs
# One decoder for the GPIO/PWM registers, shared with the self-test report -
# so the pane below and the report's tables can never disagree.
from src import periph

FIRMWARE_DIR = os.path.join(ROOT_DIR, "firmwares")
# Image shipped with OBK config flag 31 already set, so its UART1 is a command
# console the moment it boots - the one dump where typing works out of the box.
DEFAULT_IMAGE = os.path.join(
    FIRMWARE_DIR, "OpenBK7231T_QIO_1.18.300_mathDemo_obkStartupCommand_uartConsole.bin")

POLL_MS = 60            # how often the UI drains the emulator's output buffer
MAX_LINES = 4000        # per pane; older lines are dropped so a long run is bounded

# Device time per emulated second, from the emulator's own tick model rather
# than a copy of its numbers. Used only to label the status bar - it is an
# estimate, like insn_count itself.
GUEST_SECOND_INSNS = SLOW_TICK_INSNS * (1000 // SLOW_TICK_MS)

# The emulator holds queued RX bytes for exactly this long, so anything typed
# earlier is delivered rather than lost - the indicator only says when the
# firmware actually starts listening.
CONSOLE_READY_INSNS = CONSOLE_RX_HOLDOFF_INSNS

LINE_ENDINGS = {"CR+LF": b"\r\n", "LF": b"\n", "CR": b"\r", "(none)": b""}

# One-click OpenBeken console commands. Sent verbatim as ASCII with whatever
# line ending is selected, so each button does exactly what its label says.
# "5*2" is deliberate: OBK's tokenizer evaluates simple arithmetic before the
# handler runs, so channel 1 ends up 10 - handy proof the line was parsed
# rather than echoed.
#
# getChannel is here because toggleChannel is SILENT: CHANNEL_Toggle() writes
# g_channelValues[] directly and calls Channel_OnChanged(), never CHANNEL_Set(),
# so it logs nothing at all - unlike setChannel, which prints "CHANNEL_Set
# channel N has changed to V". Without a read-back button a toggle looks like a
# dead button. getChannel prints "Channel N is V", which shows it worked.
#
# Clicked left to right they chain, each building on the last value:
#   1 -> 10 (5*2) -> 12 ($CH1+2) -> 19 (+7) -> 0 -> 1 (toggle) -> read back
#
# The two setPinRole buttons drive the GPIO pane rather than a channel: they
# reassign pin 1 as a plain output held high or low, so its row flips between
# "OUTPUT = 1" (reg 0x02) and "OUTPUT = 0" (reg 0x00) as you click. Like
# toggleChannel these log NOTHING on success - CMD_SetPinRole only prints on
# "Unknown pin" / "Unknown role" - so the third column is the only place their
# effect is visible, which is the point of pairing them with it.
# Pin 1 is the UART2 RX pad, which costs nothing here - the emulator's UART2 is
# the log's transmit path and does not go through the pin mux - but on real
# silicon this would take the pad away from the debug port's receive side.
QUICK_COMMANDS = [
    "setChannel 1 1",
    "setChannel 1 5*2",
    "setChannel 1 $CH1+2",
    "addChannel 1 7",
    "setChannel 1 0",
    "toggleChannel 1",
    "getChannel 1",
    "setPinRole 1 AlwaysHigh",
    "setPinRole 1 AlwaysLow",
]
QUICK_PER_ROW = 4       # they wrap rather than run off the end of the window

# Firmware log line the "suppress" checkbox filters out of the UART2 pane.
# OpenBeken prints it on every idle tick, which crowds out everything else.
QUICKTICK = "Info:MAIN:quicktick"

# The network pane's heading. It carries a running count, so the user can see
# at a glance whether the bridge captured anything without scrolling.
NET_TITLE = "network - virtual Wi-Fi and IP bridge"
# Frames kept for the details window. Each is at most ~1.5 KB, so this bounds
# the window's memory at a few tens of MB on a very long run; older frames are
# dropped and the window says how many.
MAX_FRAMES = 20000
NET_IDLE_HINT = ("Nothing on air yet. Tick \"Wi-Fi peer\" above before Run to attach the "
                 "virtual radio and the IP bridge; this pane then shows every frame and "
                 "connection, and what the device sent inside them.")


# -chip collapses the whole BK7231 T/U/N/M/Q family onto one identity, so the
# silicon name periph reads off the filename maps down to these four.
CLI_FAMILY = {"BK7238": "BK7238", "BK7252N": "BK7252N", "BK7252": "BK7252"}


def guess_chip(path):
    """Pick the -chip identity a dump's filename implies, as the CLI docs do."""
    return CLI_FAMILY.get(periph.chip_from_name(path), "BK7231")


class SimulatorUI:
    def __init__(self, root, initial_image=None):
        self.root = root
        root.title("BekenSimulator")
        root.minsize(1280, 620)

        self.emu = None
        self.thread = None
        self.started_at = None
        self.finished = None          # message from the worker when it ends
        self.error = None             # exception text from the worker

        # Bytes the firmware has transmitted, per port, waiting to be shown.
        # The worker appends under the lock; the UI thread swaps and clears.
        self._out = {1: bytearray(), 2: bytearray()}
        self._net_lines = []            # whole [WIFI]/[NET] lines, drained by _poll
        self._net_count = 0
        # Every frame the IP bridge carried: (direction, bytes, device time).
        # Bounded, because a long run carries tens of thousands of them.
        self._frames = []
        self._frames_dropped = 0
        self._detail_win = None
        self._detail_drawn_at = 0.0     # throttle for redrawing the packet list
        self._detail_drawn_count = -1
        self._net_hint_shown = False   # is the 'nothing yet' note on screen?
        self._out_lock = threading.Lock()
        self._tx_count = {1: 0, 2: 0}
        self._hex_col = 0             # column tracker for UART1 hex formatting
        # Tail of UART2 output past the last newline. The quicktick filter works
        # a line at a time, but bytes arrive on arbitrary boundaries, so a
        # half-line is held here until its newline turns up.
        self._u2_partial = ""
        self.quick_buttons = []
        self._periph_key = None       # last GPIO/PWM snapshot drawn

        self._last_insns = 0
        self._last_rate_at = None
        self._rate = 0.0

        self.history = []
        self.history_pos = None

        self._build(initial_image or DEFAULT_IMAGE)
        self.root.after(POLL_MS, self._poll)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------------------------------------------------------- layout
    def _build(self, initial_image):
        mono = ("Consolas", 9) if sys.platform == "win32" else "TkFixedFont"

        cfg = ttk.LabelFrame(self.root, text="image", padding=6)
        cfg.pack(fill="x", padx=6, pady=(6, 3))

        self.var_image = tk.StringVar(value=initial_image if os.path.exists(initial_image) else "")
        ttk.Entry(cfg, textvariable=self.var_image).pack(side="left", fill="x", expand=True)
        ttk.Button(cfg, text="Browse...", command=self._browse, width=10).pack(side="left", padx=(4, 10))

        ttk.Label(cfg, text="chip").pack(side="left")
        self.var_chip = tk.StringVar(value=guess_chip(initial_image))
        ttk.Combobox(cfg, textvariable=self.var_chip, values=sorted(CHIP_FAMILIES),
                     state="readonly", width=9).pack(side="left", padx=(3, 10))

        ttk.Label(cfg, text="key").pack(side="left")
        self.var_key = tk.StringVar(value="TUYA")
        ttk.Combobox(cfg, textvariable=self.var_key, values=["(none)"] + sorted(KNOWN_KEYS),
                     state="readonly", width=9).pack(side="left", padx=(3, 10))

        self.var_boot = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg, text="boot ROM", variable=self.var_boot).pack(side="left")
        self.var_tuyamcu = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg, text="TuyaMCU peer", variable=self.var_tuyamcu).pack(side="left", padx=(8, 0))
        self.var_blecore = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg, text="BLE core", variable=self.var_blecore).pack(side="left", padx=(8, 0))
        # Wi-Fi MAC model + virtual AP/station + IP network (src/wifimac.py,
        # wifipeer.py, netstack.py). The device's port 80 is forwarded to
        # 127.0.0.1:8080, so a browser reaches the firmware's own web panel.
        self.var_wifi = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg, text="Wi-Fi peer (127.0.0.1:8080 -> :80)",
                        variable=self.var_wifi).pack(side="left", padx=(8, 0))

        run = ttk.Frame(self.root)
        run.pack(fill="x", padx=6)
        self.btn_run = ttk.Button(run, text="Run", command=self._on_run, width=10)
        self.btn_run.pack(side="left")
        self.btn_pause = ttk.Button(run, text="Pause", command=self._on_pause,
                                    width=10, state="disabled")
        self.btn_pause.pack(side="left", padx=4)
        self.btn_stop = ttk.Button(run, text="Stop", command=self._on_stop,
                                   width=10, state="disabled")
        self.btn_stop.pack(side="left")
        ttk.Button(run, text="Clear", command=self._clear, width=10).pack(side="left", padx=(12, 0))
        ttk.Button(run, text="Save log...", command=self._save, width=10).pack(side="left", padx=4)

        self.var_state = tk.StringVar(value="idle - pick an image and press Run")
        state = ttk.Label(self.root, textvariable=self.var_state, anchor="w",
                          relief="sunken", padding=4)
        state.pack(fill="x", padx=6, pady=4)

        # The three logs sit side by side in the top half; the network pane is
        # a full-width strip under them, in a draggable split. Its lines are
        # long (a decoded Tuya announcement is a whole JSON object), so width
        # matters more to it than height.
        split = ttk.PanedWindow(self.root, orient="vertical")
        split.pack(fill="both", expand=True, padx=6)

        panes = ttk.PanedWindow(split, orient="horizontal")

        left = ttk.LabelFrame(panes, text="UART1 - MCU link / command console", padding=4)
        self.txt1 = self._console(left, mono)
        opts = ttk.Frame(left)
        opts.pack(fill="x", pady=(4, 0))
        self.var_hex = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="show as hex", variable=self.var_hex).pack(side="left")
        ttk.Button(opts, text="Copy", width=7,
                   command=lambda: self._copy(self.txt1, "UART1")).pack(side="right")
        panes.add(left, weight=1)

        peri = ttk.LabelFrame(panes, text="GPIO / PWM", padding=4)
        pf = ttk.Frame(peri)
        pf.pack(fill="both", expand=True)
        pbar = ttk.Scrollbar(pf, orient="vertical")
        self.tree = ttk.Treeview(pf, columns=("pin", "name", "state", "reg"),
                                 show="headings", height=16, yscrollcommand=pbar.set)
        for key, title, width, anchor in (("pin", "Pin", 38, "e"), ("name", "Name", 74, "w"),
                                          ("state", "State", 250, "w"), ("reg", "Reg", 58, "e")):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor=anchor, stretch=(key == "state"))
        pbar.config(command=self.tree.yview)
        pbar.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        # A ttk Treeview draws on the NATIVE light background, not the dark one
        # the console Text widgets use, so these must be dark inks - the pale
        # greens and blues that read well in the log panes are near-invisible
        # here. Contrast ratios against white, all clearing WCAG AA (4.5:1):
        #   factory 6.0:1   out 6.6:1   func 9.3:1
        self.tree.tag_configure("factory", foreground="#5b6472")   # de-emphasised
        self.tree.tag_configure("out", foreground="#0b6b3a")       # driven output
        self.tree.tag_configure("func", foreground="#14448f")      # peripheral owns the pad

        self.var_pwm = tk.StringVar(value="no PWM channels decoded yet")
        ttk.Label(peri, textvariable=self.var_pwm, anchor="w",
                  wraplength=300, justify="left").pack(fill="x", pady=(4, 0))
        self.var_all_pins = tk.BooleanVar(value=False)
        ttk.Checkbutton(peri, text="show untouched pins", variable=self.var_all_pins,
                        command=self._refresh_periph).pack(anchor="w")

        right = ttk.LabelFrame(panes, text="UART2 - firmware debug log", padding=4)
        self.txt2 = self._console(right, mono)
        ropts = ttk.Frame(right)
        ropts.pack(fill="x", pady=(4, 0))
        self.var_hide_tick = tk.BooleanVar(value=False)
        ttk.Checkbutton(ropts, text="suppress %s" % QUICKTICK,
                        variable=self.var_hide_tick).pack(side="left")
        ttk.Button(ropts, text="Copy", width=7,
                   command=lambda: self._copy(self.txt2, "UART2")).pack(side="right")
        panes.add(right, weight=1)

        # Added last so the peripheral table is the THIRD column, to the right
        # of both logs - the two UARTs stay side by side where they are easiest
        # to read against each other.
        panes.add(peri, weight=1)
        split.add(panes, weight=3)

        # Everything the virtual radio and the IP bridge carried. These used to
        # be mixed into the UART2 pane, where they were lost among the
        # firmware's own debug output; the emulator now hands them over whole
        # (Emulator.net_sink) so they can be shown, filtered and saved apart.
        self.net_frame = ttk.LabelFrame(split, text=NET_TITLE, padding=4)
        self.txt_net = self._console(self.net_frame, mono, height=8)
        self.txt_net.tag_configure("wifi", foreground="#8ab4f8")    # 802.11 link
        self.txt_net.tag_configure("net", foreground="#7fd6a0")     # IP and above
        self.txt_net.tag_configure("payload", foreground="#e8c06a")  # decoded contents
        nopts = ttk.Frame(self.net_frame)
        nopts.pack(fill="x", pady=(4, 0))
        self.var_net_ip_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(nopts, text="IP traffic only (hide Wi-Fi link)",
                        variable=self.var_net_ip_only).pack(side="left")
        ttk.Button(nopts, text="Copy", width=7,
                   command=lambda: self._copy(self.txt_net, "network")).pack(side="right")
        ttk.Button(nopts, text="Details (bytes)...", width=18,
                   command=self._open_details).pack(side="right", padx=(0, 6))
        # Double-clicking a line in the pane opens the same window, which is
        # where someone reading a line reaches for the detail behind it.
        self.txt_net.bind("<Double-Button-1>", self._details_for_click)
        split.add(self.net_frame, weight=1)
        self._append(self.txt_net, NET_IDLE_HINT + "\n", "note")
        self._net_hint_shown = True

        send = ttk.LabelFrame(self.root, text="send to UART1", padding=6)
        send.pack(fill="x", padx=6, pady=(4, 6))

        typed = ttk.Frame(send)
        typed.pack(fill="x")

        self.var_input = tk.StringVar()
        self.entry = ttk.Entry(typed, textvariable=self.var_input, font=mono)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", lambda _e: self._on_send())
        self.entry.bind("<Up>", self._history_back)
        self.entry.bind("<Down>", self._history_fwd)

        self.var_mode = tk.StringVar(value="ASCII")
        ttk.Combobox(typed, textvariable=self.var_mode, values=["ASCII", "HEX"],
                     state="readonly", width=7).pack(side="left", padx=(6, 4))
        self.var_ending = tk.StringVar(value="CR+LF")
        ttk.Combobox(typed, textvariable=self.var_ending, values=list(LINE_ENDINGS),
                     state="readonly", width=8).pack(side="left", padx=(0, 6))
        self.btn_send = ttk.Button(typed, text="Send", command=self._on_send,
                                   width=8, state="disabled")
        self.btn_send.pack(side="left")

        # One click sends immediately - no filling the box first.
        quick = ttk.Frame(send)
        quick.pack(fill="x", pady=(6, 0))
        ttk.Label(quick, text="quick:").grid(row=0, column=0, sticky="w", padx=(0, 4))
        for i, cmd in enumerate(QUICK_COMMANDS):
            row, col = divmod(i, QUICK_PER_ROW)
            btn = ttk.Button(quick, text=cmd, state="disabled",
                             command=lambda c=cmd: self._send_command(c))
            btn.grid(row=row, column=col + 1, sticky="w", padx=(0, 4), pady=(0, 2))
            self.quick_buttons.append(btn)

    def _console(self, parent, mono, height=18):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        bar = ttk.Scrollbar(frame, orient="vertical")
        txt = tk.Text(frame, wrap="char", height=height, width=48, font=mono,
                      state="disabled", yscrollcommand=bar.set,
                      background="#101216", foreground="#d8dde3",
                      insertbackground="#d8dde3")
        bar.config(command=txt.yview)
        bar.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        txt.tag_configure("sent", foreground="#7fd6a0")
        txt.tag_configure("note", foreground="#e0a24a")
        return txt

    # ------------------------------------------------- captured traffic window
    @staticmethod
    def _filter_from_line(line):
        """A filter that narrows the packet list to the frames behind a line.

        A connection's own port is the most selective thing a [NET] line
        carries, so prefer the first ephemeral one; failing that, an address.
        Returns "" when the line names neither, which shows everything rather
        than silently hiding frames.
        """
        ports = re.findall(r"\d+\.\d+\.\d+\.\d+:(\d+)", line or "")
        for p in ports:
            if int(p) >= 1024:
                return ":" + p
        if ports:
            return ":" + ports[0]
        addrs = re.findall(r"\d+\.\d+\.\d+\.\d+", line or "")
        return addrs[0] if addrs else ""

    def _details_for_click(self, event=None):
        """Double-click in the network pane: open the bytes behind THAT line."""
        want = ""
        if event is not None:
            try:
                line = self.txt_net.get("@%d,%d linestart" % (event.x, event.y),
                                        "@%d,%d lineend" % (event.x, event.y))
                want = self._filter_from_line(line)
            except tk.TclError:
                want = ""
        self._open_details()
        if want and getattr(self, "var_frame_filter", None) is not None:
            self.var_frame_filter.set(want)
            self._refresh_details()

    def _open_details(self, _event=None):
        """A packet list over every frame the bridge carried, with its bytes.

        The pane above says what happened; this says exactly what crossed, as
        a hex dump of the frame itself. One window at a time: reopening raises
        the existing one so a double-click cannot bury the screen in windows.
        """
        if self._detail_win is not None and self._detail_win.winfo_exists():
            self._detail_win.deiconify()
            self._detail_win.lift()
            self._refresh_details()
            return
        mono = ("Consolas", 9) if sys.platform == "win32" else "TkFixedFont"
        win = tk.Toplevel(self.root)
        self._detail_win = win
        win.title("captured traffic - every frame the IP bridge carried")
        win.minsize(820, 480)

        bar = ttk.Frame(win, padding=6)
        bar.pack(fill="x")
        ttk.Label(bar, text="filter:").pack(side="left")
        self.var_frame_filter = tk.StringVar(value="")
        ent = ttk.Entry(bar, textvariable=self.var_frame_filter)
        ent.pack(side="left", fill="x", expand=True, padx=(4, 6))
        ent.bind("<Return>", lambda e: self._refresh_details())
        ttk.Button(bar, text="Apply", width=7, command=self._refresh_details).pack(side="left")
        ttk.Button(bar, text="Refresh", width=8, command=self._refresh_details).pack(side="left", padx=4)
        ttk.Button(bar, text="Save .pcap...", width=13,
                   command=self._save_pcap).pack(side="right")
        self.var_frame_count = tk.StringVar(value="")
        ttk.Label(win, textvariable=self.var_frame_count, anchor="w",
                  padding=(8, 0)).pack(fill="x")

        split = ttk.PanedWindow(win, orient="vertical")
        split.pack(fill="both", expand=True, padx=6, pady=(2, 6))

        lf = ttk.Frame(split)
        lbar = ttk.Scrollbar(lf, orient="vertical")
        self.frame_tree = ttk.Treeview(lf, columns=("no", "time", "dir", "len", "what"),
                                       show="headings", height=14, yscrollcommand=lbar.set)
        for key, title, width, anchor in (("no", "#", 52, "e"), ("time", "Time", 86, "e"),
                                          ("dir", "Direction", 92, "w"), ("len", "Bytes", 56, "e"),
                                          ("what", "Frame", 420, "w")):
            self.frame_tree.heading(key, text=title)
            self.frame_tree.column(key, width=width, anchor=anchor, stretch=(key == "what"))
        lbar.config(command=self.frame_tree.yview)
        lbar.pack(side="right", fill="y")
        self.frame_tree.pack(side="left", fill="both", expand=True)
        # Dark inks on the native light Treeview background, as the GPIO table.
        self.frame_tree.tag_configure("in", foreground="#0b6b3a")    # sent by the device
        self.frame_tree.tag_configure("out", foreground="#14448f")   # sent to the device
        self.frame_tree.bind("<<TreeviewSelect>>", self._show_frame_bytes)
        split.add(lf, weight=2)

        hf = ttk.Frame(split)
        hbar = ttk.Scrollbar(hf, orient="vertical")
        self.txt_bytes = tk.Text(hf, wrap="none", height=12, font=mono, state="disabled",
                                 yscrollcommand=hbar.set, background="#101216",
                                 foreground="#d8dde3", insertbackground="#d8dde3")
        hbar.config(command=self.txt_bytes.yview)
        hbar.pack(side="right", fill="y")
        self.txt_bytes.pack(side="left", fill="both", expand=True)
        split.add(hf, weight=1)

        ttk.Button(win, text="Copy these bytes", width=18,
                   command=lambda: self._copy(self.txt_bytes, "frame bytes")).pack(
            anchor="e", padx=6, pady=(0, 6))
        win.protocol("WM_DELETE_WINDOW", win.destroy)
        self._refresh_details()

    def _visible_frames(self):
        """The captured frames the filter box lets through, with their numbers."""
        with self._out_lock:
            frames = list(self._frames)
        base = self._frames_dropped
        needle = (getattr(self, "var_frame_filter", None).get().strip().lower()
                  if getattr(self, "var_frame_filter", None) else "")
        out = []
        for i, (direction, data, us) in enumerate(frames):
            what = netstack.describe_frame(data)
            if needle and needle not in what.lower() and needle not in direction.lower():
                continue
            out.append((base + i + 1, direction, data, us, what))
        return out

    def _refresh_details(self):
        if self._detail_win is None or not self._detail_win.winfo_exists():
            return
        rows = self._visible_frames()
        # The list is rebuilt wholesale, which would otherwise throw away what
        # the reader was looking at every time it refreshes during a run.
        was_selected = self.frame_tree.selection()
        was_at = self.frame_tree.yview()[0]
        self.frame_tree.delete(*self.frame_tree.get_children())
        # Only the tail is drawn: a Treeview with tens of thousands of rows is
        # slow to fill and no easier to read. The count line says so plainly.
        shown = rows[-2000:]
        for no, direction, data, us, what in shown:
            self.frame_tree.insert("", "end", iid=str(no),
                                   values=(no, "%.3f s" % (us / 1e6), direction, len(data), what),
                                   tags=("in" if direction == "from device" else "out",))
        total = len(self._frames) + self._frames_dropped
        note = "%d frames captured" % total
        if len(shown) != len(rows):
            note += ", showing the last %d of %d matching" % (len(shown), len(rows))
        elif len(rows) != len(self._frames):
            note += ", %d match the filter" % len(rows)
        if self._frames_dropped:
            note += " (the earliest %d were dropped)" % self._frames_dropped
        if not total:
            note = ("Nothing captured yet. Tick \"Wi-Fi peer\" before Run; every frame the "
                    "bridge carries then appears here with its bytes.")
        self.var_frame_count.set(note)
        if not shown:
            return
        keep = [i for i in was_selected if self.frame_tree.exists(i)]
        if keep:
            self.frame_tree.selection_set(keep)
            self.frame_tree.yview_moveto(was_at)
        elif was_selected:
            # What was selected has been filtered out or dropped; leave the
            # view where it was rather than jumping somewhere unrelated.
            self.frame_tree.yview_moveto(was_at)
        else:
            last = str(shown[-1][0])
            self.frame_tree.selection_set(last)
            self.frame_tree.see(last)

    def _show_frame_bytes(self, _event=None):
        sel = self.frame_tree.selection()
        if not sel:
            return
        want = int(sel[0])
        for no, direction, data, us, what in self._visible_frames():
            if no != want:
                continue
            head = ("frame %d   %s   %.6f s   %d bytes\n%s\n\n"
                    % (no, direction, us / 1e6, len(data), what))
            self.txt_bytes.configure(state="normal")
            self.txt_bytes.delete("1.0", "end")
            self.txt_bytes.insert("end", head + netstack.hexdump(data) + "\n")
            self.txt_bytes.configure(state="disabled")
            return

    def _save_pcap(self):
        """Write the captured frames as an Ethernet pcap, for Wireshark."""
        rows = self._visible_frames()
        if not rows:
            messagebox.showinfo("BekenSimulator", "Nothing captured yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            filetypes=[("pcap", "*.pcap"), ("All", "*.*")])
        if not path:
            return
        cap = netstack.EthPcap(path)
        try:
            for _no, _direction, data, us, _what in rows:
                cap.write(data, us)
        finally:
            cap.close()
        self.var_state.set("saved %d frames to %s" % (len(rows), path))

    # ------------------------------------------------------------ text panes
    def _append(self, widget, text, tag=None):
        if not text:
            return
        # Only follow the tail if the view is already at the tail, so scrolling
        # back to read something is not yanked away by new output.
        at_end = widget.yview()[1] >= 0.999
        widget.configure(state="normal")
        widget.insert("end", text, tag or ())
        lines = int(widget.index("end-1c").split(".")[0])
        if lines > MAX_LINES:
            widget.delete("1.0", "%d.0" % (lines - MAX_LINES + 1))
        widget.configure(state="disabled")
        if at_end:
            widget.see("end")

    def _render_uart1(self, data):
        """UART1 carries either console text or binary protocol frames."""
        if not self.var_hex.get():
            return data.decode("latin-1")
        out = []
        for b in data:
            out.append("%02x " % b)
            self._hex_col += 1
            if self._hex_col >= 16:
                out.append("\n")
                self._hex_col = 0
        return "".join(out)

    def _refresh_periph(self):
        """Redraw the GPIO/PWM table from the emulator's live registers.

        The emulator records every GPIO and PWM register write into
        state.gpio_cfg / state.pwm_regs unconditionally (not only under
        EMU_REPORT), so this needs no capture plumbing - and the decoding is
        periph.decode_state, the very function the HTML report renders from.
        """
        if self.emu is None:
            return
        try:
            gpio = dict(self.emu.state.gpio_cfg)
            pwm = dict(self.emu.state.pwm_regs)
        except RuntimeError:
            # The emulation thread was mid-write into the dict. Registers are
            # written tens of times per boot, so simply catching the next tick
            # is cheaper and safer than locking the write hook.
            return

        key = (tuple(sorted(gpio.items())), tuple(sorted(pwm.items())),
               self.var_all_pins.get())
        if key == self._periph_key:
            return              # nothing moved; leave the widget alone
        self._periph_key = key

        # decode_state wants the fine-grained silicon name (BK7231N, not the
        # four -chip identities), which the dump's filename carries.
        data = periph.decode_state(gpio, pwm, periph.chip_from_name(self.var_image.get()))
        self.tree.delete(*self.tree.get_children())
        if not data:
            self.var_pwm.set("firmware has not touched GPIO or PWM yet")
            return

        show_all = self.var_all_pins.get()
        for pin, alias, state, detail in data["gpio"]:
            if state == "factory" and not show_all:
                continue
            if state == "factory":
                tag = "factory"
            elif "OUTPUT" in detail:
                tag = "out"
            else:
                tag = "func"
            raw = data["raw"].get(pin)
            self.tree.insert("", "end", tags=(tag,), values=(
                pin, alias or "", detail, "" if raw is None else "0x%02X" % raw))

        for name, value in data["func"]:
            self.tree.insert("", "end", tags=("func",), values=("", name, "function select", value))

        chans = data.get("pwm_channels") or []
        if chans:
            self.var_pwm.set("PWM (%s layout), pins %s:  %s" % (
                data["pwm_layout"], data["pwm_pins"] or "-",
                "   ".join("ch%d %.0f Hz %.0f%%" % (c[0], c[3], c[4]) for c in chans)))
        else:
            self.var_pwm.set("PWM pins %s, no channels decoded"
                             % (data["pwm_pins"] or "-"))

    def _render_uart2(self, data):
        """Firmware log text, optionally with the quicktick chatter dropped.

        Splitting on "\\n" only, rather than str.splitlines(), is deliberate:
        the stream is decoded latin-1, and splitlines() would also break on
        bytes like 0x85 and 0x0C that a log can legitimately contain. Any "\\r"
        stays inside its line, so CR+LF endings survive untouched.
        """
        text = data.decode("latin-1")
        if not self.var_hide_tick.get():
            # Pass through - but do not swallow a half-line held back while the
            # filter was still on.
            if self._u2_partial:
                text, self._u2_partial = self._u2_partial + text, ""
            return text

        lines = (self._u2_partial + text).split("\n")
        self._u2_partial = lines.pop()      # tail past the last newline, if any
        # Dropping the newline along with the line is the point: a suppressed
        # tick leaves no blank gap behind.
        return "".join(ln + "\n" for ln in lines if QUICKTICK not in ln)

    def _copy(self, widget, label):
        """Put a pane's whole scrollback on the clipboard.

        Whatever the pane shows is what gets copied, so a UART1 copy is hex if
        the hex box is ticked, and a UART2 copy has the quicktick lines already
        filtered out if that box is ticked. update() hands the selection to the
        window manager so it survives this window losing focus.
        """
        text = widget.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        self.var_state.set("copied %d characters from %s" % (len(text), label))

    def _clear(self):
        self._u2_partial = ""
        for w in (self.txt1, self.txt2, self.txt_net):
            w.configure(state="normal")
            w.delete("1.0", "end")
            w.configure(state="disabled")
        self._hex_col = 0
        with self._out_lock:
            del self._net_lines[:]
            del self._frames[:]
        self._frames_dropped = 0
        self._net_count = 0
        self._refresh_details()
        self.net_frame.config(text=NET_TITLE)
        self._append(self.txt_net, NET_IDLE_HINT + "\n", "note")
        self._net_hint_shown = True

    def _save(self):
        path = filedialog.asksaveasfilename(defaultextension=".log",
                                            filetypes=[("Log", "*.log"), ("All", "*.*")])
        if not path:
            return
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write("=== UART1 ===\n")
            f.write(self.txt1.get("1.0", "end"))
            f.write("\n=== UART2 ===\n")
            f.write(self.txt2.get("1.0", "end"))
            f.write("\n=== network (virtual Wi-Fi and IP bridge) ===\n")
            f.write(self.txt_net.get("1.0", "end"))
        self.var_state.set("saved to %s" % path)

    def _browse(self):
        path = filedialog.askopenfilename(
            initialdir=FIRMWARE_DIR if os.path.isdir(FIRMWARE_DIR) else ROOT_DIR,
            filetypes=[("Flash dumps", "*.bin"), ("All files", "*.*")])
        if path:
            self.var_image.set(path)
            self.var_chip.set(guess_chip(path))

    # --------------------------------------------------------------- run/stop
    def _sink(self, port, byte):
        """Called from the emulation thread for every transmitted byte."""
        with self._out_lock:
            self._out[port].append(byte)

    def _net_sink(self, line):
        """Called from the emulation thread for each [WIFI]/[NET] line."""
        with self._out_lock:
            self._net_lines.append(line)

    def _frame_sink(self, direction, frame, now_us):
        """Called from the emulation thread for every frame the bridge carried."""
        with self._out_lock:
            self._frames.append((direction, frame, now_us))
            if len(self._frames) > MAX_FRAMES:
                drop = len(self._frames) - MAX_FRAMES
                del self._frames[:drop]
                self._frames_dropped += drop

    @staticmethod
    def _net_tag(line):
        """Which ink a network line gets: the link, the IP stack, or contents."""
        if line.startswith("[WIFI]"):
            return "wifi"
        # Lines that carry what was actually sent, rather than the fact of it.
        for mark in (" sends: ", "MQTT PUBLISH", "MQTT -> device", "Tuya LAN broadcast",
                     "HTTP GET", "answered 200"):
            if mark in line:
                return "payload"
        return "net"

    def _on_run(self):
        if self.thread is not None and self.thread.is_alive():
            return
        path = self.var_image.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("BekenSimulator", "Pick a flash dump first.")
            return

        self._clear()
        self._periph_key = None
        self._tx_count = {1: 0, 2: 0}
        self._last_insns = 0
        self._rate = 0.0
        self._last_rate_at = None
        self.finished = self.error = None
        self.emu = None
        self.started_at = time.time()

        self.btn_run.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.btn_pause.config(state="normal", text="Pause")
        self.var_state.set("loading %s ..." % os.path.basename(path))

        # Read every Tk variable HERE, on the main thread. Tkinter is not
        # thread-safe, so the worker gets plain values, never widgets.
        cfg = {"chip": self.var_chip.get(), "key": self.var_key.get(),
               "boot": self.var_boot.get(), "tuyamcu": self.var_tuyamcu.get(),
               "blecore": self.var_blecore.get(), "wifi": self.var_wifi.get()}
        self.thread = threading.Thread(target=self._worker, args=(path, cfg), daemon=True)
        self.thread.start()

    def _worker(self, path, cfg):
        """Load, set up and run the emulator. Never touches Tk - see cfg."""
        try:
            key = None if cfg["key"] == "(none)" else parse_key(cfg["key"])
            emu = build_emulator(
                path, key=key, chip=cfg["chip"],
                with_boot=cfg["boot"],
                # only_uart keeps the MMIO/trace chatter out; the panes show
                # UART bytes and the status bar shows the rest.
                only_uart=True,
                # The panes format their own bytes, so the emulator's stdout
                # hex tagging is left off and everything arrives via the sink.
                uart1_hex=False,
                tuyamcu=cfg["tuyamcu"],
                ble_core=cfg["blecore"],
                wifi=cfg["wifi"],
                uart_sink=self._sink,
                # Writing app_decrypted.bin into the working directory is a
                # command-line convenience, not something a GUI should do.
                save_decrypted=False)
            # Whole [WIFI]/[NET] lines go to the network pane instead of being
            # spliced into UART2's byte stream as they are on the console.
            emu.net_sink = self._net_sink
            emu.net_frame_sink = self._frame_sink
            if cfg["wifi"]:
                emu.attach_wifi_peer(role="auto", forwards=[(8080, 80)])
            emu.setup()
            self.emu = emu
            emu.run()
            self.finished = "emulation finished"
        except Exception as e:            # bad key, unreadable image, Unicorn error
            self.error = "%s: %s" % (type(e).__name__, e)

    def _on_pause(self):
        if self.emu is None:
            return
        if self.emu.is_paused():
            self.emu.pause(False)
            self.btn_pause.config(text="Pause")
        else:
            self.emu.pause(True)
            self.btn_pause.config(text="Resume")

    def _on_stop(self):
        if self.emu is not None:
            self.emu.stop()
        self.btn_stop.config(state="disabled")
        self.btn_pause.config(state="disabled", text="Pause")

    def _on_close(self):
        if self.emu is not None:
            self.emu.stop()
        self.root.destroy()

    # ------------------------------------------------------------------ send
    def _console_ready(self):
        return (self.emu is not None and self.thread is not None
                and self.thread.is_alive()
                and self.emu.state.insn_count >= CONSOLE_READY_INSNS)

    def _send_bytes(self, payload):
        """Put raw bytes on UART1 and show them in the pane."""
        if self.emu is None:
            return
        self.emu.feed_uart1(payload)
        # The firmware does not echo, so show the line locally - otherwise the
        # pane gives no sign anything was sent.
        if self.var_hex.get():
            shown = payload.hex(" ")
        else:
            shown = payload.decode("latin-1").replace("\r", "").rstrip("\n")
        self._append(self.txt1, "> %s\n" % shown, "sent")

    def _send_command(self, text):
        """Send a literal command line - what the quick buttons do.

        Always ASCII, whatever the ASCII/HEX selector says, because the button
        label IS the text being sent. The line ending still follows the
        selector, since some firmwares only accept one of them.
        """
        self._send_bytes(text.encode("latin-1", "replace")
                         + LINE_ENDINGS[self.var_ending.get()])
        self.history.append(text)
        self.history_pos = None

    def _on_send(self):
        if self.emu is None:
            return
        text = self.var_input.get()
        if not text and self.var_mode.get() == "HEX":
            return
        try:
            if self.var_mode.get() == "HEX":
                payload = parse_hex_blobs([text])[0]
            else:
                payload = text.encode("latin-1", "replace")
        except ValueError as e:
            self.var_state.set(str(e))
            return

        self._send_bytes(payload + LINE_ENDINGS[self.var_ending.get()])
        if text:
            self.history.append(text)
        self.history_pos = None
        self.var_input.set("")

    def _history_back(self, _event):
        if not self.history:
            return "break"
        self.history_pos = (len(self.history) - 1 if self.history_pos is None
                            else max(0, self.history_pos - 1))
        self.var_input.set(self.history[self.history_pos])
        self.entry.icursor("end")
        return "break"

    def _history_fwd(self, _event):
        if self.history_pos is None:
            return "break"
        self.history_pos += 1
        if self.history_pos >= len(self.history):
            self.history_pos = None
            self.var_input.set("")
        else:
            self.var_input.set(self.history[self.history_pos])
        self.entry.icursor("end")
        return "break"

    # ------------------------------------------------------------------ poll
    def _poll(self):
        # Rescheduling lives in `finally` on purpose. This loop is the only
        # thing draining the panes and refreshing the status bar, so if it ever
        # dies the window freezes with no output and no error - it just sits
        # there looking like a hung load. Whatever goes wrong, say so and keep
        # the loop alive.
        try:
            with self._out_lock:
                chunks = {p: bytes(b) for p, b in self._out.items() if b}
                for b in self._out.values():
                    b.clear()
                net_lines = self._net_lines[:]
                del self._net_lines[:]

            if 1 in chunks:
                self._tx_count[1] += len(chunks[1])
                self._append(self.txt1, self._render_uart1(chunks[1]))
            if 2 in chunks:
                self._tx_count[2] += len(chunks[2])
                self._append(self.txt2, self._render_uart2(chunks[2]))

            if net_lines:
                if self._net_hint_shown:
                    # The hint explains how to get traffic; once traffic
                    # arrives it is just a stale line above the real log.
                    self.txt_net.configure(state="normal")
                    self.txt_net.delete("1.0", "end")
                    self.txt_net.configure(state="disabled")
                    self._net_hint_shown = False
                ip_only = self.var_net_ip_only.get()
                for line in net_lines:
                    self._net_count += 1
                    tag = self._net_tag(line)
                    if ip_only and tag == "wifi":
                        continue
                    self._append(self.txt_net, line + "\n", tag)
                self.net_frame.config(text="%s - %d lines" % (NET_TITLE, self._net_count))

            # Keep an open details window current, but not at the poll rate:
            # redrawing a few thousand rows 16 times a second would make the
            # whole window crawl. Once a second, and only when something new
            # actually arrived.
            if (self._detail_win is not None and self._detail_win.winfo_exists()
                    and time.time() - self._detail_drawn_at > 1.0):
                with self._out_lock:
                    total = len(self._frames) + self._frames_dropped
                if total != self._detail_drawn_count:
                    self._detail_drawn_count = total
                    self._refresh_details()
                self._detail_drawn_at = time.time()

            self._refresh_periph()
            self._update_state()
        except Exception:
            detail = traceback.format_exc()
            self.var_state.set("UI error (see UART2 pane) - emulation continues")
            self._append(self.txt2, "\n[!] UI error in _poll:\n%s\n" % detail, "note")
            traceback.print_exc()
        finally:
            self.root.after(POLL_MS, self._poll)

    def _update_state(self):
        alive = self.thread is not None and self.thread.is_alive()

        if self.error:
            self.var_state.set("ERROR  %s" % self.error)
            self._append(self.txt2, "\n[!] %s\n" % self.error, "note")
            self.error = None
            self._finish()
            return
        if self.finished and not alive:
            self.var_state.set("stopped after %s insns" % self._fmt_insns())
            self._append(self.txt2, "\n--- %s ---\n" % self.finished, "note")
            self.finished = None
            self._finish()
            return
        if self.emu is None:
            return

        insns = self.emu.state.insn_count
        now = time.time()
        if self._last_rate_at is not None:
            dt = now - self._last_rate_at
            if dt >= 0.5:
                # Smoothed so the readout does not flicker between polls.
                self._rate = 0.7 * self._rate + 0.3 * ((insns - self._last_insns) / dt)
                self._last_insns, self._last_rate_at = insns, now
        else:
            self._last_insns, self._last_rate_at = insns, now

        ready = self._console_ready()
        self._set_send_enabled(ready)

        if not alive:
            what = "stopped"
        elif self.emu.is_paused():
            what = "PAUSED"
        else:
            what = "running"

        self.var_state.set(
            "%s   %s insns (%.0fk/s)   ~%.1f s guest   %.0f s wall   "
            "PC 0x%08x   TX u1 %d / u2 %d   RX queued %d   console %s"
            % (what, self._fmt_insns(), self._rate / 1000.0,
               insns / float(GUEST_SECOND_INSNS), now - self.started_at,
               self.emu.state.last_pc, self._tx_count[1], self._tx_count[2],
               len(self.emu.uart1_rx), "ready" if ready else "not listening yet"))

    def _fmt_insns(self):
        n = self.emu.state.insn_count if self.emu else 0
        return "%.1fM" % (n / 1e6) if n >= 1e6 else "%d" % n

    def _set_send_enabled(self, on):
        """The typed Send and every quick button share one enabled state."""
        state = "normal" if on else "disabled"
        self.btn_send.config(state=state)
        for btn in self.quick_buttons:
            btn.config(state=state)

    def _finish(self):
        self.btn_run.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.btn_pause.config(state="disabled", text="Pause")
        self._set_send_enabled(False)


# ---------------------------------------------------------------------------
# Self-tests: drive the network pane the way the emulation thread does, without
# running an emulator. Run: python tools/sim_ui.py --selftest
# ---------------------------------------------------------------------------
def _run_selftests():
    n = 0

    def check(cond, msg):
        nonlocal n
        assert cond, "FAIL: " + msg
        n += 1
        print("  [PASS]", msg)

    try:
        root = tk.Tk()
    except tk.TclError as e:
        # No display (a headless CI runner without xvfb). Say so and skip,
        # rather than failing a build over something unrelated to the code.
        print("  [SKIP] no display available: %s" % e)
        return 0
    root.withdraw()
    ui = SimulatorUI(root)

    def pane():
        return ui.txt_net.get("1.0", "end-1c")

    def tags_of(needle):
        return set(ui.txt_net.tag_names(ui.txt_net.search(needle, "1.0", "end"))) - {"sel"}

    print("== network pane: before a run ==")
    check(NET_IDLE_HINT.split(".")[0] in pane(), "the pane says how to switch the bridge on")
    check(ui.net_frame.cget("text") == NET_TITLE, "and its heading carries no count yet")

    print("== network pane: lines from the emulation thread ==")
    lines = [
        "[WIFI] device acts as a station (it probes for networks): peer takes the access point role",
        "[WIFI] station 4c:a9:19:14:71:50 associated to 'HojnikB WiFi' (AID 1)",
        "[NET] DHCP: device 4c:a9:19:14:71:50 got 192.168.1.100 (gateway/DNS 192.168.1.1)",
        "[NET] TCP 192.168.1.100:40127 <-> 18.185.31.196:8886 sends: TLS ClientHello (no server name)",
        '[NET] Tuya LAN broadcast from 192.168.1.100:63035: {"gwId":"bf0e","productKey":"gqmm"}',
        "[NET] MQTT -> device PUBLISH cmnd/obkSim/POWER = ON",
    ]
    for line in lines:
        ui._net_sink(line)                  # exactly what Emulator.net_log calls
    check("HojnikB" not in pane(), "a line is held until the UI drains it, not drawn from that thread")
    ui._poll()
    shown = pane()
    check(NET_IDLE_HINT.split(".")[0] not in shown,
          "the 'nothing yet' note goes once there IS something, rather than sitting above it")
    check(all(l in shown for l in lines), "after one poll every line is in the pane, verbatim")
    check(shown.index(lines[0]) < shown.index(lines[-1]), "and in the order they happened")
    check(ui.net_frame.cget("text") == "%s - 6 lines" % NET_TITLE,
          "the heading counts them, so a glance says whether anything was captured")

    print("== network pane: what each line is coloured as ==")
    check("wifi" in tags_of("device acts as a station"), "Wi-Fi link lines get the link ink")
    check("net" in tags_of("DHCP: device"), "plain IP lines get the IP ink")
    check("payload" in tags_of("TLS ClientHello"), "a line carrying what was SENT is inked apart")
    check("payload" in tags_of("Tuya LAN broadcast"), "...as is a decoded announcement")
    check("payload" in tags_of("MQTT -> device"), "...and a message pushed to the device")

    print("== network pane: the IP-only filter ==")
    ui.var_net_ip_only.set(True)
    for line in lines:
        ui._net_sink(line)
    ui._poll()
    tail = pane()[len(shown):]
    check("[WIFI]" not in tail and "DHCP: device" in tail,
          "with the filter on, link lines are hidden and IP lines still arrive")
    check(ui.net_frame.cget("text") == "%s - 12 lines" % NET_TITLE,
          "the count still reflects everything captured, not only what is shown")
    ui.var_net_ip_only.set(False)

    print("== network pane: clearing and saving ==")
    ui._clear()
    check(NET_IDLE_HINT.split(".")[0] in pane() and "HojnikB" not in pane(),
          "Clear empties the pane and puts the hint back")
    check(ui.net_frame.cget("text") == NET_TITLE, "and resets the count")
    ui._net_sink("[NET] back again")
    ui._poll()
    check("[NET] back again" in pane(), "the pane keeps working after a clear")
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    real_dialog = filedialog.asksaveasfilename
    filedialog.asksaveasfilename = lambda **kw: path
    try:
        ui._save()
        body = open(path, encoding="utf-8").read()
    finally:
        filedialog.asksaveasfilename = real_dialog
        os.remove(path)
    check("=== network (virtual Wi-Fi and IP bridge) ===" in body and "[NET] back again" in body,
          "Save log writes the network pane out under its own heading")

    print("== captured traffic window: the frames themselves ==")
    dev = bytes.fromhex("c8478c000000")
    ours = bytes.fromhex("020000000001")
    dev_ip, our_ip = netstack.str2ip("192.168.1.100"), netstack.str2ip("192.168.1.1")
    seg = netstack.tcp_segment(dev_ip, netstack.str2ip("10.200.0.2"), 40127, 1883,
                               1, 1, netstack.TCP_ACK | netstack.TCP_PSH, 8192,
                               b"\x10\x14\x00\x04MQTT\x04\x02\x00\x3c\x00\x06obkSim")
    f_in = netstack.eth_frame(ours, dev, netstack.ETH_IP, seg)
    f_out = netstack.eth_frame(dev, ours, netstack.ETH_IP,
                               netstack.udp_packet(our_ip, dev_ip, 53, 5353, b"\xbe\xef" + bytes(20)))
    ui._frame_sink("from device", f_in, 1_500_000)
    ui._frame_sink("to device", f_out, 1_600_000)
    ui._open_details()
    check(ui._detail_win is not None and ui._detail_win.winfo_exists(),
          "the details window opens from the pane")
    rows = ui.frame_tree.get_children()
    check(len(rows) == 2, "both captured frames are listed")
    # Tk hands row values back as strings whatever went in.
    vals = [str(v) for v in ui.frame_tree.item(rows[0], "values")]
    check(vals[0] == "1" and vals[2] == "from device" and vals[3] == str(len(f_in)),
          "a row gives the frame's number, direction and exact length")
    check("TCP 192.168.1.100:40127 to 10.200.0.2:1883" in vals[4],
          "and says what the frame is")
    check("(DNS)" in ui.frame_tree.item(rows[1], "values")[4], "the other direction is listed too")

    ui.frame_tree.selection_set(rows[0])
    ui._show_frame_bytes()
    dump = ui.txt_bytes.get("1.0", "end-1c")
    check("obkSim" in dump and "MQTT" in dump,
          "selecting a frame shows its bytes, the payload readable in the dump")
    first = "%08x  %s" % (0, " ".join("%02x" % b for b in f_in[:16]))
    check(first in dump, "the hex is the frame itself, from its first byte")
    check(("%d bytes" % len(f_in)) in dump and "from device" in dump,
          "with a heading saying which frame this is")

    ui.var_frame_filter.set("DNS")
    ui._refresh_details()
    check(len(ui.frame_tree.get_children()) == 1, "the filter narrows the list")
    check("1 match" in ui.var_frame_count.get() or "matching" in ui.var_frame_count.get(),
          "and the count line says how many matched")
    ui.var_frame_filter.set("")
    ui._refresh_details()
    check(len(ui.frame_tree.get_children()) == 2, "clearing the filter brings them back")

    fd, pcap_path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    real_dialog = filedialog.asksaveasfilename
    filedialog.asksaveasfilename = lambda **kw: pcap_path
    try:
        ui._save_pcap()
        blob = open(pcap_path, "rb").read()
    finally:
        filedialog.asksaveasfilename = real_dialog
        os.remove(pcap_path)
    magic, vmaj, vmin, _, _, _, link = struct.unpack("<IHHiIII", blob[:24])
    check((magic, vmaj, vmin, link) == (0xA1B2C3D4, 2, 4, 1),
          "Save .pcap writes an Ethernet capture Wireshark can open")
    off, saved = 24, []
    while off + 16 <= len(blob):
        sec, usec, incl, _orig = struct.unpack("<IIII", blob[off:off + 16])
        saved.append((sec * 1_000_000 + usec, blob[off + 16:off + 16 + incl]))
        off += 16 + incl
    check(off == len(blob) and [s[1] for s in saved] == [f_in, f_out],
          "...holding the captured frames byte for byte, in order")
    check(saved[0][0] == 1_500_000 and saved[1][0] == 1_600_000,
          "each stamped with the device time it crossed")

    print("== double-clicking a line opens the bytes behind THAT line ==")
    check(SimulatorUI._filter_from_line(
        "[NET] TCP 192.168.1.100:40127 <-> 10.200.0.2:1883 sends: MQTT CONNECT") == ":40127",
        "a connection line narrows to its own port, which is unique to it")
    check(SimulatorUI._filter_from_line("[NET] DHCP: device got 192.168.1.100") == "192.168.1.100",
          "a line with no port falls back to the address it names")
    check(SimulatorUI._filter_from_line("[WIFI] device acts as a station") == "",
          "and a line naming neither shows everything rather than hiding frames")
    ui.var_frame_filter.set("")
    ui._refresh_details()
    ui._details_for_click(None)
    check(len(ui.frame_tree.get_children()) == 2,
          "opening the window without a specific line still shows every frame")

    print("== the packet list refreshing during a run ==")
    ui.frame_tree.selection_set("1")
    ui._show_frame_bytes()
    before = ui.txt_bytes.get("1.0", "end-1c")
    ui._frame_sink("from device", f_in, 1_700_000)       # more traffic arrives
    ui._refresh_details()
    check(ui.frame_tree.selection() == ("1",),
          "a refresh keeps the frame the reader had selected")
    check(ui.txt_bytes.get("1.0", "end-1c") == before,
          "...and leaves its bytes on screen rather than jumping to the newest")
    check(len(ui.frame_tree.get_children()) == 3, "while still listing what has since arrived")

    ui._clear()
    check(not ui.frame_tree.get_children() and "Nothing captured yet" in ui.var_frame_count.get(),
          "Clear empties the captured frames as well as the pane")
    ui._detail_win.destroy()

    root.destroy()
    print("\nAll %d simulator UI self-tests passed." % n)
    return n


def main():
    if "--selftest" in sys.argv[1:]:
        _run_selftests()
        return
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    root = tk.Tk()
    SimulatorUI(root, initial)
    root.mainloop()


if __name__ == "__main__":
    main()
