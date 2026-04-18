#!/usr/bin/env python3
import argparse
import math
import os
import platform
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import re
import ctypes


def ansi(*c): return "\033[" + ";".join(map(str, c)) + "m"

RESET = ansi(0)
WHITE = ansi(97)
LIGHT_GREY = ansi(37)
FG_DARK = ansi(30)

BG_GOOD  = ansi(48, 2, 64, 128, 64)
BG_HIGH = ansi(48, 2, 128, 128, 0)
BG_WORSE  = ansi(48, 2, 255, 255, 0)
BG_LOSS  = ansi(48, 2, 255, 0, 0)
BG_BLACK = ansi(40)

FG_GOOD  = ansi(38, 2, 64, 128, 64)
FG_HIGH = ansi(38, 2, 128, 128, 0)
FG_WORSE  = ansi(38, 2, 255, 255, 0)
FG_LOSS  = ansi(38, 2, 255, 0, 0)

class Pending:
    def __init__(self):
        self.created_at = time.monotonic()

PENDING = Pending

def hide(): return "\033[?25l"
def show(): return "\033[?25h"
def move(r, c): return f"\033[{r};{c}H"

def enable_windows_ansi():
    if platform.system().lower() != "windows":
        return False
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if not kernel32.SetConsoleMode(handle, new_mode):
            return False
        return True
    except Exception:
        return False

COLOR_LUMINOSITY = {
    BG_BLACK: 0.00,
    BG_GOOD: 0.43,
    BG_HIGH: 0.93,
    BG_WORSE: 0.47,
    BG_LOSS: 0.21,
}

def font_for_bg(bg):
    return FG_DARK if COLOR_LUMINOSITY.get(bg, 0.5) > 0.5 else WHITE


def braille_from_bits(bits):
    return chr(0x2800 + bits)


def braille_bit(subx, suby):
    # Braille dot mapping: top-to-bottom left is 1,2,3,7; right is 4,5,6,8.
    if subx == 0:
        return [0x01, 0x02, 0x04, 0x40][suby]
    return [0x08, 0x10, 0x20, 0x80][suby]


def fill_pending(samples):
    last = None
    out = []
    for value in samples:
        if isinstance(value, PENDING):
            out.append(last)
        else:
            out.append(value)
            if value is not None:
                last = value
    return out


def sample_uniform(samples, width):
    count = len(samples)
    if count == 0:
        return [None] * width
    out = []
    for idx in range(width):
        pos = int(round((idx + 0.5) * count / width - 0.5))
        pos = max(0, min(count - 1, pos))
        out.append(samples[pos])
    return out


# Sentinel for "no data yet" — distinct from None (packet loss)
NO_DATA = object()


def sample_for_render(samples, width, stretch):
    """Return exactly `width` samples.
    stretch=True: scale available data to fill width (old behaviour).
    stretch=False: anchor data to the right; pad left with NO_DATA."""
    samples = fill_pending(samples)
    count = len(samples)
    if count == 0:
        return [NO_DATA] * width
    if stretch:
        if count >= width:
            return samples[-width:]
        return sample_uniform(samples, width)
    else:
        if count >= width:
            return samples[-width:]
        return [NO_DATA] * (width - count) + samples


def value_bg_color(val, warn, bad):
    """Return background color based on value severity. NO_DATA -> BG_BLACK."""
    if val is None or val is NO_DATA:
        return BG_LOSS if val is None else BG_BLACK
    if val > bad:
        return BG_WORSE
    if val > warn:
        return BG_HIGH
    return BG_GOOD


DEBUG = False
PAYLOAD_SIZE = 0
TIMEOUT = 1.0
RAW_ICMP_AVAILABLE = None


def raw_icmp_available():
    global RAW_ICMP_AVAILABLE
    if RAW_ICMP_AVAILABLE is not None:
        return RAW_ICMP_AVAILABLE
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP):
            pass
        RAW_ICMP_AVAILABLE = True
    except (PermissionError, OSError):
        RAW_ICMP_AVAILABLE = False
    return RAW_ICMP_AVAILABLE


def split_hosts(s):
    out, buf, depth = [], "", 0
    for ch in s:
        if ch == "{": depth += 1
        if ch == "}": depth -= 1
        if ch == "," and depth == 0:
            out.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        out.append(buf.strip())
    return out


def parse_host(h):
    m = re.match(r"([^{}]+)(\{([^}]*)\})?", h)
    host = m.group(1).strip()
    cfg = m.group(3)

    rate = 10.0
    ymin = None
    ymax = None
    warn = 80.0
    bad  = 150.0

    if cfg:
        p = [x.strip() for x in cfg.split(",")]
        if len(p) > 0 and p[0] != "": rate = float(p[0])
        if len(p) > 1 and p[1] != "": ymin = float(p[1])
        if len(p) > 2 and p[2] != "":
            ymax = None if p[2] == "auto" else float(p[2])
        if len(p) > 3 and p[3] != "": warn = float(p[3])
        if len(p) > 4 and p[4] != "": bad = float(p[4])

    return host, rate, ymin, ymax, warn, bad


def _icmp_checksum(source_bytes):
    # Standard 16-bit one's complement checksum over the input bytes.
    count_to = (len(source_bytes) // 2) * 2
    total = 0
    count = 0
    while count < count_to:
        # Combine two bytes into one 16-bit word (big-endian)
        this_val = (source_bytes[count] << 8) + source_bytes[count + 1]
        total += this_val
        total &= 0xFFFFFFFF
        count += 2
    if count_to < len(source_bytes):
        # If there's a leftover byte, treat it as high-order byte
        total += source_bytes[-1] << 8
        total &= 0xFFFFFFFF
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _icmp_packet(identifier, sequence):
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    # Build payload according to PAYLOAD_SIZE. If >=8 bytes, embed a network-order timestamp
    size = max(0, int(PAYLOAD_SIZE))
    if size >= 8:
        ts = struct.pack("!d", time.monotonic())
        if size == 8:
            data = ts
        else:
            data = ts + (b"\x00" * (size - 8))
    else:
        data = b"" if size == 0 else (b"\x00" * size)
    chksum = _icmp_checksum(header + data)
    header = struct.pack("!BBHHH", 8, 0, chksum, identifier, sequence)
    return header + data


def _system_ping(host, timeout):
    if platform.system().lower() == "windows":
        wait_ms = max(1, int(timeout * 1000))
        cmd = ["ping", "-n", "1", "-w", str(wait_ms), "-l", "0", host]
    else:
        wait_s = max(1, math.ceil(timeout))
        cmd = ["ping", "-c", "1", "-W", str(wait_s), "-s", "16", host]
    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    m = re.search(r"time[=<]\s*([\d\.]+)", out)
    if m:
        return float(m.group(1))
    return None


def ping(host, timeout, sequence=1):
    try:
        dest = socket.gethostbyname(host)
    except socket.gaierror:
        return None

    if not raw_icmp_available():
        if DEBUG:
            sys.stderr.write(f"[mping] raw ICMP unavailable, using system ping for {host}\n")
        try:
            return _system_ping(host, timeout)
        except Exception:
            return None

    identifier = os.getpid() & 0xFFFF
    packet = _icmp_packet(identifier, sequence)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(timeout)
            # Try to connect the raw socket to the remote dest so the kernel filters incoming ICMP
            # to this peer. Not supported on all platforms — ignore failures.
            connected = False
            try:
                sock.connect((dest, 0))
                connected = True
                if DEBUG:
                    sys.stderr.write(f"[mping] raw socket connected to {dest}\n")
            except Exception:
                if DEBUG:
                    sys.stderr.write(f"[mping] raw socket connect to {dest} failed, will recv all ICMP\n")
            # Record the local send time as a fallback if the remote reply doesn't contain our timestamp
            # Use monotonic to avoid jumps from system clock adjustments
            send_ts = time.monotonic()
            if connected:
                try:
                    sock.send(packet)
                except Exception:
                    sock.sendto(packet, (dest, 0))
            else:
                sock.sendto(packet, (dest, 0))
            while True:
                try:
                    recvd, addr = sock.recvfrom(1024)
                except socket.timeout:
                    return None
                except OSError:
                    return None
                
                if addr[0] != dest:
                    if DEBUG:
                        sys.stderr.write(f"[mping] recv from {addr[0]} (expected {dest}), skipping\n")
                    continue
                if len(recvd) < 8:
                    if DEBUG:
                        sys.stderr.write(f"[mping] recv too short ({len(recvd)}) from {addr[0]}\n")
                    continue
                
                # Try to detect if IP header is included (Linux/Mac behavior)
                first_byte = recvd[0]
                if first_byte >> 4 == 4 and len(recvd) >= 20:
                    # IPv4 header present, calculate its length
                    ip_header_len = (first_byte & 0x0F) * 4
                else:
                    # No IPv4 header (Windows behavior)
                    ip_header_len = 0
                
                icmp_offset = ip_header_len
                # Ensure we have at least the ICMP header
                if len(recvd) < icmp_offset + 8:
                    if DEBUG:
                        sys.stderr.write(f"[mping] icmp packet too short ({len(recvd) - icmp_offset}) from {addr[0]}\n")
                    continue
                
                try:
                    icmp_header = recvd[icmp_offset:icmp_offset + 8]
                    type_, code, _, pkt_id, seq = struct.unpack("!BBHHH", icmp_header)
                except struct.error:
                    continue
                
                # Check for echo reply with matching identifier and sequence
                if type_ == 0 and code == 0 and pkt_id == identifier and seq == sequence:
                    # Prefer the embedded timestamp, but fall back to local send time if payload missing/truncated
                    elapsed = None
                    used_payload = False
                    if len(recvd) >= icmp_offset + 16:
                        try:
                            t0 = struct.unpack("!d", recvd[icmp_offset + 8:icmp_offset + 16])[0]
                            # t0 was recorded using monotonic()
                            elapsed = (time.monotonic() - t0) * 1000
                            used_payload = True
                        except (struct.error, ValueError):
                            elapsed = None
                    if elapsed is None:
                        # Use local measured send time as fallback (monotonic)
                        elapsed = (time.monotonic() - send_ts) * 1000

                    if DEBUG:
                        src = addr[0]
                        method = "payload" if used_payload else "local-send"
                        sys.stderr.write(f"[mping] reply from {src} id={pkt_id} seq={seq} method={method} rtt={elapsed:.3f}ms\n")

                    # Sanity check: ping time should be positive and under 1 minute
                    if elapsed is not None and elapsed > 0 and elapsed < 60000:
                        return elapsed
    except PermissionError:
        try:
            return _system_ping(host, timeout)
        except Exception:
            return None
    except socket.gaierror:
        return None
    except Exception:
        try:
            return _system_ping(host, timeout)
        except Exception:
            return None
    return None


# Global ICMP manager to multiplex a single raw socket across all workers.
icmp_manager = None


def get_icmp_manager():
    global icmp_manager
    if icmp_manager is None:
        icmp_manager = ICMPManager()
    return icmp_manager


class ICMPManager:
    def __init__(self):
        self.sock = None
        self.lock = threading.Lock()
        # pending: key=(dest_ip, identifier, sequence) -> {'event': Event, 'result': None, 'send_ts': float}
        self.pending = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(None)
            self.sock = s
            self.thread = threading.Thread(target=self._recv_loop, daemon=True)
            self.thread.start()
            if DEBUG:
                sys.stderr.write("[mping] ICMPManager: raw socket opened\n")
        except PermissionError:
            if DEBUG:
                sys.stderr.write("[mping] ICMPManager: permission denied for raw socket, falling back to system ping\n")
            self.sock = None
        except Exception as e:
            if DEBUG:
                sys.stderr.write(f"[mping] ICMPManager: raw socket open error: {e}\n")
            self.sock = None

    def request(self, dest, timeout, identifier, sequence):
        if self.sock is None or not raw_icmp_available():
            if DEBUG:
                sys.stderr.write(f"[mping] ICMPManager: raw ICMP unavailable, falling back to system ping for {dest}\n")
            try:
                return _system_ping(dest, timeout)
            except Exception:
                return None

        try:
            dest_ip = socket.gethostbyname(dest)
        except socket.gaierror:
            return None

        key = (dest_ip, identifier, sequence)
        ev = threading.Event()
        entry = {"event": ev, "result": None, "send_ts": time.monotonic()}
        with self.lock:
            self.pending[key] = entry
        if DEBUG:
            sys.stderr.write(f"[mping] ICMPManager: registered pending {key}\n")

        packet = _icmp_packet(identifier, sequence)
        try:
            self.sock.sendto(packet, (dest_ip, 0))
        except Exception as e:
            with self.lock:
                self.pending.pop(key, None)
            if DEBUG:
                sys.stderr.write(f"[mping] ICMPManager sendto failed: {e}\n")
            try:
                return _system_ping(dest, timeout)
            except Exception:
                return None

        ev.wait(timeout)
        with self.lock:
            res_entry = self.pending.pop(key, None)
        if res_entry:
            return res_entry.get("result")
        return None

    def _recv_loop(self):
        while True:
            try:
                recvd, addr = self.sock.recvfrom(4096)
            except Exception:
                time.sleep(0.01)
                continue
            if not recvd:
                continue

            first_byte = recvd[0]
            if first_byte >> 4 == 4 and len(recvd) >= 20:
                ip_header_len = (first_byte & 0x0F) * 4
                src = addr[0]
            else:
                ip_header_len = 0
                src = addr[0]

            icmp_offset = ip_header_len
            if len(recvd) < icmp_offset + 8:
                continue

            try:
                icmp_header = recvd[icmp_offset:icmp_offset + 8]
                type_, code, _, pkt_id, seq = struct.unpack("!BBHHH", icmp_header)
            except struct.error:
                continue

            # Only handle echo replies
            if type_ != 0 or code != 0:
                continue

            found_key = (src, pkt_id, seq)
            with self.lock:
                entry = self.pending.get(found_key)

            if entry is None:
                continue

            elapsed = None
            if len(recvd) >= icmp_offset + 16:
                try:
                    t0 = struct.unpack("!d", recvd[icmp_offset + 8:icmp_offset + 16])[0]
                    elapsed = (time.monotonic() - t0) * 1000
                except Exception:
                    elapsed = None

            if elapsed is None:
                send_ts = entry.get("send_ts")
                if send_ts:
                    elapsed = (time.monotonic() - send_ts) * 1000

            result = None if (elapsed is None or elapsed <= 0 or elapsed >= 60000) else elapsed

            if DEBUG:
                sys.stderr.write(f"[mping] ICMPManager got reply from {src} id={pkt_id} seq={seq} rtt={result}\n")

            with self.lock:
                e = self.pending.get(found_key)
                if e is not None:
                    e["result"] = result
                    e["event"].set()


class Worker(threading.Thread):
    def __init__(self, host, rate):
        super().__init__(daemon=True)
        self.host = host
        self.rate = rate
        self.data = []
        self.braille_data = []
        self.lock = threading.Lock()
        self.sequence = 0
        self.identifier = id(self) & 0xFFFF

    def run(self):
        interval = 1 / max(0.1, self.rate)
        next_tick = time.monotonic()
        while True:
            now = time.monotonic()
            if now < next_tick:
                time.sleep(next_tick - now)
            self.sequence = (self.sequence + 1) & 0xFFFF
            slot = PENDING()
            seq = self.sequence
            with self.lock:
                self.data.append(slot)
                self.data = self.data[-2000:]
            threading.Thread(target=self._resolve, args=(slot, interval, seq), daemon=True).start()
            next_tick += interval

    def _resolve(self, slot, timeout, sequence):
        try:
            manager = get_icmp_manager()
        except Exception:
            manager = None

        if manager is not None and getattr(manager, "sock", None) is not None:
            try:
                result = manager.request(self.host, TIMEOUT, self.identifier, sequence)
            except Exception:
                result = None
        else:
            result = ping(self.host, TIMEOUT, sequence)
        with self.lock:
            for idx, item in enumerate(self.data):
                if item is slot:
                    self.data[idx] = result
                    break
            self.braille_data.append(result)
            self.braille_data = self.braille_data[-2000:]

    def snap(self, n):
        with self.lock:
            return self.data[-n:]

    def snap_braille(self, n):
        """Return raw braille samples (no padding)."""
        with self.lock:
            raw = self.braille_data[-(n * 2):]

        # Pair WITHOUT padding
        pairs = []
        for i in range(0, len(raw), 2):
            left = raw[i]
            right = raw[i + 1] if i + 1 < len(raw) else NO_DATA
            pairs.append((left, right))

        return pairs



def layout(n, rows=None, cols=None):
    if rows is not None and cols is not None:
        return rows, cols
    if rows is not None:
        cols = (n + rows - 1) // rows
        return rows, cols
    if cols is not None:
        rows = (n + cols - 1) // cols
        return rows, cols
    if n == 1:
        return 1, 1
    if n == 2:
        return 2, 1
    if n <= 4:
        return 2, 2
    c = int(n ** 0.5)
    r = (n + c - 1) // c
    return r, c

def render(workers, cfgs, cols, rows, grid_rows=None, grid_cols=None, braille=False, stretch=False):
    if braille:
        return render_braille(workers, cfgs, cols, rows, grid_rows=grid_rows, grid_cols=grid_cols, stretch=stretch)
    return render_highres(workers, cfgs, cols, rows, grid_rows=grid_rows, grid_cols=grid_cols, stretch=stretch)


def render_highres(workers, cfgs, cols, rows, grid_rows=None, grid_cols=None, stretch=False):
    grid_r, grid_c = layout(len(workers), rows=grid_rows, cols=grid_cols)
    cell_w = max(1, cols // grid_c)

    row_base = rows // grid_r
    row_extra = rows % grid_r
    if row_base >= 4:
        row_heights = [row_base + (1 if i < row_extra else 0) for i in range(grid_r)]
    else:
        row_heights = [max(4, row_base)] * grid_r

    row_offsets = [1]
    for height in row_heights[:-1]:
        row_offsets.append(row_offsets[-1] + height)

    out = []

    for i, w in enumerate(workers):
        host, _, ymin, ymax, warn, bad = cfgs[i]

        row = i // grid_c
        col = i % grid_c
        cell_h = row_heights[row]
        r0 = row_offsets[row]
        c0 = col * cell_w + 1

        snap = sample_for_render(w.snap(min(2000, cell_w)), cell_w, stretch)
        valid = [x for x in snap if x is not None and x is not NO_DATA and not isinstance(x, PENDING)]

        gmax = max(valid) if valid else 100.0
        if ymax is not None:
            gmax = ymax
        if ymin is not None:
            gmin = ymin
        else:
            gmin = min(valid) if valid else 0.0

        fmt = "{:.2f}" if (gmax - gmin) < 2 else "{:.1f}" if (gmax - gmin) < 10 else "{:.0f}"

        canvas = [[BG_BLACK + " " + RESET] * cell_w for _ in range(cell_h)]

        # Draw graph on ALL rows, including the top row
        for x in range(cell_w):
            val = snap[x * len(snap) // cell_w] if snap else None
            if isinstance(val, PENDING) or val is NO_DATA:
                continue
            color = value_bg_color(val, warn, bad)

            for y in range(cell_h):
                level = gmax - (y / (cell_h - 1) * (gmax - gmin)) if cell_h > 1 else gmax
                if val is None or val >= level:
                    canvas[y][x] = color + " " + RESET

        # Y-axis labels
        top_label = fmt.format(gmax)
        for j, ch in enumerate(top_label):
            if j < cell_w:
                bg = canvas[0][j].split("m", 1)[0] + "m"
                canvas[0][j] = bg + font_for_bg(bg) + ch + RESET

        bottom_label = fmt.format(gmin)
        for j, ch in enumerate(bottom_label):
            if j < cell_w:
                bg = canvas[cell_h-1][j].split("m", 1)[0] + "m"
                canvas[cell_h-1][j] = bg + font_for_bg(bg) + ch + RESET

        # Middle labels
        num_middle = min(3, cell_h - 3)
        if num_middle > 0:
            for k in range(1, num_middle + 1):
                y = int((k * (cell_h - 1)) / (num_middle + 1))
                if 0 < y < cell_h - 1:
                    val = gmax - (y / (cell_h - 1)) * (gmax - gmin)
                    lbl = fmt.format(val)
                    for j, ch in enumerate(lbl):
                        if j < cell_w:
                            bg = canvas[y][j].split("m", 1)[0] + "m"
                            canvas[y][j] = bg + font_for_bg(bg) + ch + RESET

        # Header placement
        avg = sum(valid)/len(valid) if valid else 0
        mn = min(valid) if valid else 0
        mx = max(valid) if valid else 0
        resolved_count = len([x for x in snap if x is not NO_DATA and not isinstance(x, PENDING)])
        loss_count = sum(1 for x in snap if x is None)
        loss_pct = 100 * loss_count / resolved_count if resolved_count else 0

        if mx < 2:
            stats = f"min:{mn:.2f} avg:{avg:.2f} max:{mx:.2f} loss:{loss_count} ({loss_pct:.0f}%)"
        elif mx < 10:
            stats = f"min:{mn:.1f} avg:{avg:.1f} max:{mx:.1f} loss:{loss_count} ({loss_pct:.0f}%)"
        else:
            stats = f"min:{mn:.0f} avg:{avg:.0f} max:{mx:.0f} loss:{loss_count} ({loss_pct:.0f}%)"

        label_len = len(top_label)
        max_padding = 4
        min_padding = 1
        start_col = label_len + max_padding
        stats_sections = [
            f"min:{mn:.2f}" if mx < 2 else f"min:{mn:.1f}" if mx < 10 else f"min:{mn:.0f}",
            f"avg:{avg:.2f}" if mx < 2 else f"avg:{avg:.1f}" if mx < 10 else f"avg:{avg:.0f}",
            f"max:{mx:.2f}" if mx < 2 else f"max:{mx:.1f}" if mx < 10 else f"max:{mx:.0f}",
            f"loss:{loss_count} ({loss_pct:.0f}%)"
        ]
        header_sections = [host] + stats_sections

        # If the header doesn't fit, use up to 3 of the padding spaces first.
        total_length = len(host) + sum(len(s) + 1 for s in stats_sections)
        if total_length > cell_w - start_col:
            start_col = max(label_len + min_padding, cell_w - total_length)
            if start_col > label_len + max_padding:
                start_col = label_len + max_padding

        row = 0
        col = start_col
        for idx, section in enumerate(header_sections):
            seg = section if idx == 0 else " " + section
            if col + len(seg) > cell_w and row == 0:
                row = 1
                col = start_col
            if col >= cell_w:
                break
            for ch in seg:
                if col >= cell_w:
                    break
                bg = canvas[row][col].split("m", 1)[0] + "m"
                canvas[row][col] = bg + font_for_bg(bg) + ch + RESET
                col += 1

        # Output cell
        for y in range(cell_h):
            out.append(move(r0 + y, c0) + "".join(canvas[y]))

    # Fill empty cells
    total_cells = grid_r * grid_c
    if len(workers) < total_cells:
        for i in range(len(workers), total_cells):
            r0 = (i // grid_c) * cell_h + 1
            c0 = (i % grid_c) * cell_w + 1
            for y in range(cell_h):
                out.append(move(r0 + y, c0) + (BG_BLACK + " " + RESET) * cell_w)

    return "".join(out)


def render_braille(workers, cfgs, cols, rows, grid_rows=None, grid_cols=None, stretch=False):
    grid_r, grid_c = layout(len(workers), rows=grid_rows, cols=grid_cols)
    cell_w = max(1, cols // grid_c)

    row_base = rows // grid_r
    row_extra = rows % grid_r
    if row_base >= 4:
        row_heights = [row_base + (1 if i < row_extra else 0) for i in range(grid_r)]
    else:
        row_heights = [max(4, row_base)] * grid_r

    row_offsets = [1]
    for height in row_heights[:-1]:
        row_offsets.append(row_offsets[-1] + height)

    out = []

    for i, w in enumerate(workers):
        host, _, ymin, ymax, warn, bad = cfgs[i]

        row = i // grid_c
        col = i % grid_c
        cell_h = row_heights[row]
        r0 = row_offsets[row]
        c0 = col * cell_w + 1

        # snap_braille returns pairs; get enough for cell_w columns
        raw_pairs = w.snap_braille(cell_w)
        have = len(raw_pairs)

        if stretch:
            # Flatten and stretch
            flat = []
            for a, b in raw_pairs:
                flat.append(a)
                flat.append(b)
            snap = sample_for_render(flat, cell_w * 2, stretch=True)
        else:
            # Flatten first
            flat = []
            for a, b in raw_pairs:
                flat.append(a)
                flat.append(b)

            snap = sample_for_render(flat, cell_w * 2, stretch=False)

        virtual_w = cell_w * 2
        valid = [x for x in snap if x is not None and x is not NO_DATA and not isinstance(x, PENDING)]

        gmax = max(valid) if valid else 100.0
        if ymax is not None:
            gmax = ymax
        if ymin is not None:
            gmin = ymin
        else:
            gmin = min(valid) if valid else 0.0

        fmt = "{:.2f}" if (gmax - gmin) < 2 else "{:.1f}" if (gmax - gmin) < 10 else "{:.0f}"

        pixel_h = cell_h * 4
        pixels = [[False] * virtual_w for _ in range(pixel_h)]
        col_colors = [BG_BLACK] * virtual_w

        for vx in range(virtual_w):
            val = snap[vx]

            if val is NO_DATA or isinstance(val, PENDING):
                col_colors[vx] = BG_BLACK
                continue

            col_colors[vx] = value_bg_color(val, warn, bad)

            if val is None:
                # packet loss → full red column
                for py in range(pixel_h):
                    pixels[py][vx] = True
            else:
                for py in range(pixel_h):
                    level = gmax - (py / (pixel_h - 1) * (gmax - gmin)) if pixel_h > 1 else gmax
                    if val >= level:
                        pixels[py][vx] = True

        canvas = [[BG_BLACK + " " + RESET] * cell_w for _ in range(cell_h)]
        for y in range(cell_h):
            for x in range(cell_w):
                bits = 0
                for subx in range(2):
                    for suby in range(4):
                        px = x * 2 + subx
                        py = y * 4 + suby
                        if py < pixel_h and px < virtual_w and pixels[py][px]:
                            bits |= braille_bit(subx, suby)

                if bits:
                    left_color = col_colors[x * 2] if x * 2 < virtual_w else BG_BLACK
                    right_color = col_colors[x * 2 + 1] if x * 2 + 1 < virtual_w else BG_BLACK
                    severity = {BG_BLACK: 0, BG_GOOD: 1, BG_HIGH: 2, BG_WORSE: 3, BG_LOSS: 4}
                    bg_color = left_color if severity.get(left_color, 0) >= severity.get(right_color, 0) else right_color
                    fg_map = {BG_GOOD: FG_GOOD, BG_HIGH: FG_HIGH, BG_WORSE: FG_WORSE, BG_LOSS: FG_LOSS, BG_BLACK: FG_GOOD}
                    fg_color = fg_map.get(bg_color, FG_GOOD)
                    canvas[y][x] = BG_BLACK + fg_color + braille_from_bits(bits) + RESET
                else:
                    canvas[y][x] = BG_BLACK + " " + RESET

        top_label = fmt.format(gmax)
        for j, ch in enumerate(top_label):
            if j < cell_w:
                bg = canvas[0][j].split("m", 1)[0] + "m"
                canvas[0][j] = bg + font_for_bg(bg) + ch + RESET

        bottom_label = fmt.format(gmin)
        for j, ch in enumerate(bottom_label):
            if j < cell_w:
                bg = canvas[cell_h-1][j].split("m", 1)[0] + "m"
                canvas[cell_h-1][j] = bg + font_for_bg(bg) + ch + RESET

        num_middle = min(3, cell_h - 3)
        if num_middle > 0:
            for k in range(1, num_middle + 1):
                y = int((k * (cell_h - 1)) / (num_middle + 1))
                if 0 < y < cell_h - 1:
                    val = gmax - (y / (cell_h - 1)) * (gmax - gmin)
                    lbl = fmt.format(val)
                    for j, ch in enumerate(lbl):
                        if j < cell_w:
                            bg = canvas[y][j].split("m", 1)[0] + "m"
                            canvas[y][j] = bg + font_for_bg(bg) + ch + RESET

        avg = sum(valid)/len(valid) if valid else 0
        mn = min(valid) if valid else 0
        mx = max(valid) if valid else 0
        resolved_count = len([x for x in snap if x is not NO_DATA and not isinstance(x, PENDING)])
        loss_count = sum(1 for x in snap if x is None)
        loss_pct = 100 * loss_count / resolved_count if resolved_count else 0

        if mx < 2:
            stats = f"min:{mn:.2f} avg:{avg:.2f} max:{mx:.2f} loss:{loss_count} ({loss_pct:.0f}%)"
        elif mx < 10:
            stats = f"min:{mn:.1f} avg:{avg:.1f} max:{mx:.1f} loss:{loss_count} ({loss_pct:.0f}%)"
        else:
            stats = f"min:{mn:.0f} avg:{avg:.0f} max:{mx:.0f} loss:{loss_count} ({loss_pct:.0f}%)"

        label_len = len(top_label)
        max_padding = 4
        min_padding = 1
        start_col = label_len + max_padding
        stats_sections = [
            f"min:{mn:.2f}" if mx < 2 else f"min:{mn:.1f}" if mx < 10 else f"min:{mn:.0f}",
            f"avg:{avg:.2f}" if mx < 2 else f"avg:{avg:.1f}" if mx < 10 else f"avg:{avg:.0f}",
            f"max:{mx:.2f}" if mx < 2 else f"max:{mx:.1f}" if mx < 10 else f"max:{mx:.0f}",
            f"loss:{loss_count} ({loss_pct:.0f}%)"
        ]
        header_sections = [host] + stats_sections

        total_length = len(host) + sum(len(s) + 1 for s in stats_sections)
        if total_length > cell_w - start_col:
            start_col = max(label_len + min_padding, cell_w - total_length)
            if start_col > label_len + max_padding:
                start_col = label_len + max_padding

        row = 0
        col = start_col
        for idx, section in enumerate(header_sections):
            seg = section if idx == 0 else " " + section
            if col + len(seg) > cell_w and row == 0:
                row = 1
                col = start_col
            if col >= cell_w:
                break
            for ch in seg:
                if col >= cell_w:
                    break
                bg = canvas[row][col].split("m", 1)[0] + "m"
                canvas[row][col] = bg + font_for_bg(bg) + ch + RESET
                col += 1

        for y in range(cell_h):
            out.append(move(r0 + y, c0) + "".join(canvas[y]))

    total_cells = grid_r * grid_c
    if len(workers) < total_cells:
        for i in range(len(workers), total_cells):
            r0 = (i // grid_c) * cell_h + 1
            c0 = (i % grid_c) * cell_w + 1
            for y in range(cell_h):
                out.append(move(r0 + y, c0) + (BG_BLACK + " " + RESET) * cell_w)

    return "".join(out)


def main():
    ap = argparse.ArgumentParser(
        prog="pngr",
        description="pngr v1.2 — terminal ping grapher. Monitor latency and packet loss for one or more hosts in a live grid.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("hosts", nargs="+",
        help=("Host definitions. Use comma-separated hosts or separate entries.\nExamples:\n  pngr 1.1.1.1 8.8.8.8\n  pngr 1.1.1.1{10,0,auto,100,200} 8.8.8.8{5,,200}\nLeave individual config fields empty to keep defaults, e.g. host{,10,,200,150}.")
    )
    ap.add_argument("--rows", type=int, default=None,
        help="Force the graph grid to use this many rows. Columns auto-adjust unless --cols is also supplied."
    )
    ap.add_argument("--cols", type=int, default=None,
        help="Force the graph grid to use this many columns. Rows auto-adjust unless --rows is also supplied."
    )
    ap.add_argument("--debug", action="store_true",
        help="Enable debug output to stderr"
    )
    ap.add_argument("--payload-size", type=int, default=None,
        help="ICMP payload size in bytes (0 = minimal, 8 embeds timestamp). Overrides default behavior."
    )
    ap.add_argument("--timeout", type=float, default=3.0,
        help="Ping timeout in seconds for each probe. This is separate from the send rate."
    )
    ap.add_argument("--braille", action="store_true",
        help="Use Unicode braille rendering for the graphs. High-resolution half-block mode is the default."
    )
    ap.add_argument("--stretch", action="store_true",
        help="Stretch data to fill the full width before the buffer is full. Default is to scroll in from the right with the left side black."
    )
    ap.add_argument("--version", action="version", version="pngr v1.1")
    args = ap.parse_args()

    # Enable module debug output if requested
    global DEBUG, TIMEOUT
    DEBUG = bool(args.debug)
    TIMEOUT = max(0.01, float(args.timeout))
    global PAYLOAD_SIZE
    if args.payload_size is not None:
        PAYLOAD_SIZE = max(0, int(args.payload_size))

    if sys.stdout.isatty() and platform.system().lower() == "windows":
        enabled = enable_windows_ansi()
        if DEBUG:
            sys.stderr.write(f"[mping] Windows ANSI enabled: {enabled}\n")
        if not enabled:
            sys.stderr.write("[mping] warning: Windows ANSI not enabled, output may not render correctly in this terminal\n")

    if len(args.hosts) == 1:
        hosts = split_hosts(args.hosts[0])
    else:
        hosts = []
        for token in args.hosts:
            hosts.extend(split_hosts(token))
    cfgs = [parse_host(h) for h in hosts]

    workers = [Worker(c[0], c[1]) for c in cfgs]
    for w in workers:
        w.start()

    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    sys.stdout.write(hide())
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

    try:
        prev_cols, prev_rows = shutil.get_terminal_size((120, 40))
        while True:
            cols, rows = shutil.get_terminal_size((120, 40))
            frame = render(
                workers,
                cfgs,
                cols,
                rows,
                grid_rows=args.rows,
                grid_cols=args.cols,
                braille=args.braille,
                stretch=args.stretch,
            )
            sys.stdout.write("\033[H")
            if cols != prev_cols or rows != prev_rows:
                sys.stdout.write("\033[0J")
                prev_cols, prev_rows = cols, rows
            sys.stdout.write(frame)
            sys.stdout.flush()
            time.sleep(0.1)
    finally:
        sys.stdout.write(show() + "\n")


if __name__ == "__main__":
    main()
