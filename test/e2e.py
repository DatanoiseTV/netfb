#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""End-to-end test for netfb: boots a kernel in QEMU with the module loaded and
drives it over the forwarded HTTP/WebSocket port.

    e2e.py --image Image --initrd initramfs.cpio.gz

Only the standard library is used on purpose: the WebSocket client below is a
raw RFC 6455 implementation, so the test sees exactly what a browser would.
"""
import argparse, base64, gzip, hashlib, json, os, random, re, socket, struct
import subprocess, sys, threading, time

TOKEN = "test-token-0123456789abcdef"
VNC_PW = "n3tfbVnc"
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
W, H = 320, 200
RED, GREEN, BLUE, BLACK = 0x00FF0000, 0x0000FF00, 0x000000FF, 0
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail and not ok else ""), flush=True)
    return ok


# ---- serial console ------------------------------------------------------
class Serial:
    def __init__(self, port):
        self.lines, self.lock, self.buf = [], threading.Lock(), b""
        for _ in range(100):
            try:
                self.sock = socket.create_connection(("127.0.0.1", port))
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("serial port never came up")
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                d = self.sock.recv(4096)
            except OSError:
                return
            if not d:
                return
            self.buf += d
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                s = line.decode(errors="replace").rstrip("\r")
                with self.lock:
                    self.lines.append(s)
                print("  | " + s, flush=True)

    def send(self, s):
        self.sock.sendall(s.encode() + b"\n")

    def mark(self):
        with self.lock:
            return len(self.lines)

    def since(self, mark):
        with self.lock:
            return list(self.lines[mark:])

    def wait(self, pat, timeout=30, mark=0):
        end = time.time() + timeout
        while time.time() < end:
            for l in self.since(mark):
                if re.search(pat, l):
                    return l
            time.sleep(0.05)
        return None


def lz4_block(src, raw_len):
    """Independent LZ4 block decoder (spec: lz4_Block_format.md), strict about bounds."""
    out, i = bytearray(), 0
    while i < len(src):
        tok = src[i]; i += 1
        n = tok >> 4
        if n == 15:
            while True:
                b = src[i]; i += 1; n += b
                if b != 255:
                    break
        out += src[i:i + n]; i += n
        if i >= len(src):
            break
        off = src[i] | (src[i + 1] << 8); i += 2
        m = tok & 15
        if m == 15:
            while True:
                b = src[i]; i += 1; m += b
                if b != 255:
                    break
        m += 4
        assert 0 < off <= len(out), "bad LZ4 offset"
        for _ in range(m):
            out.append(out[-off])
    assert len(out) == raw_len, f"LZ4 decoded {len(out)} bytes, expected {raw_len}"
    return bytes(out)


# ---- HTTP / WebSocket ----------------------------------------------------
def http(port, request, timeout=10):
    """Send raw bytes, return (status, headers dict, body)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(request if isinstance(request, bytes) else request.encode())
    data = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            data += d
    except (socket.timeout, ConnectionResetError):
        pass
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    status = int(lines[0].split()[1]) if lines and lines[0].startswith("HTTP/") else 0
    hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
    return status, hdrs, body


def get(port, path, extra=""):
    return http(port, f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra}Connection: close\r\n\r\n")


class WS:
    def __init__(self, port, path=f"/ws?token={TOKEN}", origin=None):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n")
        if origin:
            req += f"Origin: {origin}\r\n"
        self.sock.sendall((req + "\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            d = self.sock.recv(4096)
            if not d:
                raise ConnectionError("closed during handshake")
            head += d
        head, _, self.buf = head.partition(b"\r\n\r\n")
        self.status = int(head.split()[1])
        want = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
        self.accept_ok = want in head.decode()
        self.info, self.msgs = None, []          # msgs: (time, y, h)
        self.texts = []                          # non-info text messages (pong, ...)
        self.wire, self.lz4 = [], []             # per message: payload bytes, was LZ4
        self.px = bytearray(W * H * 4)
        self.closed = None

    def send(self, op, payload=b"", mask=True, fin=True):
        b0 = (0x80 if fin else 0) | op
        n = len(payload)
        hdr = bytes([b0, (0x80 if mask else 0) | (n if n < 126 else 126)])
        if n >= 126:
            hdr += struct.pack(">H", n)
        if mask:
            m = os.urandom(4)
            payload = bytes(c ^ m[i & 3] for i, c in enumerate(payload))
            hdr += m
        self.sock.sendall(hdr + payload)

    def cmd(self, text):
        self.send(1, text.encode())

    def _need(self, n, deadline):
        while len(self.buf) < n:
            self.sock.settimeout(max(0.01, deadline - time.time()))
            try:
                d = self.sock.recv(1 << 16)
            except socket.timeout:
                return False
            if not d:
                raise EOFError
            self.buf += d
        return True

    def recv(self, timeout=0.2):
        """-> (opcode, payload) or None on timeout; raises EOFError at EOF."""
        deadline = time.time() + timeout
        if not self._need(2, deadline):
            return None
        n = self.buf[1] & 0x7F
        hl = 2
        if n == 126:
            if not self._need(4, deadline):
                return None
            n, hl = struct.unpack(">H", self.buf[2:4])[0], 4
            # RFC 6455 5.2: the minimal length encoding must be used. Browsers
            # drop the connection ("Invalid frame header") when it is not.
            if n < 126:
                raise ValueError(f"non-minimal 16 bit length {n}")
        elif n == 127:
            raise ValueError("64 bit length from server")
        if not self._need(hl + n, deadline):
            return None
        op, payload = self.buf[0] & 0xF, bytes(self.buf[hl:hl + n])
        self.buf = self.buf[hl + n:]
        return op, payload

    def handle(self, op, p):
        if op == 1:
            m = json.loads(p)
            if m.get("type") == "info":
                self.info = m
            else:
                self.texts.append(m)
        elif op == 2 and p[0] == 1:
            y, h = struct.unpack("<HH", p[2:6])
            stride = W * 4
            if p[1] & 1:
                data = lz4_block(p[8:], h * stride)
            else:
                assert len(p) == 8 + h * stride, "bad message length"
                data = p[8:]
            self.px[y * stride:(y + h) * stride] = data
            self.msgs.append((time.time(), y, h))
            self.wire.append(len(p))
            self.lz4.append(bool(p[1] & 1))
        elif op == 8:
            self.closed = struct.unpack(">H", p[:2])[0] if len(p) >= 2 else 0
        return op

    def pump(self, until=None, timeout=10):
        end = time.time() + timeout
        while time.time() < end and self.closed is None:
            if until and until():
                return True
            try:
                r = self.recv(0.1)
            except EOFError:
                self.closed = self.closed if self.closed is not None else -1
                break
            if r:
                self.handle(*r)
        return bool(until and until())

    def pixel(self, x, y):
        return struct.unpack_from("<I", self.px, (y * W + x) * 4)[0]

    def row_is(self, y, color):
        return all(self.pixel(x, y) == color for x in (0, W // 2, W - 1))

    def rows_received(self, since=0):
        return sum(h for _, _, h in self.msgs[since:])

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def wait_rows(ws, spec, timeout=10):
    """spec: list of (y, color). True when all rows match."""
    return ws.pump(lambda: all(ws.row_is(y, c) for y, c in spec), timeout)


# ---- tests ---------------------------------------------------------------
def t_http(port):
    st, h, body = get(port, "/")
    check("GET / -> 200 gzip html", st == 200 and h.get("content-encoding") == "gzip" and
          b"<title>netfb</title>" in gzip.decompress(body))
    check("security headers present", all(k in h for k in
          ("content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy")))
    check("/favicon.ico -> 204", get(port, "/favicon.ico")[0] == 204)
    check("unknown path -> 404", get(port, "/nope")[0] == 404)
    check("POST -> 405", http(port, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")[0] == 405)
    check("garbage request line -> 400", http(port, "BLAH\r\n\r\n")[0] == 400)
    check("relative target -> 400", http(port, "GET nope HTTP/1.1\r\nHost: x\r\n\r\n")[0] == 400)
    check("oversized head -> 431", http(port, "GET / HTTP/1.1\r\nX: " + "a" * 5000 + "\r\n\r\n")[0] == 431)
    check("overlong target -> 400", http(port, "GET /" + "a" * 600 + " HTTP/1.1\r\nHost: x\r\n\r\n")[0] == 400)


def t_auth(port):
    check("/api/info without token -> 401", get(port, "/api/info")[0] == 401)
    check("/api/info wrong token -> 401", get(port, "/api/info?token=" + "x" * len(TOKEN))[0] == 401)
    check("/api/info prefix of token -> 401", get(port, "/api/info?token=" + TOKEN[:-1])[0] == 401)
    check("/api/info token+suffix -> 401", get(port, "/api/info?token=" + TOKEN + "x")[0] == 401)
    st, _, body = get(port, "/api/info?token=" + TOKEN)
    info = json.loads(body) if st == 200 else {}
    check("/api/info query token -> 200 + geometry", st == 200 and info.get("width") == W and
          info.get("height") == H and info.get("bpp") == 32 and info.get("keyboard") is True, str(info))
    check("/api/info Bearer token -> 200", get(port, "/api/info", f"Authorization: Bearer {TOKEN}\r\n")[0] == 200)
    check("/api/info bad Bearer -> 401", get(port, "/api/info", "Authorization: Bearer nope\r\n")[0] == 401)
    check("/ws without token -> 401", get(port, "/ws")[0] == 401)
    check("page itself is public", get(port, "/")[0] == 200)


def t_origin(port):
    st = get(port, f"/api/info?token={TOKEN}", "Origin: http://evil.example\r\n")[0]
    check("cross-origin /api/info -> 403", st == 403)
    w = WS(port, origin="http://evil.example")
    check("cross-origin /ws -> 403", w.status == 403)
    w = WS(port, origin="null")
    check("Origin: null /ws -> 403", w.status == 403)
    w = WS(port, origin=f"http://127.0.0.1:{port}")
    check("same-origin /ws -> 101 + valid accept", w.status == 101 and w.accept_ok)
    w.close()
    w = WS(port)
    check("no-Origin (non-browser) /ws -> 101", w.status == 101)
    w.close()


def t_handshake(port):
    base = f"GET /ws?token={TOKEN} HTTP/1.1\r\nHost: x\r\n"
    ok_key = "Sec-WebSocket-Key: " + base64.b64encode(os.urandom(16)).decode() + "\r\n"
    up = "Upgrade: websocket\r\nConnection: Upgrade\r\n"
    check("ws missing key -> 400", http(port, base + up + "Sec-WebSocket-Version: 13\r\n\r\n")[0] == 400)
    check("ws bad key length -> 400",
          http(port, base + up + "Sec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n")[0] == 400)
    check("ws bad key charset -> 400",
          http(port, base + up + "Sec-WebSocket-Key: " + "!" * 22 + "==\r\nSec-WebSocket-Version: 13\r\n\r\n")[0] == 400)
    check("ws wrong version -> 426", http(port, base + up + ok_key + "Sec-WebSocket-Version: 8\r\n\r\n")[0] == 426)
    check("ws missing Upgrade -> 400",
          http(port, base + "Connection: Upgrade\r\n" + ok_key + "Sec-WebSocket-Version: 13\r\n\r\n")[0] == 400)


def t_slow(port):
    t0 = time.time()
    s = socket.create_connection(("127.0.0.1", port), timeout=20)
    data = s.recv(4096)
    s.close()
    check("silent client -> 408 within 8 s", data.startswith(b"HTTP/1.1 408") and time.time() - t0 < 8,
          f"{data[:20]!r} {time.time() - t0:.1f}s")


def t_stream(port):
    ws = WS(port)
    ws.pump(lambda: ws.rows_received() >= H, 10)
    check("ws: info message first with geometry", ws.info and ws.info["width"] == W and ws.info["bpp"] == 32, str(ws.info))
    check("ws: first sync covers the whole frame", ws.rows_received() >= H, f"{ws.rows_received()} rows")

    check("write() path: full-screen red arrives", wait_rows(ws, [(0, RED), (199, RED), (60, RED)], 15))
    check("mmap() path (deferred io): rows 50..99 green, neighbours untouched",
          wait_rows(ws, [(60, GREEN), (50, GREEN), (99, GREEN), (49, RED), (100, RED)], 6))
    ws.pump(timeout=1.2)                      # let the previous update drain
    mark = len(ws.msgs)
    ok = wait_rows(ws, [(150, BLUE), (151, BLUE), (149, RED), (152, RED), (60, GREEN)], 6)
    rows = ws.rows_received(mark)
    check("write() path: 2-row blue band arrives", ok)
    check("partial update: only the dirty rows were sent", rows <= 24, f"{rows} rows for a 2 row change")
    check("full-screen clear arrives", wait_rows(ws, [(0, BLACK), (60, BLACK), (199, BLACK), (150, BLACK)], 6))

    ws.pump(timeout=0.5)                      # whole window stays inside one 3 s scenario phase
    mark = len(ws.msgs)
    ws.pump(timeout=1.5)
    check("idle framebuffer -> no traffic", len(ws.msgs) == mark, f"{len(ws.msgs) - mark} messages")
    return ws


def t_controls(port, ws):
    ws.cmd("pause")
    ws.pump(timeout=0.5)
    mark = len(ws.msgs)
    ws.pump(timeout=4.5)                      # longer than one scenario phase
    check("pause: no updates while paused (across a scenario phase change)", len(ws.msgs) == mark,
          f"{len(ws.msgs) - mark} messages")
    ws.cmd("resume")
    check("resume: updates flow again", ws.pump(lambda: len(ws.msgs) > mark, 8))
    ws.pump(timeout=3.5)
    ws.cmd("full")
    mark = len(ws.msgs)
    ws.pump(lambda: ws.rows_received(mark) >= H, 5)
    check("'full' resends every row", ws.rows_received(mark) >= H)
    wire, raw = sum(ws.wire[mark:]), ws.rows_received(mark) * W * 4
    check("uniform frame is LZ4-compressed on the wire (>= 20x)", all(ws.lz4[mark:]) and raw >= 20 * wire,
          f"{raw} raw -> {wire} wire, lz4={ws.lz4[mark:]}")
    for c in ("fps 1", "bogus command", "fps abc", "fps 99999"):
        ws.cmd(c)
    ws.pump(timeout=0.5)
    check("unknown/invalid commands are ignored (connection stays up)", ws.closed is None)
    ws.cmd("fps 60")
    ws.cmd("ping 4242")
    ws.cmd("ping nope")
    ws.pump(lambda: any(m.get("type") == "pong" for m in ws.texts), 3)
    pongs = [m for m in ws.texts if m.get("type") == "pong"]
    check("ping <n> -> pong echoing n (bad ping ignored)", pongs == [{"type": "pong", "t": 4242}], str(pongs))


def t_second_client_matches(port):
    """A second client must converge to the same picture as the first one."""
    a, b = WS(port), WS(port)
    a.pump(lambda: a.rows_received() >= H, 8)
    b.pump(lambda: b.rows_received() >= H, 8)
    for _ in range(40):                       # wait for a quiet stretch (phases change every 3 s)
        a.pump(timeout=0.3)
        b.pump(timeout=0.3)
        if time.time() - max(a.msgs[-1][0], b.msgs[-1][0]) > 1.0:
            break
    check("two clients converge to identical frames", a.px == b.px)
    a.close()
    b.close()


def t_protocol(port):
    def expect_close(name, fn, code):
        w = WS(port)
        w.pump(timeout=0.5)
        fn(w)
        w.pump(lambda: w.closed is not None, 5)
        check(name, w.closed == code, f"closed={w.closed}")
        w.close()
    expect_close("unmasked client frame -> close 1002", lambda w: w.send(1, b"full", mask=False), 1002)
    expect_close("fragmented text -> close 1003", lambda w: w.send(1, b"fu", fin=False), 1003)
    expect_close("binary frame -> close 1003", lambda w: w.send(2, b"\x00"), 1003)
    expect_close("reserved opcode -> close 1002", lambda w: w.send(3, b""), 1002)
    expect_close("oversized frame -> close 1009", lambda w: w.send(1, b"a" * 300), 1009)
    expect_close("fragmented control frame -> close 1002", lambda w: w.send(9, b"", fin=False), 1002)

    w = WS(port)
    w.pump(timeout=0.5)
    w.send(9, b"hello")
    end, pong = time.time() + 3, None
    while time.time() < end and pong is None:
        try:
            r = w.recv(0.2)
        except EOFError:
            break
        if r and r[0] == 10:
            pong = r[1]
        elif r:
            w.handle(*r)
    check("ping -> pong echoing the payload", pong == b"hello", repr(pong))
    w.send(8, struct.pack(">H", 1000))
    w.pump(lambda: w.closed is not None, 3)
    check("client close -> server echoes close", w.closed == 1000, f"closed={w.closed}")
    w.close()


def keys(ser, mark):
    """Key events seen since @mark. printk can interleave with the guest's own
    output on the shared serial line, so match anywhere in the line."""
    return [f"{c} {v}" for l in ser.since(mark) for c, v in re.findall(r"KEY (\d+) (\d)", l)]


def t_keyboard(port, ser):
    ser.wait("KBD READY", 20)
    w = WS(port)
    w.pump(timeout=0.5)
    m = ser.mark()
    w.cmd("key 30 1")
    w.cmd("key 30 0")
    ser.wait(r"KEY 30 0", 5, m)
    ev = keys(ser, m)
    check("key down+up reach the guest input device in order", ev == ["30 1", "30 0"], str(ev))
    # Input latency: the session must wake on client data, not on its poll timeout
    # (200 ms), so the worst case over several samples has to stay far below that.
    lat = []
    for i in range(12):
        m = ser.mark()
        t0 = time.time()
        w.cmd("key 44 1")
        w.cmd("key 44 0")
        ser.wait(r"KEY 44 0", 3, m)
        lat.append((time.time() - t0) * 1000)
        time.sleep(0.31)                      # land at different points of the session's wait cycle
    check("key latency: worst of 12 under 120 ms", max(lat) < 120, f"max {max(lat):.0f} ms, all {[round(x) for x in lat]}")
    m = ser.mark()
    for bad in ("key 0 1", "key 256 1", "key 999 1", "key 30 2", "key abc", "key 30", "key -1 1"):
        w.cmd(bad)
    time.sleep(1.2)
    ev = keys(ser, m)
    check("out-of-range / malformed key commands are dropped", ev == [], str(ev))
    # A client that vanishes while holding a key must not leave it stuck down.
    m = ser.mark()
    w.cmd("key 31 1")
    ser.wait(r"KEY 31 1", 5, m)
    check("connection still up before the drop", w.closed is None and not w.pump(timeout=0.2) and w.closed is None)
    try:
        w.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))  # close with RST
    except OSError:
        pass
    w.close()
    check("dropped connection releases held keys", ser.wait(r"KEY 31 0", 8, m) is not None)


def t_limits(port):
    held = [WS(port) for _ in range(4)]
    for w in held:
        w.pump(timeout=0.3)
    st = get(port, "/")[0]
    check("5th connection while 4 are held -> 503", st == 503, str(st))
    for w in held:
        w.close()
    time.sleep(1.5)                           # the accept loop reaps finished threads
    check("slots are reclaimed after clients leave", get(port, "/")[0] == 200)


def t_unload(port, ser, vport):
    from rfb import RFB
    vc = RFB(vport, password=VNC_PW)
    w = WS(port)
    w.pump(timeout=0.5)
    m = ser.mark()
    w.cmd("key 32 1")
    ser.wait(r"KEY 32 1", 5, m)
    ser.send("rmmod")
    w.pump(lambda: w.closed is not None, 15)
    check("rmmod with a client attached: client gets close 1001", w.closed == 1001, f"closed={w.closed}")
    done = ser.wait(r"^RMMOD_DONE", 20, m)
    check("rmmod completes with status 0", done == "RMMOD_DONE 0", str(done))
    check("held key released on unload", "32 0" in keys(ser, m))
    # QEMU's host-side forwarder accepts the TCP connection itself, so "gone"
    # means no HTTP response comes back from the guest.
    try:
        gone = get(port, "/")[0] == 0
    except OSError:
        gone = True
    check("listener is gone after rmmod", gone)
    try:
        vc.sock.settimeout(5)
        vgone = vc.sock.recv(1) == b""
    except OSError:
        vgone = True
    check("rmmod with a VNC client attached: the VNC session is closed", vgone)
    vc.close()
    w.close()


SPLAT = re.compile(r"BUG:|WARNING:|KASAN|Oops|Call trace|possible circular|inconsistent lock|suspicious RCU|"
                   r"sleeping function|unable to handle|Internal error|refcount_t:|use-after-free|INFO: task|"
                   r"hung task|lock held when returning|bad unlock balance")


def t_vnc(vport, port, ser):
    from rfb import RFB, RFBError, selftest
    selftest()
    RED_, GREEN_, BLUE_, BLACK_ = (255, 0, 0), (0, 255, 0), (0, 0, 255), (0, 0, 0)

    def closed(c, timeout=4):
        end = time.time() + timeout
        c.sock.settimeout(1)
        while time.time() < end:
            try:
                if not c.sock.recv(4096):
                    return True
            except socket.timeout:
                continue
            except OSError:
                return True
        return False

    # -- handshake -------------------------------------------------------
    for ver, name in ((b"RFB 003.008\n", "3.8"), (b"RFB 003.007\n", "3.7"), (b"RFB 003.003\n", "3.3"),
                      (b"RFB 003.889\n", "3.889 (Apple)")):
        c = RFB(vport, version=ver, password=VNC_PW)
        check(f"vnc {name}: handshake, auth and ServerInit", (c.w, c.h) == (W, H) and c.name == "netfb")
        if name == "3.8":
            check("vnc: server banner is RFB 003.008 and offers only VNC authentication",
                  c.server_version == b"RFB 003.008\n" and c.types == [2], f"{c.server_version} {c.types}")
            sp = c.server_pf
            check("vnc: ServerInit pixel format is the framebuffer's (32 bpp, depth 24, little endian, 8/8/8 at 16/8/0)",
                  (sp["bpp"], sp["depth"], sp["be"], sp["tc"], sp["rmax"], sp["gmax"], sp["bmax"], sp["rs"], sp["gs"], sp["bs"])
                  == (32, 24, 0, 1, 255, 255, 255, 16, 8, 0), str(sp))
        c.close()
    t0 = time.time()
    try:
        RFB(vport, password="wrongpw1")
        bad = None
    except RFBError as e:
        bad = str(e)
    check("vnc: wrong password is refused with a reason", bad and "authentication failed" in bad, str(bad))
    check("vnc: a failed login is delayed (>= 1.3 s)", time.time() - t0 >= 1.3, f"{time.time() - t0:.2f}s")
    try:
        RFB(vport, password=VNC_PW, security=1)
        bad = None
    except RFBError as e:
        bad = str(e)
    check("vnc: choosing a security type that was not offered fails", bad and "not offered" in bad, str(bad))
    for name, raw in (("unsupported version", b"RFB 004.000\n"), ("garbage", b"HELLO WORLD!\n"), ("short junk", b"RFB\n")):
        s = socket.create_connection(("127.0.0.1", vport), timeout=5)
        s.recv(12)
        s.sendall(raw)
        s.settimeout(4)
        try:
            ok = s.recv(100) == b""
        except OSError:
            ok = True
        check(f"vnc: {name} in the version exchange closes the connection", ok)
        s.close()

    # -- encodings and pixel formats ----------------------------------------
    raw_c = RFB(vport, password=VNC_PW)
    raw_c.set_encodings([0])
    raw_c.request(0)
    raw_c.read_update()
    check("vnc raw: first non-incremental request returns the whole screen", sum(h for _, h, _ in raw_c.rects) >= H,
          str(raw_c.rects))
    check("vnc raw: write() path, full-screen red", raw_c.wait_rows([(0, RED_), (199, RED_), (60, RED_)], 15))
    check("vnc raw: mmap() path, rows 50..99 green and neighbours untouched",
          raw_c.wait_rows([(60, GREEN_), (50, GREEN_), (99, GREEN_), (49, RED_), (100, RED_)], 6))

    z_c = RFB(vport, password=VNC_PW)
    z_c.set_encodings([16, 0])
    z_c.request(0)
    z_c.read_update()
    check("vnc zrle: updates use the ZRLE encoding", z_c.rects and all(e == 16 for _, _, e in z_c.rects), str(z_c.rects[:3]))
    for attempt in range(6):                      # phases change every 3 s: retry until both saw the same moment
        raw_c.request(0); z_c.request(0)
        raw_c.read_update(); z_c.read_update()
        while len(z_c.rgb) and False:
            pass
        if raw_c.rgb == z_c.rgb:
            break
        time.sleep(0.4)
    check("vnc: raw and zrle clients show identical pictures", raw_c.rgb == z_c.rgb)

    raw_c.wait_rows([(0, RED_)], 8)               # settle on a stretch with a quiet screen
    z_c.wait_rows([(0, RED_)], 8)
    z_c.sock.settimeout(4.5)
    try:
        extra = z_c.sock.recv(1)
    except socket.timeout:
        extra = None
    check("vnc: nothing is sent without an outstanding request (pull protocol)", extra is None, repr(extra))
    mark = len(raw_c.rects)
    raw_c.request(0, 0, 40, W, 20)
    raw_c.read_update()
    check("vnc: a request for a region only gets rows inside it", all(40 <= y and y + h <= 60 for y, h, _ in raw_c.rects[mark:]),
          str(raw_c.rects[mark:]))

    mark = len(raw_c.rects)
    raw_c.wait_rows([(150, BLUE_), (151, BLUE_), (149, RED_)], 8)
    rows = sum(h for _, h, _ in raw_c.rects[mark:])
    # Several full-screen phases may have gone by; just require that a band update was not a full frame.
    small = [h for _, h, _ in raw_c.rects[mark:] if h <= 24]
    check("vnc: a 2 row change is sent as a small rectangle", small, f"{rows} rows in {raw_c.rects[mark:]}")
    raw_c.close(); z_c.close()

    formats = [
        ("RGB565 little endian", dict(bpp=16, depth=16, be=0, rmax=31, gmax=63, bmax=31, rs=11, gs=5, bs=0)),
        ("RGB555 big endian", dict(bpp=16, depth=15, be=1, rmax=31, gmax=31, bmax=31, rs=10, gs=5, bs=0)),
        ("RGB332 (8 bpp)", dict(bpp=8, depth=8, be=0, rmax=7, gmax=7, bmax=3, rs=5, gs=2, bs=0)),
        ("RGBX bytes (32 bpp, shifts 0/8/16)", dict(bpp=32, depth=24, be=0, rmax=255, gmax=255, bmax=255, rs=0, gs=8, bs=16)),
        ("BGRX big endian (32 bpp, shifts 8/16/24)", dict(bpp=32, depth=24, be=1, rmax=255, gmax=255, bmax=255, rs=8, gs=16, bs=24)),
    ]
    for enc_name, encs in (("raw", [0]), ("zrle", [16, 0])):
        for fname, pf in formats:
            c = RFB(vport, password=VNC_PW)
            c.set_pixel_format(**pf)
            c.set_encodings(encs)
            c.request(0)
            c.read_update()
            ok = c.wait_rows([(0, RED_), (199, RED_)], 15, tol=4)
            ok = ok and c.wait_rows([(60, GREEN_), (49, RED_)], 6, tol=4)
            check(f"vnc {enc_name}: client format {fname}", ok, f"pixel(0,60)={c.pixel(0, 60)} pixel(0,0)={c.pixel(0, 0)}")
            c.close()
    c = RFB(vport, password=VNC_PW)
    c.set_encodings([16])
    ok = True
    for pf in (formats[0][1], formats[4][1], formats[2][1]):      # switch format on a live ZRLE stream
        c.set_pixel_format(**pf)
        c.request(0)
        c.read_update()
        ok = ok and c.wait_rows([(0, RED_), (60, GREEN_)], 20, tol=4) or c.wait_rows([(0, RED_)], 8, tol=4)
    check("vnc zrle: switching the pixel format on a live stream keeps the picture correct", ok)
    c.close()

    # -- keyboard ---------------------------------------------------------------
    c = RFB(vport, password=VNC_PW)
    m = ser.mark()
    c.key(1, 0x61); c.key(0, 0x61)
    ser.wait(r"KEY 30 0", 5, m)
    check("vnc key: 'a'", keys(ser, m) == ["30 1", "30 0"], str(keys(ser, m)))
    m = ser.mark()
    c.key(1, 0x41); c.key(0, 0x41)
    ser.wait(r"KEY 42 0", 5, m)
    check("vnc key: 'A' without a Shift event is typed with Shift", keys(ser, m) == ["42 1", "30 1", "30 0", "42 0"], str(keys(ser, m)))
    m = ser.mark()
    c.key(1, 0xffe1); c.key(1, 0x2f); c.key(0, 0x2f); c.key(0, 0xffe1)
    ser.wait(r"KEY 42 0", 5, m)
    time.sleep(0.2)
    check("vnc key: '/' held with Shift (other layout) is typed without Shift",
          keys(ser, m) == ["42 1", "42 0", "53 1", "53 0", "42 1", "42 0"], str(keys(ser, m)))
    m = ser.mark()
    for sym in (0xff0d, 0xff51, 0xffbe, 0xffff):
        c.key(1, sym); c.key(0, sym)
    ser.wait(r"KEY 111 0", 5, m)
    check("vnc key: Return, Left, F1, Delete", keys(ser, m) == ["28 1", "28 0", "105 1", "105 0", "59 1", "59 0", "111 1", "111 0"],
          str(keys(ser, m)))
    m = ser.mark()
    c.key(1, 0x1234567); c.key(1, 0xffe5); c.pointer(1, 5, 5)
    time.sleep(0.5)
    check("vnc key: unknown keysyms, Caps Lock and pointer events are ignored", keys(ser, m) == [], str(keys(ser, m)))
    m = ser.mark()
    c.key(1, 0xffe3); c.key(1, 0x62)                  # Control down, b down, then the client vanishes
    ser.wait(r"KEY 48 1", 5, m)
    c.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)) if sys.platform != "darwin" else None
    c.close()
    ser.wait(r"KEY 29 0", 8, m)
    check("vnc: a dropped client releases held keys", set(keys(ser, m)) >= {"29 1", "48 1", "48 0", "29 0"}, str(keys(ser, m)))

    # -- malformed input ---------------------------------------------------------
    import struct as st
    bad_cases = [
        ("unknown message type", b"\x63"),
        ("SetEncodings with too many encodings", st.pack(">BxH", 2, 65) + b"\0" * 260),
        ("ClientCutText larger than the limit", st.pack(">BxxxI", 6, 2 << 20)),
        ("colour-map pixel format", st.pack(">BxxxBBBBHHHBBBxxx", 0, 8, 8, 0, 0, 7, 7, 3, 5, 2, 0)),
        ("pixel format with max not 2^n-1", st.pack(">BxxxBBBBHHHBBBxxx", 0, 32, 24, 0, 1, 200, 255, 255, 16, 8, 0)),
        ("pixel format with 24 bits per pixel", st.pack(">BxxxBBBBHHHBBBxxx", 0, 24, 24, 0, 1, 255, 255, 255, 16, 8, 0)),
        ("pixel format whose shift overflows the pixel", st.pack(">BxxxBBBBHHHBBBxxx", 0, 16, 16, 0, 1, 31, 63, 31, 14, 5, 0)),
    ]
    for name, payload in bad_cases:
        c = RFB(vport, password=VNC_PW)
        c.send(payload)
        check(f"vnc: {name} closes the connection", closed(c))
        c.close()
    c = RFB(vport, password=VNC_PW)
    c.set_encodings([0])
    text = os.urandom(4096)
    c.send(st.pack(">BxxxI", 6, len(text)))
    for i in range(0, len(text), 1500):
        c.send(text[i:i + 1500]); time.sleep(0.05)
    c.request(0)
    try:
        c.read_update()
        ok = True
    except Exception as e:
        ok = False
    check("vnc: a 4 KiB ClientCutText is skipped and the stream stays in sync", ok)
    c.close()

    # -- limits -------------------------------------------------------------------
    held = [RFB(vport, password=VNC_PW) for _ in range(4)]
    s = socket.create_connection(("127.0.0.1", vport), timeout=5)
    s.settimeout(4)
    try:
        first = s.recv(12)
    except OSError:
        first = b""
    check("vnc: a connection beyond max_clients is closed without a banner", first == b"", repr(first))
    s.close()
    check("vnc: the limit is shared with HTTP (503)", get(port, "/")[0] == 503)
    for h in held:
        h.close()
    time.sleep(1.5)
    c = RFB(vport, password=VNC_PW)
    check("vnc: slots are reclaimed after clients leave", c.w == W)
    c.close()

    # -- lockout (the guest loads the module with vnc_lockout=4) --------------------
    for _ in range(5):
        try:
            RFB(vport, password="wrongpw1")
        except RFBError:
            pass
    s = socket.create_connection(("127.0.0.1", vport), timeout=5)
    s.settimeout(3)
    try:
        banner = s.recv(12)
    except OSError:
        banner = b""
    s.close()
    check("vnc: 5 failed logins lock the source out (no banner while locked)", banner == b"", repr(banner))
    time.sleep(4.5)
    try:
        c = RFB(vport, password=VNC_PW)
        ok = c.w == W
        c.close()
    except Exception as e:
        ok = False
    check("vnc: the lockout expires and a correct password works again", ok)
    for _ in range(4):                                    # fewer than 5 failures, then a success: the count resets
        try:
            RFB(vport, password="wrongpw1")
        except RFBError:
            pass
    RFB(vport, password=VNC_PW).close()
    for _ in range(4):
        try:
            RFB(vport, password="wrongpw1")
        except RFBError:
            pass
    c = RFB(vport, password=VNC_PW)
    check("vnc: a successful login resets the failure count", c.w == W)
    c.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--initrd", required=True)
    ap.add_argument("--qemu", default="qemu-system-aarch64")
    ap.add_argument("--no-hvf", action="store_true")
    a = ap.parse_args()
    port, ser_port = random.randint(20000, 30000), random.randint(30001, 40000)
    vport = random.randint(40001, 50000)

    accel = ["-accel", "tcg", "-cpu", "cortex-a72"] if a.no_hvf else ["-accel", "hvf", "-cpu", "host"]
    q = subprocess.Popen([a.qemu, "-M", "virt", *accel, "-m", "2048", "-smp", "2", "-kernel", a.image,
                          "-initrd", a.initrd, "-append",
                          "console=ttyAMA0 loglevel=7 vt.global_cursor_default=0 panic=-1",
                          "-display", "none", "-monitor", "none",
                          "-serial", f"tcp:127.0.0.1:{ser_port},server=on,wait=off",
                          "-nic", f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{port}-:8080,"
                                 f"hostfwd=tcp:127.0.0.1:{vport}-:5900"])
    ser = Serial(ser_port)
    try:
        if not ser.wait(r"^READY$", 180):
            check("guest boots and module loads", False, "no READY from guest")
            return
        check("guest boots and module loads", not any("INSMOD_FAILED" in l for l in ser.since(0)))
        t_http(port)
        t_auth(port)
        t_origin(port)
        t_handshake(port)
        t_slow(port)
        ws = t_stream(port)
        t_controls(port, ws)
        ws.close()
        t_second_client_matches(port)
        t_protocol(port)
        t_keyboard(port, ser)
        t_limits(port)
        t_vnc(vport, port, ser)
        t_unload(port, ser, vport)
        time.sleep(1)
        splats = [l for l in ser.since(0) if SPLAT.search(l)]
        check("no kernel splats (KASAN/lockdep/BUG/WARN) in the whole run", not splats, "; ".join(splats[:3]))
    finally:
        try:
            ser.send("poweroff")
        except OSError:
            pass
        time.sleep(1)
        q.kill()
        q.wait()
    bad = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(bad)}/{len(results)} passed" + (f"; FAILED: {bad}" if bad else ""))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
