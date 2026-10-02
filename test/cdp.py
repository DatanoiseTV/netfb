# SPDX-License-Identifier: GPL-2.0-only
"""Minimal Chrome DevTools Protocol client (standard library only).

Launches a headless Chrome with a throw-away profile on a random debugging
port (a fixed port can serve a stale page from an earlier run) and exposes
call()/eval(). Used by browser.py and browser_keys.py.
"""
import base64, json, os, random, shutil, socket, struct, subprocess, time, urllib.parse, urllib.request

CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")


class Chrome:
    def __init__(self, width=1280, height=860, html=None):
        port = random.randint(41000, 49000)
        self.profile = f"/tmp/netfb-chrome-{port}"
        self.proc = subprocess.Popen(
            [CHROME, "--headless=new", f"--user-data-dir={self.profile}", f"--remote-debugging-port={port}",
             f"--window-size={width},{height}",
             # A page served through Fetch.fulfillRequest has no address space, which trips
             # Local Network Access when it talks to the loopback server it was meant for.
             "--disable-features=LocalNetworkAccessChecks,BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessSendPreflights",
             "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pages = None
        for _ in range(100):
            try:
                pages = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
                break
            except Exception:
                time.sleep(0.2)
        if not pages:
            raise RuntimeError("Chrome did not start")
        path = [p for p in pages if p["type"] == "page"][0]["webSocketDebuggerUrl"].split(str(port), 1)[1]
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
                           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.sock.recv(4096)
        self.buf = head.partition(b"\r\n\r\n")[2]
        self.n = 0
        self.events = []
        self.results = {}
        self.html = html           # serve this file for "/" instead of what the server sends
        self.call("Runtime.enable"); self.call("Log.enable"); self.call("Page.enable"); self.call("Network.enable")
        # Without this a headless page is never "focused" and Input.dispatchKeyEvent is dropped.
        if html:
            self.call("Fetch.enable", patterns=[{"urlPattern": "*", "requestStage": "Request"}])
        self.call("Emulation.setFocusEmulationEnabled", enabled=True)
        self.call("Page.bringToFront")

    def _read(self, n, deadline):
        while len(self.buf) < n:
            self.sock.settimeout(max(0.01, deadline - time.time()))
            try:
                d = self.sock.recv(1 << 18)
            except socket.timeout:
                return False
            if not d:
                raise EOFError
            self.buf += d
        return True

    def _frame(self, timeout):
        deadline = time.time() + timeout
        if not self._read(2, deadline):
            return None
        n, hl = self.buf[1] & 0x7F, 2
        if n == 126:
            if not self._read(4, deadline):
                return None
            n, hl = struct.unpack(">H", self.buf[2:4])[0], 4
        elif n == 127:
            if not self._read(10, deadline):
                return None
            n, hl = struct.unpack(">Q", self.buf[2:10])[0], 10
        if not self._read(hl + n, deadline):
            return None
        payload = bytes(self.buf[hl:hl + n])
        self.buf = self.buf[hl + n:]
        return payload

    def _send(self, obj):
        data = json.dumps(obj).encode()
        n, mask = len(data), os.urandom(4)
        hdr = b"\x81" + (bytes([0x80 | n]) if n < 126 else b"\xfe" + struct.pack(">H", n) if n < 65536 else b"\xff" + struct.pack(">Q", n))
        self.sock.sendall(hdr + mask + bytes(c ^ mask[i & 3] for i, c in enumerate(data)))

    def pump(self, seconds):
        """Collect events for a while."""
        end = time.time() + seconds
        while time.time() < end:
            f = self._frame(min(0.1, max(0.01, end - time.time())))
            if f:
                self._dispatch(json.loads(f))

    def _dispatch(self, m):
        if "id" in m:
            self.results[m["id"]] = m
            return
        self.events.append(m)
        if m["method"] == "Fetch.requestPaused":
            p = m["params"]
            path = urllib.parse.urlparse(p["request"]["url"]).path
            if self.html and path in ("/", "/index.html"):
                body = base64.b64encode(open(self.html, "rb").read()).decode()
                self._send({"id": self._next(), "method": "Fetch.fulfillRequest", "params": {
                    "requestId": p["requestId"], "responseCode": 200,
                    "responseHeaders": [{"name": "Content-Type", "value": "text/html; charset=utf-8"}], "body": body}})
            else:
                self._send({"id": self._next(), "method": "Fetch.continueRequest", "params": {"requestId": p["requestId"]}})

    def _next(self):
        self.n += 1
        return self.n

    def call(self, method, timeout=15, **params):
        mid = self._next()
        self._send({"id": mid, "method": method, "params": params})
        end = time.time() + timeout
        while time.time() < end:
            if mid in self.results:
                m = self.results.pop(mid)
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("result", {})
            f = self._frame(0.2)
            if f:
                self._dispatch(json.loads(f))
        raise TimeoutError(method)

    def eval(self, expr):
        r = self.call("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in r:
            raise RuntimeError(json.dumps(r["exceptionDetails"])[:300])
        return r["result"].get("value")

    def console_errors(self):
        out = []
        for m in self.events:
            if m["method"] == "Log.entryAdded" and m["params"]["entry"]["level"] in ("error", "warning"):
                out.append(m["params"]["entry"]["text"])
            elif m["method"] == "Runtime.exceptionThrown":
                out.append(json.dumps(m["params"])[:200])
        return out

    def screenshot(self, path):
        open(path, "wb").write(base64.b64decode(self.call("Page.captureScreenshot", format="png")["data"]))

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)
