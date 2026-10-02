# SPDX-License-Identifier: GPL-2.0-only
"""A small RFB (VNC, RFC 6143) client for testing netfb's VNC server.

It is an independent implementation: its own handshake, DES (via the host's OpenSSL,
checked against a known-answer vector), Raw and ZRLE decoders, and any true-colour
pixel format. It decodes into an RGB24 frame so results do not depend on the format
the server was asked for.
"""
import socket, struct, subprocess, time, zlib


class RFBError(Exception):
    pass


def bitrev(b):
    return int(f"{b:08b}"[::-1], 2)


def vnc_response(password, challenge):
    """DES-ECB of the 16 byte challenge; the key is the password, NUL padded, each byte bit-reversed."""
    key = bytes(bitrev(c) for c in (password.encode()[:8].ljust(8, b"\0")))
    out = subprocess.run(["openssl", "enc", "-des-ecb", "-provider", "legacy", "-provider", "default",
                          "-K", key.hex(), "-nopad"], input=challenge, capture_output=True, check=True).stdout
    assert len(out) == 16
    return out


NATIVE = dict(bpp=32, depth=24, be=0, rmax=255, gmax=255, bmax=255, rs=16, gs=8, bs=0)


class RFB:
    def __init__(self, port, version=b"RFB 003.008\n", password=None, security=None, timeout=10):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.buf = b""
        self.zin = zlib.decompressobj()
        self.server_version = self.recv(12)
        self.sock.sendall(version)
        minor = int(version[8:11])
        self.minor = 8 if minor >= 8 else 7 if minor == 7 else 3
        self.reason = None
        if self.minor >= 7:
            n = self.recv(1)[0]
            if n == 0:
                raise RFBError("no security types: " + self._reason().decode(errors="replace"))
            self.types = list(self.recv(n))
            chosen = security if security is not None else self.types[0]
            self.sock.sendall(bytes([chosen]))
        else:
            chosen = struct.unpack(">I", self.recv(4))[0]
            self.types = [chosen]
        self.security = chosen
        if chosen == 2:
            self.sock.sendall(vnc_response(password or "", self.recv(16)))
        if chosen == 2 or self.minor >= 8:
            res = struct.unpack(">I", self.recv(4))[0]
            if res != 0:
                self.reason = self._reason().decode(errors="replace") if self.minor >= 8 else ""
                raise RFBError(f"security failed ({res}): {self.reason}")
        self.sock.sendall(b"\x01")                                  # ClientInit: shared
        self.w, self.h = struct.unpack(">HH", self.recv(4))
        pf = self.recv(16)
        self.server_pf = dict(bpp=pf[0], depth=pf[1], be=pf[2], tc=pf[3],
                              rmax=struct.unpack(">H", pf[4:6])[0], gmax=struct.unpack(">H", pf[6:8])[0],
                              bmax=struct.unpack(">H", pf[8:10])[0], rs=pf[10], gs=pf[11], bs=pf[12])
        nlen = struct.unpack(">I", self.recv(4))[0]
        self.name = self.recv(nlen).decode()
        self.pf = dict(NATIVE, **{k: v for k, v in self.server_pf.items() if k in NATIVE})
        self.rgb = bytearray(self.w * self.h * 3)
        self.rects = []                                             # (y, h, encoding) of every rect received

    # -- io ---------------------------------------------------------------
    def recv(self, n, timeout=None):
        if timeout is not None:
            self.sock.settimeout(timeout)
        while len(self.buf) < n:
            d = self.sock.recv(1 << 16)
            if not d:
                raise EOFError
            self.buf += d
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _reason(self):
        return self.recv(struct.unpack(">I", self.recv(4))[0])

    def send(self, data):
        self.sock.sendall(data)

    # -- client messages ---------------------------------------------------
    def set_pixel_format(self, bpp, depth, be, rmax, gmax, bmax, rs, gs, bs, true_colour=1):
        self.send(struct.pack(">BxxxBBBBHHHBBBxxx", 0, bpp, depth, be, true_colour, rmax, gmax, bmax, rs, gs, bs))
        self.pf = dict(bpp=bpp, depth=depth, be=be, rmax=rmax, gmax=gmax, bmax=bmax, rs=rs, gs=gs, bs=bs)

    def set_encodings(self, encs):
        self.send(struct.pack(">BxH", 2, len(encs)) + b"".join(struct.pack(">i", e) for e in encs))

    def request(self, incremental=0, x=0, y=0, w=None, h=None):
        self.send(struct.pack(">BBHHHH", 3, incremental, x, y, self.w if w is None else w, self.h if h is None else h))

    def key(self, down, sym):
        self.send(struct.pack(">BBxxI", 4, 1 if down else 0, sym))

    def pointer(self, mask, x, y):
        self.send(struct.pack(">BBHH", 5, mask, x, y))

    def cut_text(self, text):
        self.send(struct.pack(">BxxxI", 6, len(text)) + text)

    # -- server messages -----------------------------------------------------
    def _cpixel_bytes(self):
        pf = self.pf
        if pf["bpp"] != 32:
            return pf["bpp"] // 8, 0
        mask = (pf["rmax"] << pf["rs"]) | (pf["gmax"] << pf["gs"]) | (pf["bmax"] << pf["bs"])
        if mask & 0xFF000000 == 0:
            return 3, (1 if pf["be"] else 0)
        if mask & 0x000000FF == 0:
            return 3, (0 if pf["be"] else 1)
        return 4, 0

    def _value(self, raw):
        pf = self.pf
        n = len(raw)
        v = int.from_bytes(raw, "big" if pf["be"] else "little")
        if pf["bpp"] == 32 and n == 3:        # a CPIXEL: re-expand to the wire position
            full = bytearray(4)
            _, off = self._cpixel_bytes()
            full[off:off + 3] = raw
            v = int.from_bytes(full, "big" if pf["be"] else "little")
        r = ((v >> pf["rs"]) & pf["rmax"]) * 255 // pf["rmax"]
        g = ((v >> pf["gs"]) & pf["gmax"]) * 255 // pf["gmax"]
        b = ((v >> pf["bs"]) & pf["bmax"]) * 255 // pf["bmax"]
        return bytes((r, g, b))

    def _put(self, x, y, rgb):
        o = (y * self.w + x) * 3
        self.rgb[o:o + 3] = rgb

    def _decode_raw(self, x, y, w, h):
        bp = self.pf["bpp"] // 8
        data = self.recv(w * h * bp)
        for j in range(h):
            for i in range(w):
                o = (j * w + i) * bp
                self._put(x + i, y + j, self._value(data[o:o + bp]))

    def _decode_zrle(self, x, y, w, h):
        clen = struct.unpack(">I", self.recv(4))[0]
        data = self.zin.decompress(self.recv(clen))
        cp, _ = self._cpixel_bytes()
        pos = 0
        for ty in range(0, h, 64):
            th = min(64, h - ty)
            for tx in range(0, w, 64):
                tw = min(64, w - tx)
                sub = data[pos]
                pos += 1
                if sub == 1:                                    # solid
                    rgb = self._value(data[pos:pos + cp]); pos += cp
                    for j in range(th):
                        for i in range(tw):
                            self._put(x + tx + i, y + ty + j, rgb)
                elif sub == 0:                                  # raw CPIXELs
                    for j in range(th):
                        for i in range(tw):
                            self._put(x + tx + i, y + ty + j, self._value(data[pos:pos + cp])); pos += cp
                else:
                    raise RFBError(f"ZRLE sub-encoding {sub} is not produced by this server")
        if pos != len(data):
            raise RFBError(f"ZRLE data left over: {len(data) - pos} bytes")

    def read_update(self, timeout=5):
        """Reads one server message; returns the list of (y, h) rects of an update, or None for others."""
        mtype = self.recv(1, timeout)[0]
        if mtype == 0:
            self.recv(1)
            n = struct.unpack(">H", self.recv(2))[0]
            out = []
            for _ in range(n):
                x, y, w, h, enc = struct.unpack(">HHHHi", self.recv(12))
                if x + w > self.w or y + h > self.h:
                    raise RFBError(f"rect outside the screen: {(x, y, w, h)}")
                if enc == 0:
                    self._decode_raw(x, y, w, h)
                elif enc == 16:
                    self._decode_zrle(x, y, w, h)
                else:
                    raise RFBError(f"unexpected encoding {enc}")
                out.append((y, h))
                self.rects.append((y, h, enc))
            return out
        raise RFBError(f"unexpected server message type {mtype}")

    def pixel(self, x, y):
        o = (y * self.w + x) * 3
        return tuple(self.rgb[o:o + 3])

    def row_is(self, y, rgb, tol=0):
        return all(all(abs(a - b) <= tol for a, b in zip(self.pixel(x, y), rgb)) for x in (0, self.w // 2, self.w - 1))

    def wait_rows(self, spec, timeout=10, tol=0, encodings=None):
        """Keeps requesting incremental updates until every (y, rgb) in spec matches."""
        end = time.time() + timeout
        while time.time() < end:
            if all(self.row_is(y, c, tol) for y, c in spec):
                return True
            self.request(1)
            try:
                self.read_update(timeout=max(0.2, min(3, end - time.time())))
            except (socket.timeout, TimeoutError):
                pass
        return all(self.row_is(y, c, tol) for y, c in spec)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def selftest():
    """DES known-answer test (FIPS 46 example) and the VNC key schedule."""
    out = subprocess.run(["openssl", "enc", "-des-ecb", "-provider", "legacy", "-provider", "default",
                          "-K", "133457799BBCDFF1", "-nopad"], input=bytes.fromhex("0123456789ABCDEF"),
                         capture_output=True, check=True).stdout
    assert out.hex().upper() == "85E813540F0AB405", out.hex()
    assert bitrev(0x01) == 0x80 and bitrev(0x61) == 0x86


if __name__ == "__main__":
    selftest()
    print("rfb.py self-test ok")
