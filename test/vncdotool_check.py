#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Checks netfb's VNC server with vncdotool, an independent third-party client.

    pip install vncdotool
    vncdotool_check.py HOST::PORT PASSWORD

Run it against a guest booted from test/guest/init (the screen cycles red, a green
band, a blue band, black every 3 s). It captures the screen three times 3.2 s apart
and checks the colours, then types a few keys; compare them with the "KEY" lines on the
guest console.
"""
import os, sys, tempfile, time
from PIL import Image
from vncdotool import api


def main():
    server, password = sys.argv[1], sys.argv[2]
    client = api.connect(server, password=password)
    try:
        seen = set()
        for i in range(4):
            path = os.path.join(tempfile.gettempdir(), f"netfb-vnc-{i}.png")
            client.captureScreen(path)
            im = Image.open(path).convert("RGB")
            seen.add((im.getpixel((10, 5)), im.getpixel((10, 60)), im.getpixel((10, 151))))
            time.sleep(3.2)
        colours = {c for s in seen for c in s}
        ok = {(255, 0, 0), (0, 255, 0), (0, 0, 255)} <= colours
        print("colours seen:", sorted(colours), "PASS" if ok else "FAIL")
        client.keyPress("a")
        for ch in "Hi!":
            client.keyPress(ch)
        time.sleep(0.5)
        sys.exit(0 if ok else 1)
    finally:
        api.shutdown()


if __name__ == "__main__":
    main()
