#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Loads the web UI in a real headless Chrome and checks that it reaches "Live"
and stays connected without console errors.

    browser.py URL [seconds] [screenshot.png] [--html=web/index.html]

Browsers are stricter than the raw client in e2e.py: Chrome drops a WebSocket on a
non-minimal frame length ("Invalid frame header"), which the protocol-level tests
did not notice.
"""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdp import Chrome


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--html=")]
    html = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--html=")), None)
    url = args[0]
    seconds = float(args[1]) if len(args) > 1 else 8
    c = Chrome(html=html)
    try:
        c.call("Page.navigate", url=url)
        c.pump(seconds)
        page = json.loads(c.eval("JSON.stringify({status: document.getElementById('statusText').textContent,"
                                 " hud: document.getElementById('hRatio').textContent,"
                                 " rtt: document.getElementById('hRtt').textContent})"))
        closed = sum(1 for m in c.events if m["method"] == "Network.webSocketClosed")
        errors = c.console_errors()
        print("page:", page, "| ws closed:", closed, "| console errors:", errors)
        if len(args) > 2:
            c.screenshot(args[2])
        ok = page["status"] == "Live" and not errors and closed == 0 and page["hud"].startswith("×") and page["rtt"].endswith("ms")
        print("PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)
    finally:
        c.close()


if __name__ == "__main__":
    main()
