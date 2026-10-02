#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Keyboard behaviour of the web UI, driven with real browser key events.

    browser_keys.py URL      (the server must have been loaded with keyboard=1)

WebSocket.send is wrapped before the page loads so the "key <code> <0|1>" commands
are recorded instead of reaching the machine. Layout cases are simulated by sending
the key/code pairs a given keyboard would produce (e.g. a German layout types "z"
on the physical KeyY). The Mac cases need a Mac browser, because the page keys its
Cmd handling off navigator.platform.
"""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cdp import Chrome

SHIM = """
window.__sent = [];
const __send = WebSocket.prototype.send;
WebSocket.prototype.send = function (d) {
  if (typeof d === 'string' && d.startsWith('key ')) { window.__sent.push(d); return; }
  return __send.call(this, d);
};
"""
VK = {"ShiftLeft": 16, "ControlLeft": 17, "AltLeft": 18, "MetaLeft": 91, "CapsLock": 20, "Escape": 27, "Space": 32}
MOD = {"alt": 1, "ctrl": 2, "meta": 4, "shift": 8}
results = []


def check(name, got, want):
    ok = got == want
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + ("" if ok else f"\n        got  {got}\n        want {want}"), flush=True)


class T:
    def __init__(self, c):
        self.c = c

    def key(self, down, code, key, mods=0, text="", repeat=False):
        vk = VK.get(code) or (ord(code[-1]) if code.startswith(("Key", "Digit")) else 0)
        self.c.call("Input.dispatchKeyEvent", type="keyDown" if down else "keyUp", modifiers=mods, key=key, code=code,
                    text=text if down else "", windowsVirtualKeyCode=vk, autoRepeat=repeat)

    def tap(self, code, key, mods=0, text=""):
        self.key(True, code, key, mods, text)
        self.key(False, code, key, mods)

    def sent(self, settle=0.0):
        if settle:
            time.sleep(settle)
        v = self.c.eval("(() => { const s = window.__sent; window.__sent = []; return s; })()")
        return v

    def js(self, expr):
        return self.c.eval(expr)

    def setting(self, sel_id, value):
        self.js(f"(() => {{ const s = document.getElementById('{sel_id}'); s.value = '{value}'; s.dispatchEvent(new Event('change')); }})()")

    def reset(self):
        self.js("window.dispatchEvent(new Event('blur'))")
        self.sent(0.05)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--html=")]
    html = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--html=")), None)
    url = args[0]
    c = Chrome(html=html)
    t = T(c)
    try:
        c.call("Page.addScriptToEvaluateOnNewDocument", source=SHIM)
        c.call("Page.navigate", url=url)
        for _ in range(60):
            c.pump(0.25)
            if t.js("document.getElementById('statusText').textContent") == "Live" and t.js("!document.getElementById('bCapture').hidden"):
                break
        else:
            print("page never became live with a keyboard-capable server"); sys.exit(2)
        mac = t.js("/Mac/.test(navigator.platform)")
        print("platform is Mac:", mac)

        # --- shortcuts while NOT capturing (matched by character, not by position) ---
        crisp = lambda: t.js("document.getElementById('setSharp').checked")
        before = crisp()
        t.tap("KeyP", "p", 0, "p")
        check("shortcut: p toggles crisp pixels", crisp(), not before)
        t.tap("Semicolon", "p", 0, "p")                       # AZERTY-style: the P key is where ; sits on US
        check("shortcut: matched by key character on another layout", crisp(), before)
        t.tap("KeyP", "π", MOD["alt"], "π")                   # Option+P on a Mac composes a character
        check("shortcut: Option-composed key does not trigger p", crisp(), before)
        mod = MOD["meta"] if mac else MOD["ctrl"]
        mcode, mvk = ("MetaLeft", "Meta") if mac else ("ControlLeft", "Control")
        t.key(True, mcode, mvk, mod); t.key(True, "KeyK", "k", mod, "k")
        check("shortcut: mod+k opens the palette", t.js("document.getElementById('palette').open"), True)
        t.key(False, "KeyK", "k", mod); t.key(False, mcode, mvk, 0)
        t.tap("Escape", "Escape")
        check("palette closes on Escape", t.js("document.getElementById('palette').open"), False)

        # --- enter capture ---
        t.js("document.getElementById('bCapture').click()")
        check("capture on", t.js("document.getElementById('bCapture').getAttribute('aria-pressed')"), "true")
        t.sent()

        t.tap("KeyA", "a", 0, "a")
        check("plain key: a", t.sent(), ["key 30 1", "key 30 0"])

        t.key(True, "ShiftLeft", "Shift", MOD["shift"])
        t.key(True, "KeyA", "A", MOD["shift"], "A")
        t.key(False, "KeyA", "A", MOD["shift"])
        t.key(False, "ShiftLeft", "Shift", 0)
        check("Shift+A", t.sent(), ["key 42 1", "key 30 1", "key 30 0", "key 42 0"])

        t.key(True, "KeyA", "a", 0, "a"); t.key(True, "KeyA", "a", 0, "a", repeat=True); t.key(False, "KeyA", "a")
        check("auto-repeat is not forwarded (the guest repeats itself)", t.sent(), ["key 30 1", "key 30 0"])

        t.tap("KeyY", "z", 0, "z")
        check("German layout: typed z (physical KeyY) -> z", t.sent(), ["key 44 1", "key 44 0"])
        t.tap("KeyZ", "y", 0, "y")
        check("German layout: typed y (physical KeyZ) -> y", t.sent(), ["key 21 1", "key 21 0"])
        t.tap("Minus", "ß", 0, "ß")
        check("character with no US equivalent falls back to the physical key", t.sent(), ["key 12 1", "key 12 0"])
        t.setting("setMode", "phys")
        t.tap("KeyY", "z", 0, "z")
        check("Physical mode: KeyY stays at the Y position", t.sent(), ["key 21 1", "key 21 0"])
        t.setting("setMode", "chars")

        # Option+L on a German Mac produces "@": the guest must see @ (Shift+2), not Alt+@.
        t.key(True, "AltLeft", "Alt", MOD["alt"])
        t.key(True, "KeyL", "@", MOD["alt"], "@")
        t.key(False, "KeyL", "@", MOD["alt"])
        t.key(False, "AltLeft", "Alt", 0)
        check("Option-composed @ is typed without Alt", t.sent(),
              ["key 56 1", "key 42 1", "key 56 0", "key 3 1", "key 3 0", "key 42 0", "key 56 1", "key 56 0"])

        # Shift+7 on a German layout is "/", which is unshifted on the US layout.
        t.key(True, "ShiftLeft", "Shift", MOD["shift"])
        t.key(True, "Digit7", "/", MOD["shift"], "/")
        t.key(False, "Digit7", "/", MOD["shift"])
        t.key(False, "ShiftLeft", "Shift", 0)
        check("German Shift+7 = / is typed without Shift", t.sent(),
              ["key 42 1", "key 42 0", "key 53 1", "key 53 0", "key 42 1", "key 42 0"])
        t.reset()

        if mac:
            # macOS delivers no keyup for keys pressed while Cmd is held.
            t.key(True, "MetaLeft", "Meta", MOD["meta"])
            t.key(True, "KeyC", "c", MOD["meta"], "c")
            check("Cmd+C: key is released without a keyup", t.sent(0.3), ["key 125 1", "key 46 1", "key 46 0"])
            t.key(False, "MetaLeft", "Meta", 0)
            check("Cmd released", t.sent(), ["key 125 0"])

            t.setting("setCmd", "1")
            t.key(True, "MetaLeft", "Meta", MOD["meta"])
            t.key(True, "KeyC", "c", MOD["meta"], "c")
            t.key(False, "MetaLeft", "Meta", 0)
            check("Cmd sends Ctrl when configured: Cmd+C -> Ctrl+C", t.sent(0.3), ["key 29 1", "key 46 1", "key 46 0", "key 29 0"])
            t.setting("setCmd", "0")

            t.key(True, "CapsLock", "CapsLock")
            check("Characters mode: Caps Lock is not forwarded", t.sent(0.1), [])
            t.setting("setMode", "phys")
            t.key(True, "CapsLock", "CapsLock")
            check("Physical mode on a Mac: one event toggles Caps Lock (pulse)", t.sent(0.2), ["key 58 1", "key 58 0"])
            t.setting("setMode", "chars")

        # Cmd+V / Ctrl+Shift+V must reach the paste handler, not the guest.
        pm = (MOD["meta"], "MetaLeft", "Meta") if mac else (MOD["ctrl"] | MOD["shift"], "ControlLeft", "Control")
        t.key(True, pm[1], pm[2], pm[0]); t.key(True, "KeyV", "v", pm[0], "v")
        got = [s for s in t.sent(0.1) if not s.startswith(("key 125", "key 29", "key 42"))]
        check("paste combo is not forwarded as a key", got, [])
        t.key(False, "KeyV", "v", pm[0]); t.key(False, pm[1], pm[2], 0); t.reset()

        t.js("(() => { const dt = new DataTransfer(); dt.setData('text', 'Hi!'); document.dispatchEvent(new ClipboardEvent('paste', {clipboardData: dt})); })()")
        check("paste types the text (H i !)", t.sent(0.5),
              ["key 42 1", "key 35 1", "key 35 0", "key 42 0", "key 23 1", "key 23 0", "key 42 1", "key 2 1", "key 2 0", "key 42 0"])

        t.key(True, "KeyA", "a", 0, "a")
        t.js("window.dispatchEvent(new Event('blur'))")
        check("window blur releases held keys", t.sent(0.05), ["key 30 1", "key 30 0"])

        t.key(True, "MediaPlayPause", "MediaPlayPause")
        check("unknown keys are left to the browser", t.sent(0.05), [])

        # Ctrl+Alt+K must release the keyboard even though Option composes "˚" on a Mac.
        t.key(True, "ControlLeft", "Control", MOD["ctrl"]); t.key(True, "AltLeft", "Alt", MOD["ctrl"] | MOD["alt"])
        t.key(True, "KeyK", "˚", MOD["ctrl"] | MOD["alt"], "˚")
        sent = t.sent(0.05)
        check("Ctrl+Alt+K releases capture", t.js("document.getElementById('bCapture').getAttribute('aria-pressed')"), "false")
        check("modifiers are released when capture ends", sorted(sent), sorted(["key 29 1", "key 56 1", "key 29 0", "key 56 0"]))
        t.key(False, "KeyK", "˚", MOD["ctrl"] | MOD["alt"]); t.key(False, "AltLeft", "Alt", MOD["ctrl"]); t.key(False, "ControlLeft", "Control", 0)
        check("nothing is sent after capture ends", t.sent(0.05), [])

        # On-screen keyboard (touch): text arrives as input events on a hidden field.
        c.call("Emulation.setTouchEmulationEnabled", enabled=True, maxTouchPoints=5)   # makes (pointer: coarse) match
        t.js("document.getElementById('bCapture').click()")      # capture was released by Ctrl+Alt+K above
        check("touch: capture focuses the hidden input", t.js("document.activeElement && document.activeElement.id"), "softkb")
        t.sent()
        c.call("Input.insertText", text="Hi")
        check("touch: soft-keyboard text is typed", t.sent(0.4),
              ["key 42 1", "key 35 1", "key 35 0", "key 42 0", "key 23 1", "key 23 0"])
        t.key(True, "Backspace", "Backspace"); t.key(False, "Backspace", "Backspace")
        check("touch: Backspace works", t.sent(0.1), ["key 14 1", "key 14 0"])
        c.call("Emulation.setTouchEmulationEnabled", enabled=False)

        errs = c.console_errors()
        check("no console errors during the run", errs, [])
    finally:
        c.close()
    bad = results.count(False)
    print(f"\n{len(results) - bad}/{len(results)} passed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
