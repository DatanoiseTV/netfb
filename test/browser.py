#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Loads the web UI in a real headless Chrome (over the DevTools protocol) and
checks that it reaches "Live" and stays connected without console errors.

    browser.py URL [seconds] [screenshot.png]

This exists because browsers are stricter than the raw client in e2e.py: Chrome
drops a WebSocket on a non-minimal frame length ("Invalid frame header"), which
the protocol-level tests did not notice.
"""
import os, sys, json, time, random, subprocess, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import e2e
port=random.randint(41000,49000); prof=f"/tmp/netfb-chr-{port}"
ch=subprocess.Popen(["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome","--headless=new",f"--user-data-dir={prof}",f"--remote-debugging-port={port}","--window-size=1280,860","about:blank"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try: pages=json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json")); break
        except Exception: time.sleep(0.2)
    pg=[p for p in pages if p["type"]=="page"][0]
    path=pg["webSocketDebuggerUrl"].split(str(port))[1]
    c=e2e.WS.__new__(e2e.WS)
    import socket,base64,os
    c.sock=socket.create_connection(("127.0.0.1",port),timeout=10); key=base64.b64encode(os.urandom(16)).decode()
    c.sock.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    h=b""
    while b"\r\n\r\n" not in h: h+=c.sock.recv(4096)
    c.buf=h.partition(b"\r\n\r\n")[2]; c.closed=None; c.info=None; c.msgs=[]; c.wire=[]; c.lz4=[]
    def recv64(timeout=0.2):
        import struct
        deadline=time.time()+timeout
        if not c._need(2,deadline): return None
        n=c.buf[1]&0x7f; hl=2
        if n==126:
            if not c._need(4,deadline): return None
            n=struct.unpack('>H',c.buf[2:4])[0]; hl=4
        elif n==127:
            if not c._need(10,deadline): return None
            n=struct.unpack('>Q',c.buf[2:10])[0]; hl=10
        if not c._need(hl+n,deadline): return None
        op,pl=c.buf[0]&0xf,bytes(c.buf[hl:hl+n]); c.buf=c.buf[hl+n:]; return op,pl
    c.recv=recv64
    n=[0]; logs=[]; page_state='{}'
    def call(m,**p):
        n[0]+=1; c.send(1,json.dumps({"id":n[0],"method":m,"params":p}).encode()); return n[0]
    def drain(t):
        end=time.time()+t
        while time.time()<end:
            try: r=c.recv(0.1)
            except EOFError: break
            if r and r[0]==1:
                m=json.loads(r[1])
                if m.get("method") in ("Runtime.consoleAPICalled","Log.entryAdded","Runtime.exceptionThrown"): logs.append(json.dumps(m["params"])[:300])
                yield m
    for m in ("Runtime.enable","Log.enable","Page.enable","Network.enable"): call(m)
    call("Page.navigate",url=sys.argv[1]); 
    nets=[]
    for _ in range(1):
        for m in drain(float(sys.argv[2] if len(sys.argv) > 2 else "8")):
            if m.get("method")=="Network.webSocketCreated": nets.append("ws created "+m["params"]["url"])
            if m.get("method")=="Network.webSocketClosed": nets.append("ws closed")
            if m.get("method")=="Network.webSocketHandshakeResponseReceived": nets.append("ws handshake status %s"%m["params"]["response"]["status"])
            if m.get("method")=="Network.responseReceived": nets.append("http %s %s"%(m["params"]["response"]["status"],m["params"]["response"]["url"]))
            if m.get("method")=="Network.loadingFailed": nets.append("FAILED "+json.dumps(m["params"])[:200])
    i=call("Runtime.evaluate",expression="JSON.stringify({status:document.getElementById('statusText').textContent,overlay:document.getElementById('overlayText').textContent,fps:document.getElementById('fpsNow').textContent,fmt:document.getElementById('fmt').textContent,total:document.getElementById('total').textContent})",returnByValue=True)
    for m in drain(2):
        if m.get("id")==i: page_state=m["result"]["result"].get("value"); print("PAGE:",page_state)
    print("NET:",*nets,sep="\n  "); print("CONSOLE:",*logs,sep="\n  ")
    if len(sys.argv) > 3:
        i=call("Page.captureScreenshot",format="png")
        for m in drain(5):
            if m.get("id")==i: open(sys.argv[3],"wb").write(base64.b64decode(m["result"]["data"])); print("saved",sys.argv[3])
    page=json.loads(page_state)
    ok = page["status"]=="Live" and not logs and "compressed" in page["total"] and not any("closed" in x for x in nets)
    print("PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
finally:
    ch.terminate()
