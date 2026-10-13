#!/usr/bin/env python3
"""fp-live4 — live touch-detection page backed by the REAL sensor readings.

Runs `cc-touch ... noinit` (keeps an existing TLS session alive; probes the
sensor's fdt every 2 s), parses its output, and serves an honest live view:
  - every probe shows the sensor's six fdt values + mean
  - touches flip the card green (mean < 0x130 = finger present)
  - image-request events are shown as they happen
"""
import json
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CC_TOUCH = str(Path(__file__).resolve().parent / "cc-touch")
NODE = "/dev/spidev0.0"

STATE = {
    "started": time.time(),
    "probes": 0,
    "touches": 0,
    "last_mean": None,
    "last_vals": "",
    "last_probe_at": 0.0,
    "last_touch_at": 0.0,
    "events": deque(maxlen=60),     # (t, text)
    "img_requests": 0,
    "proc": None,
}
LOCK = threading.Lock()


def runner():
    while True:
        with LOCK:
            STATE["events"].append((time.time(), "starting capture tool"))
        p = subprocess.Popen(
            [CC_TOUCH, NODE, "0", "10000000", "3600", "2", "noinit"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with LOCK:
            STATE["proc"] = p
        for line in p.stdout:
            line = line.strip()
            now = time.time()
            with LOCK:
                if "FDT" in line and "vals" in line:
                    STATE["probes"] += 1
                    STATE["last_probe_at"] = now
                    try:
                        parts = line.split()
                        vi = parts.index("vals")
                        STATE["last_vals"] = " ".join(parts[vi+1:vi+7])
                        mi = parts.index("mean")
                        STATE["last_mean"] = parts[mi+1]
                    except Exception:
                        pass
                    if "FINGER" in line:
                        if now - STATE["last_touch_at"] > 1.0:
                            STATE["touches"] += 1
                            STATE["events"].append((now, "TOUCH detected " + STATE["last_vals"]))
                        STATE["last_touch_at"] = now
                elif "requesting image" in line:
                    STATE["img_requests"] += 1
                    STATE["events"].append((now, "image requested (0x20) — body still unsupported"))
                elif "IMAGE" in line:
                    STATE["events"].append((now, "IMAGE FRAME! " + line))
        with LOCK:
            STATE["events"].append((time.time(), "capture tool exited; restarting"))
        time.sleep(2)


def snapshot():
    now = time.time()
    with LOCK:
        return {
            "elapsed": round(now - STATE["started"], 0),
            "probes": STATE["probes"],
            "touches": STATE["touches"],
            "last_mean": STATE["last_mean"],
            "last_vals": STATE["last_vals"],
            "finger_now": (now - STATE["last_touch_at"]) < 4.0 if STATE["last_touch_at"] else False,
            "last_probe_ago": round(now - STATE["last_probe_at"], 1) if STATE["last_probe_at"] else None,
            "img_requests": STATE["img_requests"],
            "events": [(round(t - STATE["started"], 1), s) for t, s in list(STATE["events"])[-14:]][::-1],
        }


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>GXFP5120 live</title>
<style>
 body{background:#101418;color:#d7dde3;font-family:system-ui,sans-serif;margin:0;padding:24px}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:16px}
 .card{background:#1a2027;border-radius:10px;padding:16px 20px;min-width:200px}
 .card h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#8b98a5;margin:0 0 8px}
 .big{font-size:30px;font-weight:600}
 .touch{border:2px solid #2c3642;transition:all .15s}
 .touch.on{border-color:#31d158;background:#14351f;box-shadow:0 0 28px #31d15855}
 .ok{color:#31d158}.dim{color:#8b98a5}
 .mono{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
 .log{background:#151b21;border-radius:10px;padding:12px 16px;margin-top:8px;max-width:900px}
 .log div{padding:3px 0;border-bottom:1px solid #1e262e;font-size:13px}
 .hint{color:#8b98a5;margin-top:14px;font-size:13px;max-width:820px;line-height:1.5}
</style></head><body>
<h1 id="title">GXFP5120 fingerprint — live touch detection</h1>
<div id="flash" style="display:none;background:#14351f;border:2px solid #31d158;border-radius:10px;padding:14px 20px;margin-bottom:16px;font-size:24px;font-weight:700;color:#31d158">👆 TOUCH DETECTED</div>
<div class="cards">
 <div class="card touch" id="tc"><h2>finger now</h2>
  <div class="big" id="fn">–</div>
  <div class="dim" id="fnmeta"></div></div>
 <div class="card"><h2>touches detected</h2>
  <div class="big ok" id="tt">–</div>
  <div class="dim" id="ttmeta"></div></div>
 <div class="card"><h2>sensor readings</h2>
  <div class="big mono" id="vals" style="font-size:16px">–</div>
  <div class="dim" id="mean"></div></div>
 <div class="card"><h2>session</h2>
  <div class="big" id="timer">–</div>
  <div class="dim" id="probes"></div></div>
</div>
<div class="log" id="log"></div>
<div class="hint">These are the sensor's own measurements, probed live (every ~2 s): while your finger
is on the sensor the values drop from ~0x16x to ~0x0xx and the card flashes green. This is real
detection — the fingerprint <i>image</i> itself is still blocked on one bridge-protocol detail
(the bulk read), so login isn't wired up yet.</div>
<script>
async function tick(){
 try{
  const d = await (await fetch('/data',{cache:'no-store'})).json();
  document.getElementById('fn').textContent = d.finger_now ? 'FINGER' : 'no finger';
  document.getElementById('fn').className = 'big ' + (d.finger_now ? 'ok' : 'dim');
  document.getElementById('tc').classList.toggle('on', d.finger_now);
  document.getElementById('flash').style.display = d.finger_now ? 'block' : 'none';
  document.title = d.finger_now ? '👆 TOUCH!' : 'GXFP5120 live';
  document.getElementById('fnmeta').textContent = d.last_probe_ago!==null ? ('last probe '+d.last_probe_ago+'s ago') : 'starting…';
  document.getElementById('tt').textContent = d.touches;
  document.getElementById('ttmeta').textContent = d.img_requests + ' image requests sent';
  document.getElementById('vals').textContent = d.last_vals || '–';
  document.getElementById('mean').textContent = 'mean ' + (d.last_mean||'–') + '  (finger < 0x130)';
  const t = Math.floor(d.elapsed);
  document.getElementById('timer').textContent =
     String(Math.floor(t/60)).padStart(2,'0')+':'+String(t%60).padStart(2,'0');
  document.getElementById('probes').textContent = d.probes + ' probes';
  document.getElementById('log').innerHTML = d.events.map(e=>'<div><span class="dim">'+e[0]+'s</span>  '+e[1]+'</div>').join('');
 }catch(e){}
}
tick(); setInterval(tick, 500);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/data":
            body = json.dumps(snapshot()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        else:
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    threading.Thread(target=runner, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", 8765), H)
    print("serving on http://127.0.0.1:8765")
    srv.serve_forever()
