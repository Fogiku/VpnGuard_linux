#!/usr/bin/env python3
"""Client for a user-started, time-limited Windows support session."""
import argparse,json,urllib.request
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument("--config",type=Path,required=True)
p.add_argument("--script",type=Path)
p.add_argument("--stop",action="store_true")
p.add_argument("--timeout",type=int,default=120)
a=p.parse_args()
c=json.loads(a.config.read_text(encoding="utf-8"))
path="/health"
data=None
if a.script:
    path="/run";data=json.dumps({"script":a.script.read_text(encoding="utf-8-sig")}).encode()
if a.stop:
    path="/stop";data=b"{}"
r=urllib.request.Request(c["url"]+path,data=data,headers={"X-Vg-Support":c["token"],"Content-Type":"application/json"})
with urllib.request.urlopen(r,timeout=a.timeout) as response:
    result=json.load(response)
print(result.get("output") or json.dumps(result,ensure_ascii=False,indent=2))
if not result.get("ok"): raise SystemExit(1)
