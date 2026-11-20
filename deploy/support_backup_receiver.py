import argparse,hashlib,http.server,json,re,threading,os
from pathlib import Path
from urllib.parse import urlsplit
p=argparse.ArgumentParser();p.add_argument("--config",type=Path,required=True);p.add_argument("--file",type=Path,required=True);p.add_argument("--port",type=int,default=8871);a=p.parse_args()
c=json.loads(a.config.read_text());target=urlsplit(c["url"]).hostname
class Handler(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  if self.client_address[0]!=target or self.path!="/"+c["id"]+"/backup" or self.headers.get("X-Vg-Support")!=c["token"]:
   self.send_error(403);return
  n=int(self.headers.get("Content-Length","0")); expected=self.headers.get("X-Backup-Sha256","")
  if not 0<n<2*1024**3 or not re.fullmatch("[0-9a-f]{64}",expected):
   self.send_error(400);return
  part=a.file.with_suffix(".part");h=hashlib.sha256();total=0
  with part.open("wb") as f:
   while total<n:
    b=self.rfile.read(min(4*1024*1024,n-total))
    if not b: raise IOError("Incomplete backup upload")
    f.write(b);h.update(b);total+=len(b)
   f.flush();os.fsync(f.fileno())
  if h.hexdigest()!=expected:
   part.unlink(missing_ok=True);self.send_error(400,"Checksum mismatch");return
  part.replace(a.file)
  data=json.dumps({"ok":True,"sha256":h.hexdigest(),"bytes":total}).encode()
  self.send_response(200);self.send_header("Content-Length",str(len(data)));self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(data);self.wfile.flush()
  print("Backup received and SHA256 verified; bytes="+str(total),flush=True)
  threading.Thread(target=self.server.shutdown,daemon=True).start()
 def log_message(self,*args):pass
s=http.server.ThreadingHTTPServer(("0.0.0.0",a.port),Handler)
print("Authenticated backup receiver ready",flush=True)
t=threading.Timer(1200,lambda:threading.Thread(target=s.shutdown,daemon=True).start());t.daemon=True;t.start()
try:s.serve_forever()
finally:s.server_close();t.cancel()
