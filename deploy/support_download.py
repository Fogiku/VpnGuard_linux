import argparse,http.server,ipaddress,threading
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument("--file",type=Path,required=True);p.add_argument("--route",required=True);p.add_argument("--target",required=True);p.add_argument("--port",type=int,default=8870);a=p.parse_args()
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.client_address[0] not in (a.target,"127.0.0.1"):
   self.send_error(403);return
  if self.path!=a.route:
   self.send_error(404);return
  data=a.file.read_bytes();self.send_response(200);self.send_header("Content-Type","application/octet-stream");self.send_header("Content-Length",str(len(data)));self.end_headers();self.wfile.write(data)
 def log_message(self,fmt,*args): print("download:",self.client_address[0],self.command,flush=True)
s=http.server.ThreadingHTTPServer(("0.0.0.0",a.port),Handler)
s.timeout=1
print("Support download ready on port "+str(a.port),flush=True)
threading.Timer(1800,lambda: threading.Thread(target=s.shutdown,daemon=True).start()).start()
s.serve_forever()
