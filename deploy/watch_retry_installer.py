"""One-shot controller: approve only the captured installer after verified SSH."""
import argparse,datetime,json,subprocess,sys,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--access',type=Path,required=True);p.add_argument('--seconds',type=int,default=14400);a=p.parse_args()
    access=a.access.resolve();deadline=time.monotonic()+a.seconds
    status=access/'auto-install-status.json'
    def save(stage,**kw):
        status.write_text(json.dumps(dict(stage=stage,time=datetime.datetime.now(datetime.timezone.utc).isoformat(),**kw),indent=2))
    save('waiting-for-usb-removal')
    while time.monotonic()<deadline and Path('E:/vpnguard/install.json').exists():time.sleep(5)
    save('waiting-for-pinned-installer-ssh')
    command=[sys.executable,'-X','utf8',str(Path(__file__).with_name('verify_installer_ssh.py')),'--access',str(access)]
    attempts=0
    while time.monotonic()<deadline:
        attempts+=1
        try:
            result=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',timeout=50)
            if result.returncode==0:
                expected=json.loads((access/'expected-install.json').read_text())
                save('approval-attempt-started',attempts=attempts,**expected)
                (access/'approval-receipt.json').write_text(status.read_text())
                try:
                    approval=subprocess.run(command+['--approve'],capture_output=True,text=True,encoding='utf-8',timeout=50)
                    stage='approved-once' if approval.returncode==0 else 'approval-result-unknown-no-retry'
                except subprocess.TimeoutExpired:
                    stage='approval-result-unknown-no-retry'
                save(stage,attempts=attempts,**expected)
                (access/'approval-receipt.json').write_text(status.read_text())
                print(stage,flush=True)
                return
            save('waiting-for-pinned-installer-ssh',attempts=attempts)
        except subprocess.TimeoutExpired:save('waiting-for-pinned-installer-ssh',attempts=attempts)
        time.sleep(10)
    save('expired-without-approval',attempts=attempts)
    print('Controller expired without approving partitioning.',flush=True)

if __name__=='__main__':main()
