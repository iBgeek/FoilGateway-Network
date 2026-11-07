#!/usr/bin/env python3
"""Run actual mutating API/browser checks with no host service/config access."""
import os,sys,subprocess,json,time,signal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=Path(os.environ.get('FOILGW_TEST_EVIDENCE',str(ROOT/'versions/1.1.0/verification/api-ui')))
if '--inside'not in sys.argv:
 os.execvp('unshare',['unshare','-Urnm',sys.executable,__file__,'--inside',os.readlink('/proc/self/ns/net'),os.readlink('/proc/self/ns/mnt'),str(os.stat('/run').st_dev)])
assert len(sys.argv)==5 and os.readlink('/proc/self/ns/net')!=sys.argv[2] and os.readlink('/proc/self/ns/mnt')!=sys.argv[3]
mapping=Path('/proc/self/uid_map').read_text().split();assert len(mapping)==3 and mapping[0]=='0'and mapping[2]=='1'
def run(*a):subprocess.run(a,check=True)
run('mount','--make-rprivate','/');run('mount','--bind','/etc','/etc');run('mount','-o','remount,bind,ro','/etc')
run('mount','-t','sysfs','-o','ro','sysfs','/sys')
assert os.statvfs('/sys').f_flag&os.ST_RDONLY, 'refusing writable sysfs'
for protected in ['/proc/sys']:
 run('mount','--bind',protected,protected);run('mount','-o','remount,bind,ro',protected)
for path,size in [('/run','8m'),('/tmp','256m'),('/var/log','8m')]:run('mount','-t','tmpfs','-o','size='+size,'tmpfs',path)
assert os.statvfs('/etc').f_flag&os.ST_RDONLY
assert str(os.stat('/run').st_dev)!=sys.argv[4]
assert not Path('/run/systemd/private').exists()and not Path('/run/dbus/system_bus_socket').exists()
state=Path('/tmp/fgw-isolated-state');state.mkdir()
os.environ['PATH']=os.environ.get('FOILGW_TEST_NFT_DIR','/usr/sbin')+':/usr/sbin:/sbin:'+os.environ['PATH']
for key in list(os.environ):
 if key.startswith('DBUS_')or key.startswith('SYSTEMD_'):del os.environ[key]
os.environ.update(FOILGW_STATE=str(state),FOILGW_ALLOW_NO_SYSTEMD='1',FOILGW_ISOLATED_API='1',DBUS_SYSTEM_BUS_ADDRESS='unix:path=/run/no-system-bus',DBUS_SESSION_BUS_ADDRESS='unix:path=/run/no-session-bus',CARGO_NET_OFFLINE='true',NODE_PATH=str(ROOT/'_scratch/browser/node_modules'))
run('ip','link','set','lo','up');run('ip','link','add','br-fgw','type','bridge');run('ip','link','set','br-fgw','up')
for n in ['eth0','eth1']:
 run('ip','link','add',n,'type','veth','peer','name',n+'peer');run('ip','link','set',n,'master','br-fgw');run('ip','link','set',n,'up')
children=[]
for name,mac,address in [('eth0peer','02:00:00:00:00:01','8.8.8.8'),('eth1peer','02:00:00:00:00:02','8.8.8.9')]:
 child=subprocess.Popen(['unshare','-n',sys.executable,'-c','import signal;signal.pause()']);children.append(child)
 for _ in range(100):
  if os.readlink(f'/proc/{child.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
  time.sleep(.01)
 else:raise RuntimeError('private peer did not start')
 run('ip','link','set',name,'netns',str(child.pid));run('nsenter','-t',str(child.pid),'-n','ip','link','set',name,'address',mac);run('nsenter','-t',str(child.pid),'-n','ip','link','set',name,'up');run('nsenter','-t',str(child.pid),'-n','ip','addr','add',address+'/24','dev',name)
os.environ['FOILGW_TEST_CLIENT_PID']=str(children[1].pid)
OUT.mkdir(parents=True,exist_ok=True)
proof={'net':os.readlink('/proc/self/ns/net'),'parent_net':sys.argv[2],'mount':os.readlink('/proc/self/ns/mnt'),'parent_mount':sys.argv[3],'etc_readonly':True,'run_private':True,'host_service_sockets_absent':True,'state':str(state),'uid_map':mapping}
(OUT/'sandbox-proof.json').write_text(json.dumps(proof,indent=2))
try:
 run('node',str(ROOT/'tests'/os.environ.get('FOILGW_BROWSER_SCRIPT','speed-browser-110.cjs')))
finally:
 for child in children:child.terminate()
 for child in children:child.wait(timeout=5)
assert os.statvfs('/etc').f_flag&os.ST_RDONLY and not Path('/run/systemd/private').exists()
print('PASS sandbox remained protected after mutating API/failure/cancel checks')
