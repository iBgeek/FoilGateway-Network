#!/usr/bin/env python3
"""Real packets and production-generated rules, exclusively in throwaway net namespaces."""
import os,sys,subprocess,time,json,signal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=Path(os.environ.get('FOILGW_TEST_EVIDENCE',str(ROOT/'versions/1.1.0/verification')))
if '--inside' not in sys.argv:
    os.execvp('unshare',['unshare','-Urn',sys.executable,__file__,'--inside',os.readlink('/proc/self/ns/net')])
assert len(sys.argv)==3 and sys.argv[1]=='--inside' and sys.argv[2].startswith('net:['), 'launcher required; refusing network operations'
assert os.readlink('/proc/self/ns/net')!=sys.argv[2], 'refusing host network execution'
mapping=Path('/proc/self/uid_map').read_text().split()
assert len(mapping)==3 and mapping[0]=='0' and mapping[2]=='1', 'a fresh restricted user namespace is required'
os.environ['PATH']=os.environ.get('FOILGW_TEST_NFT_DIR','/usr/sbin')+':/usr/sbin:/usr/bin:/bin'
children=[]
def run(*args,check=True,input=None):
    try:return subprocess.run(args,input=input,text=True,capture_output=True,check=check)
    except subprocess.CalledProcessError as e:print(e.stderr,file=sys.stderr);raise
def ip(*a):return run('ip',*a)
def in_ns(pid,*a):return run('nsenter','-t',str(pid),'-n',*a)
def spawn_ns(pid,code,*args):
    p=subprocess.Popen(['nsenter','-t',str(pid),'-n',sys.executable,'-u','-c',code,*args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);children.append(p);return p
try:
 for _ in range(2):
    p=subprocess.Popen(['unshare','-n',sys.executable,'-c','import signal; signal.pause()']);children.append(p)
    for i in range(100):
        if os.readlink(f'/proc/{p.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
        time.sleep(.01)
    else:raise RuntimeError('child network namespace did not start')
 router,client=[p.pid for p in children[:2]]
 ip('link','add','eth0','type','veth','peer','name','rpeer');ip('link','set','rpeer','netns',str(router))
 ip('link','add','eth1','type','veth','peer','name','cpeer');ip('link','set','cpeer','netns',str(client))
 ip('link','add','br-fgw','type','bridge','mcast_snooping','0');ip('link','set','br-fgw','up')
 for n in ['eth0','eth1']:ip('link','set',n,'master','br-fgw');ip('link','set',n,'up')
 for pid,iface,mac,v4,v6 in [(router,'rpeer','02:00:00:00:00:01','8.8.8.8','2606:4700::1'),(client,'cpeer','02:00:00:00:00:02','8.8.8.9','2606:4700::2')]:
    in_ns(pid,'ip','link','set','lo','up');in_ns(pid,'ip','link','set',iface,'address',mac);in_ns(pid,'ip','link','set',iface,'up');in_ns(pid,'ip','addr','add',v4+'/24','dev',iface);in_ns(pid,'ip','-6','addr','add',v6+'/64','dev',iface,'nodad')
 in_ns(client,'ip','-6','neigh','replace','2606:4700::1','lladdr','02:00:00:00:00:01','dev','cpeer','nud','permanent')
 in_ns(router,'ip','-6','neigh','replace','2606:4700::2','lladdr','02:00:00:00:00:02','dev','rpeer','nud','permanent')
 for family in ['iptables','ip6tables']:
    assert Path('/proc/sys/net/bridge/bridge-nf-call-'+family).read_text().strip()=='1','bridge filtering unavailable; no sysctl change attempted'
 server_code='''import socket,threading,sys
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],8082));s.listen();print('READY',flush=True)
last=[None,0]
def echo(c):
 try:
  while True:
   b=c.recv(4)
   if not b:break
   if c is last[0]:last[1]+=1
   c.sendall(b)
 except OSError:pass
def accept():
 while True:
  c,_=s.accept();last[0]=c;last[1]=0;threading.Thread(target=echo,args=(c,),daemon=True).start()
threading.Thread(target=accept,daemon=True).start()
for line in sys.stdin:
 try:
  if line.strip()=='count':print(last[1],flush=True)
  else:last[0].sendall(b'PUSH');print('SENT',flush=True)
 except OSError:print('CLOSED',flush=True)
'''
 servers=[spawn_ns(router,server_code,addr)for addr in ['8.8.8.8','2606:4700::1']]
 for s in servers:assert s.stdout.readline().strip()=='READY'
 def load(name):
    run('nft','-f',str(OUT/'nft-cases'/f'{name}.nft'))
    for chain in ['drop_mode','drop_country']:
        run('nft','insert','rule','inet','foilgateway',chain,'counter')
 def read_production(case,expected=None):
    if not os.environ.get('FOILGW_TEST_DETECTION'):return
    run('nft','list','tables')
    run('nft','-t','list','table','inet','foilgateway')
    binaries=[p for p in (ROOT/'target/debug/deps').glob('foilgw-*')if p.is_file()and os.access(p,os.X_OK)]
    binary=max(binaries,key=lambda p:p.stat().st_mtime_ns)
    env=dict(os.environ,FOILGW_TEST_PARENT_NETNS=sys.argv[2],FOILGW_DD_CASE=case)
    if expected is not None:env['FOILGW_DD_EXPECT_SYN']=str(expected)
    result=subprocess.run([str(binary),'detection::tests::isolated_kernel_snapshot','--ignored','--nocapture'],env=env,text=True,capture_output=True,timeout=25)
    (OUT/(case+'-production-reader.log')).write_text(result.stdout+result.stderr)
    assert result.returncode==0,(case,result.stdout,result.stderr)
    print('production reader/engine',case,'PASS',flush=True)
 def counters(chain):
    v=json.loads(run('nft','-j','list','chain','inet','foilgateway',chain).stdout)
    return sum(e['counter']['packets']for r in v['nftables']for e in r.get('rule',{}).get('expr',[])if 'counter'in e)
 def observed():
    rows=[]
    for n in ['map_out4','map_in4','map_out6','map_in6']:
        rows.extend(json.loads(run('nft','-j','list','set','inet','foilgateway',n).stdout)['nftables'])
    v={'nftables':rows};assert all(t.get('set',{}).get('name','').startswith('map_')for t in rows if 'set'in t);total=0
    for t in v['nftables']:
     if t.get('set',{}).get('name','').startswith('map_'):
      for e in t['set'].get('elem',[]):
       el=e.get('elem',{});pair=el.get('val',{}).get('concat',[])
       if len(pair)==2 and pair[1] in ['8.8.8.8','2606:4700::1']:total+=el.get('counter',{}).get('bytes',0)
    return total
 # A probe failure is expected in blocked cases, so avoid check=True there.
 def probe(addr):
    p=subprocess.run(['nsenter','-t',str(client),'-n',sys.executable,'-c',"import socket,sys; s=socket.create_connection((sys.argv[1],8082),timeout=.5);s.sendall(b'TEST');assert s.recv(4)==b'TEST'",addr],capture_output=True,text=True)
    return p.returncode==0
 for name,expected in [('allowed',(True,True)),('ipv6-blocked',(True,False)),('country-blocked',(False,False)),('country-audit',(True,True)),('country-trusted',(True,True)),('country-allow',(True,True)),('country-whitelist',(True,True)),('country-device-audit',(True,True)),('country-safety',(False,False)),('ipv6-safety',(True,False))]:
    load(name);got=tuple(probe(a)for a in ['8.8.8.8','2606:4700::1']);assert got==expected,(name,got,expected)
    if name=='country-blocked':assert observed()==0 and counters('drop_country')>0
    if name=='ipv6-blocked':assert counters('drop_mode')>0
    if os.environ.get('FOILGW_TEST_DETECTION'):
     snapshots={n+str(f):json.loads(run('nft','-j','-n','list','set','inet','foilgateway','dd_'+n+str(f)).stdout)for n in ['eligible','syn','ack','rst']for f in [4,6]}
     (OUT/(name+'-signals.json')).write_text(json.dumps(snapshots))
     import socket,struct
     def attributes(b):
      result=[];i=0
      while i+4<=len(b):
       length,typ=struct.unpack_from('HH',b,i);assert length>=4 and i+length<=len(b);result.append((typ&0x3fff,b[i+4:i+length]));i+=(length+3)&~3
      return result
     def raw_keys(setname):
      def attr(t,b):return struct.pack('HH',len(b)+4,t)+b+b'\0'*((-len(b))%4)
      req=b'\x01\0\0\0'+attr(1,b'foilgateway\0')+attr(2,setname.encode()+b'\0')
      with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12)as sock:
       sock.settimeout(1);sock.bind((0,0));sock.send(struct.pack('IHHII',len(req)+16,(10<<8)|13,0x301,123,0)+req);keys=[]
       while True:
        buf=sock.recv(65536);off=0
        while off+16<=len(buf):
         length,typ,flags,seq,pid=struct.unpack_from('IHHII',buf,off);part=buf[off+16:off+length];off+=(length+3)&~3
         if typ==3:return keys
         assert typ!=2,(typ,part.hex())
         for t,data in attributes(part[4:]):
          if t==3:
           for _,element in attributes(data):
            for t,key in attributes(element):
             if t==1:
              for t,value in attributes(key):
               if t==1:keys.append(value.hex())
     raw={n+str(f):raw_keys('dd_'+n+str(f))for n in ['eligible','syn','ack','rst']for f in [4,6]}
     (OUT/(name+'-raw-signals.json')).write_text(json.dumps(raw))
     if name=='allowed':
      assert len(bytes.fromhex(raw['syn4'][0]))==28
      b=bytes.fromhex(raw['syn4'][0]);assert int.from_bytes(b[18:20],'big')==8082 and int.from_bytes(b[24:28],sys.byteorder)==1,b.hex()

     count=sum(len(t.get('set',{}).get('elem',[]))for k,v in snapshots.items()if k.startswith('syn')for t in v['nftables'])
     for key,data in snapshots.items():
      for row in data['nftables']:
       for el in row.get('set',{}).get('elem',[]):
        fields=el['elem']['val']['concat'];assert len(fields)==4 and fields[0]=='02:00:00:00:00:02',(key,fields)
     assert (count>0)==(name in ['allowed','ipv6-blocked','country-audit','country-device-audit','ipv6-safety']),(name,count)
     read_production(name,count)
     print('actual unresolved post-filter SYN records',name,count,flush=True)
    print(name,got,'observer bytes',observed(),flush=True)
 if os.environ.get('FOILGW_TEST_DETECTION'):
  # Real RST refusals, successful handshakes then resets, and a silent target.
  # Every endpoint is an isolated veth peer; there is no outside route.
  attempts="""import socket,sys,struct
mode=sys.argv[1]
for address in ['8.8.8.8','2606:4700::1']:
 for n in range(12 if mode=='sweep'else 8):
  s=socket.socket(socket.AF_INET6 if ':'in address else socket.AF_INET);s.settimeout(.1)
  port=12000+n if mode=='sweep'else 12100 if mode=='timeout'else 8082 if mode=='success-reset'else 12099
  try:
   s.connect((address,port))
   if mode=='success-reset':
    s.sendall(b'TEST');assert s.recv(4)==b'TEST';s.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
  except (ConnectionRefusedError,TimeoutError):pass
  finally:s.close()
"""
  for mode in ['sweep','refused','success-reset','timeout']:
   load('allowed')
   if mode=='timeout':
    run('nsenter','-t',str(router),'-n','nft','-f','-',input='table inet silent_target {\n chain input {\n type filter hook input priority 0; policy accept;\n tcp dport 12100 drop;\n }\n}\n')
   in_ns(client,sys.executable,'-c',attempts,mode)
   read_production(mode)
   if mode=='timeout':in_ns(router,'nft','delete','table','inet','silent_target')
 if os.environ.get('FOILGW_TEST_DETECTION'):
  for name in ['device-block','device-lan','threat-block','hardening-block']:
   load(name);assert not probe('8.8.8.8')and not probe('2606:4700::1');read_production(name,0)
  load('allowed-off');assert probe('8.8.8.8')and probe('2606:4700::1');read_production('off')
  for mode in ['sweep','refused']:
   load('incoming-audit');code=attempts.replace("['8.8.8.8','2606:4700::1']","['8.8.8.9','2606:4700::2']");in_ns(router,sys.executable,'-c',code,mode);read_production('incoming-'+mode)
  raw_syn="""import socket,struct,sys
vary=sys.argv[1]=='distinct-isn'
def checksum(b):
 if len(b)%2:b+=b'\\0'
 s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s>>16)+(s&65535);s+=(s>>16);return (~s)&65535
for v6,src,dst in [(False,'8.8.8.9','8.8.8.8'),(True,'2606:4700::2','2606:4700::1')]:
 af=socket.AF_INET6 if v6 else socket.AF_INET;a=socket.inet_pton(af,src);b=socket.inet_pton(af,dst)
 s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind(('cpeer',0))
 for n in range(8):
  seq=123400+n if vary else 123400
  tcp=struct.pack('!HHIIBBHHH',40000,12099,seq,0,80,2,65535,0,0)
  pseudo=a+b+(struct.pack('!I3xB',20,6)if v6 else struct.pack('!BBH',0,6,20));c=checksum(pseudo+tcp);tcp=tcp[:16]+struct.pack('!H',c)+tcp[18:]
  if v6:ip=struct.pack('!IHBB',6<<28,20,6,64)+a+b
  else:
   ip=struct.pack('!BBHHHBBH',69,0,40,n,0,64,6,0)+a+b;c=checksum(ip);ip=ip[:10]+struct.pack('!H',c)+ip[12:]
  s.send(bytes.fromhex('020000000001020000000002')+struct.pack('!H',0x86dd if v6 else 0x800)+ip+tcp)
 s.close()
"""
  for mode in ['retransmit','distinct-isn']:
   load('allowed');in_ns(client,sys.executable,'-c',raw_syn,mode);time.sleep(.1);read_production(mode)
  # Real late SYN-ACKs settle only matching failed attempts, not the service.
  load('allowed')
  run('nsenter','-t',str(router),'-n','nft','-f','-',input='table inet late_target {\n chain input {\n type filter hook input priority 0; policy accept; tcp dport 12101 drop;\n }\n}\n')
  initial=raw_syn.replace('40000,12099,seq,0,80,2','40000+n,12101,seq,0,80,2')
  in_ns(client,sys.executable,'-c',initial,'distinct-isn')
  binary=max([p for p in(ROOT/'target/debug/deps').glob('foilgw-*')if p.is_file()and os.access(p,os.X_OK)],key=lambda p:p.stat().st_mtime_ns)
  proc=subprocess.Popen([str(binary),'detection::tests::isolated_kernel_snapshot','--ignored','--nocapture'],env=dict(os.environ,FOILGW_TEST_PARENT_NETNS=sys.argv[2],FOILGW_DD_CASE='late-success'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);children.append(proc);log=[]
  def until(marker):
   while True:
    line=proc.stdout.readline();log.append(line)
    if marker in line:return
    if not line:raise AssertionError('late success: '+''.join(log))
  until('DD_LATE_READY')
  reply=raw_syn.replace("'8.8.8.9','8.8.8.8'","'8.8.8.8','8.8.8.9'").replace("'2606:4700::2','2606:4700::1'","'2606:4700::1','2606:4700::2'").replace("('cpeer',0)","('rpeer',0)").replace('020000000001020000000002','020000000002020000000001').replace('40000,12099,seq,0,80,2','12101,40000+n,987654,seq+1,80,18')
  in_ns(router,sys.executable,'-c',reply.replace('range(8)','range(3)'),'distinct-isn');time.sleep(.1);proc.stdin.write('sample\n');proc.stdin.flush();until('DD_LATE_PARTIAL')
  in_ns(router,sys.executable,'-c',reply.replace('range(8)','range(3,8)'),'distinct-isn');time.sleep(.1);proc.stdin.write('sample\n');proc.stdin.flush();log.extend(proc.stdout.readlines());assert proc.wait(timeout=5)==0,''.join(log);(OUT/'late-success-production-reader.log').write_text(''.join(log));print('production reader/engine late-success exact flow partial/full resolution PASS',flush=True)
  in_ns(router,'nft','delete','table','inet','late_target')
  load('allowed');read_production('permission');read_production('generation')
  # Exceed actual dynamic-set capacity; forwarding must still succeed.
  in_ns(client,sys.executable,'-c',attempts.replace("range(12 if mode=='sweep'else 8)","range(530)").replace('12000+n','20000+n'),'sweep')
  assert probe('8.8.8.8')and probe('2606:4700::1'),'full metadata cannot change verdicts'
  read_production('overflow');load('allowed');assert probe('8.8.8.8');read_production('recovered')
 # These LAN-observed link-local/multicast packets must not cross with Block IPv6 On.
 in_ns(client,'ip','-6','addr','add','fe80::2/64','dev','cpeer','nodad')
 for mode,expected in [('allowed','SEEN'),('ipv6-blocked','NONE')]:
  for dest,port in [('ff02::fb',5353),('ff02::1:3',5355),('ff02::fb',67)]:
    load(mode)
    capture=spawn_ns(router,"""import socket,sys,time
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86dd));s.bind(('rpeer',0));s.settimeout(.2);end=time.monotonic()+1.2;print('READY',flush=True);seen=False
while time.monotonic()<end:
 try:
  b=s.recv(2048)
  if b[38:54]==socket.inet_pton(socket.AF_INET6,sys.argv[1]) and int.from_bytes(b[56:58],'big')==int(sys.argv[2]):seen=True
 except TimeoutError:pass
print('SEEN'if seen else 'NONE',flush=True)
""",dest,str(port))
    assert capture.stdout.readline().strip()=='READY'
    in_ns(client,sys.executable,'-c',"import socket,sys;s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);i=socket.if_nametoindex('cpeer');s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_IF,i);s.bind(('fe80::2',68 if int(sys.argv[2])==67 else 0,0,i));s.sendto(b'LOCAL-MULTICAST',(sys.argv[1],int(sys.argv[2]),0,i))",dest,str(port))
    result=capture.stdout.readline().strip();assert result==expected,(mode,dest,result)
    if mode=='ipv6-blocked':assert counters('drop_mode')>0
    print(mode,'fe80::2 ->',dest,result,flush=True)
 # DHCP infrastructure is another existing country-check exception, not a Safety free pass.
 for destination,receiver_pid,sender_pid,source,sport,dport in [('8.8.8.8',router,client,'8.8.8.9',68,67),('8.8.8.9',client,router,'8.8.8.8',67,68)]:
    load('country-blocked')
    receiver=spawn_ns(receiver_pid,"import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],int(sys.argv[2])));s.settimeout(1);print('READY',flush=True);print(s.recv(64).decode(),flush=True)",destination,str(dport));assert receiver.stdout.readline().strip()=='READY'
    in_ns(sender_pid,sys.executable,'-c',"import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],int(sys.argv[2])));s.sendto(b'DHCP-PORT-EXCEPTION',(sys.argv[3],int(sys.argv[4])))",source,str(sport),destination,str(dport))
    assert receiver.stdout.readline().strip()=='DHCP-PORT-EXCEPTION';assert observed()>0
    print('EXISTING EXCEPTION: IPv4 UDP',sport,'->',dport,'infrastructure ports bypass country list',flush=True)
 # Record the existing explicit-open-port exception; do not change its precedence.
 for addr,local in [('8.8.8.9','8.8.8.8'),('2606:4700::2','2606:4700::1')]:
    load('country-open-port')
    receiver=spawn_ns(client,"import socket,sys;s=socket.socket(socket.AF_INET6 if ':'in sys.argv[1]else socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],8084));s.settimeout(1);print('READY',flush=True);print(s.recv(32).decode(),flush=True)",addr)
    assert receiver.stdout.readline().strip()=='READY'
    in_ns(router,sys.executable,'-c',"import socket,sys;s=socket.socket(socket.AF_INET6 if ':'in sys.argv[1]else socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[2],0));s.sendto(b'OPEN-PORT',(sys.argv[1],8084))",addr,local)
    assert receiver.stdout.readline().strip()=='OPEN-PORT';assert observed()>0
    print('EXISTING EXCEPTION:',addr,'explicit router-side open UDP port accepts NEW traffic before country list',flush=True)
 # Existing sessions must re-check after a country policy generation changes.
 peer_code="""import socket,sys
s=socket.create_connection((sys.argv[1],8082),timeout=.6);s.settimeout(.6);print('READY',flush=True)
for line in sys.stdin:
 try:
  if line.strip()=='send':s.sendall(b'PING')
  print(s.recv(4).decode() or 'CLOSED',flush=True)
 except OSError:print('TIMEOUT',flush=True)
"""
 for server,address in zip(servers,['8.8.8.8','2606:4700::1']):
  load('allowed')
  peer=spawn_ns(client,peer_code,address);assert peer.stdout.readline().strip()=='READY';peer.stdin.write('send\n');peer.stdin.flush();assert peer.stdout.readline().strip()=='PING'
  server.stdin.write('count\n');server.stdin.flush();assert server.stdout.readline().strip()=='1'
  load('country-blocked')
  server.stdin.write('push\n');server.stdin.flush();assert server.stdout.readline().strip()=='SENT'
  peer.stdin.write('receive\n');peer.stdin.flush();assert peer.stdout.readline().strip()=='TIMEOUT';assert counters('drop_country')>0 and observed()==0
  peer.stdin.write('send\n');peer.stdin.flush();assert peer.stdout.readline().strip()=='TIMEOUT';assert observed()==0
  server.stdin.write('count\n');server.stdin.flush();assert server.stdout.readline().strip()=='1','outbound payload must not reach the server, not merely lose its reply'
  print(address,'established session: blocked in both directions; no new payload reached the server or post-filter observer',flush=True)
 print('PASS isolated real-packet IPv4/IPv6, country, audit/trust/allow exceptions and established-session cases',flush=True)
finally:
 for p in reversed(children):
    p.terminate()
 for p in reversed(children):
    try:p.wait(timeout=2)
    except subprocess.TimeoutExpired:p.kill();p.wait()
