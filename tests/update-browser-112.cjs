// 1.1.2 update-check regression: final static binary in the private sandbox (no internet, so GitHub
// is unreachable), seeded update-check.json caches, Dashboard/global notice. Optional phase 2 uses
// the cargo TEST build with a local TLS release API named api.github.com (test CA, private mount ns).
const fs=require('fs'),path=require('path'),{spawn,execFileSync}=require('child_process'),assert=require('assert'),puppeteer=require('puppeteer-core');
const ROOT=path.resolve(__dirname,'..'),OUT=process.env.FOILGW_TEST_EVIDENCE||path.join(ROOT,'versions/1.1.2/verification/update-ui');fs.mkdirSync(OUT,{recursive:true});
assert.equal(process.env.FOILGW_ISOLATED_API,'1','run through tests/isolated-api-browser.py');
const BIN=process.env.FOILGW_FINAL_BINARY;assert(BIN,'FOILGW_FINAL_BINARY required');
let log='',api,browser;const report={binary:BIN,cases:{}},failures=[];
const check=(name,ok,detail)=>{report.cases[name]={ok:!!ok,detail};if(!ok)failures.push(name);console.log((ok?'PASS ':'FAIL ')+name+' '+JSON.stringify(detail).slice(0,400));};
const start=(cmd,args,env)=>{const off=log.length;api=spawn(cmd,args,{cwd:ROOT,env:{...process.env,...env},detached:true,stdio:['ignore','pipe','pipe']});for(const s of [api.stdout,api.stderr])s.on('data',b=>log+=b);return off;};
const waitLog=(off,text,ms=300000)=>new Promise((res,rej)=>{const end=Date.now()+ms;const t=setInterval(()=>{if(log.slice(off).includes(text)){clearInterval(t);res()}else if(Date.now()>end||api.exitCode!==null){clearInterval(t);rej(new Error(log.slice(off)))}},50)});
const stop=async()=>{if(api.exitCode===null){process.kill(-api.pid,'SIGTERM');await new Promise(r=>api.once('exit',r));}};
const now=()=>Math.floor(Date.now()/1000);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let p,state;
async function boot(cache){
 fs.rmSync(path.join(state,'update-check.json'),{force:true});if(cache)fs.writeFileSync(path.join(state,'update-check.json'),JSON.stringify(cache));
 const off=start(BIN,['serve'],{FOILGW_STATE:state,FOILGW_CONF:path.join(state,'gateway.conf'),FOILGW_PORT:'18843'});await waitLog(off,'settings page on https:',30000);
 await p.goto('https://127.0.0.1:18843/login',{waitUntil:'networkidle0'});
 assert.equal(await p.evaluate(()=>fetch('/api/login',{method:'POST',headers:{'X-FG':'1','Content-Type':'application/json'},body:JSON.stringify({user:'tester',password:'local-fixture-password'})}).then(r=>r.status)),200);
}
const get=u=>p.evaluate(u=>fetch(u).then(r=>r.json()),u);
const cache=(latest,ago,extra={})=>({last_checked:now()-ago,latest,current:latest,newer:false,published_at:'',notes:'',html_url:'',bin_url:latest==='1.0.1'?'':'https://github.com/x/'+latest,web_url:'',sums_url:'',error:'',...extra});
(async()=>{
 // Fixture state (admin user) from the existing test API server.
 let off=start('cargo',['test','--locked','browser_api_server','--','--ignored','--nocapture'],{FOILGW_TEST_MEASUREMENT:'http://127.0.0.1:18773'});await waitLog(off,'LOCAL_API_READY');
 const fixture=log.slice(off).match(/LOCAL_API_READY (\/tmp\/foilgw-api-test-[^\s]+)/)[1];await stop();
 browser=await puppeteer.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--ignore-certificate-errors','--disable-background-networking']});
 // P: cargo TEST build, real TLS release API fixture (test CA), short checker timings; Dashboard stays open while a release arrives.
 {const https=require('https'),dir='/tmp/fgw-rel-fixture';fs.rmSync(dir,{recursive:true,force:true});fs.mkdirSync(dir);const o=(...a)=>execFileSync('openssl',a,{cwd:dir,stdio:'pipe'});
  o('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','2','-subj','/CN=FoilGateway update test CA');o('req','-newkey','rsa:2048','-nodes','-keyout','k.pem','-out','l.csr','-subj','/CN=localhost');fs.writeFileSync(dir+'/ext','subjectAltName=DNS:localhost\n');o('x509','-req','-in','l.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','c.pem','-days','2','-extfile','ext');o('x509','-in','ca.pem','-outform','der','-out','c.der');
  let tag='v1.1.1',hits=0;const asset=n=>({name:n,browser_download_url:'https://example.invalid/'+n});
  const srv=https.createServer({key:fs.readFileSync(dir+'/k.pem'),cert:fs.readFileSync(dir+'/c.pem')},(q,r)=>{hits++;const b=JSON.stringify({tag_name:tag,body:'n',published_at:'2026-11-08T00:00:00Z',html_url:'https://example.invalid/r',assets:['foilgw-x86_64','foilgw-riscv64','foilgw-web.tar.gz','SHA256SUMS'].map(asset)});r.writeHead(200,{'Content-Type':'application/json'});r.end(b);});
  await new Promise(r=>srv.listen(18774,'127.0.0.1',r));
  const off2=start('cargo',['test','--locked','browser_api_server','--','--ignored','--nocapture'],{FOILGW_TEST_MEASUREMENT:'http://127.0.0.1:18773',FOILGW_TEST_UPDATE_API:'https://localhost:18774/repos/iBgeek/FoilGateway-Network/releases/latest',FOILGW_TEST_UPDATE_CA_DER:dir+'/c.der'});await waitLog(off2,'LOCAL_API_READY');
  const bp=await browser.newPage();await bp.setViewport({width:1440,height:1000,deviceScaleFactor:1});await bp.goto('https://127.0.0.1:18843/login',{waitUntil:'networkidle0'});
  await bp.evaluate(()=>fetch('/api/login',{method:'POST',headers:{'X-FG':'1','Content-Type':'application/json'},body:JSON.stringify({user:'tester',password:'local-fixture-password'})}));
  await bp.goto('https://127.0.0.1:18843/',{waitUntil:'networkidle0'});await sleep(4000);
  const before=await bp.evaluate(()=>!!document.querySelector('#update-notice'));const hitsBefore=hits;
  tag='v9.9.9';let appeared=false;const t0=Date.now();try{await bp.waitForFunction(()=>document.querySelector('#update-notice')?.textContent.includes('9.9.9'),{timeout:20000});appeared=true;}catch{}
  const loads=await bp.evaluate(()=>performance.getEntriesByType('navigation').length);
  const pu=await bp.evaluate(()=>fetch('/api/updates').then(r=>r.json()));check('P1_release_arrives_while_dashboard_open',!before&&appeared&&hitsBefore>=1,{updates:{latest:pu.latest,error:pu.error,progress:pu.progress},noticeBefore:before,appeared,seconds:(Date.now()-t0)/1000,hitsBefore,hits,navigations:loads});
  await bp.screenshot({path:path.join(OUT,'test-build-dashboard-release-arrived.png')});
  const reqsPerPoll=hits;await sleep(3000);check('P2_browser_polls_do_not_call_github',hits-reqsPerPoll<=2,{hitsDuring3s:hits-reqsPerPoll,note:'checker interval 3 s in test build; dashboard polls every few s'});
  await bp.close();await stop();srv.close();}
 state='/tmp/fgw-update-112';fs.rmSync(state,{recursive:true,force:true});fs.mkdirSync(state,{recursive:true});for(const n of ['gateway.conf','policy.json','users.json'])fs.copyFileSync(path.join(fixture,n),path.join(state,n));
 browser=browser||await puppeteer.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--ignore-certificate-errors','--disable-background-networking']});
 p=await browser.newPage();await p.setViewport({width:1440,height:1000,deviceScaleFactor:1});const errors=[];p.on('pageerror',e=>errors.push(e.message));
 // G: final binary, REAL GitHub through a byte relay (no TLS termination): private /etc/hosts maps api.github.com to 127.0.0.1,
 // a 127.0.0.1:443 listener forwards bytes to a Unix socket whose outside end connects only to api.github.com:443.
 if(process.env.FOILGW_GH_RELAY_SOCK){const net=require('net');const sock=process.env.FOILGW_GH_RELAY_SOCK;const relay=net.createServer(c=>{const u=net.connect(sock);c.pipe(u);u.pipe(c);c.on('error',()=>u.destroy());u.on('error',()=>c.destroy());});
  await new Promise(r=>relay.listen(443,'127.0.0.1',r));const hosts='/tmp/fgw-gh-hosts';fs.writeFileSync(hosts,'127.0.0.1 localhost api.github.com\n');execFileSync('mount',['--bind',hosts,'/etc/hosts']);
  const seededG=now()-600;await boot(cache('1.0.1',600));let ug,endG=Date.now()+30000;do{await sleep(500);ug=await get('/api/updates');}while(Date.now()<endG&&ug.last_checked===seededG&&!ug.error);
  const saved=JSON.parse(fs.readFileSync(path.join(state,'update-check.json'),'utf8'));
  await p.goto('https://127.0.0.1:18843/settings/updates',{waitUntil:'networkidle0'});await sleep(2500);const page=await p.$eval('main',e=>e.textContent);await p.screenshot({path:path.join(OUT,'final-real-github-updates.png')});
  check('G_final_binary_real_github_check',ug.last_checked>seededG&&ug.latest==='1.1.1'&&ug.newer===false&&!ug.error&&ug.progress.busy===false&&saved.latest==='1.1.1'&&saved.last_checked===ug.last_checked&&page.includes('Up To Date')&&page.includes('1.1.1'),{latest:ug.latest,newer:ug.newer,current:ug.current,error:ug.error,progress:ug.progress,last_checked:ug.last_checked,seededG,saved:{latest:saved.latest,last_checked:saved.last_checked,bin_url:saved.bin_url,web_url:saved.web_url,sums_url:saved.sums_url},pageHasUpToDate:page.includes('Up To Date')});
  await stop();execFileSync('umount',['/etc/hosts']);relay.close();}
 // A: native-like stale cache (checked 1 h ago by an older build, latest 1.0.1). A fresh check must run after start.
 const seeded=now()-3600;await boot(cache('1.0.1',3600));
 let u,end=Date.now()+15000;do{await sleep(500);u=await get('/api/updates');}while(Date.now()<end&&!(u.error||u.last_checked!==seeded));
 check('A_fresh_check_after_start_despite_recent_cache',u.last_checked!==seeded||!!u.error,{last_checked:u.last_checked,seeded,error:u.error,progress:u.progress});
 // B: GitHub unreachable: busy must clear and the error must be reported.
 check('B_unreachable_clears_busy_and_reports',u.progress&&u.progress.busy===false&&!!(u.error||u.progress.error),{progress:u.progress,error:u.error});
 const manual=await p.evaluate(()=>fetch('/api/updates/check',{method:'POST',headers:{'X-FG':'1','Content-Type':'application/json'},body:'{}'}).then(async r=>({status:r.status,body:await r.text()})));
 u=await get('/api/updates');check('B2_manual_check_after_failure_not_stuck',u.progress&&u.progress.busy===false,{manual,progress:u.progress});
 await stop();
 // C: a known newer release (cache) must stay known after a failed check and show a notice on Dashboard and other pages.
 await boot(cache('9.9.9',600,{newer:true,bin_url:'https://github.com/x/foilgw-x86_64'}));await sleep(4000);
 u=await get('/api/updates');check('C1_failed_check_keeps_known_update',u.newer===true&&u.latest==='9.9.9',{newer:u.newer,latest:u.latest,error:u.error});
 for(const [route,name] of [['/','dashboard'],['/devices','devices'],['/settings','settings']]){
  await p.goto('https://127.0.0.1:18843'+route,{waitUntil:'networkidle0'});await sleep(1500);
  const n=await p.evaluate(()=>{const e=document.querySelector('#update-notice');if(!e)return null;const r=e.getBoundingClientRect();return{text:e.textContent,href:e.querySelector('a')?.getAttribute('href'),visible:r.width>0&&r.height>0,clipped:e.scrollWidth>e.clientWidth+1}});
  check('C2_notice_'+name,n&&n.visible&&n.text.includes('9.9.9')&&n.href==='/settings/updates'&&!n.clipped,n);await p.screenshot({path:path.join(OUT,`notice-${name}-1440.png`)});
 }
 const n=await p.$('#update-notice a');if(n){await Promise.all([p.waitForNavigation({waitUntil:'networkidle0'}),n.click()]);const prog=await get('/api/updates/progress');check('C3_notice_opens_updates_without_install',new URL(p.url()).pathname==='/settings/updates'&&prog.phase!=='Downloading'&&prog.phase!=='Installing',{url:p.url(),prog});}else check('C3_notice_opens_updates_without_install',false,'no notice');
 await p.setViewport({width:390,height:900,deviceScaleFactor:1});await p.goto('https://127.0.0.1:18843/',{waitUntil:'networkidle0'});await sleep(1500);
 const narrow=await p.evaluate(()=>{const e=document.querySelector('#update-notice');return{present:!!e,overflow:document.documentElement.scrollWidth>innerWidth+1,clipped:e?e.scrollWidth>e.clientWidth+1:null}});check('C4_notice_390',narrow.present&&!narrow.overflow&&!narrow.clipped,narrow);await p.screenshot({path:path.join(OUT,'notice-dashboard-390.png')});
 await p.setViewport({width:1440,height:1000,deviceScaleFactor:1});
 // D: rollback/version change: cache written by a newer build (current 9.9.9, latest 9.9.9) -> this older build must report it as available.
 await stop();await boot(cache('9.9.9',60,{current:'9.9.9',newer:false,bin_url:'https://github.com/x/foilgw-x86_64'}));u=await get('/api/updates');check('D_rollback_recomputes_newer',u.newer===true,{newer:u.newer,latest:u.latest,current:u.current});
 // F: the new notice data (status on every page) must not confirm a pending install. Dashboard and Updates already confirmed it
 // before 1.1.2 (web.rs dashboard_view and updates_status call ack_pending); that is unchanged and not tested as new.
 const pend=path.join(state,'update-pending.json');fs.writeFileSync(pend,JSON.stringify({from:'1.1.1',to:'9.9.9',deadline:now()+3600}));
 await p.goto('https://127.0.0.1:18843/devices',{waitUntil:'networkidle0'});await sleep(6000);const kept=fs.existsSync(pend);
 await p.goto('https://127.0.0.1:18843/settings/updates',{waitUntil:'networkidle0'});await sleep(3000);check('F_notice_pages_do_not_ack_pending_updates_page_does',kept&&!fs.existsSync(pend),{keptAfterDashboard:kept,afterUpdatesPage:fs.existsSync(pend)});
 // E: unauthenticated mutation refused.
 const anon=await browser.createBrowserContext();const q=await anon.newPage();await q.goto('https://127.0.0.1:18843/login',{waitUntil:'networkidle0'});
 const unauth=await q.evaluate(async()=>({check:(await fetch('/api/updates/check',{method:'POST',headers:{'X-FG':'1','Content-Type':'application/json'},body:'{}'})).status,install:(await fetch('/api/updates/install',{method:'POST',headers:{'X-FG':'1','Content-Type':'application/json'},body:'{}'})).status}));check('E_unauthenticated_refused',unauth.check===401&&unauth.install===401,unauth);await anon.close();
 const pid=api.pid;report.resources={children:fs.readdirSync(`/proc/${pid}/task`).map(t=>fs.readFileSync(`/proc/${pid}/task/${t}/children`,'utf8').trim()).join(''),threads:Number(fs.readFileSync(`/proc/${pid}/status`,'utf8').match(/^Threads:\s+(\d+)/m)[1])};
 await stop();
 report.pageErrors=errors;report.failures=failures;fs.writeFileSync(path.join(OUT,'update-report-'+path.basename(path.dirname(BIN))+'.json'),JSON.stringify(report,null,2));
 await browser.close();console.log(failures.length?'FAIL '+failures.join(','):'PASS update-browser-112');process.exit(failures.length?1:0);
})().catch(async e=>{console.error('FAIL',e);try{await browser?.close()}catch{}try{process.kill(-api.pid,'SIGKILL')}catch{}process.exit(2)});
