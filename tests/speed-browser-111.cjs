// 1.1.1 speed-test measurement correction: real Rust API routes (test build, loopback-only
// paced endpoint) and the final static binary's Settings page, inside the private sandbox.
const fs=require('fs'),path=require('path'),http=require('http'),{spawn}=require('child_process'),assert=require('assert'),puppeteer=require('puppeteer-core');
const ROOT=path.resolve(__dirname,'..'),OUT=process.env.FOILGW_TEST_EVIDENCE||path.join(ROOT,'versions/1.1.1/verification/api-ui');fs.mkdirSync(OUT,{recursive:true});
assert.equal(process.env.FOILGW_ISOLATED_API,'1','run through tests/isolated-api-browser.py');
// Paced endpoint: 150 ms before every response's first byte, then 20 KB/s in 512-byte chunks.
let mode='success',downloadBytes=0,uploadBytes=0,serverLog='',api,browser;const report={};
const TTFB=150,RATE=20000;
const measurement=http.createServer((req,res)=>{
 if(mode==='fail'){res.writeHead(503);return res.end();}
 if(req.method==='POST'){let n=0;req.on('data',c=>n+=c.length);req.on('end',()=>{uploadBytes+=n;assert(n<=4096);setTimeout(()=>{res.writeHead(200,{'Content-Length':0});res.end();},TTFB);});return;}
 const n=Number(new URL(req.url,'http://localhost').searchParams.get('bytes'));assert(n<=8192,'download cap');
 setTimeout(()=>{if(req.destroyed)return;res.writeHead(200,{'Content-Length':n});let sent=0;const t0=Date.now();
  const tick=()=>{if(sent>=n)return res.end();const k=Math.min(512,n-sent);res.write(Buffer.alloc(k,7));sent+=k;downloadBytes+=k;const due=t0+sent/RATE*1000;timer=setTimeout(tick,Math.max(0,due-Date.now()));};
  let timer=setTimeout(tick,0);res.on('close',()=>clearTimeout(timer));},mode==='slowdl'&&n>0?2000:TTFB);
});
const waitLog=(offset,text,ms=60000)=>new Promise((resolve,reject)=>{const end=Date.now()+ms;const t=setInterval(()=>{if(serverLog.slice(offset).includes(text)){clearInterval(t);resolve()}else if(Date.now()>end||api.exitCode!==null){clearInterval(t);reject(new Error(serverLog.slice(offset)))}},50)});
const start=(cmd,args,env)=>{api=spawn(cmd,args,{cwd:ROOT,env:{...process.env,...env},detached:true,stdio:['ignore','pipe','pipe']});for(const s of [api.stdout,api.stderr])s.on('data',b=>serverLog+=b);};
const stop=async()=>{process.kill(-api.pid,'SIGTERM');await new Promise(r=>api.exitCode!==null?r():api.once('exit',r));};

const rustPidOf=pid=>{const c=fs.readFileSync(`/proc/${pid}/task/${pid}/children`,'utf8').trim();return c?Number(c.split(/\s+/)[0]):pid;};
const kids=pid=>fs.readdirSync(`/proc/${pid}/task`).map(t=>fs.readFileSync(`/proc/${pid}/task/${t}/children`,'utf8').trim()).join(' ').trim();
async function finalTransfer(p,read,pid){
 const https=require('https'),{execFileSync}=require('child_process'),dir='/tmp/fgw-cf-fixture';fs.mkdirSync(dir,{recursive:true});
 const o=(...a)=>execFileSync('openssl',a,{cwd:dir,stdio:'pipe'});
 o('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','2','-subj','/CN=FoilGateway test CA');
 o('req','-newkey','rsa:2048','-nodes','-keyout','leaf.key','-out','leaf.csr','-subj','/CN=speed.cloudflare.com');
 fs.writeFileSync(path.join(dir,'ext'),'subjectAltName=DNS:speed.cloudflare.com\n');
 o('x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','leaf.pem','-days','2','-extfile','ext');
 // Name only resolves inside this private mount namespace; private net namespace has no route out.
 fs.writeFileSync(path.join(dir,'hosts'),'127.0.0.1 localhost speed.cloudflare.com\n');execFileSync('mount',['--bind',path.join(dir,'hosts'),'/etc/hosts']);
 const routes=execFileSync('ip',['route','show','table','all']).toString();
 const DOWN=2_000_000,UP=1_000_000,REPLY=40;let fmode='ok',down=0,up=0,maxReq=0;
 const srv=https.createServer({key:fs.readFileSync(path.join(dir,'leaf.key')),cert:fs.readFileSync(path.join(dir,'leaf.pem'))},(req,res)=>{
  if(fmode==='fail'){res.writeHead(503);return res.end();}
  if(req.method==='POST'){let n=0;const t0=Date.now();req.on('data',c=>{n+=c.length;up+=c.length;const ahead=t0+n/UP*1000-Date.now();if(ahead>0){req.pause();setTimeout(()=>req.resume(),ahead);}});req.on('end',()=>setTimeout(()=>{res.writeHead(200,{'Content-Length':0});res.end();},REPLY));return;}
  const n=Number(new URL(req.url,'https://x').searchParams.get('bytes'));maxReq=Math.max(maxReq,n);
  setTimeout(()=>{res.writeHead(200,{'Content-Length':n});let sent=0;const t0=Date.now();let timer;
   const tick=()=>{if(sent>=n||res.destroyed)return res.end();const k=Math.min(16384,n-sent);res.write(Buffer.alloc(k,7));sent+=k;down+=k;timer=setTimeout(tick,Math.max(0,t0+sent/DOWN*1000-Date.now()));};
   timer=setTimeout(tick,0);res.on('close',()=>clearTimeout(timer));},REPLY);});
 await new Promise(r=>srv.listen(443,'127.0.0.1',r));
 const post=a=>p.evaluate(a=>fetch('/api/speed-test',{method:'POST',headers:{'X-FG':'1','Content-Type':'application/json'},body:JSON.stringify({action:a})}).then(r=>r.status),a);
 const until=async(f,ms)=>{const end=Date.now()+ms;while(Date.now()<end){const r=await read();if(f(r))return r;await new Promise(r=>setTimeout(r,100));}throw new Error('timeout '+JSON.stringify(await read()));};
 const out={routes,downRate:DOWN,upRate:UP,replyDelayMs:REPLY,before:{children:kids(pid),fds:fs.readdirSync(`/proc/${pid}/fd`).length}};
 const t0=Date.now();assert.equal(await post('run'),200);const done=await until(r=>!r.running,45000);out.success={state:done.state,error:done.error,last:done.last,seconds:(Date.now()-t0)/1000,downBytes:down,upBytes:up,maxDownloadRequest:maxReq};
 assert.equal(done.state,'complete',JSON.stringify(done));assert.equal(maxReq,64*1024*1024,'production download cap requested');assert(down<20*1024*1024,'time window, not the cap, ended download');assert(up<=16*1024*1024);
 out.success.downRatio=done.last.download_mbps/(DOWN*8/1e6);out.success.upRatio=done.last.upload_mbps/(UP*8/1e6);
 assert(out.success.downRatio>0.75&&out.success.downRatio<1.25,'down '+out.success.downRatio);assert(out.success.upRatio>0.75&&out.success.upRatio<1.25,'up '+out.success.upRatio);
 await p.reload({waitUntil:'networkidle0'});await p.waitForFunction(()=>document.querySelector('#internet-speed-test').textContent.includes('Last run:'));await p.$eval('#internet-speed-test',e=>e.scrollIntoView());await p.screenshot({path:path.join(OUT,'final-static-transfer-complete.png')});
 down=0;assert.equal(await post('run'),200);const mid=await until(r=>r.phase==='Download'&&down>0,15000);out.cancel={midProgress:mid.progress,childrenDuring:kids(pid)};assert(out.cancel.childrenDuring,'curl visible during download');
 assert.equal(await post('cancel'),200);const c=await until(r=>!r.running,5000);await new Promise(r=>setTimeout(r,200));out.cancel.state=c.state;out.cancel.childrenAfter=kids(pid);out.cancel.lastKept=c.last&&c.last.at===done.last.at;assert.equal(c.state,'cancelled');assert.equal(out.cancel.childrenAfter,'');
 fmode='fail';assert.equal(await post('run'),200);const f=await until(r=>!r.running,15000);out.failure={state:f.state,error:f.error,lastKept:f.last&&f.last.at===done.last.at,childrenAfter:kids(pid)};assert.equal(f.state,'failed');assert.equal(out.failure.childrenAfter,'');
 await new Promise(r=>setTimeout(r,200));out.after={children:kids(pid),fds:fs.readdirSync(`/proc/${pid}/fd`).length};
 srv.close();execFileSync('umount',['/etc/hosts']);return out;
}
(async()=>{
 await new Promise(r=>measurement.listen(18773,'127.0.0.1',r));
 start('cargo',['test','--locked','browser_api_server','--','--ignored','--nocapture'],{FOILGW_TEST_MEASUREMENT:'http://127.0.0.1:18773'});await waitLog(0,'LOCAL_API_READY',300000);
 browser=await puppeteer.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox','--ignore-certificate-errors','--disable-background-networking']});
 const p=await browser.newPage();const errors=[];p.on('pageerror',e=>errors.push(e.message));await p.setViewport({width:1440,height:1000,deviceScaleFactor:1});
 await p.goto('https://127.0.0.1:18843/login',{waitUntil:'networkidle0'});
 assert.equal(await p.evaluate(()=>fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-FG':'1'},body:JSON.stringify({user:'tester',password:'local-fixture-password'})}).then(r=>r.status)),200);
 await p.goto('https://127.0.0.1:18843/settings',{waitUntil:'networkidle0'});await p.waitForSelector('#speed-test-action');
 const read=()=>p.evaluate(()=>fetch('/api/speed-test').then(r=>r.json()));
 const waitState=async(state,ms=12000)=>{const end=Date.now()+ms;while(Date.now()<end){const r=await read();if(r.state===state&&!r.running)return r;await new Promise(r=>setTimeout(r,50));}throw new Error('state '+state+': '+JSON.stringify(await read()));};
 const rustPid=Number(fs.readFileSync(`/proc/${api.pid}/task/${api.pid}/children`,'utf8').trim().split(/\s+/)[0]);
 const resources=()=>({threads:Number(fs.readFileSync(`/proc/${rustPid}/status`,'utf8').match(/^Threads:\s+(\d+)/m)[1]),fds:fs.readdirSync(`/proc/${rustPid}/fd`).length,children:fs.readdirSync(`/proc/${rustPid}/task`).map(t=>fs.readFileSync(`/proc/${rustPid}/task/${t}/children`,'utf8').trim()).join('')});const before=resources();
 // Run, duplicate start, progress during Download, Cancel.
 mode='slowdl';await p.click('#speed-test-action');assert.equal((await read()).running,true);
 assert.equal(await p.evaluate(()=>fetch('/api/speed-test',{method:'POST',headers:{'X-FG':'1','Content-Type':'application/json'},body:JSON.stringify({action:'run'})}).then(r=>r.status)),409);
 await p.waitForFunction(()=>document.querySelector('#speed-test-action').textContent==='Cancel'&&document.querySelector('#internet-speed-test').textContent.includes('Download ·')&&document.querySelector('#internet-speed-test progress').value>=10,{timeout:10000});
 report.running=await read();await p.screenshot({path:path.join(OUT,'speed-running-1440.png')});
 await p.click('#speed-test-action');const cancelled=await waitState('cancelled');assert.equal(cancelled.last,null);mode='success';
 await p.waitForFunction(()=>document.querySelector('#internet-speed-test').textContent.includes('Test cancelled'));await p.screenshot({path:path.join(OUT,'speed-cancelled-1440.png')});
 // Complete with a slow first byte: download must reflect the paced rate, not setup.
 downloadBytes=0;await p.click('#speed-test-action');const complete=await waitState('complete');report.complete=complete;report.completeDownloadBytes=downloadBytes;
 const ratio=complete.last.download_mbps/(RATE*8/1e6);report.ratio=ratio;assert(ratio>0.75&&ratio<1.25,'download ratio '+ratio);
 assert(complete.last.latency_ms>=TTFB-10&&complete.last.latency_ms<TTFB+250,'HTTP response latency '+complete.last.latency_ms);
 await p.waitForFunction(()=>document.querySelector('#internet-speed-test').textContent.includes('Last run:'));
 const panel=await p.$eval('#internet-speed-test',e=>e.textContent);report.panelText=panel;assert(panel.includes('HTTP response latency'));assert(!/HTTP latency/.test(panel));
 await p.screenshot({path:path.join(OUT,'speed-complete-1440.png')});
 // Failure keeps the last completed result.
 mode='fail';await p.click('#speed-test-action');const failed=await waitState('failed');assert.equal(failed.last.at,complete.last.at);await p.waitForFunction(()=>document.querySelector('#internet-speed-test').textContent.includes('Test failed'));
 mode='success';await p.screenshot({path:path.join(OUT,'speed-failed-1440.png')});
 await new Promise(r=>setTimeout(r,200));const after=resources();report.resources={before,after};
 assert.equal(after.children,'','curl must be reaped');assert(after.threads<=before.threads+1,'worker threads must finish');assert(after.fds<=before.fds+2,'pipes must close');
 // Minimum supported width.
 await p.setViewport({width:390,height:900,deviceScaleFactor:1});await p.reload({waitUntil:'networkidle0'});await p.waitForFunction(()=>document.querySelector('#internet-speed-test').textContent.includes('HTTP response latency'));
 const narrow=await p.evaluate(()=>{const r=document.querySelector('#internet-speed-test');const b=r.getBoundingClientRect();return{horizontal:document.documentElement.scrollWidth>innerWidth+1,panelRight:b.right,width:innerWidth,clipped:[...r.querySelectorAll('div,span,button')].filter(e=>e.scrollWidth>e.clientWidth+1&&getComputedStyle(e).overflow!=='visible').length}});report.narrow=narrow;assert(!narrow.horizontal&&narrow.panelRight<=narrow.width+1);
 await p.$eval('#internet-speed-test',e=>e.scrollIntoView());await p.screenshot({path:path.join(OUT,'speed-complete-390.png')});
 const fixtureState=serverLog.match(/LOCAL_API_READY (\/tmp\/foilgw-api-test-[^\s]+)/)?.[1];assert(fixtureState);await stop();
 // Final static artifact: page renders the corrected labels. Run is NOT clicked (it would contact the public endpoint).
 if(process.env.FOILGW_FINAL_BINARY){
  const st='/tmp/fgw-final-111';fs.mkdirSync(st,{recursive:true});for(const n of ['gateway.conf','policy.json','users.json'])fs.copyFileSync(path.join(fixtureState,n),path.join(st,n));
  const off=serverLog.length;start(process.env.FOILGW_FINAL_BINARY,['serve'],{FOILGW_STATE:st,FOILGW_CONF:path.join(st,'gateway.conf'),FOILGW_PORT:'18843',CURL_CA_BUNDLE:'/tmp/fgw-cf-fixture/ca.pem'});await waitLog(off,'settings page on https:');
  const v=await (await p.goto('https://127.0.0.1:18843/api/version').catch(()=>null));report.finalBinary=process.env.FOILGW_FINAL_BINARY;
  for(const width of [1440,390]){await p.setViewport({width,height:1000,deviceScaleFactor:1});await p.goto('https://127.0.0.1:18843/login',{waitUntil:'networkidle0'});assert.equal(await p.evaluate(()=>fetch('/api/login',{method:'POST',headers:{'X-FG':'1','Content-Type':'application/json'},body:JSON.stringify({user:'tester',password:'local-fixture-password'})}).then(r=>r.status)),200);
   await p.goto('https://127.0.0.1:18843/settings',{waitUntil:'networkidle0'});await p.waitForFunction(()=>document.querySelector('#internet-speed-test')&&document.querySelector('#internet-speed-test').textContent.includes('HTTP response latency'));
   assert.equal(await p.$eval('#speed-test-action',e=>e.textContent),'Run speed test');const s=await read();assert.equal(s.state,'idle');
   const b=await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);assert(!b);await p.$eval('#internet-speed-test',e=>e.scrollIntoView());await p.screenshot({path:path.join(OUT,`final-static-settings-${width}.png`)});}
  // Packaged/embedded Help: the supported route is /s/manual.html (+ /s/help/bundle.json).
  for(const route of ['/s/manual.html','/s/help/bundle.json']){const r=await p.evaluate(u=>fetch(u).then(async r=>({status:r.status,text:await r.text()})),route);report['finalHelp '+route]={status:r.status,mentions:r.text.includes('HTTP response latency')};assert.equal(r.status,200);assert(r.text.includes('HTTP response latency'),route);}
  // Final static transfer at production limits against a private HTTPS fixture named speed.cloudflare.com.
  const ft=await finalTransfer(p,read,rustPidOf(api.pid));report.finalTransfer=ft;
  await stop();
 }
 report.pageErrors=errors;assert.deepEqual(errors,[]);fs.writeFileSync(path.join(OUT,'speed-111-report.json'),JSON.stringify(report,null,2));
 console.log('PASS speed-browser-111',JSON.stringify({ratio:report.ratio,latency:report.complete.last.latency_ms,download_mbps:report.complete.last.download_mbps}));
 await browser.close();measurement.close();
})().catch(async e=>{console.error('FAIL',e);try{await browser?.close()}catch{}try{process.kill(-api.pid,'SIGKILL')}catch{}process.exit(1)});
