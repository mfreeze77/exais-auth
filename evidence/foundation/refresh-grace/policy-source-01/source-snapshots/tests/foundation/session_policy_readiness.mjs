/** Actual Node application and three actual Core configurations in an owned DB.
 * Proxy transports real responses, or fails the transport. No fabricated auth,
 * readiness, protocol or capability responses are used.
 */
import http from 'node:http';
import {spawn} from 'node:child_process';
import {createHash, randomUUID} from 'node:crypto';
import {readFile, writeFile} from 'node:fs/promises';
import {createInterface} from 'node:readline';
import {once} from 'node:events';

const output=process.env.EVIDENCE_DIR, key=process.env.EXPERTAUTH_CORE_API_KEY;
const origin=process.env.EXPERTAUTH_PUBLIC_ORIGIN;
const hosts=['A','B','C'].map(name=>process.env['GRACE_CORE_'+name]);
if(!output || !key || !hosts.every((host,i)=>new RegExp(`^expertauth-reset-core-${'abc'[i]}-[a-f0-9]+$`).test(host))) throw Error('Disposable lab required');
const rows=[],wire=[],users=new Set(),logs={stdout:'',stderr:''};
const started=new Date().toISOString(), delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
let target=0, unavailable=false, app, session, fatal=false;
const input=createInterface({input:process.stdin});
class CheckError extends Error {}
function need(value,message){if(!value)throw new CheckError(message);}
async function check(id,action){
 try{rows.push({id,outcome:'passed',requirements:['SES-003','SES-004','SES-006'],...await action()});}
 catch(error){rows.push({id,outcome:'failed',error:error instanceof CheckError?error.message:error.name});}
 console.log(JSON.stringify({check:id,outcome:rows.at(-1).outcome}));
}
const proxy=http.createServer((request,response)=>{
 const entry={method:request.method,path:new URL(request.url,'http://proxy').pathname,replica:target,cdi:request.headers['cdi-version']??null};wire.push(entry);
 if(unavailable){entry.transport_error=true;request.resume();response.destroy();return;}
 const upstream=http.request({host:hosts[target],port:3567,path:request.url,method:request.method,
  headers:{...request.headers,host:`${hosts[target]}:3567`}},incoming=>{
   entry.http=incoming.statusCode;response.writeHead(incoming.statusCode,incoming.headers);incoming.pipe(response);
   incoming.on('error',()=>response.destroy());
  });
 upstream.setTimeout(5000,()=>upstream.destroy());upstream.on('error',()=>{entry.transport_error=true;response.destroy();});
 request.on('error',()=>upstream.destroy());request.pipe(upstream);
});
async function direct(i,path,body,authorized=true){
 const response=await fetch(`http://${hosts[i]}:3567${path}`,{method:body?'POST':'GET',redirect:'error',
  headers:{...(authorized?{'api-key':key}:{}),'cdi-version':'5.4',rid:'session','content-type':'application/json'},
  ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(5000)});
 const text=await response.text();let value;try{value=JSON.parse(text);}catch{value={};}
 return {http:response.status,body:value};
}
async function call(path,{token,body,method,rid='session'}={}){
 const response=await fetch('http://127.0.0.1:3000'+path,{method:method??(body||path.toLowerCase().startsWith('/auth/')?'POST':'GET'),
  headers:{origin,'content-type':'application/json','fdi-version':'4.2',rid,'st-auth-mode':'header',...(token?{authorization:`Bearer ${token}`}:{})},
  ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(8000)});
 return {http:response.status,body:await response.json(),access:response.headers.get('st-access-token'),refresh:response.headers.get('st-refresh-token')};
}
const email=`policy-${randomUUID()}@example.test`,password=`Synthetic-${randomUUID()}-9a!`;
const credentials={formFields:[{id:'email',value:email},{id:'password',value:password}]};
async function deniedProfile(index,drop=false){
 target=index;unavailable=drop;
 need((await call('/health/live')).http===200&&(await call('/health/ready')).http===503,'Mismatch readiness/liveness incorrect');
 const before=wire.length;
 const attempts=[['/auth/signup',{body:credentials,rid:'emailpassword'}],['/auth/signin',{body:credentials,rid:'emailpassword'}],
  ['/auth/session/refresh',{token:session.refresh}],['/auth/signout',{token:session.access}],
  ['/api/session/online',{token:session.access}],['/api/session',{token:session.access}],
  ['/api/tenants/public/session',{token:session.access}],['/AUTH/SIGNIN/',{body:credentials,rid:'emailpassword'}]];
 for(const [path,args] of attempts){const r=await call(path,args);need(r.http===503&&r.body.error==='SESSION_POLICY_UNAVAILABLE'&&!r.access&&!r.refresh,'Mismatched request reached authentication');}
 const observed=wire.slice(before);
 need(observed.length>=attempts.length&&observed.every(r=>r.method==='GET'&&r.path==='/public/expertauth/password/session'),'Rejected profile made a business request');
 // Offline verification remains an explicit signature/claim-only boundary.
 need((await call('/api/session/offline',{token:session.access})).http===200,'Offline contract changed');
 return {ready_http:503,live_http:200,rejected_requests:attempts.length,business_requests:0,offline_jwt_http:200,replica:index,transport_dropped:drop};
}
try{
 for(let i=0;i<hosts.length;i++){
  let ready=false;
  for(let n=0;n<45;n++){try{ready=(await direct(i,'/users/count')).http===200;}catch{}if(ready)break;await delay(500);}
  need(ready,'Actual Core storage unavailable');
 }
 await new Promise(resolve=>proxy.listen(3101,'127.0.0.1',resolve));
 app=spawn(process.execPath,['/app/server.js'],{env:{...process.env,EXPERTAUTH_CORE_URL:'http://127.0.0.1:3101',
  EXPERTAUTH_RESET_POLICY:'atomic-v1',EXPERTAUTH_SESSION_POLICY:'core-cdi56-grace-v1'},stdio:['ignore','pipe','pipe']});
 for(const stream of ['stdout','stderr'])app[stream].on('data',bytes=>{if(logs[stream].length<65536)logs[stream]+=bytes.toString().slice(0,65536-logs[stream].length);});
 let live=false;
 for(let n=0;n<40;n++){need(app.exitCode===null,'App exited at startup');try{live=(await call('/health/live')).http===200;}catch{}if(live)break;await delay(250);}
 need(live,'App never became live');
 const answer=once(input,'line');console.log(JSON.stringify({control:'policy_started'}));
 let timer;try{const [line]=await Promise.race([answer,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Host inspection timeout')),30000);})]);need(JSON.parse(line).ok,'Host inspection failed');}finally{clearTimeout(timer);}
 await check('POLICY56-EFFECTIVE-PRIVATE-SETTINGS',async()=>{
  const settings=[];
  for(let i=0;i<3;i++){
   const r=await direct(i,'/public/expertauth/password/session');
   need(r.http===200&&r.body.status==='OK'&&r.body.policy==='EXPERTAUTH-PASSWORD-SESSION-1','Private capability missing');
   const effective=r.body.sessionPolicy;
   need(effective.refreshTokenRotationGracePeriodSeconds===[5,0,5][i]&&effective.recentTokenReuseBehaviour===(i===2?'UNAUTHORISED':'TOKEN_THEFT'),'Effective settings differ from installed config');
   need((await direct(i,'/public/expertauth/password/session',undefined,false)).http===401,'Capability exposed without key');
   const versions=await direct(i,'/apiversion');need(versions.http===200&&versions.body.versions.includes('5.6'),'CDI5.6 not actually advertised');
   settings.push(effective);
  }
  return {settings,all_advertise_cdi56:true,unauthenticated_http:401};
 });
 await check('POLICY56-HEALTHY-AUTHENTICATION',async()=>{
  need((await call('/health/ready')).http===200,'Correct policy not ready');
  session=await call('/auth/signup',{body:credentials,rid:'emailpassword'});
  if(session.body.status==='OK'&&session.body.user?.id)users.add(session.body.user.id);
  need(session.http===200&&session.body.status==='OK'&&session.refresh&&session.access,'Signup failed');
  const refreshed=await call('/auth/session/refresh',{token:session.refresh});need(refreshed.http===200&&refreshed.refresh,'Healthy refresh failed');session=refreshed;
  need((await call('/api/session/online',{token:session.access})).http===200,'Healthy online session failed');
  need((await call('/api/session/offline',{token:session.access})).http===200,'Offline fixture invalid');
  return {ready_http:200,signup_http:200,refresh_http:200,online_http:200};
 });
 need(session?.refresh,'No valid session for negative policy cases');
 await check('POLICY56-ZERO-GRACE-REJECTED',()=>deniedProfile(1));
 await check('POLICY56-REUSE-BEHAVIOUR-REJECTED',()=>deniedProfile(2));
 await check('POLICY56-UNAVAILABLE-REJECTED',()=>deniedProfile(0,true));
 await check('POLICY56-CONCURRENT-MISMATCH-REJECTED',async()=>{
  target=1;unavailable=false;const before=wire.length;
  const results=await Promise.all(Array.from({length:8},(_,i)=>call(i%2?'/api/session/online':'/auth/session/refresh',{token:i%2?session.access:session.refresh})));
  need(results.every(r=>r.http===503&&r.body.error==='SESSION_POLICY_UNAVAILABLE'&&!r.refresh&&!r.access),'Concurrent mismatch issued credentials');
  need(wire.slice(before).length===8&&wire.slice(before).every(r=>r.path==='/public/expertauth/password/session'&&r.method==='GET'),'Concurrent mismatch reached business API');
  return {concurrent_requests:8,http_statuses:results.map(r=>r.http),business_requests:0};
 });
 await check('POLICY56-RECOVERY-WITHOUT-APP-RESTART',async()=>{
  target=0;unavailable=false;need(app.exitCode===null&&(await call('/health/ready')).http===200,'Recovery not ready');
  const r=await call('/auth/session/refresh',{token:session.refresh});need(r.http===200&&r.refresh,'Denied requests changed valid session');
  need((await call('/api/session/online',{token:r.access})).http===200,'Recovered session denied');
  const count=await direct(0,'/users/count');need(count.http===200&&count.body.count===1,'Rejected signup created identity');
  return {ready_http:200,refresh_http:200,online_http:200,app_restarted:false,owned_database_users:1};
 });
}catch(error){fatal=true;rows.push({id:'POLICY56-HARNESS',outcome:'failed',error:error instanceof CheckError?error.message:error.name});}
finally{
 target=0;unavailable=false;
 await check('POLICY56-OWNED-FIXTURE-CLEANUP',async()=>{
  for(const userId of users){const r=await direct(0,'/user/remove',{userId,removeAllLinkedAccounts:false});need(r.http===200&&r.body.status==='OK','Owned user cleanup failed');}
  need((await direct(0,'/users/count')).body.count===0,'Owned database not empty');
  return {owned_users_removed:users.size,source_database_contacted:false};
 });
 if(app&&app.exitCode===null){app.kill('SIGTERM');await Promise.race([once(app,'exit'),delay(2000)]);if(app.exitCode===null)app.kill('SIGKILL');}
 proxy.closeAllConnections();if(proxy.listening)await new Promise(resolve=>proxy.close(resolve));input.close();
 await writeFile('/private/app-output.json',JSON.stringify(logs),{flag:'wx'});
 const inputs={};for(const name of ['server.js','client.jsx','package-lock.json'])inputs[name]=hash(await readFile('/app/'+name));
 const report={kind:'actual-session-policy-readiness',started,finished:new Date().toISOString(),rows,wire,inputs,fatal,
  failed:rows.filter(r=>r.outcome!=='passed').length,skipped:0,foundation_passed:false,complete:false,independent_human_review:false,
  limitations:['Preflight is not atomic with a later Core operation; heterogeneous load-balancer configurations remain unqualified.','One public tenant; full configured tenant/provider/native profiles remain blocked.']};
 await writeFile(output+'/policy-results.json',JSON.stringify(report,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({rows:rows.length,failed:report.failed,fatal}));process.exitCode=report.failed||fatal?1:0;
}
