/* SSL Checker app JS (offline, vendored). Depends on ../js/lucide.min.js (optional — UI works without it). */
(function(){
"use strict";
var csrf=document.querySelector('meta[name="csrf-token"]').getAttribute('content');
var DISP_TZ=((document.querySelector('meta[name="display-tz"]')||{}).content||'UTC');var TZ_LABEL=((document.querySelector('meta[name="tz-label"]')||{}).content||DISP_TZ);
function fmtDT(iso){try{var d=new Date(iso);if(isNaN(d))return '—';var p=new Intl.DateTimeFormat('en-CA',{timeZone:DISP_TZ,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}).formatToParts(d);var o={};p.forEach(function(x){o[x.type]=x.value;});if(o.hour==='24')o.hour='00';return o.year+'-'+o.month+'-'+o.day+' '+o.hour+':'+o.minute;}catch(_){return String(iso||'').slice(0,16).replace('T',' ');}}
var cache={results:[],summary:null,checked_at:null};
var sortKey='days',sortDir=1;
var certPage=1,certPerPage=20,dbPage=1,dbPerPage=20,dbFull=[],dbView=[];
function $(id){return document.getElementById(id);}
function icons(){try{if(window.lucide&&lucide.createIcons)lucide.createIcons();}catch(_){}}
/* Nepal Standard Time (UTC+5:45, no DST): every human-readable export uses NPT wall time. */
function fmtNPT(iso){try{var d=new Date(iso);if(isNaN(d))return '';var p=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Kathmandu',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}).formatToParts(d);var o={};p.forEach(function(x){o[x.type]=x.value;});if(o.hour==='24')o.hour='00';return o.year+'-'+o.month+'-'+o.day+' '+o.hour+':'+o.minute;}catch(_){return '';}}
function nptIso(iso){try{var d=new Date(iso);if(isNaN(d))return iso;var p=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Kathmandu',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).formatToParts(d);var o={};p.forEach(function(x){o[x.type]=x.value;});if(o.hour==='24')o.hour='00';return o.year+'-'+o.month+'-'+o.day+'T'+o.hour+':'+o.minute+':'+o.second+'+05:45';}catch(_){return iso;}}
function setPager(prefix,page,pages,total,perPage){var info=$(prefix+'PageInfo');if(info){var rng=perPage===Infinity?('All '+total+' rows'):('Rows '+(total?((page-1)*perPage+1):0)+'–'+Math.min(page*perPage,total)+' of '+total);info.textContent=rng+' · Page '+page+' of '+pages;}var pv=$(prefix+'Prev'),nx=$(prefix+'Next');if(pv)pv.disabled=page<=1;if(nx)nx.disabled=page>=pages;}
function perPageVal(sel,fallback){var v=$(sel)?$(sel).value:'';return v==='all'?Infinity:(parseInt(v,10)||fallback||20);}
function applyTheme(t){if(t!=='dark'&&t!=='light')t='dark';document.documentElement.setAttribute('data-theme',t);try{localStorage.setItem('ssl-theme',t);}catch(_){}
var b=$('btnTheme');if(b){b.textContent='';var ic=document.createElement('i');ic.setAttribute('data-lucide',t==='dark'?'sun':'moon');b.appendChild(ic);var lb=document.createElement('span');lb.textContent=t==='dark'?'Light':'Dark';b.appendChild(lb);}icons();}
window.addEventListener('error',function(ev){try{var m='JS error: '+(ev.message||'unknown');var e=document.getElementById('errbox');if(e){e.style.display='block';e.textContent=m;}toast(m);}catch(_){}});
function toast(m){var d=document.createElement('div');d.textContent=m;$('toast').appendChild(d);setTimeout(function(){d.remove();},4200);}
function esc(s){return String(s==null?'':s);}
function setStats(s){if(!s)s={total:0,ok:0,warning:0,critical:0,expired:0,failed:0};
$('sTotal').textContent=s.total;$('sOk').textContent=s.ok;$('sWarn').textContent=s.warning;
$('sCrit').textContent=s.critical;$('sExp').textContent=s.expired;$('sFail').textContent=s.failed;}
function badge(st){var s=document.createElement('span');s.className='badge '+String(st).toLowerCase();s.textContent=st;return s;}
function domainCell(text){var td=document.createElement('td');td.className='mono';var s=String(text==null?'':text);if(s.length>=25){td.textContent=s.slice(0,25)+'…';td.title=s;}else td.textContent=s;return td;}
function val(r,k){if(k==='domain')return r.domain;if(k==='port')return r.port;if(k==='expires')return r.expires_on||'';if(k==='days')return r.days_remaining==null?1e9:r.days_remaining;if(k==='status')return r.status;return '';}
function filtered(){var q=$('q').value.toLowerCase(),f=$('fStatus').value;
var rows=cache.results.filter(function(r){return r.success;});
if(f)rows=rows.filter(function(r){return r.status===f;});
if(q)rows=rows.filter(function(r){var hay=(r.domain+' '+(r.issuer||'')+' '+(r.note||'')).toLowerCase();return q.split(/\s+/).every(function(tok){return tok===''||hay.indexOf(tok)>=0;});});
var ff=$('fFrom')?$('fFrom').value:'',tt=$('fTo')?$('fTo').value:'';
if(ff||tt)rows=rows.filter(function(r){var e=r.expires_on?String(r.expires_on).slice(0,10):'';if(!e)return false;return (!ff||e>=ff)&&(!tt||e<=tt);});
rows.sort(function(a,b){var x=val(a,sortKey),y=val(b,sortKey);if(x<y)return -1*sortDir;if(x>y)return 1*sortDir;return a.domain<b.domain?-1:1;});
return rows;}
function render(){var rows=filtered(),tb=$('tbody');tb.textContent='';
var pages=Math.max(1,Math.ceil(rows.length/certPerPage));if(certPage>pages)certPage=pages;
var slice=rows.slice((certPage-1)*certPerPage,certPage*certPerPage);
if(!rows.length){var tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=7;td.className='muted';td.textContent=cache.results.length?'No rows match the current search/filter.':'No results yet — paste domains and press Check.';tr.appendChild(td);tb.appendChild(tr);}
slice.forEach(function(r){var tr=document.createElement('tr');
var c0=domainCell(r.domain);tr.appendChild(c0);
var c1=document.createElement('td');c1.textContent=r.port;tr.appendChild(c1);
var c2=document.createElement('td');c2.className='mono';c2.textContent=r.expires_on_display||'—';tr.appendChild(c2);
var c3=document.createElement('td');c3.textContent=r.expires_in||'—';tr.appendChild(c3);
var c4=document.createElement('td');c4.appendChild(badge(r.status));tr.appendChild(c4);
var c5=document.createElement('td');c5.className='mono';c5.textContent=r.issuer||'';c5.title=r.issuer||'';tr.appendChild(c5);
var c6=document.createElement('td');c6.textContent=r.note||'';tr.appendChild(c6);
tb.appendChild(tr);});
var errs=cache.results.filter(function(r){return !r.success;}),eb=$('ebody');eb.textContent='';
$('errCount').textContent=errs.length;
if(!errs.length){var er=document.createElement('tr'),ed=document.createElement('td');ed.colSpan=4;ed.className='muted';ed.textContent='No errors.';er.appendChild(ed);eb.appendChild(er);}
errs.forEach(function(r){var tr=document.createElement('tr');
var a=domainCell(r.domain);tr.appendChild(a);
var b=document.createElement('td');b.textContent=r.port;tr.appendChild(b);
var c=document.createElement('td');c.appendChild(badge(r.status));tr.appendChild(c);
var d=document.createElement('td');d.textContent=r.error||'';tr.appendChild(d);
eb.appendChild(tr);});setPager('cert',certPage,pages,rows.length,certPerPage);icons();}
function setBusy(b){$('btnCheck').disabled=b;$('progress').style.display=b?'block':'none';$('skeleton').style.display=b?'block':'none';if(b){var w=5;$('bar').style.width='5%';window.__pt=setInterval(function(){w=Math.min(92,w+7);$('bar').style.width=w+'%';},350);}else{clearInterval(window.__pt);$('bar').style.width='100%';setTimeout(function(){$('progress').style.display='none';},400);}}
function showErr(m){var e=$('errbox');if(!m){e.style.display='none';e.textContent='';return;}e.style.display='block';e.textContent=m;}
async function doCheck(){showErr('');var t=$('domains').value;if(!t.trim()){showErr('Paste at least one domain first.');return;}
setBusy(true);try{var res=await fetch('/api/check',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({domains_text:t})});
var data=await res.json();if(!res.ok)throw new Error(data.error||('HTTP '+res.status));
cache=data;setStats(data.summary);certPage=1;
$('lastChecked').textContent='Checked '+fmtDT(data.checked_at)+' '+TZ_LABEL;$('footTime').textContent='Last checked '+fmtDT(data.checked_at)+' '+TZ_LABEL;
render();toast('Checked '+data.summary.total+' domain(s): '+data.summary.ok+' OK, '+data.summary.warning+' warning, '+data.summary.critical+' critical, '+data.summary.expired+' expired, '+data.summary.failed+' failed.');}
catch(e){showErr(String(e.message||e));toast('Check failed: '+String(e.message||e));}finally{setBusy(false);}}
function download(name,mime,text){var b=new Blob([text],{type:mime}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=name;document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove();},800);}
function toCsv(){var rows=[['domain','port','expires_on_npt','days_remaining','status','issuer','note','error']];
cache.results.forEach(function(r){rows.push([r.domain,r.port,r.expires_on?fmtNPT(r.expires_on):'',r.days_remaining==null?'':r.days_remaining,r.status,r.issuer||'',r.note||'',r.error||'']);});
return rows.map(function(rr){return rr.map(function(c){c=String(c);return /[",\n]/.test(c)?'"'+c.replace(/"/g,'""')+'"':c;}).join(',');}).join('\n');}
function reportCss(){return "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;margin:0;background:#edf0f5;color:#17233a}"
+".wrap{max-width:1100px;margin:0 auto;padding:28px 20px 24px}"
+".hero{background:linear-gradient(135deg,#0c1930 0%,#24479e 60%,#2456e6 100%);color:#fff;border-radius:16px;padding:24px 26px;box-shadow:0 8px 24px rgba(12,25,48,.25)}"
+".hero h1{margin:0;font-size:22px;letter-spacing:-.01em}.hero p{margin:6px 0 0;color:#c3d2f2;font-size:13px}"
+".pills{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}"
+".pill{background:#fff;border:1px solid #e2e7f0;color:#33415c;border-radius:999px;padding:5px 14px;font-size:12px;font-weight:700}"
+".pill.ok{background:#dcf5e3;border-color:#b7e6c3;color:#157a3a}.pill.warn{background:#fdf0d2;border-color:#f3dca6;color:#96600a}"
+".pill.crit{background:#fbdfdf;border-color:#f3c1c1;color:#c11f1f}.pill.err{background:#ece4fb;border-color:#d9c8f5;color:#6d28d9}"
+".card{background:#fff;border-radius:14px;box-shadow:0 1px 2px rgba(16,24,40,.06),0 2px 8px rgba(16,24,40,.05);overflow:auto}"
+"table{width:100%;border-collapse:collapse;font-size:13px}"
+"th,td{padding:9px 12px;border-bottom:1px solid #eef1f6;text-align:left;vertical-align:top}"
+"tbody tr:nth-child(even){background:#e9eff7}"
+"tbody tr:last-child td{border-bottom:0}th{background:#f7f9fc;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#5b6b84;white-space:nowrap}"
+".mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}"
+".badge{display:inline-block;padding:3px 11px;border-radius:999px;font-size:12px;font-weight:800;white-space:nowrap}"
+".badge.ok{background:#dcf5e3;color:#157a3a}.badge.warning{background:#fdf0d2;color:#96600a}"
+".badge.critical,.badge.expired{background:#fbdfdf;color:#c11f1f}.badge.error{background:#ece4fb;color:#6d28d9}.badge.new{background:#eef1f6;color:#475569}"
+".footer{margin:20px 0 10px;text-align:center;color:#66748c;font-size:12px}"
+".footer strong{color:#0c1930}.footer a{color:#2456e6;font-weight:700;text-decoration:none}.footer a:hover{text-decoration:underline}";}
function reportBadge(e,st){var c=String(st||'').toLowerCase();return '<span class="badge '+c+'">'+e(st)+'</span>';}
function reportFoot(){return '<div class="footer">Powered by <a href="https://sagarmalla.info.np">Sagar Malla</a> · SSL Checker report</div>';}
function toHtml(){function e(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
var s=cache.summary||{total:0,ok:0,warning:0,critical:0,expired:0,failed:0};
var body=cache.results.map(function(r){return '<tr><td class="mono">'+e(r.domain)+'</td><td>'+e(r.port)+'</td><td class="mono">'+e(r.expires_on_display||'')+'</td><td>'+e(r.expires_in||'')+'</td><td>'+reportBadge(e,r.status)+'</td><td class="mono">'+e(r.issuer||'')+'</td><td>'+e(r.note||r.error||'')+'</td></tr>';}).join('');
var pills='<div class="pills"><span class="pill">Total '+s.total+'</span><span class="pill ok">OK '+s.ok+'</span><span class="pill warn">Warning '+s.warning+'</span><span class="pill crit">Critical '+s.critical+'</span><span class="pill crit">Expired '+s.expired+'</span><span class="pill err">Failed '+s.failed+'</span></div>';
return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>SSL Certificate Report</title><style>'+reportCss()+'</style></head><body><div class="wrap"><div class="hero"><h1>SSL Certificate Report</h1><p>Generated '+fmtNPT(new Date().toISOString())+' · All times Nepal Standard Time (UTC+05:45).</p></div>'+pills+'<div class="card"><table><tr><th>Domain</th><th>Port</th><th>Expires (NPT)</th><th>In</th><th>Status</th><th>Issuer</th><th>Note</th></tr>'+body+'</table></div>'+reportFoot()+'</div></body></html>';}
async function sendTeams(){if(!cache.results.length){toast('Nothing to send — run a check first.');return;}
try{var res=await fetch('/api/notify',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({results:cache.results,teams_format:'adaptive',notify_on:'warning'})});
var data=await res.json();if(!res.ok||!data.ok)throw new Error((data&&data.message)||'send failed');toast('Teams: '+data.message);}catch(e){toast('Teams failed: '+String(e.message||e));}}
$('btnCheck').addEventListener('click',doCheck);
$('btnTeams').addEventListener('click',sendTeams);
$('q').addEventListener('input',function(){certPage=1;render();});$('fStatus').addEventListener('change',function(){certPage=1;render();});
document.querySelectorAll('#tbl th[data-k]').forEach(function(th){th.addEventListener('click',function(){var k=th.getAttribute('data-k');if(sortKey===k)sortDir*=-1;else{sortKey=k;sortDir=1;}certPage=1;render();});});
$('certPrev').addEventListener('click',function(){if(certPage>1){certPage--;render();}});
$('certNext').addEventListener('click',function(){certPage++;render();});
$('certPerPage').addEventListener('change',function(){certPerPage=perPageVal('certPerPage',20);certPage=1;render();});
$('fFrom').addEventListener('change',function(){certPage=1;render();});
$('fTo').addEventListener('change',function(){certPage=1;render();});
$('btnClearFilters').addEventListener('click',function(){$('q').value='';$('fStatus').value='';$('fFrom').value='';$('fTo').value='';certPage=1;render();toast('Filters cleared.');});
$('btnMonitorAll').addEventListener('click',function(){if(!cache.results.length){toast('Nothing to monitor — run a check first.');return;}
var lines=cache.results.map(function(r){return r.domain+':'+r.port;});
req('POST','/api/domains/import',{domains_text:lines.join('\n')}).then(function(d){refreshDb();refreshAnalytics();toast('Watch list updated: '+d.added+' new, '+d.total+' parsed.');}).catch(function(e){toast('Monitor failed: '+e.message);});});
$('dlCsv').addEventListener('click',function(){if(!cache.results.length)return toast('No results.');download('ssl-report.csv','text/csv',toCsv());});
$('dlJson').addEventListener('click',function(){if(!cache.results.length)return toast('No results.');var out={summary:cache.summary,checked_at:cache.checked_at?nptIso(cache.checked_at):cache.checked_at,results:cache.results.map(function(r){var o={};for(var k in r)o[k]=r[k];if(o.expires_on)o.expires_on=nptIso(o.expires_on);return o;})};download('ssl-report.json','application/json',JSON.stringify(out,null,2));});
$('dlHtml').addEventListener('click',function(){if(!cache.results.length)return toast('No results.');download('ssl-report.html','text/html',toHtml());});
function dbRowsToCsv(list){var rows=[['domain','ips','port','enabled','last_checked_at','days_remaining','status','issuer','note','error']];
list.forEach(function(d){rows.push([d.domain,d.last_ips||'',d.port,d.enabled?1:0,d.last_checked_at?fmtNPT(d.last_checked_at):'',(d.last_days==null?'':d.last_days),d.last_status||'',d.last_issuer||'',d.last_note||'',d.last_error||'']);});
return rows.map(function(rr){return rr.map(function(c){c=String(c);return /[",\n]/.test(c)?'"'+c.replace(/"/g,'""')+'"':c;}).join(',');}).join('\n');}
function dbToCsv(){return dbRowsToCsv(dbFull);}
function dbRowsToHtml(list){function e(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
var on=list.filter(function(d){return d.enabled;}).length;
var body=list.map(function(d){return '<tr><td class="mono">'+e(d.domain)+'</td><td class="mono">'+e(d.last_ips||'')+'</td><td>'+e(d.port)+'</td><td>'+(d.enabled?'yes':'no')+'</td><td class="mono">'+e(d.last_checked_at?fmtNPT(d.last_checked_at):'')+'</td><td>'+(d.last_days==null?'':d.last_days)+'</td><td>'+reportBadge(e,d.last_status||'NEW')+'</td><td class="mono">'+e(d.last_issuer||'')+'</td><td>'+e(d.last_note||d.last_error||'')+'</td></tr>';}).join('');
var pills='<div class="pills"><span class="pill">Total '+list.length+'</span><span class="pill ok">Enabled '+on+'</span><span class="pill">Paused '+(list.length-on)+'</span></div>';
return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>SSL Checker — Monitored Domains</title><style>'+reportCss()+'</style></head><body><div class="wrap"><div class="hero"><h1>Monitored Domains ('+list.length+')</h1><p>Generated '+fmtNPT(new Date().toISOString())+' · All times Nepal Standard Time (UTC+05:45).</p></div>'+pills+'<div class="card"><table><tr><th>Domain</th><th>IPs</th><th>Port</th><th>Enabled</th><th>Last check (NPT)</th><th>Days left</th><th>Status</th><th>Issuer</th><th>Note</th></tr>'+body+'</table></div>'+reportFoot()+'</div></body></html>';}
function dbToHtml(){return dbRowsToHtml(dbFull);}
$('dlDbCsv').addEventListener('click',function(){if(!dbFull.length)return toast('Watch list is empty.');download('monitored-domains.csv','text/csv',dbToCsv());});
$('dlDbJson').addEventListener('click',function(){if(!dbFull.length)return toast('Watch list is empty.');var out=dbFull.map(function(d){var o={};for(var k in d)o[k]=d[k];if(o.last_checked_at)o.last_checked_at=nptIso(o.last_checked_at);if(o.last_expires_on)o.last_expires_on=nptIso(o.last_expires_on);return o;});download('monitored-domains.json','application/json',JSON.stringify(out,null,2));});
$('dlDbHtml').addEventListener('click',function(){if(!dbFull.length)return toast('Watch list is empty.');download('monitored-domains.html','text/html',dbToHtml());});
$('btnDefault').addEventListener('click',async function(){try{var r=await fetch('/api/defaults');var d=await r.json();if(d.text)$('domains').value=d.text;updCount();toast('Loaded default list ('+(d.count||0)+' domains). Auto-checking…');doCheck();}catch(e){toast('Could not load defaults.');}});
function isTxtFile(f){return f&&f.name&&/\.txt$/i.test(f.name);}
function handleUploadFile(f){showErr('');var ue=$('uploadErr');if(ue){ue.style.display='none';ue.textContent='';}
function uerr(m){if(ue){ue.style.display='block';ue.textContent=m;}showErr(m);}
if(!f)return;if(!isTxtFile(f)){uerr('Only .txt files are accepted — download the Sample.txt below for the expected format.');return;}
if(f.size>5242880){uerr('Upload exceeds 5 MB limit.');return;}
var rd=new FileReader();rd.onload=function(){var cur=$('domains').value;var add=String(rd.result||'');$('domains').value=(cur?cur.replace(/\s+$/,'')+'\n':'')+add;updCount();closeUploadModal();toast('Attached '+f.name+' ('+f.size+' bytes). Auto-checking…');doCheck();};rd.readAsText(f);}
function openUploadModal(){var m=$('uploadModal');if(!m)return;m.classList.add('open');m.setAttribute('aria-hidden','false');var e=$('uploadErr');if(e){e.style.display='none';e.textContent='';}icons();}
function closeUploadModal(){var m=$('uploadModal');if(!m)return;m.classList.remove('open');m.setAttribute('aria-hidden','true');}
$('btnUploadModal').addEventListener('click',openUploadModal);
$('uploadModalClose').addEventListener('click',closeUploadModal);
$('uploadModalCancel').addEventListener('click',closeUploadModal);
$('uploadModal').addEventListener('click',function(ev){if(ev.target===this)closeUploadModal();});
document.addEventListener('keydown',function(ev){if(ev.key==='Escape')closeUploadModal();});
$('btnBrowse').addEventListener('click',function(ev){ev.stopPropagation();$('file').click();});
$('file').addEventListener('change',function(ev){var f=ev.target.files[0];ev.target.value='';handleUploadFile(f);});
(function(){var dz=$('dropzone');if(!dz)return;
dz.addEventListener('click',function(ev){if(ev.target.closest&&ev.target.closest('#btnBrowse'))return;$('file').click();});
dz.addEventListener('keydown',function(ev){if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();$('file').click();}});
['dragenter','dragover'].forEach(function(t){dz.addEventListener(t,function(ev){ev.preventDefault();dz.classList.add('dragover');});});
['dragleave','drop'].forEach(function(t){dz.addEventListener(t,function(ev){ev.preventDefault();dz.classList.remove('dragover');});});
dz.addEventListener('drop',function(ev){var f=ev.dataTransfer&&ev.dataTransfer.files&&ev.dataTransfer.files[0];handleUploadFile(f);});})();
function updCount(){var n=$('domains').value.split('\n').filter(function(x){return x.trim()&&!x.trim().startsWith('#');}).length;$('inputCount').textContent=n+' line(s)';}
$('domains').addEventListener('input',updCount);updCount();render();
/* ---- SQLite watch list + scheduler + analytics (DB-backed) ---- */
function req(method,path,body){var o={method:method,headers:{'X-CSRF-Token':csrf}};if(body!==undefined){o.headers['Content-Type']='application/json';o.body=JSON.stringify(body);}return fetch(path,o).then(function(r){return r.json().then(function(d){if(!r.ok){if(r.status===403&&/csrf/i.test(d.error||''))csrfExpired();var e=new Error(d.error||('HTTP '+r.status));e.details=d.errors||null;e.status=r.status;throw e;}return d;});});}
function csrfExpired(){if(window.__csrfReload)return;window.__csrfReload=true;window.__csrfAt=Date.now();toast('Session expired (the server restarted?) — reloading for a fresh token…');setTimeout(function(){location.reload();},1500);}
function csrfJustHandled(){return !!window.__csrfAt&&Date.now()-window.__csrfAt<5000;}
function stBadge(st){var s=document.createElement('span');s.className='badge '+(String(st||'NEW').toLowerCase().replace('never_checked','error'));s.textContent=st||'NEW';return s;}
var dbSelected={};
var dbSortKey='days',dbSortDir=1;
function dbVal(d,k){if(k==='domain')return (d.domain||'').toLowerCase();if(k==='port')return d.port;if(k==='checked')return d.last_checked_at||'';if(k==='ips')return (d.last_ips||'').toLowerCase();if(k==='days')return d.last_days==null?1e9:d.last_days;if(k==='status')return d.last_status||'';return '';}
function dbExpFilter(d){var f=$('fDbFrom')?$('fDbFrom').value:'',t=$('fDbTo')?$('fDbTo').value:'';if(!f&&!t)return true;var e=d.last_expires_on?String(d.last_expires_on).slice(0,10):'';if(!e)return false;return (!f||e>=f)&&(!t||e<=t);}
function dbSearchFilter(d){var q=$('dbQ')?$('dbQ').value.toLowerCase().trim():'';if(!q)return true;var hay=(d.domain+' '+d.port+' '+(d.last_status||'')).toLowerCase();return q.split(/\s+/).every(function(tok){return tok===''||hay.indexOf(tok)>=0;});}
function getSelectedIds(){return Object.keys(dbSelected).map(function(x){return parseInt(x,10);}).filter(function(n){return n>0;});}
function updateBulkBar(){var ids=getSelectedIds(),bar=$('bulkBar');if(bar)bar.classList.toggle('on',ids.length>0);
var sc=$('selCount');if(sc)sc.textContent=ids.length+' selected';
var all=$('dbSelectAll');if(all){var boxes=document.querySelectorAll('#dbody input.rowcheck');var total=boxes.length,checked=0;for(var i=0;i<boxes.length;i++)if(boxes[i].checked)checked++;
all.checked=total>0&&checked===total;all.indeterminate=checked>0&&checked<total;}}
function renderDb(list){dbFull=list||[];var tb=$('dbody');tb.textContent='';$('dbCount').textContent=dbFull.length+' monitored';
var nc=$('navDomCount');if(nc)nc.textContent=dbFull.length;
var valid={};dbFull.forEach(function(d){valid[d.id]=1;});Object.keys(dbSelected).forEach(function(k){if(!valid[k])delete dbSelected[k];});
if(!dbFull.length){var tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=9;td.className='muted';td.textContent='Watch list is empty — add a domain above or import the pasted list.';tr.appendChild(td);tb.appendChild(tr);updateBulkBar();setPager('db',1,1,0,dbPerPage);return;}
var view=dbFull.filter(dbExpFilter).filter(dbSearchFilter);
view.sort(function(a,b){var x=dbVal(a,dbSortKey),y=dbVal(b,dbSortKey);if(x<y)return -1*dbSortDir;if(x>y)return 1*dbSortDir;var ad=String(a.domain||'').toLowerCase(),bd=String(b.domain||'').toLowerCase();return ad<bd?-1:1;});
dbView=view;
if(!view.length){var tr2=document.createElement('tr'),td2=document.createElement('td');td2.colSpan=9;td2.className='muted';var hasQ=$('dbQ')&&$('dbQ').value.trim()!=='';td2.textContent=hasQ?'No domains match the current search.':'No domains match the current expiry filter.';tr2.appendChild(td2);tb.appendChild(tr2);updateBulkBar();setPager('db',1,1,0,dbPerPage);return;}
var pages=Math.max(1,Math.ceil(view.length/dbPerPage));if(dbPage>pages)dbPage=pages;
view.slice((dbPage-1)*dbPerPage,dbPage*dbPerPage).forEach(function(d){var tr=document.createElement('tr');if(!d.enabled)tr.style.opacity='.55';
var sel=!!dbSelected[d.id];if(sel)tr.classList.add('selected');
var cb=document.createElement('td');var inp=document.createElement('input');inp.type='checkbox';inp.className='rowcheck';inp.setAttribute('data-id',d.id);inp.setAttribute('aria-label','Select '+d.domain);inp.checked=sel;cb.appendChild(inp);tr.appendChild(cb);
var c0=domainCell(d.domain);tr.appendChild(c0);
var cip=domainCell(d.last_ips||'—');tr.appendChild(cip);
var c1=document.createElement('td');c1.textContent=d.port;tr.appendChild(c1);
var c2=document.createElement('td');c2.textContent=d.enabled?'yes':'no';tr.appendChild(c2);
var c3=document.createElement('td');c3.className='mono';c3.textContent=d.last_checked_at?fmtDT(d.last_checked_at):'—';tr.appendChild(c3);
var c4=document.createElement('td');c4.textContent=(d.last_days==null)?'—':String(d.last_days);tr.appendChild(c4);
var c5=document.createElement('td');c5.appendChild(stBadge(d.last_status));tr.appendChild(c5);
var c6=document.createElement('td');
[['hist','History','ghost small','history'],[d.enabled?'disable':'enable',d.enabled?'Pause':'Resume','warnbtn small',d.enabled?'pause':'play'],['del','Delete','danger small','trash-2']].forEach(function(a){var label=a[0]==='hist'?'History':(a[0]==='del'?'Delete':(d.enabled?'Pause':'Resume'));var b=document.createElement('button');b.type='button';b.className='btn icon-only '+a[1];b.title=label;b.setAttribute('aria-label',label);var ic=document.createElement('i');ic.setAttribute('data-lucide',a[3]);b.appendChild(ic);b.setAttribute('data-act',a[0]);b.setAttribute('data-id',d.id);c6.appendChild(b);c6.appendChild(document.createTextNode(' '));});
tr.appendChild(c6);tb.appendChild(tr);});updateBulkBar();setPager('db',dbPage,Math.max(1,Math.ceil(view.length/dbPerPage)),view.length,dbPerPage);icons();}
function refreshDb(){req('GET','/api/domains').then(function(d){renderDb(d.domains||[]);}).catch(function(e){toast('Watch list: '+e.message);});}
$('dbody').addEventListener('change',function(ev){var c=ev.target.closest?ev.target.closest('input.rowcheck'):null;if(!c)return;var id=c.getAttribute('data-id');if(c.checked)dbSelected[id]=1;else delete dbSelected[id];
var tr=c.closest('tr');if(tr)tr.classList.toggle('selected',c.checked);updateBulkBar();});
$('dbSelectAll').addEventListener('change',function(){var on=this.checked;var boxes=document.querySelectorAll('#dbody input.rowcheck');for(var i=0;i<boxes.length;i++){var id=boxes[i].getAttribute('data-id');boxes[i].checked=on;var tr=boxes[i].closest('tr');if(tr)tr.classList.toggle('selected',on);if(on)dbSelected[id]=1;else delete dbSelected[id];}updateBulkBar();});
$('btnClearSel').addEventListener('click',function(){dbSelected={};document.querySelectorAll('#dbody input.rowcheck').forEach(function(b){b.checked=false;var tr=b.closest('tr');if(tr)tr.classList.remove('selected');});updateBulkBar();});
function selectedRows(){var ids={};getSelectedIds().forEach(function(id){ids[id]=1;});return dbFull.filter(function(d){return ids[d.id];});}
function selectedTxt(rows){return rows.map(function(d){return d.domain+(d.port!==443?':'+d.port:'');}).join('\n')+'\n';}
$('btnSelTxt').addEventListener('click',function(){var rows=selectedRows();if(!rows.length)return toast('Select at least one domain first.');download('selected-domains.txt','text/plain',selectedTxt(rows));toast('Exported '+rows.length+' selected domain(s) as TXT.');});
$('btnSelCsv').addEventListener('click',function(){var rows=selectedRows();if(!rows.length)return toast('Select at least one domain first.');download('selected-domains.csv','text/csv',dbRowsToCsv(rows));toast('Exported '+rows.length+' selected domain(s) as CSV.');});
$('btnSelHtml').addEventListener('click',function(){var rows=selectedRows();if(!rows.length)return toast('Select at least one domain first.');download('selected-domains.html','text/html',dbRowsToHtml(rows));toast('Exported '+rows.length+' selected domain(s) as HTML.');});
$('btnBulkDelete').addEventListener('click',function(){var ids=getSelectedIds();if(!ids.length)return;if(!confirm('Delete '+ids.length+' selected domain(s) from monitoring?'))return;var b=this;b.disabled=true;
req('DELETE','/api/domains',{ids:ids}).then(function(d){ids.forEach(function(id){delete dbSelected[id];});renderDb(d.domains||[]);refreshAnalytics();toast('Deleted '+(d.deleted||0)+' domain(s).');}).catch(function(e){toast('Bulk delete failed: '+e.message);}).finally(function(){b.disabled=false;});});
function bulkToggle(enabled){var ids=getSelectedIds();if(!ids.length)return;req('PATCH','/api/domains',{ids:ids,enabled:enabled}).then(function(d){renderDb(d.domains||[]);refreshAnalytics();toast((enabled?'Resumed ':'Paused ')+(d.updated||0)+' domain(s).');}).catch(function(e){toast('Bulk update failed: '+e.message);});}
$('btnBulkEnable').addEventListener('click',function(){bulkToggle(true);});
$('btnBulkDisable').addEventListener('click',function(){bulkToggle(false);});
$('dbody').addEventListener('click',function(ev){var b=ev.target.closest?ev.target.closest('button[data-act]'):null;if(!b)return;var id=b.getAttribute('data-id'),act=b.getAttribute('data-act');
if(act==='del'){if(!confirm('Remove this domain from monitoring?'))return;req('DELETE','/api/domains/'+id).then(function(d){renderDb(d.domains||[]);toast('Domain removed.');}).catch(function(e){toast('Delete failed: '+e.message);});}
else if(act==='enable'||act==='disable'){req('PATCH','/api/domains/'+id,{enabled:(act==='enable')}).then(function(d){renderDb(d.domains||[]);}).catch(function(e){toast('Update failed: '+e.message);});}
else if(act==='hist'){req('GET','/api/history?domain_id='+id+'&limit=10').then(function(d){renderHist(id,d.history||[]);}).catch(function(e){toast('History: '+e.message);});}});
function renderHist(id,rows){var box=$('histBox');box.textContent='';var h=document.createElement('b');h.textContent='Last '+rows.length+' checks (#'+id+'): ';box.appendChild(h);
if(!rows.length){box.appendChild(document.createTextNode('no checks recorded yet.'));return;}
var t=document.createElement('table');var thead=document.createElement('thead');var hr=document.createElement('tr');['Checked ('+TZ_LABEL+')','Days','Status','Note / error'].forEach(function(x){var th=document.createElement('th');th.textContent=x;hr.appendChild(th);});thead.appendChild(hr);t.appendChild(thead);
var tb=document.createElement('tbody');rows.forEach(function(r){var tr=document.createElement('tr');
var a=document.createElement('td');a.className='mono';a.textContent=r.checked_at?fmtDT(r.checked_at):'—';tr.appendChild(a);
var bb=document.createElement('td');bb.textContent=(r.days_remaining==null?'—':r.days_remaining);tr.appendChild(bb);
var c=document.createElement('td');c.appendChild(stBadge(r.status));tr.appendChild(c);
var dd=document.createElement('td');dd.textContent=r.note||r.error||'';tr.appendChild(dd);tb.appendChild(tr);});
t.appendChild(tb);box.appendChild(t);icons();}
function jumpToDomain(id){var ix=dbView.findIndex(function(d){return d.id===id;});
if(ix<0){var q=$('dbQ');if(q)q.value='';var f1=$('fDbFrom');if(f1)f1.value='';var f2=$('fDbTo');if(f2)f2.value='';dbPage=1;renderDb(dbFull);
ix=dbView.findIndex(function(d){return d.id===id;});
if(ix<0){toast('Saved, but the row is not in the current list.');return;}
toast('Saved — search/filter cleared to show it.');}
var per=dbPerPage===Infinity?(dbView.length||1):dbPerPage;dbPage=Math.floor(ix/per)+1;renderDb(dbFull);}
$('btnAdd').addEventListener('click',function(){var d=$('newDomain').value.trim(),p=$('newPort').value.trim()||'443';if(!d){toast('Type a domain first.');return;}
req('POST','/api/domains',{domain:d,port:parseInt(p,10)||443}).then(function(r){renderDb(r.domains||[]);$('newDomain').value='';$('newPort').value='';toast('Domain added to monitoring.');jumpToDomain(r.id);refreshAnalytics();}).catch(function(e){toast('Add failed: '+e.message);});});
$('btnImportDb').addEventListener('click',function(){var t=$('domains').value;if(!t.trim()){toast('Paste domains above first.');return;}
var before={};dbFull.forEach(function(d){before[d.id]=1;});
req('POST','/api/domains/import',{domains_text:t}).then(function(r){renderDb(r.domains||[]);var nid=0;(r.domains||[]).forEach(function(x){if(!nid&&!before[x.id])nid=x.id;});if(nid)jumpToDomain(nid);toast('Imported: '+r.added+' new, '+r.total+' parsed.');refreshAnalytics();}).catch(function(e){toast('Import failed: '+e.message);});});
$('dbFile').addEventListener('change',function(ev){var f=ev.target.files[0];if(!f)return;if(!isTxtFile(f)){toast('Only .txt files can be imported — grab the sample import.txt for the expected format.');ev.target.value='';return;}
if(f.size>5242880){toast('Upload exceeds 5 MB limit.');ev.target.value='';return;}
var fd=new FormData();fd.append('file',f);toast('Importing '+f.name+'…');
var beforeF={};dbFull.forEach(function(d){beforeF[d.id]=1;});
fetch('/api/domains/import',{method:'POST',headers:{'X-CSRF-Token':csrf},body:fd}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error||('HTTP '+r.status));return d;});}).then(function(d){renderDb(d.domains||[]);var nid=0;(d.domains||[]).forEach(function(x){if(!nid&&!beforeF[x.id])nid=x.id;});if(nid)jumpToDomain(nid);refreshAnalytics();toast('Imported '+f.name+': '+d.added+' new, '+d.total+' parsed.');}).catch(function(e){toast('Import failed: '+e.message);}).finally(function(){ev.target.value='';});});
$('btnRefreshDb').addEventListener('click',function(){refreshDb();refreshAnalytics();});
$('dbPrev').addEventListener('click',function(){if(dbPage>1){dbPage--;renderDb(dbFull);}});
$('dbNext').addEventListener('click',function(){dbPage++;renderDb(dbFull);});
$('dbPerPage').addEventListener('change',function(){dbPerPage=perPageVal('dbPerPage',20);dbPage=1;renderDb(dbFull);});
document.querySelectorAll('#view-domains th[data-db-k]').forEach(function(th){th.addEventListener('click',function(){var k=th.getAttribute('data-db-k');if(dbSortKey===k)dbSortDir*=-1;else{dbSortKey=k;dbSortDir=1;}dbPage=1;renderDb(dbFull);});});
$('fDbFrom').addEventListener('change',function(){dbPage=1;renderDb(dbFull);});
$('fDbTo').addEventListener('change',function(){dbPage=1;renderDb(dbFull);});
$('dbQ').addEventListener('input',function(){dbPage=1;renderDb(dbFull);});
$('btnClearDbFilters').addEventListener('click',function(){$('dbQ').value='';$('fDbFrom').value='';$('fDbTo').value='';dbPage=1;renderDb(dbFull);toast('Search and expiry filters cleared.');});
$('btnTheme').addEventListener('click',function(){applyTheme(document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark');});
$('btnCheckNow').addEventListener('click',async function(){var b=this;if(b.disabled)return;b.disabled=true;toast('Check started in background — large lists take minutes; progress shows below. No need to keep this tab open.');
try{var r=await req('POST','/api/check-now',{});if(!r.started)toast('A check is already running — watching it finish.');pollCheckCycle(0);}
catch(e){if(!csrfJustHandled())toast('Check-now failed: '+e.message);b.disabled=false;}});
function pollCheckCycle(n){req('GET','/api/analytics').then(function(d){renderAnalytics(d);var s=d.scheduler||{};
if(s.cycle_running&&n<240){setTimeout(function(){pollCheckCycle(n+1);},5000);return;}
var b=$('btnCheckNow');if(b)b.disabled=false;refreshDb();refreshAnalytics();
var sum=s.last_summary||{};if(sum&&sum.checked!=null)toast('Check finished: '+sum.checked+' domain(s), '+(sum.alerts_due||0)+' alert(s) due. '+(sum.detail||''));else toast('Check finished.');}).catch(function(e){var b=$('btnCheckNow');if(b)b.disabled=false;toast('Check status unknown: '+e.message);});}
function renderAnalytics(a){var s=a.scheduler||{};var pill=$('schedStatus');var mins=Math.round((s.interval_seconds||300)/60);
pill.textContent=(s.running?'Scheduler running':'Scheduler idle')+(s.cycle_running?' · check in progress…':'')+' · every '+mins+' min'+(s.last_run_at?(' · last run '+fmtDT(s.last_run_at)+' '+TZ_LABEL):' · not run yet');
var ns=$('navSched');if(ns){ns.textContent='';var dot=document.createElement('span');dot.className='sched-dot'+(s.running?'':' off');ns.appendChild(dot);ns.appendChild(document.createTextNode((s.running?('Every '+mins+' min'):'Scheduler idle')+(s.last_run_at?(' · '+fmtDT(s.last_run_at).slice(11)+' '+TZ_LABEL):'')));}
var dist=a.status_distribution||{},order=['OK','WARNING','CRITICAL','EXPIRED','ERROR','NEVER_CHECKED'],colors={OK:'#22c55e',WARNING:'#eab308',CRITICAL:'#f97316',EXPIRED:'#ef4444',ERROR:'#a855f7',NEVER_CHECKED:'#cbd5e1'};
var total=0,i;for(i=0;i<order.length;i++)total+=(dist[order[i]]||0);
var bar=$('mixBar');bar.textContent='';if(!total){var em=document.createElement('span');em.className='muted';em.textContent='No monitored domains yet.';bar.appendChild(em);}else{for(i=0;i<order.length;i++){var n=dist[order[i]]||0;if(!n)continue;var seg=document.createElement('div');seg.style.width=(100*n/total)+'%';seg.style.background=colors[order[i]];seg.title=order[i]+': '+n;bar.appendChild(seg);}}
var lg=$('mixLegend');lg.textContent='';for(i=0;i<order.length;i++){var sp=document.createElement('span');var dot=document.createElement('span');dot.className='dot';dot.style.background=colors[order[i]];sp.appendChild(dot);sp.appendChild(document.createTextNode(order[i]+' '+(dist[order[i]]||0)));lg.appendChild(sp);}
var b=a.expiry_buckets||{};var defs=[['expired','Expired','#ef4444'],['d0_7','0–7 days','#f97316'],['d8_14','8–14 days','#eab308'],['d15_30','15–30 days','#a3a32a'],['d31_60','31–60 days','#60a5fa'],['d60p','60+ days','#22c55e'],['no_data','No data','#94a3b8']];
var mx=1;for(i=0;i<defs.length;i++)mx=Math.max(mx,b[defs[i][0]]||0);
var bk=$('buckets');bk.textContent='';for(i=0;i<defs.length;i++){var row=document.createElement('div');row.className='bar-row';
var lb=document.createElement('span');lb.className='lbl';lb.textContent=defs[i][1];row.appendChild(lb);
var trk=document.createElement('div');trk.className='track';var fl=document.createElement('div');fl.className='fill';fl.style.width=(100*(b[defs[i][0]]||0)/mx)+'%';fl.style.background=defs[i][2];trk.appendChild(fl);row.appendChild(trk);
var ct=document.createElement('span');ct.className='cnt';ct.textContent=(b[defs[i][0]]||0);row.appendChild(ct);bk.appendChild(row);}
window.__aCache=a;drawDonut(a.status_distribution||{});renderMilestones(a.alerts_by_milestone||{});drawDaily(a.daily||[]);}
function themeInk(){var dark=document.documentElement.getAttribute('data-theme')==='dark';return {dark:dark,mut:dark?'#8fa1bd':'#64748b',ink:dark?'#e6edf8':'#0f172a',grid:dark?'#22304d':'#e2e8f0'};}
function fitCanvas(cv,hCss){var dpr=window.devicePixelRatio||1;var w=cv.clientWidth||(cv.parentElement&&cv.parentElement.clientWidth)||600;if(w<50)w=600;cv.width=Math.round(w*dpr);cv.height=Math.round(hCss*dpr);var ctx=cv.getContext('2d');ctx.setTransform(dpr,0,0,dpr,0,0);return {ctx:ctx,W:w,H:hCss};}
function drawDaily(days){var cv=$('dailyChart');if(!cv||!cv.getContext)return;var f=fitCanvas(cv,200),ctx=f.ctx,W=f.W,H=f.H,t=themeInk();ctx.clearRect(0,0,W,H);
if(!days.length){ctx.fillStyle=t.mut;ctx.font='13px sans-serif';ctx.fillText('No check history yet — the scheduler records a row every 5 minutes.',20,H/2);return;}
var mx=1,i;for(i=0;i<days.length;i++)mx=Math.max(mx,days[i].checks);
ctx.strokeStyle=t.grid;ctx.lineWidth=1;for(i=1;i<=3;i++){var gy=26+(H-54)*i/4;ctx.beginPath();ctx.moveTo(36,gy);ctx.lineTo(W-8,gy);ctx.stroke();}
var n=days.length,bw=(W-48)/n;for(i=0;i<n;i++){var d=days[i],h=(H-58)*(d.checks/mx),x=42+i*bw+2,y=H-28-h;
ctx.fillStyle='#93c5fd';ctx.fillRect(x,y,Math.max(bw-4,2),h);
if(d.failed>0){var fh=(H-58)*(d.failed/mx);ctx.fillStyle='#ef4444';ctx.fillRect(x,H-28-fh,Math.max(bw-4,2),fh);}
ctx.fillStyle=t.mut;ctx.font='10px sans-serif';if(bw>26)ctx.fillText(String(d.day).slice(5),x,H-12);}
ctx.fillStyle=t.ink;ctx.font='12px sans-serif';ctx.fillText('Checks/day (blue), failed overlay (red) — peak '+mx+'/day',42,16);}
function drawDonut(dist){var cv=$('statusDonut');if(!cv||!cv.getContext)return;var f=fitCanvas(cv,220),ctx=f.ctx,W=f.W,H=f.H,t=themeInk();ctx.clearRect(0,0,W,H);
var order=['OK','WARNING','CRITICAL','EXPIRED','ERROR','NEVER_CHECKED'],colors={OK:'#22c55e',WARNING:'#eab308',CRITICAL:'#f97316',EXPIRED:'#ef4444',ERROR:'#a855f7',NEVER_CHECKED:'#94a3b8'};
var total=0,i;for(i=0;i<order.length;i++)total+=(dist[order[i]]||0);
var lg=$('statusLegend');if(lg){lg.textContent='';for(i=0;i<order.length;i++){var sp=document.createElement('span');var dot=document.createElement('span');dot.className='dot';dot.style.background=colors[order[i]];sp.appendChild(dot);sp.appendChild(document.createTextNode(order[i].replace(/_/g,' ')+' '+(dist[order[i]]||0)));lg.appendChild(sp);}}
if(!total){ctx.fillStyle=t.mut;ctx.font='13px sans-serif';ctx.textAlign='center';ctx.fillText('No monitored domains yet.',W/2,H/2);ctx.textAlign='left';return;}
var cx=W<480?W/2:112,cy=W<480?102:H/2,r=W<480?68:80,inner=W<480?46:54;
var ang=-Math.PI/2;for(i=0;i<order.length;i++){var v=dist[order[i]]||0;if(!v)continue;var a2=ang+Math.PI*2*v/total;ctx.beginPath();ctx.arc(cx,cy,r,ang,a2);ctx.arc(cx,cy,inner,a2,ang,true);ctx.closePath();ctx.fillStyle=colors[order[i]];ctx.fill();ang=a2;}
try{var sep=getComputedStyle(cv).backgroundColor;ctx.lineWidth=2;ctx.strokeStyle=sep;ctx.beginPath();ctx.arc(cx,cy,r,0,7);ctx.stroke();ctx.beginPath();ctx.arc(cx,cy,inner,0,7);ctx.stroke();}catch(_){}
ctx.textAlign='center';ctx.fillStyle=t.ink;ctx.font='800 26px Inter,system-ui,sans-serif';ctx.fillText(String(total),cx,cy+3);ctx.fillStyle=t.mut;ctx.font='11px sans-serif';ctx.fillText('domains',cx,cy+19);ctx.textAlign='left';}
function renderMilestones(m){var box=$('msBars');if(!box)return;box.textContent='';var defs=[['30d','30-day warning','#60a5fa'],['15d','15-day warning','#eab308'],['daily','Daily · ≤14d','#f97316'],['error-daily','Error daily','#a855f7']];
var mx=1,i,any=false;for(i=0;i<defs.length;i++){mx=Math.max(mx,m[defs[i][0]]||0);if(m[defs[i][0]])any=true;}
if(!any){var em=document.createElement('span');em.className='muted';em.textContent='No alerts sent yet.';box.appendChild(em);return;}
for(i=0;i<defs.length;i++){var row=document.createElement('div');row.className='bar-row';
var lb=document.createElement('span');lb.className='lbl';lb.textContent=defs[i][1];row.appendChild(lb);
var trk=document.createElement('div');trk.className='track';var fl=document.createElement('div');fl.className='fill';fl.style.width=(100*(m[defs[i][0]]||0)/mx)+'%';fl.style.background=defs[i][2];trk.appendChild(fl);row.appendChild(trk);
var ct=document.createElement('span');ct.className='cnt';ct.textContent=(m[defs[i][0]]||0);row.appendChild(ct);box.appendChild(row);}}
function refreshAnalytics(){req('GET','/api/analytics').then(renderAnalytics).catch(function(e){$('schedStatus').textContent='Analytics unavailable: '+e.message;});
req('GET','/api/alerts?limit=20').then(function(d){var tb=$('abody');tb.textContent='';var rows=d.alerts||[];
if(!rows.length){var tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=5;td.className='muted';td.textContent='No alerts sent yet. Milestones: once at 30d, once at 15d, daily from 14d to expiry.';tr.appendChild(td);tb.appendChild(tr);return;}
rows.forEach(function(a){var tr=document.createElement('tr');
var c0=document.createElement('td');c0.className='mono';var ad=String(a.domain||'');c0.textContent=(ad.length>=25?ad.slice(0,25)+'…':ad)+':'+a.port;c0.title=ad+':'+a.port;tr.appendChild(c0);
var c1=document.createElement('td');c1.textContent=a.milestone;tr.appendChild(c1);
var c2=document.createElement('td');c2.textContent=(a.days_remaining==null?'—':a.days_remaining);tr.appendChild(c2);
var c3=document.createElement('td');c3.appendChild(stBadge(a.status));tr.appendChild(c3);
var c4=document.createElement('td');c4.className='mono';c4.textContent=a.sent_at?fmtDT(a.sent_at):'—';tr.appendChild(c4);tb.appendChild(tr);});}).catch(function(){/* alerts table stays as-is */});}
/* ---- Enterprise shell: tabbed views ---- */
var VIEW_TITLES={dashboard:['Dashboard','Fleet health at a glance'],certs:['Import Domains','Ad-hoc checks — paste, upload, verify'],domains:['Monitored domains','SQLite watch list · checked automatically'],analytics:['Analytics','History, trends and alert log'],settings:['Settings','Checker, Teams and policy']};
function showView(v){if(!document.getElementById('view-'+v))v='dashboard';
document.querySelectorAll('.view').forEach(function(s){s.classList.toggle('active',s.id==='view-'+v);});
document.querySelectorAll('.navlink').forEach(function(n){n.classList.toggle('active',n.getAttribute('data-view')===v);});
var t=VIEW_TITLES[v];$('navTitle').textContent=t[0];$('navCrumb').textContent=t[1];
document.body.classList.remove('nav-open');
try{if(location.hash!=='#/'+v)history.replaceState(null,'','#/'+v);}catch(_){}
window.scrollTo(0,0);
if(v==='analytics'&&window.__aCache){var __c=window.__aCache;drawDaily(__c.daily||[]);drawDonut(__c.status_distribution||{});}}
var __rzT=null;window.addEventListener('resize',function(){clearTimeout(__rzT);__rzT=setTimeout(function(){var av=document.getElementById('view-analytics');if(window.__aCache&&av&&av.classList.contains('active')){var __c2=window.__aCache;drawDaily(__c2.daily||[]);drawDonut(__c2.status_distribution||{});}},250);});
document.querySelectorAll('.navlink').forEach(function(n){n.addEventListener('click',function(){showView(n.getAttribute('data-view'));});});
$('navToggle').addEventListener('click',function(){document.body.classList.toggle('nav-open');});
(function(){var g=$('goTop');if(!g)return;window.addEventListener('scroll',function(){g.classList.toggle('show',window.scrollY>400);},{passive:true});g.addEventListener('click',function(){window.scrollTo({top:0,behavior:'smooth'});});})();
(function(){var h=String(location.hash||'').replace('#/','');if(h&&document.getElementById('view-'+h))showView(h);})();
document.querySelectorAll('.stat[data-f]').forEach(function(c){function go(){var f=c.getAttribute('data-f')||'';showView('certs');$('fStatus').value=f;certPage=1;render();if(!cache.results.length)toast('Run a check to populate results, then filter.');}c.addEventListener('click',go);c.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();go();}});});
(function(){var t='dark';try{t=localStorage.getItem('ssl-theme')||'dark';}catch(_){}applyTheme(t);})();
refreshDb();refreshAnalytics();icons();setInterval(function(){refreshDb();refreshAnalytics();},60000);
/* ---- Settings page ---- */
var webhookDirty=false;
$('setWebhook').addEventListener('input',function(){webhookDirty=true;});
function srcTag(key,src){var el=document.getElementById('src_'+key);if(!el)return;el.textContent=src;el.className='src '+src;}
function applySettingsView(d){var s=d.settings||{};
$('setWebhook').value='';webhookDirty=false;
$('setFormat').value=s.teams_format.value;
$('setNotif').value=s.notifications_enabled.value;
$('setInterval').value=(parseFloat(s.check_interval_seconds.value)/60);
$('setTimeout').value=s.check_timeout_seconds.value;
$('setWorkers').value=s.check_workers.value;
$('setUiUrl').value=s.ui_url.value;
$('setPriv').value=s.allow_private.value;
$('setTz').value=s.display_timezone.value;
Object.keys(s).forEach(function(k){srcTag(k,s[k].source);});
var w=s.teams_webhook_url;$('setStatus').textContent=w.configured?('Teams webhook: configured ('+w.masked+' · '+w.source+')'):'Teams webhook: NOT set — milestone alerts cannot be sent';}
function loadSettings(){req('GET','/api/settings').then(applySettingsView).catch(function(e){$('setStatus').textContent='Settings unavailable: '+e.message;});}
$('btnSaveSettings').addEventListener('click',function(){var b=this;b.disabled=true;$('setMsg').textContent='Saving…';
var mins=parseFloat($('setInterval').value||'5');
var body={teams_format:$('setFormat').value,notifications_enabled:$('setNotif').value,
check_interval_seconds:String(Math.round(mins*60)),check_timeout_seconds:$('setTimeout').value,
check_workers:$('setWorkers').value,ui_url:$('setUiUrl').value.trim(),allow_private:$('setPriv').value,
display_timezone:$('setTz').value.trim()};
if(webhookDirty&&$('setWebhook').value)body.teams_webhook_url=$('setWebhook').value;
req('PUT','/api/settings',body).then(function(d){applySettingsView(d);$('setMsg').textContent='Saved.';toast('Settings saved — check interval and toggles apply live.');}).catch(function(e){var m=e.message;if(e.details&&typeof e.details==='object'){var p=[];Object.keys(e.details).forEach(function(k){p.push(k+': '+e.details[k]);});if(p.length)m+=' — '+p.join('; ');}$('setMsg').textContent='Save failed.';toast('Save failed: '+m);}).finally(function(){b.disabled=false;});});
$('btnClearWebhook').addEventListener('click',function(){if(!confirm('Remove the saved webhook URL and fall back to the TEAMS_WEBHOOK_URL env var?'))return;
req('PUT','/api/settings',{clear_webhook:true}).then(function(d){applySettingsView(d);toast('Saved webhook removed — using env var.');}).catch(function(e){toast('Remove failed: '+e.message);});});
$('btnTestWebhook').addEventListener('click',async function(){if(!confirm('Send a test card to the configured Teams webhook?'))return;var b=this;b.disabled=true;
try{var r=await req('POST','/api/settings/test',{});toast(r.ok?('Test card sent ('+r.message+')'):('Test failed: '+r.message));}
catch(e){toast('Test failed: '+e.message);}finally{b.disabled=false;}});
loadSettings();
})();
