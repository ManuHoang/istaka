/* Back Room table framework: relay networking (host + phones), table codes, TV panel, join screen. */
(function(){
'use strict';
const SITE='https://manuhoang.github.io/istaka/';
const CODE_AB='ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const GAMES=['okey','poker','punto'];
const PAGES={okey:'okey.html',poker:'poker.html',punto:'punto.html'};
const NAMES={okey:'Okey',poker:'Poker',punto:'Punto Banco'};
const BROKERS=['wss://test.mosquitto.org:8081/mqtt','wss://broker.emqx.io:8084/mqtt','wss://broker.hivemq.com:8884/mqtt'];
const T={};
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function randInt(n){const a=new Uint32Array(1);crypto.getRandomValues(a);return a[0]%n;}
const clean=s=>String(s||'').replace(/[\u0000-\u001f<>]/g,'').trim().slice(0,16);
const b64=u8=>{let s='';for(const b of u8)s+=String.fromCharCode(b);return btoa(s);};
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
let toastT;
function toast(m){let t=$('#toast');if(!t){t=document.createElement('div');t.id='toast';t.className='toast';document.body.appendChild(t);}t.textContent=m;t.hidden=false;clearTimeout(toastT);toastT=setTimeout(()=>{t.hidden=true;},3000);}
const LS={get(k,d){try{const v=localStorage.getItem(k);return v==null?d:v;}catch(e){return d;}},set(k,v){try{localStorage.setItem(k,v);}catch(e){}}};

/* ---------- codes ---------- */
function normCode(c){return String(c||'').toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,5);}
function codeGame(code){code=normCode(code);const k=CODE_AB.indexOf(code[0]);if(code.length!==5||k<0)return null;return GAMES[Math.floor((k%9)/3)]||null;}
function codeBroker(code){return CODE_AB.indexOf(normCode(code)[0])%3;}
function makeCode(game,broker){
  const g=GAMES.indexOf(game);
  const firsts=[...CODE_AB].filter((_,k)=>k%9===g*3+broker);
  return firsts[randInt(firsts.length)]+Array.from({length:4},()=>CODE_AB[randInt(CODE_AB.length)]).join('');
}
function pageBase(){return /^https?:$/.test(location.protocol)?location.origin+location.pathname.replace(/[^/]*$/,''):SITE;}
function joinURL(game,code){return pageBase()+PAGES[game]+'?t='+code;}
function gid(){
  let id=null;try{id=sessionStorage.getItem('br.gid');}catch(e){}
  if(!id){id='g'+Date.now().toString(36)+randInt(1e9).toString(36);try{sessionStorage.setItem('br.gid',id);}catch(e){}}
  return id;
}

/* ---------- scripts ---------- */
const scriptP={};
function loadScript(src,test){
  if(test())return Promise.resolve(true);
  if(scriptP[src])return scriptP[src];
  scriptP[src]=new Promise(res=>{const sc=document.createElement('script');sc.src=src;sc.onload=()=>res(test());sc.onerror=()=>{delete scriptP[src];res(false);};document.head.appendChild(sc);setTimeout(()=>res(test()),12000);});
  return scriptP[src];
}
const loadMqtt=()=>loadScript('https://unpkg.com/mqtt@5.10.1/dist/mqtt.min.js',()=>!!window.mqtt);
const loadQR=()=>loadScript('https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js',()=>!!window.qrcode);

/* ---------- crypto (messages are encrypted with a key derived from the table code) ---------- */
async function codeKey(code){
  if(!(window.crypto&&crypto.subtle))return null;
  const te=new TextEncoder();
  const base=await crypto.subtle.importKey('raw',te.encode(code),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:te.encode('backroom-v1'),iterations:60000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function seal(key,obj){
  const txt=JSON.stringify(obj);
  if(!key)return 'P'+txt;
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(txt));
  return 'E'+b64(iv)+'.'+b64(new Uint8Array(ct));
}
async function unseal(key,str){
  if(str[0]==='P')return key?null:JSON.parse(str.slice(1));
  if(str[0]!=='E'||!key)return null;
  const i=str.indexOf('.');
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(str.slice(1,i))},key,unb64(str.slice(i+1)));
  return JSON.parse(new TextDecoder().decode(pt));
}
function brokerConnect(url){
  return new Promise(res=>{
    let c;try{c=mqtt.connect(url,{connectTimeout:7000,reconnectPeriod:2000,keepalive:30,clean:true});}catch(e){res(null);return;}
    let done=false;
    c.once('connect',()=>{if(!done){done=true;res(c);}});
    setTimeout(()=>{if(!done){done=true;try{c.end(true);}catch(e){}res(null);}},8000);
  });
}

/* ---------- host ---------- */
async function host(opts){
  // opts: {game,max,onJoin(g),onLeave(g),onMsg(g,d)}
  if(!(await loadMqtt()))throw new Error('relay');
  let client=null,bi=-1;
  for(let i=0;i<BROKERS.length&&!client;i++){client=await brokerConnect(BROKERS[i]);if(client)bi=i;}
  if(!client)throw new Error('relay');
  const code=makeCode(opts.game,bi);
  const key=await codeKey(code);
  const base='br/v1/'+code+'/';
  const guests=new Map();
  let outq=Promise.resolve(),inq=Promise.resolve(),closed=false;
  const pub=(topic,obj)=>{outq=outq.then(async()=>{if(closed)return;try{client.publish(base+topic,await seal(key,obj),{qos:1});}catch(e){}});};
  const toG=(id,obj)=>pub('g/'+id,obj);
  const drop=(g,why)=>{if(!guests.has(g.id))return;guests.delete(g.id);try{opts.onLeave&&opts.onLeave(g,why);}catch(e){console.error(e);}};
  client.on('message',(topic,payload)=>{
    const str=payload.toString();
    inq=inq.then(async()=>{
      let m;try{m=await unseal(key,str);}catch(e){return;}
      if(!m||typeof m!=='object'||typeof m.f!=='string')return;
      const id=m.f.slice(0,48);
      let g=guests.get(id);
      if(m.t==='join'){
        if(g&&g.sid===m.sid){g.last=Date.now();toG(id,{t:'welcome'});return;}
        if(g)drop(g,'rejoin');
        if(guests.size>=(opts.max||8)){toG(id,{t:'full'});return;}
        g={id,sid:m.sid,name:clean(m.name)||'Player',last:Date.now()};
        guests.set(id,g);toG(id,{t:'welcome'});
        try{opts.onJoin&&opts.onJoin(g);}catch(e){console.error(e);}
        return;
      }
      if(!g)return;
      g.last=Date.now();
      if(m.t==='m'){try{opts.onMsg&&opts.onMsg(g,m.d);}catch(e){console.error(e);}}
      else if(m.t==='bye')drop(g,'left');
    });
  });
  client.subscribe(base+'h',{qos:1});
  const hb=setInterval(()=>{
    for(const g of [...guests.values()]){toG(g.id,{t:'ping'});if(Date.now()-g.last>20000)drop(g,'timeout');}
  },4000);
  return {
    code,
    guests,
    send(id,d){if(guests.has(id))toG(id,{t:'m',d});},
    sendAll(fn){for(const g of guests.values()){const d=fn(g);if(d!=null)toG(g.id,{t:'m',d});}},
    close(){for(const g of guests.values())toG(g.id,{t:'bye'});clearInterval(hb);setTimeout(()=>{closed=true;try{client.end(true);}catch(e){}},700);}
  };
}

/* ---------- phone side ---------- */
async function connect(opts){
  // opts: {code,name,onWelcome,onMsg(d),onClose(reason),onStatus(text)}
  const code=normCode(opts.code),me=gid();
  const status=t=>{try{opts.onStatus&&opts.onStatus(t);}catch(e){}};
  status('Reaching the relay…');
  if(!(await loadMqtt()))throw new Error('relay');
  const client=await brokerConnect(BROKERS[codeBroker(code)]);
  if(!client)throw new Error('relay');
  const key=await codeKey(code);
  const base='br/v1/'+code+'/';
  const sid=Math.random().toString(36).slice(2);
  let outq=Promise.resolve(),inq=Promise.resolve(),welcomed=false,closed=false,last=Date.now();
  const pub=obj=>{obj.f=me;outq=outq.then(async()=>{if(closed)return;try{client.publish(base+'h',await seal(key,obj),{qos:1});}catch(e){}});};
  const finish=reason=>{if(closed)return;closed=true;clearInterval(hb);clearInterval(jt);setTimeout(()=>{try{client.end(true);}catch(e){}},500);try{opts.onClose&&opts.onClose(reason);}catch(e){console.error(e);}};
  client.on('message',(topic,payload)=>{
    const str=payload.toString();
    inq=inq.then(async()=>{
      let m;try{m=await unseal(key,str);}catch(e){return;}
      if(!m||typeof m!=='object'||closed)return;
      last=Date.now();
      if(m.t==='welcome'){if(!welcomed){welcomed=true;clearInterval(jt);status('');try{opts.onWelcome&&opts.onWelcome();}catch(e){console.error(e);}}}
      else if(m.t==='m'&&welcomed){try{opts.onMsg&&opts.onMsg(m.d);}catch(e){console.error(e);}}
      else if(m.t==='full')finish('full');
      else if(m.t==='bye')finish('closed');
    });
  });
  client.on('offline',()=>status('Connection lost, reconnecting…'));
  await new Promise(r=>client.subscribe(base+'g/'+me,{qos:1},()=>r()));
  status('Looking for the table…');
  let tries=0;
  const sendJoin=()=>pub({t:'join',name:opts.name,sid});
  sendJoin();
  const jt=setInterval(()=>{if(welcomed){clearInterval(jt);return;}if(++tries>7){finish('notfound');return;}sendJoin();},1500);
  const hb=setInterval(()=>{if(!welcomed)return;pub({t:'ping'});if(Date.now()-last>15000)finish('lost');},4000);
  return {send(d){if(welcomed&&!closed)pub({t:'m',d});},leave(){if(!closed){pub({t:'bye'});outq.then(()=>finish('left'));}}};
}

/* phone session with automatic reconnect */
function session(opts){
  // opts: {code,name,onReady,onMsg,onStatus,onEnd(reason)}
  const S={conn:null,retries:0,ended:false};
  const reasons={full:'That table is full.',closed:'The host closed the table.',notfound:'No open table with that code. Check it, and make sure the TV page stays open.',relay:"Couldn't reach the relay. Check your internet."};
  async function go(){
    try{
      S.conn=await connect({code:opts.code,name:opts.name,onStatus:opts.onStatus,
        onWelcome(){S.retries=0;opts.onReady&&opts.onReady();},
        onMsg:opts.onMsg,
        onClose(r){
          S.conn=null;if(S.ended||r==='left')return;
          if((r==='lost')&&S.retries<8){S.retries++;opts.onStatus&&opts.onStatus('Connection lost, reconnecting…');setTimeout(go,1500);return;}
          S.ended=true;opts.onEnd&&opts.onEnd(reasons[r]||'Disconnected.');
        }});
    }catch(e){
      if(S.retries>0&&S.retries<8){S.retries++;setTimeout(go,2500);return;}
      S.ended=true;opts.onEnd&&opts.onEnd(reasons.relay);
    }
  }
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&!S.ended&&!S.conn){S.retries=Math.max(S.retries,1);go();}});
  go();
  return {send(d){S.conn&&S.conn.send(d);},leave(){S.ended=true;S.conn&&S.conn.leave();}};
}

/* ---------- device niceties ---------- */
let WL=null,AC=null;
async function wakeLock(){try{if('wakeLock' in navigator&&document.visibilityState==='visible')WL=await navigator.wakeLock.request('screen');}catch(e){}}
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&T._wantWake)wakeLock();});
function keepAwake(){T._wantWake=true;wakeLock();}
function unlockAudio(){try{AC=AC||new (window.AudioContext||window.webkitAudioContext)();if(AC.state==='suspended')AC.resume();const b=AC.createBuffer(1,1,22050),s=AC.createBufferSource();s.buffer=b;s.connect(AC.destination);s.start(0);}catch(e){}}
function ping(){if(!AC)return;try{const t=AC.currentTime,o=AC.createOscillator(),g=AC.createGain();o.frequency.setValueAtTime(880,t);o.frequency.setValueAtTime(1175,t+.12);g.gain.setValueAtTime(.0001,t);g.gain.exponentialRampToValueAtTime(.3,t+.02);g.gain.exponentialRampToValueAtTime(.0001,t+.32);o.connect(g);g.connect(AC.destination);o.start(t);o.stop(t+.35);}catch(e){}}
function toggleFS(){
  const d=document,el=d.documentElement;
  try{
    if(d.fullscreenElement||d.webkitFullscreenElement)(d.exitFullscreen||d.webkitExitFullscreen).call(d);
    else{const r=el.requestFullscreen||el.webkitRequestFullscreen;if(!r){toast('Press F11 for full screen.');return;}const p=r.call(el);if(p&&p.catch)p.catch(()=>toast('Press F11 for full screen.'));}
  }catch(e){toast('Press F11 for full screen.');}
}
const isFS=()=>!!(document.fullscreenElement||document.webkitFullscreenElement);

/* ---------- TV panel ---------- */
let QR={url:'',src:''};
async function qrFor(url){
  if(QR.url===url&&QR.src)return QR.src;
  if(!(await loadQR()))return '';
  try{const q=qrcode(0,'M');q.addData(url);q.make();QR={url,src:q.createDataURL(8,1)};return QR.src;}catch(e){return '';}
}
function tvPanel(el,o){
  // o: {game,code,players:[{name,kind,extra}],extra:html}
  const url=o.code?joinURL(o.game,o.code):'';
  const img=QR.url===url&&QR.src?`<img alt="QR code to join" src="${QR.src}">`:(url?'Loading QR…':'Opening the table…');
  el.innerHTML=`<div class="tools"><a class="small" href="./">← Menu</a><button class="small${isFS()?' on':''}" data-tv="fs">${isFS()?'Exit full screen':'Full screen'}</button></div>
    <div class="lbl" style="font-weight:700">Scan with your phone camera to join</div>
    <div class="qr" id="qrBox">${img}</div>
    <div class="lbl">or open the menu and type</div>
    <div class="bigcode">${esc(o.code||'·····')}</div>
    <div class="url">${esc(url)}</div>
    <div class="who">${(o.players||[]).map(p=>`<div><span>${esc(p.name)}</span><span class="${p.kind==='phone'?'ph':'muted'}">${esc(p.extra!=null?p.extra:p.kind)}</span></div>`).join('')}</div>
    ${o.extra||''}`;
  if(url&&!(QR.url===url&&QR.src))qrFor(url).then(src=>{const b=document.getElementById('qrBox');if(src&&b&&!b.querySelector('img'))b.innerHTML=`<img alt="QR code to join" src="${src}">`;});
}
document.addEventListener('click',e=>{const b=e.target.closest('[data-tv="fs"]');if(b)toggleFS();});
document.addEventListener('keydown',e=>{if(document.body.classList.contains('tv')&&(e.key==='f'||e.key==='F')&&!/INPUT|TEXTAREA|SELECT/.test((e.target||{}).tagName||''))toggleFS();});
['fullscreenchange','webkitfullscreenchange'].forEach(ev=>document.addEventListener(ev,()=>{T.onFS&&T.onFS();}));

/* ---------- join + chooser screens ---------- */
function joinScreen(el,o){
  // o: {game,code,msg,onJoin(name,code)}
  el.hidden=false;el.className='screen';
  el.innerHTML=`<form class="jcard" id="jForm"><div class="brand">${esc(NAMES[o.game]||'Back Room').toUpperCase().replace(/(\S+)$/,'<span>$1</span>')}</div>
    <label class="muted" for="jName">Your name</label><input class="txt" id="jName" maxlength="16" value="${esc(LS.get('br.nick',''))}" placeholder="Your name" autocomplete="nickname">
    <label class="muted" for="jCode">Table code (on the TV)</label><input class="codein" id="jCode" maxlength="5" value="${esc(normCode(o.code))}" autocapitalize="characters" autocomplete="off" spellcheck="false" placeholder="•••••">
    <button class="btn gold" id="jGo" type="submit">Join the table</button>
    <div class="muted" id="jStatus">${esc(o.msg||'')}</div>
    <a href="./" style="font-size:13px">← Back to the menu</a></form>`;
  el.querySelector('#jForm').addEventListener('submit',e=>{
    e.preventDefault();
    const name=clean(el.querySelector('#jName').value),code=normCode(el.querySelector('#jCode').value);
    if(!name){toast('Type your name first.');return;}
    if(code.length!==5){toast('The table code is 5 characters, shown on the TV.');return;}
    const g=codeGame(code);
    if(g&&g!==o.game){location.href=PAGES[g]+'?t='+code;return;}
    LS.set('br.nick',name);
    unlockAudio();keepAwake();
    if(document.activeElement)document.activeElement.blur();
    el.querySelector('#jStatus').textContent='Connecting…';
    o.onJoin(name,code);
  });
}
function chooser(el,game){
  el.hidden=false;el.className='screen';
  el.innerHTML=`<div class="jcard"><div class="brand">${esc(NAMES[game].toUpperCase())}</div>
    <a class="btn gold" href="?tv" style="text-align:center;text-decoration:none">Host on this screen (TV)</a>
    <a class="btn dark" href="?t=" style="text-align:center;text-decoration:none">Join a table with a code</a>
    <a href="./" style="font-size:13px">← Back to the menu</a></div>`;
}

Object.assign(T,{SITE,CODE_AB,GAMES,PAGES,NAMES,$,esc,randInt,clean,toast,LS,normCode,codeGame,makeCode,joinURL,gid,host,connect,session,keepAwake,unlockAudio,ping,toggleFS,isFS,tvPanel,joinScreen,chooser,qrFor});
window.TABLE=T;
})();
