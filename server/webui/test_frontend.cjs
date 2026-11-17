'use strict';
// Executes the shipped inline JS, not a rewritten payload builder. No network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const uid = 'a'.repeat(32), other = 'b'.repeat(32);
const flush = async () => { for (let i=0;i<30;i++) await Promise.resolve(); };
function snapshot(id='A') {
  return {schema:1,ok:true,csrf:'csrf',managedAvailable:true,server:{id},
    users:[{id:uid,name:'same',role:'admin',status:'active'}, {id:other,name:'same',role:'user',status:'active'}],
    services:[{unit:'xio-stack',active:'active',sub:'running',enabled:'enabled'}],
    cascade:{kind:'legacy-rivet-gateway',state:'active',unit:'xio-rivet-gateway'},
    nativeCascade:{available:true,enabled:false}};
}
async function setup(storage=new Map([['xio_token','fixture']]), pathname='/') {
  class Element {
    constructor(attrs={}) { this.attrs=attrs;this.listeners={};this.value='';this.hidden=false;this.disabled=false;this.innerHTML='';this.textContent='';this.clicks=0;this.href='';this.download=''; }
    getAttribute(k){return this.attrs[k] ?? null;}
    setAttribute(k,v){this.attrs[k]=String(v);}
    removeAttribute(k){delete this.attrs[k];}
    addEventListener(k,fn){this.listeners[k]=fn;}
    focus(){}
    select(){}
    click(){this.clicks++;if(this.listeners.click)this.listeners.click({target:this});}
    remove(){this.removed=true;}
  }
  const elements = new Map(), events={}, calls=[], copied=[], downloads=[];
  const el = id => {if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
  let current=snapshot(), post=()=>Promise.resolve({status:200,ok:true,json:async()=>({schema:1,ok:true,data:{revoked:uid,serverId:'A'},outcomeUnknown:false})});
  let get=()=>Promise.resolve({status:200,ok:true,json:async()=>current});
  let confirms=[];
  const sandbox={document:{getElementById:el,addEventListener:(k,fn)=>events[k]=fn},HTMLElement:Element,
    window:{location:{search:'',pathname},history:{replaceState(){}},addEventListener(){}},
    sessionStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},
    fetch:(url,opts)=>{calls.push({url,...opts,body:opts.body?JSON.parse(opts.body):null});return opts.method==='POST'?post():get();},
    confirm:msg=>{confirms.push(msg);return true;},URLSearchParams,Promise,Date,JSON,Error,Number,String,isFinite,
    atob:s=>Buffer.from(s,'base64').toString('binary'),Uint8Array,TextDecoder,
    setInterval:()=>1,clearInterval(){},setTimeout:()=>1,clearTimeout(){}};
  vm.runInNewContext(script,sandbox,{filename:'actual-index-inline.js'});
  await flush();
  return {el,events,calls,storage,confirms,Element,sandbox,setPost:fn=>post=fn,setGet:fn=>get=fn,
    async refresh(value){current=value;el('refresh').listeners.click();await flush();},
    click(attrs){events.click({target:new Element(attrs)});}};
}
(async()=>{
  // Actual rendering includes immutable IDs even for duplicate display names.
  let h=await setup();
  assert.match(h.el('users').innerHTML,new RegExp('data-revoke="'+uid+'"'));
  assert.match(h.el('users').innerHTML,new RegExp('data-revoke="'+other+'"'));
  assert.match(h.el('services').innerHTML,/data-server="A"/);
  assert.match(h.el('native-state').textContent,/"enabled": false/);
  assert.equal(h.el('cascade-state').textContent,'active');
  console.log('PASS actual rendering / duplicate names / distinct native');

  const empty=snapshot(); empty.users=[];
  await h.refresh(empty); assert.match(h.el('users').innerHTML,/пользователей: 0/);
  const unknown=snapshot(); unknown.users=null; unknown.managedAvailable=false; unknown.server.id=null;
  await h.refresh(unknown); assert.match(h.el('users').innerHTML,/пользователи: неизвестно/);
  assert.equal(h.el('cascade-on').disabled,true);
  console.log('PASS known empty versus unknown state');

  // Old rendered control A must not be retargeted to current global state B.
  await h.refresh(snapshot('B'));
  h.click({'data-revoke':uid,'data-server':'A','data-name':'same','data-role':'admin'});
  await flush();
  const mutation=h.calls.find(c=>c.method==='POST');
  assert.deepEqual(mutation.body,{expectedServerId:'A',id:uid});
  assert.match(h.confirms[0],/дочерние/);
  assert.equal(h.storage.has('xio_webui_pending_v1'),false);
  console.log('PASS stale rendered identity / UID payload / admin warning');

  h=await setup();
  h.setPost(()=>Promise.resolve({status:502,ok:false,json:async()=>({schema:1,ok:false,error:'partial',errorCode:'OPERATION_FAILED',outcomeUnknown:true})}));
  h.click({'data-revoke':uid,'data-server':'A','data-name':'same'});
  h.click({'data-revoke':uid,'data-server':'A','data-name':'same'});
  await flush();
  assert.equal(h.calls.filter(c=>c.method==='POST').length,1);
  assert.ok(h.storage.has('xio_webui_pending_v1'));
  const revoked=snapshot();revoked.users[0].revoked=true;
  await h.refresh(revoked);
  assert.ok(h.storage.has('xio_webui_pending_v1'));
  assert.match(h.el('mutation-state').textContent,/НЕИЗВЕСТЕН/);
  let reloaded=await setup(h.storage);
  reloaded.click({'data-revoke':uid,'data-server':'A'});await flush();
  assert.equal(reloaded.calls.filter(c=>c.method==='POST').length,0);
  console.log('PASS partial unknown / duplicate suppression / refresh+reload sticky');

  for(const reply of [()=>Promise.reject(new Error('lost')),()=>Promise.resolve({status:200,ok:true,json:async()=>({ok:false,error:'bad'})}),
                      ()=>Promise.resolve({status:200,ok:true,json:async()=>({})})]) {
    h=await setup();h.setPost(reply);
    h.click({'data-verb':'restart','data-unit':'xio-stack','data-server':'A'});await flush();
    assert.ok(h.storage.has('xio_webui_pending_v1'));
    assert.equal(h.calls.filter(c=>c.method==='POST').length,1);
    assert.deepEqual(h.calls.find(c=>c.method==='POST').body,{expectedServerId:'A'});
  }
  console.log('PASS no success from HTTP2xx / missing envelope / lost fetch');

  h=await setup();
  h.setGet(()=>Promise.reject(new Error('refresh lost')));
  h.click({'data-revoke':uid,'data-server':'A','data-name':'same'});await flush();
  assert.equal(h.storage.has('xio_webui_pending_v1'),false);
  assert.match(h.el('user-msg').textContent,/подтверждена/);
  assert.equal(h.el('cascade-on').disabled,true);
  console.log('PASS successful mutation distinct from failed refresh');

  h=await setup();
  h.sandbox.confirm=()=>false;
  h.click({'data-revoke':uid,'data-server':'A'});await flush();
  assert.equal(h.calls.filter(c=>c.method==='POST').length,0);
  h.el('logout').listeners.click();
  h.click({'data-revoke':uid,'data-server':'A'});await flush();
  assert.equal(h.calls.filter(c=>c.method==='POST').length,0);
  assert.match(html, /id="add-form"/);
  assert.match(html, /Выпустить профиль/);
  assert.doesNotMatch(html, /полный выпуск остаётся в работе/);
  console.log('PASS cancel / logout invalidation / real issuance control');

  // The one-time profile lives only in the issuance field and memory, never
  // in storage. An invalid success envelope must not show a profile.
  h = await setup();
  const profile = 'xio://'+Buffer.from(JSON.stringify({schema:1,name:'Alice',userId:uid,
    serverId:'A',configs:{awg:'[Interface]\nPrivateKey = fixture\n'}})).toString('base64url');
  h.setPost(()=>Promise.resolve({status:200,ok:true,json:async()=>({schema:1,ok:true,outcomeUnknown:false,
    data:{uid,profile}})}));
  h.el('add-name').value = 'Alice';
  h.el('add-form').listeners.submit({preventDefault(){}});
  await flush();
  assert.equal(h.el('issuance').hidden,false);
  assert.equal(h.el('issued-profile').value,profile);
  assert.equal(h.el('issued-uid').textContent,uid);
  assert.equal(h.storage.has('xio_webui_pending_v1'),false);
  for (const [key,value] of h.storage) assert.notEqual(value,profile);
  h.el('clear-profile').listeners.click();
  assert.equal(h.el('issuance').hidden,true);
  assert.equal(h.el('issued-profile').value,'');
  h = await setup();
  h.setPost(()=>Promise.resolve({status:200,ok:true,json:async()=>({schema:1,ok:true,outcomeUnknown:false,
    data:{uid,profile:'not-a-profile'}})}));
  h.el('add-name').value = 'Alice';
  h.el('add-form').listeners.submit({preventDefault(){}});
  await flush();
  assert.ok(h.storage.has('xio_webui_pending_v1'));
  assert.equal(h.el('issuance').hidden,true);
  console.log('PASS one-time issuance memory only / reject forged profile');

  h = await setup(undefined, '/xio/');
  assert.equal(h.calls.find(c=>c.method!=='POST').url, '/xio/api/state');
  console.log('PASS reverse-proxy API prefix / same-origin calls');

  for (const data of [{}, {revoked:other,serverId:'A'}, {revoked:uid,serverId:'B'}, {revoked:uid}]) {
    h=await setup();h.setPost(()=>Promise.resolve({status:200,ok:true,json:async()=>({schema:1,ok:true,data,outcomeUnknown:false})}));
    h.click({'data-revoke':uid,'data-server':'A'});await flush();
    assert.ok(h.storage.has('xio_webui_pending_v1'));
    assert.doesNotMatch(h.el('user-msg').textContent,/команда подтверждена/);
    assert.equal(h.calls.filter(c=>c.method==='POST').length,1);
  }
  console.log('PASS revoke receipt exact original UID and server');

  for (const service of [undefined,{}, {serverId:'B',unit:'xio-stack',verb:'stop'},
                         {serverId:'A',unit:'xio-ready',verb:'stop'}, {serverId:'A',unit:'xio-stack',verb:'start'}]) {
    h=await setup();h.setPost(()=>Promise.resolve({status:200,ok:true,json:async()=>({schema:1,ok:true,data:service?{service}:undefined,outcomeUnknown:false})}));
    h.click({'data-verb':'stop','data-unit':'xio-stack','data-server':'A'});await flush();
    assert.ok(h.storage.has('xio_webui_pending_v1'));
    assert.doesNotMatch(h.el('svc-msg').textContent,/команда подтверждена/);
    assert.equal(h.calls.filter(c=>c.method==='POST').length,1);
  }
  for(const legacy of [false,true]) {
    h=await setup();
    h.setPost(()=>Promise.resolve({status:200,ok:true,json:async()=>({schema:1,ok:true,data:{service:{serverId:'A',unit:legacy?'xio-rivet-gateway':'xio-stack',verb:'stop'}},outcomeUnknown:false})}));
    if(legacy) h.el('cascade-off').listeners.click();
    else h.click({'data-verb':'stop','data-unit':'xio-stack','data-server':'A'});
    await flush();assert.equal(h.storage.has('xio_webui_pending_v1'),false);
    assert.equal(h.calls.filter(c=>c.method==='POST').length,1);
  }
  console.log('PASS service tuple receipt and legacy alias confirmation');

  for(const staleError of [false,true]) {
    h=await setup();let resolves=[];h.setGet(()=>new Promise(resolve=>resolves.push(resolve)));
    h.el('token-input').value='new-token';h.el('login-form').listeners.submit({preventDefault(){}});
    h.el('refresh').listeners.click();await flush();assert.equal(resolves.length,2);
    resolves[1]({status:200,ok:true,json:async()=>snapshot('B')});await flush();
    resolves[0](staleError?{status:401,ok:false,json:async()=>({ok:false,error:'authentication required'})}:
                           {status:200,ok:true,json:async()=>snapshot('A')});await flush();
    assert.match(h.el('users').innerHTML,/data-server="B"/);
    assert.equal(h.storage.get('xio_token'),'new-token');
    assert.equal(h.el('login').hidden,true);
  }
  console.log('PASS shared login/poll ordering ignores stale success and auth failure');

  h=await setup();let resolves=[];h.setGet(()=>new Promise(resolve=>resolves.push(resolve)));
  h.el('refresh').listeners.click();
  h.el('token-input').value='new-token';h.el('login-form').listeners.submit({preventDefault(){}});await flush();
  resolves[1]({status:200,ok:true,json:async()=>snapshot('B')});await flush();
  resolves[0]({status:200,ok:true,json:async()=>snapshot('A')});await flush();
  assert.match(h.el('users').innerHTML,/data-server="B"/);
  console.log('PASS newer login also supersedes older refresh');

  h=await setup();resolves=[];h.setGet(()=>new Promise(resolve=>resolves.push(resolve)));
  h.setPost(()=>Promise.resolve({status:401,ok:false,json:async()=>({ok:false,error:'authentication required'})}));
  h.click({'data-revoke':uid,'data-server':'A'});await flush();assert.equal(resolves.length,1);
  h.el('token-input').value='bad-new-token';h.el('login-form').listeners.submit({preventDefault(){}});await flush();
  resolves[1]({status:401,ok:false,json:async()=>({ok:false,error:'authentication required'})});await flush();
  resolves[0]({status:200,ok:true,json:async()=>snapshot('A')});await flush();
  assert.doesNotMatch(h.el('users').innerHTML,/data-revoke=/);
  assert.doesNotMatch(h.el('services').innerHTML,/data-verb=/);
  assert.equal(h.el('cascade-on').disabled,true);
  h.click({'data-revoke':uid,'data-server':'A'});await flush();
  assert.equal(h.calls.filter(c=>c.method==='POST').length,1);
  console.log('PASS latest failed login invalidates stale actionable context');

  h=await setup();let late;h.setGet(()=>new Promise(resolve=>late=resolve));
  h.el('refresh').listeners.click();h.storage.delete('xio_token');h.el('refresh').listeners.click();await flush();
  assert.doesNotMatch(h.el('users').innerHTML,/data-revoke=/);
  assert.equal(h.el('cascade-on').disabled,true);
  late({status:200,ok:true,json:async()=>snapshot('A')});await flush();
  assert.doesNotMatch(h.el('users').innerHTML,/data-revoke=/);
  h.click({'data-revoke':uid,'data-server':'A'});await flush();
  assert.equal(h.calls.filter(c=>c.method==='POST').length,0);
  console.log('PASS absent token invalidates even during an outstanding read');

  h=await setup();h.setPost(()=>Promise.reject(new Error('lost reply')));
  h.click({'data-revoke':uid,'data-server':'A'});await flush();
  const unknownMarker=h.storage.get('xio_webui_pending_v1');assert.ok(unknownMarker);
  h.setGet(()=>Promise.resolve({status:401,ok:false,json:async()=>({ok:false,error:'authentication required'})}));
  h.el('token-input').value='bad-token';h.el('login-form').listeners.submit({preventDefault(){}});await flush();
  assert.doesNotMatch(h.el('users').innerHTML,/data-revoke=/);
  assert.equal(h.storage.get('xio_webui_pending_v1'),unknownMarker);
  h.el('refresh').listeners.click();await flush();
  assert.equal(h.storage.get('xio_webui_pending_v1'),unknownMarker);
  assert.equal(h.calls.filter(c=>c.method==='POST').length,1);
  console.log('PASS failed login and absent-token invalidation preserve pending UNKNOWN');
})().catch(error=>{console.error(error);process.exitCode=1;});
