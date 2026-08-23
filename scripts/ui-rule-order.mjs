import { spawn } from 'node:child_process';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { authenticateCDP } from './ui-auth.mjs';

// closeChrome ends the browser and removes its throwaway profile.
//
// kill() only delivers the signal; the process is still alive and still holding the profile open
// when it returns, so removing right after it failed every time on Windows and left the directory
// behind. Six hundred of them, and 9.3 GB, was enough to fill the system drive and make an unrelated
// gate fail at the linker with "not enough space on the disk".
//
// Bounded wait, then a best-effort removal: a wedged browser must not hang a gate, and failing to
// tidy up must not fail one either.
async function closeChrome(child, dir) {
  if (child && child.exitCode === null && !child.killed) child.kill();
  if (child) {
    await Promise.race([
      new Promise((r) => child.once('exit', r)),
      new Promise((r) => setTimeout(r, 3000)),
    ]);
  }
  if (!dir) return;
  for (let i = 0; i < 12; i++) {
    try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 4, retryDelay: 150 }); return; }
    catch (_) { await new Promise((r) => setTimeout(r, 250)); }
  }
  // Falling out of that loop used to be silent, so a profile dir that could not be removed — and the
  // browser that may still be holding it — went unnoticed until somebody counted /tmp. Enough of them
  // starve a later gate run.
  console.error(`note: could not remove the Chrome profile dir ${dir}`);
}
// Every sibling gate reads CHROME from the environment; this one hardcoded the Windows install path,
// so it was the single gate that could not run anywhere else — a Linux runner would spawn a path that
// does not exist. CDP_PORT matches ui-wide.mjs, so two gates can run concurrently without colliding.
const PORT = Number(process.env.CDP_PORT || 9522);
const CHROME = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep=ms=>new Promise(r=>setTimeout(r,ms)); const j=async u=>(await fetch(u)).json();
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ord-'));
const c=spawn(CHROME,['--headless=new','--disable-gpu','--no-sandbox','--no-first-run','--hide-scrollbars',
 `--remote-debugging-port=${PORT}`,`--user-data-dir=${dir}`,'--window-size=1280,900','about:blank'],{stdio:'ignore'});
let fails=0; const check=(n,ok,d)=>{ if(!ok)fails++; console.log(`  ${ok?'PASS':'FAIL'}  ${n}${d?'   ['+d+']':''}`); };
try{
 for(let i=0;i<60;i++){try{await j(`http://127.0.0.1:${PORT}/json/version`);break}catch{await sleep(250)}}
 const t=await j(`http://127.0.0.1:${PORT}/json/list`);
 const ws=new WebSocket((t.find(x=>x.type==='page')||t[0]).webSocketDebuggerUrl);
 await new Promise((r,e)=>{ws.onopen=r;ws.onerror=e});
 let id=0; const w=new Map();
 ws.onmessage=e=>{const m=JSON.parse(e.data); if(m.id&&w.has(m.id)){w.get(m.id)(m);w.delete(m.id)}};
 // A CDP command with no reply used to hang this script forever: node exits 13, "unsettled top-level
 // await", printing nothing at all — no gate name, no location. Every sibling script had the same
 // hole; this one hid from the sweep that fixed them because it names the map `w` rather than
 // `waiting`. A deadline turns silence into a locatable error.
 const send=(m,p={})=>new Promise((res,rej)=>{const i=++id;
   const to=setTimeout(()=>{w.delete(i);rej(new Error(`CDP ${m} got no reply in 30000ms`))},30000);
   w.set(i,x=>{clearTimeout(to);return x.error?rej(new Error(x.error.message)):res(x.result)});
   ws.send(JSON.stringify({id:i,method:m,params:p}))});
 const ev=async x=>{const r=await send('Runtime.evaluate',{expression:x,awaitPromise:true,returnByValue:true});
   if(r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description||'eval'); return r.result.value};
 await send('Page.enable');await send('Runtime.enable');
 await send('Page.navigate',{url:process.argv[2]});
 for(let i=0;i<160;i++){if(await ev('typeof route==="function"').catch(()=>false))break;await sleep(250)}
 await authenticateCDP({ send, evaluate: ev, url: process.argv[2] });

 for (const [page, sel] of [['routing','[data-rlstatus]'],['dns','.dns-rule']]) {
   await ev(`location.hash='#${page}'`); await sleep(2600);
   const r = await ev(`(() => {
     const nums = [...document.querySelectorAll('.ord-n')].map(n => n.textContent.trim());
     const btns = [...document.querySelectorAll('.ord-btn')];
     const names = btns.map(b => b.getAttribute('aria-label'));
     return { nums, btnCount: btns.length,
              firstUpDisabled: btns.length ? btns[0].hasAttribute('disabled') : null,
              lastDownDisabled: btns.length ? btns[btns.length-1].hasAttribute('disabled') : null,
              uniqueNames: new Set(names.filter(Boolean)).size, totalNames: names.filter(Boolean).length };
   })()`);
   check(`${page}: positions are shown`, r.nums.length > 0 && r.nums.join(',') === r.nums.map((_,i)=>String(i+1)).join(','),
     `positions=[${r.nums.join(',')}]`);
   check(`${page}: the ends cannot move further out`, r.firstUpDisabled === true && r.lastDownDisabled === true,
     `firstUp=${r.firstUpDisabled} lastDown=${r.lastDownDisabled}`);
   check(`${page}: every move button names its object`, r.totalNames > 0 && r.uniqueNames === r.totalNames,
     `${r.uniqueNames}/${r.totalNames} unique`);
 }

 // Move the first DNS rule down and confirm the daemon kept it.
 await ev(`location.hash='#dns'`); await sleep(2600);
 const dnsURL = process.argv[2].replace(/\/$/,'') + '/api/dns';
 const storedIds = async () => (((await (await fetch(dnsURL)).json()).dns||{}).rules||[]).map(r => r && r.id);
 // The daemon's order BEFORE the click. Without it there is nothing to compare the result against,
 // which is how this check came to assert a count instead: the rendered row shows resolved display
 // names and the API returns raw rules, so those two are not comparable — but the daemon is
 // comparable to ITSELF.
 const storedBefore = await storedIds();
 const before = await ev(`(() => [...document.querySelectorAll('.dns-rule .m')].map(n => n.textContent.trim()))()`);
 await ev(`document.querySelectorAll('.dns-rule .ord-btn')[1].click()`);   // first row's "down"
 await sleep(2500);
 const after = await ev(`(() => [...document.querySelectorAll('.dns-rule .m')].map(n => n.textContent.trim()))()`);
 const storedAfter = await storedIds();
 check('a DNS rule can be moved', before.length>1 && before[0]!==after[0], `${JSON.stringify(before)} -> ${JSON.stringify(after)}`);
 // What stood here was `stored.length > 1` — the daemon holds more than one DNS rule. That was true
 // before anything moved, true for a UI that reorders only in the browser, and true for a PUT the
 // daemon silently drops. The name promised the reorder had been persisted and the measurement was a
 // count, so the single failure this check exists to catch was the one failure it could not see. Its
 // own evidence line printed the swapped order every run; nothing compared it to anything.
 //
 // Unidentifiable rules FAIL rather than pass: an order comparison with nothing stable to order by is
 // not a weaker check, it is no check.
 const identified = storedBefore.length > 1 && storedBefore.every(Boolean) &&
   new Set(storedBefore).size === storedBefore.length;
 const expected = identified ? [storedBefore[1], storedBefore[0], ...storedBefore.slice(2)] : [];
 check('the new order reached the daemon',
   identified && storedAfter.join('|') === expected.join('|'),
   identified ? `daemon [${storedBefore.slice(0,4).join(',')}…] -> [${storedAfter.slice(0,4).join(',')}…]`
              : `the daemon's rules carry no usable identity, so nothing can be compared: ${JSON.stringify(storedBefore.slice(0,4))}`);
 ws.close();
}finally{await closeChrome(c, dir)}
console.log(fails?`\n${fails} check(s) failed`:'\nall order checks passed');
process.exit(fails?1:0);
