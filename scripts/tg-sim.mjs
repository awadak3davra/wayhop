#!/usr/bin/env node
// tg-sim.mjs: a local stand-in for the Telegram Bot API, with a chat page to drive it, so the
// WayHop bot can be developed and demonstrated without a real bot token or a phone.
//
//   node scripts/tg-sim.mjs [--port 18081]
//
// Point the daemon at it with telegram.api_base = "http://127.0.0.1:18081" and any token of the
// right shape (123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA). Open http://127.0.0.1:18081/ to chat.
//
// It implements the methods internal/tgbot calls: getMe, getUpdates (long poll), sendMessage,
// editMessageText, answerCallbackQuery, deleteMessage, setMyCommands, deleteMyCommands, deleteWebhook,
// sendDocument.
// POST /sim/upgrade {"chat": -700} turns the group into a supergroup the way Telegram does, and
// POST /sim/block {"chat": 800} makes a chat refuse the bot as if the person had blocked it.
// Loopback only: it is a development tool, not a relay.

import http from "node:http";

const args = process.argv.slice(2);
const port = Number(args[args.indexOf("--port") + 1] || 0) || 18081;

const BOT = { id: 7000000001, is_bot: true, first_name: "WayHop (simulated)", username: "wayhop_sim_bot" };
const CHATS = [
  { id: 500, type: "private", first_name: "Sam", language_code: "ru", title: "Sam" },
  { id: 600, type: "private", first_name: "Mom", language_code: "ru", title: "Mom" },
  { id: 800, type: "private", first_name: "Guest", language_code: "en", title: "Guest (unpaired)" },
  { id: 900, type: "private", first_name: "Cousin", language_code: "uk", title: "Cousin (unpaired)" },
  { id: -700, type: "group", title: "Family", language_code: "en" },
];

// Update ids keep growing across restarts of the stand-in, as Telegram's do: a bot that goes on
// polling with the offset it had would otherwise never see an update again.
let updateSeq = Date.now();
let msgSeq = 1;
const updates = [];          // pending updates, oldest first
const waiters = new Set();   // long polls waiting for an update
const messages = new Map();  // chat id -> [{...}]
const toasts = [];           // answerCallbackQuery texts, newest last
let commands = {};           // language -> [{command, description}]
let chatCommands = {};       // chat id -> its own menu, which outranks the ones per language
let descriptions = {};       // language -> what an empty chat shows before /start
const log = [];              // method calls, for the page's footer
const upgradedTo = new Map(); // group id -> the supergroup it became (POST /sim/upgrade)
const blocked = new Set(process.env.SIM_BLOCK_GUEST ? [800] : []); // chats that blocked the bot (POST /sim/block)

for (const c of CHATS) messages.set(c.id, []);

function now() { return Math.floor(Date.now() / 1000); }
function chatOf(id) { return CHATS.find((c) => c.id === id); }

function pushUpdate(u) {
  u.update_id = ++updateSeq;
  updates.push(u);
  for (const w of waiters) w();
}

function userFor(chat) {
  const c = chatOf(chat);
  if (c.type === "private") return { id: c.id, is_bot: false, first_name: c.first_name, language_code: c.language_code };
  return { id: 501, is_bot: false, first_name: "Sam", language_code: c.language_code };
}

function chatObj(id) {
  const c = chatOf(id);
  const o = { id: c.id, type: c.type };
  if (c.type === "private") o.first_name = c.first_name; else o.title = c.title;
  return o;
}

function reply(res, result) {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true, result }));
}

function fail(res, code, description, extra = {}) {
  res.writeHead(code, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: false, error_code: code, description, ...extra }));
}

// Telegram's own refusal once a group has become a supergroup: it names the new id.
function upgradedFail(res, chat) {
  return fail(res, 400, "Bad Request: group chat was upgraded to a supergroup chat",
    { parameters: { migrate_to_chat_id: upgradedTo.get(chat) } });
}

async function body(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks);
}

function parseMultipart(buf, ctype) {
  const m = /boundary=(.+)$/.exec(ctype || "");
  const out = {};
  if (!m) return out;
  const parts = buf.toString("latin1").split("--" + m[1]);
  for (const p of parts) {
    const nm = /name="([^"]+)"(?:; filename="([^"]+)")?/.exec(p);
    if (!nm) continue;
    const val = p.slice(p.indexOf("\r\n\r\n") + 4).replace(/\r\n$/, "");
    out[nm[1]] = nm[2] ? { filename: nm[2], size: Buffer.byteLength(val, "latin1") } : Buffer.from(val, "latin1").toString("utf8");
  }
  return out;
}

async function botAPI(req, res, method) {
  const raw = await body(req);
  const ct = req.headers["content-type"] || "";
  const p = ct.startsWith("multipart/") ? parseMultipart(raw, ct) : (raw.length ? JSON.parse(raw.toString("utf8")) : {});
  if (method !== "getUpdates") log.push({ t: Date.now(), method });
  if (log.length > 200) log.splice(0, log.length - 200);
  switch (method) {
    case "getMe":
      return reply(res, BOT);
    case "deleteWebhook":
      return reply(res, true);
    case "setMyCommands":
      if (p.scope && p.scope.type === "chat") chatCommands[p.scope.chat_id] = p.commands || [];
      else commands[p.language_code || ""] = p.commands || [];
      return reply(res, true);
    case "setMyDescription":
      descriptions[p.language_code || ""] = p.description || "";
      return reply(res, true);
    case "setMyShortDescription":
      return reply(res, true);
    case "deleteMyCommands":
      if (p.scope && p.scope.type === "chat") delete chatCommands[p.scope.chat_id];
      else delete commands[p.language_code || ""];
      return reply(res, true);
    case "getUpdates": {
      const offset = Number(p.offset || 0);
      if (offset) while (updates.length && updates[0].update_id < offset) updates.shift();
      const ready = () => updates.filter((u) => u.update_id >= offset);
      if (ready().length || !p.timeout) return reply(res, ready().slice(0, 100));
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        waiters.delete(wake);
        clearTimeout(timer);
        reply(res, ready().slice(0, 100));
      };
      const wake = () => setTimeout(finish, 30);
      waiters.add(wake);
      const timer = setTimeout(finish, Math.min(Number(p.timeout), 50) * 1000);
      req.on("close", () => { waiters.delete(wake); clearTimeout(timer); done = true; });
      return;
    }
    case "sendMessage":
    case "sendDocument": {
      const chat = Number(p.chat_id);
      if (upgradedTo.has(chat)) return upgradedFail(res, chat);
      if (!messages.has(chat)) return fail(res, 400, "Bad Request: chat not found");
      if (blocked.has(chat)) return fail(res, 403, "Forbidden: bot was blocked by the user");
      const m = {
        message_id: msgSeq++, from: "bot", date: now(), html: p.text ?? p.caption ?? "",
        markup: p.reply_markup ? (typeof p.reply_markup === "string" ? JSON.parse(p.reply_markup) : p.reply_markup) : null,
        silent: !!p.disable_notification, reply_to: p.reply_parameters?.message_id || null,
        document: method === "sendDocument" ? p.document : null,
      };
      messages.get(chat).push(m);
      return reply(res, { message_id: m.message_id, chat: chatObj(chat), date: m.date, text: m.html });
    }
    case "editMessageText": {
      if (upgradedTo.has(Number(p.chat_id))) return upgradedFail(res, Number(p.chat_id));
      const list = messages.get(Number(p.chat_id)) || [];
      const m = list.find((x) => x.message_id === Number(p.message_id));
      if (!m) return fail(res, 400, "Bad Request: message to edit not found");
      const markup = p.reply_markup || null;
      if (m.html === p.text && JSON.stringify(m.markup) === JSON.stringify(markup)) {
        return fail(res, 400, "Bad Request: message is not modified: specified new message content and reply markup are exactly the same as a current content and reply markup of the message");
      }
      m.html = p.text;
      m.markup = markup;
      m.edited = now();
      return reply(res, true);
    }
    case "deleteMessage": {
      const list = messages.get(Number(p.chat_id)) || [];
      const i = list.findIndex((x) => x.message_id === Number(p.message_id));
      if (i >= 0) list.splice(i, 1);
      return reply(res, true);
    }
    case "answerCallbackQuery":
      if (p.text) toasts.push({ t: Date.now(), text: p.text, alert: !!p.show_alert });
      return reply(res, true);
    default:
      return fail(res, 404, "Not Found: method not implemented by the simulator");
  }
}

async function simAPI(req, res, path) {
  if (path === "/sim/state") {
    const since = Number(new URL(req.url, "http://x").searchParams.get("toasts") || 0);
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    return res.end(JSON.stringify({
      bot: BOT, chats: CHATS, commands, chatCommands, descriptions, log: log.slice(-12),
      messages: Object.fromEntries([...messages].map(([k, v]) => [k, v])),
      toasts: toasts.filter((t) => t.t > since),
    }));
  }
  const p = JSON.parse((await body(req)).toString("utf8") || "{}");
  const chat = Number(p.chat);
  if (!chatOf(chat)) return fail(res, 400, "unknown chat");
  if (path === "/sim/send") {
    const m = { message_id: msgSeq++, from: "user", date: now(), text: String(p.text || "") };
    messages.get(chat).push(m);
    pushUpdate({ message: { message_id: m.message_id, date: m.date, text: m.text, chat: chatObj(chat), from: userFor(chat) } });
    return reply(res, true);
  }
  if (path === "/sim/press") {
    const m = (messages.get(chat) || []).find((x) => x.message_id === Number(p.message_id));
    if (!m) return fail(res, 400, "no such message");
    pushUpdate({ callback_query: { id: String(Date.now()), from: userFor(chat), data: p.data,
      message: { message_id: m.message_id, date: m.date, chat: chatObj(chat), text: m.html } } });
    return reply(res, true);
  }
  // /sim/upgrade turns a group into a supergroup, as Telegram does when an admin changes certain
  // settings: a new chat with a new id, sends to the old id refused. {"announce": false} skips the
  // two service messages Telegram posts, which is the case of a bot that was down at the time.
  if (path === "/sim/upgrade") {
    const old = chatOf(chat);
    if (old.type !== "group" || upgradedTo.has(chat)) return fail(res, 400, "not an ordinary group");
    const id = Number("-100" + Math.abs(chat));
    CHATS.push({ id, type: "supergroup", title: old.title, language_code: old.language_code });
    messages.set(id, []);
    upgradedTo.set(chat, id);
    old.title += " (old group)";
    if (p.announce !== false) {
      pushUpdate({ message: { message_id: msgSeq++, date: now(), chat: chatObj(chat), from: userFor(chat), migrate_to_chat_id: id } });
      pushUpdate({ message: { message_id: msgSeq++, date: now(), chat: chatObj(id), from: userFor(id), migrate_from_chat_id: chat } });
    }
    return reply(res, { id });
  }
  // /sim/block {"chat": 800, "blocked": true|false}: the person blocks the bot, or lets it back.
  if (path === "/sim/block") {
    if (p.blocked === false) blocked.delete(chat); else blocked.add(chat);
    return reply(res, { blocked: [...blocked] });
  }
  if (path === "/sim/lang") {
    chatOf(chat).language_code = ["en", "ru", "uk"].includes(p.lang) ? p.lang : "ru";
    return reply(res, true);
  }
  return fail(res, 404, "not found");
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    const bm = /^\/bot([^/]+)\/([A-Za-z]+)$/.exec(url.pathname);
    if (bm && req.method === "POST") {
      if (!/^[0-9]{3,20}:[A-Za-z0-9_-]{20,100}$/.test(bm[1])) return fail(res, 401, "Unauthorized");
      return await botAPI(req, res, bm[2]);
    }
    if (url.pathname.startsWith("/sim/")) return await simAPI(req, res, url.pathname);
    if (url.pathname === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      return res.end(PAGE);
    }
    res.writeHead(404);
    res.end();
  } catch (e) {
    fail(res, 500, "simulator: " + e.message);
  }
});
server.listen(port, "127.0.0.1", () => console.log(`tg-sim: Bot API and chat page on http://127.0.0.1:${port}/`));

const PAGE = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bot chat simulator</title>
<style>
:root{--bg:#0f1419;--panel:#161d25;--line:#232d38;--text:#e6edf3;--muted:#8b98a5;--bot:#1d2733;--me:#1f4e79;--accent:#4aa3ff;--btn:#243140;--btnh:#2d3d50;--warn:#ffb454}
@media (prefers-color-scheme: light){:root:not([data-theme=dark]){--bg:#eef2f6;--panel:#fff;--line:#d9e1ea;--text:#16202b;--muted:#5d6b79;--bot:#fff;--me:#d7ebff;--accent:#1a73e8;--btn:#eaf1f8;--btnh:#dde8f3;--warn:#b86e00}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;height:100vh;display:flex}
aside{width:250px;background:var(--panel);border-right:1px solid var(--line);display:flex;flex-direction:column}
aside h1{font-size:15px;margin:0;padding:16px;border-bottom:1px solid var(--line)}aside h1 small{display:block;color:var(--muted);font-weight:400;font-size:12px;margin-top:2px}
.chat{padding:12px 16px;cursor:pointer;border-bottom:1px solid var(--line)}.chat:hover{background:var(--btn)}.chat.on{background:var(--btnh)}
.chat b{display:block}.chat span{color:var(--muted);font-size:12px}
.foot{margin-top:auto;padding:12px 16px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);max-height:34vh;overflow:auto}
main{flex:1;display:flex;flex-direction:column;min-width:0}
header{padding:12px 20px;border-bottom:1px solid var(--line);background:var(--panel);display:flex;align-items:center;gap:12px}
header b{flex:1}header select{background:var(--btn);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:4px 8px}
#log{flex:1;overflow:auto;padding:20px;display:flex;flex-direction:column;gap:10px}
.msg{max-width:min(560px,85%);padding:10px 12px;border-radius:14px;background:var(--bot);border:1px solid var(--line);white-space:pre-wrap;word-wrap:break-word;position:relative}
.msg.mine{align-self:flex-end;background:var(--me);border-color:transparent}
.msg .meta{font-size:11px;color:var(--muted);margin-top:6px;display:flex;gap:8px}
.msg .quote{border-left:3px solid var(--accent);padding:2px 8px;margin:-2px 0 8px;font-size:13px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.msg code{font-family:ui-monospace,Consolas,monospace;font-size:13px;background:rgba(127,127,127,.15);padding:0 4px;border-radius:4px}
.kb{display:grid;gap:6px;margin-top:8px}.kb .row{display:flex;gap:6px}
.kb button{flex:1;background:var(--btn);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:8px 6px;font:inherit;font-size:13px;cursor:pointer}
.kb button:hover{background:var(--btnh)}
form{display:flex;gap:8px;padding:12px 16px;border-top:1px solid var(--line);background:var(--panel)}
form input{flex:1;background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:12px;padding:10px 12px;font:inherit}
form button{background:var(--accent);color:#fff;border:0;border-radius:12px;padding:0 18px;font:inherit;cursor:pointer}
.cmds{display:flex;gap:6px;flex-wrap:wrap;padding:8px 16px 0;background:var(--panel)}.cmds button{background:var(--btn);color:var(--text);border:1px solid var(--line);border-radius:999px;padding:3px 10px;font-size:12px;cursor:pointer}
#toast{position:fixed;top:16px;left:50%;transform:translateX(-50%);background:#111a;backdrop-filter:blur(6px);color:#fff;padding:10px 16px;border-radius:12px;display:none;max-width:80%;z-index:9}
#toast.alert{background:#7a1f1f}
.silent{opacity:.9}.silent .meta::after{content:"🔕 silent"}
.empty{color:var(--muted);text-align:center;margin:auto}
@media (max-width:700px){aside{width:120px}.chat span{display:none}}
</style></head><body>
<aside><h1>Bot chat simulator<small>local Bot API stand-in</small></h1><div id="chats"></div><div class="foot" id="calls"></div></aside>
<main><header><b id="title"></b><label>client language <select id="lang"><option value="ru">ru</option><option value="uk">uk</option><option value="en">en</option></select></label></header>
<div id="log"></div><div class="cmds" id="cmds"></div>
<form id="f"><input id="in" autocomplete="off" placeholder="Message or /command"><button>Send</button></form></main>
<div id="toast"></div>
<script>
let cur = 500, state = null, lastToast = Date.now(), lastRender = "";
const $ = (id) => document.getElementById(id);
const ALLOWED = new Set(["B","STRONG","I","EM","U","S","CODE","PRE","A","BR"]);
function safe(html){
  const t = document.createElement("template"); t.innerHTML = html.replace(/\n/g,"<br>");
  const walk = (n) => { for (const c of [...n.childNodes]) { if (c.nodeType === 1) {
    if (!ALLOWED.has(c.tagName)) { c.replaceWith(document.createTextNode(c.textContent)); continue; }
    for (const a of [...c.attributes]) if (!(c.tagName === "A" && a.name === "href" && /^https?:/.test(a.value))) c.removeAttribute(a.name);
    walk(c); } } };
  walk(t.content); return t.innerHTML;
}
function esc(s){return s.replace(/[&<>]/g,(c)=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
async function post(path, body){ await fetch(path,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)}); refresh(); }
function render(){
  const s = state; if (!s) return;
  $("chats").innerHTML = s.chats.map(c => '<div class="chat'+(c.id===cur?' on':'')+'" data-id="'+c.id+'"><b>'+esc(c.title)+'</b><span>'+c.type+' · '+c.id+'</span></div>').join("");
  const c = s.chats.find(x => x.id === cur); $("title").textContent = c.title + " · " + c.type; $("lang").value = c.language_code;
  const msgs = s.messages[cur] || [];
  const html = msgs.length ? msgs.map(m => {
    const q = m.reply_to ? (msgs.find(x => x.message_id === m.reply_to)) : null;
    const quote = q ? '<div class="quote">↪ '+esc((q.html||q.text||"").replace(/<[^>]+>/g,"").split("\n")[0])+'</div>' : "";
    const kb = m.markup && m.markup.inline_keyboard ? '<div class="kb">'+m.markup.inline_keyboard.map(r => '<div class="row">'+r.map(b =>
      b.url ? '<button onclick="window.open(\''+b.url+'\')">'+esc(b.text)+' ↗</button>' :
      '<button data-msg="'+m.message_id+'" data-cb="'+esc(b.callback_data||"")+'">'+esc(b.text)+'</button>').join("")+'</div>').join("")+'</div>' : "";
    const body = m.from === "user" ? esc(m.text) : safe(m.html || "") + (m.document ? '<div>📎 '+esc(m.document.filename)+' ('+m.document.size+' B)</div>' : "");
    const meta = '<div class="meta">'+new Date(m.date*1000).toLocaleTimeString()+(m.edited?' · edited':'')+'</div>';
    return '<div class="msg'+(m.from==="user"?' mine':'')+(m.silent?' silent':'')+'">'+quote+body+kb+meta+'</div>';
  }).join("") : '<div class="empty">'+(esc((s.descriptions||{})[c.language_code] || (s.descriptions||{})[""] || "No messages yet. Pair this chat: make a code in the panel (Settings → Telegram) and send it here.")).replace(/\n/g, "<br>")+'</div>';
  if (html !== lastRender) { const atEnd = $("log").scrollTop + $("log").clientHeight >= $("log").scrollHeight - 40; $("log").innerHTML = html; lastRender = html; if (atEnd) $("log").scrollTop = $("log").scrollHeight; }
  const menu = s.chatCommands[c.id] || s.commands[c.language_code] || s.commands[""] || [];
  $("cmds").innerHTML = menu.map(m => '<button title="'+esc(m.description)+'" data-cmd="/'+m.command+'">/'+m.command+'</button>').join("");
  $("calls").innerHTML = "<b>Bot API calls</b><br>" + s.log.map(l => new Date(l.t).toLocaleTimeString()+" "+l.method).reverse().join("<br>");
  for (const t of s.toasts) { lastToast = Math.max(lastToast, t.t); const el = $("toast"); el.textContent = t.text; el.className = t.alert ? "alert" : ""; el.style.display = "block"; clearTimeout(el._h); el._h = setTimeout(() => el.style.display = "none", t.alert ? 5000 : 2500); }
}
async function refresh(){ const r = await fetch("/sim/state?toasts="+lastToast); state = await r.json(); render(); }
document.addEventListener("click", (e) => {
  const ch = e.target.closest(".chat"); if (ch) { cur = Number(ch.dataset.id); lastRender = ""; render(); $("log").scrollTop = 1e9; return; }
  const b = e.target.closest("button[data-cb]"); if (b) { post("/sim/press", {chat: cur, message_id: Number(b.dataset.msg), data: b.dataset.cb}); return; }
  const cm = e.target.closest("button[data-cmd]"); if (cm) { post("/sim/send", {chat: cur, text: cm.dataset.cmd}); }
});
$("f").addEventListener("submit", (e) => { e.preventDefault(); const v = $("in").value.trim(); if (!v) return; $("in").value = ""; post("/sim/send", {chat: cur, text: v}); });
$("lang").addEventListener("change", () => post("/sim/lang", {chat: cur, lang: $("lang").value}));
refresh(); setInterval(refresh, 1000);
</script></body></html>`;
