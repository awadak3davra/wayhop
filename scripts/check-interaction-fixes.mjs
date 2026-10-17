#!/usr/bin/env node
// Focused, dependency-free regression harness for three interaction bugs found on the Keenetic UI.
// It executes the shipped functions with tiny DOM/browser doubles, so the cases stay deterministic:
// no clipboard API (plain HTTP), a historical Diagnostics result after the input changes, and a
// language choice whose dictionary was not part of the one-language bootstrap payload.
import fs from 'node:fs';
import vm from 'node:vm';

const app = fs.readFileSync('web/dist/app.js', 'utf8');
const conns = fs.readFileSync('web/dist/page-connections.js', 'utf8');
const diag = fs.readFileSync('web/dist/page-diagnostics.js', 'utf8');
const connections = fs.readFileSync('web/dist/page-connections.js', 'utf8');
const updater = fs.readFileSync('web/dist/page-updater.js', 'utf8');
const server = fs.readFileSync('web/dist/page-server.js', 'utf8');
const diagnostics = fs.readFileSync('web/dist/page-diagnostics.js', 'utf8');
const dns = fs.readFileSync('web/dist/page-dns.js', 'utf8');
const failures = [];
let checks = 0;

function check(ok, message, detail = '') {
  checks++;
  if (!ok) failures.push(message + (detail ? ` [${detail}]` : ''));
}

// arrowSource does for `const name = (args) => { ... }` what functionSource does for a declaration.
// The review dialog builds its rows in arrow functions closed over the dialog's state, so its
// subjects are unreachable to the declaration scanner — which is how the finding row went unpinned.
// Re-emitted as a declaration so the vm can call it by name.
function arrowSource(source, name) {
  const start = source.indexOf(`const ${name} = (`);
  if (start < 0) throw new Error(`arrow function ${name} was not found`);
  const args = source.slice(source.indexOf('(', start) + 1, source.indexOf(')', start));
  const open = source.indexOf('{', source.indexOf('=>', start));
  const body = balancedBlock(source, open);
  return `function ${name}(${args}) ${body}`;
}

// Return the exact shipped function declaration without copying its implementation into this test.
// The scanner ignores braces in comments, strings and template literals.
function functionSource(source, name) {
  let start = source.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`function ${name} was not found`);
  // Keep the `async` that a declaration may carry. Slicing from `function` alone produced a body
  // whose `await`s were a SyntaxError, so an async subject could not be asserted on at all.
  if (source.slice(Math.max(0, start - 6), start) === 'async ') start -= 6;
  const open = source.indexOf('{', start);
  return source.slice(start, open) + balancedBlock(source, open, name);
}

// balancedBlock returns `{ … }` starting at open, ignoring braces inside comments, strings and
// template literals. Shared by both extractors so an arrow subject is scanned exactly like a
// declaration one — two copies of this loop would be two chances to disagree about a brace.
function balancedBlock(source, open, name = 'block') {
  let depth = 0;
  let quote = '';
  let lineComment = false;
  let blockComment = false;
  let escaped = false;
  for (let i = open; i < source.length; i++) {
    const c = source[i], n = source[i + 1];
    if (lineComment) { if (c === '\n') lineComment = false; continue; }
    if (blockComment) { if (c === '*' && n === '/') { blockComment = false; i++; } continue; }
    if (quote) {
      if (escaped) { escaped = false; continue; }
      if (c === '\\') { escaped = true; continue; }
      if (c === quote) quote = '';
      continue;
    }
    if (c === '/' && n === '/') { lineComment = true; i++; continue; }
    if (c === '/' && n === '*') { blockComment = true; i++; continue; }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '{') depth++;
    if (c === '}' && --depth === 0) return source.slice(open, i + 1);
  }
  throw new Error(`function ${name} has no closing brace`);
  throw new Error(`${name} has no closing brace`);
}

function walk(node, fn) {
  if (!node || typeof node !== 'object') return;
  fn(node);
  for (const child of node.children || []) walk(child, fn);
}

function tinyEl(tag, attrs = {}, ...children) {
  const node = {
    tag, attrs, children: children.filter((c) => c != null), value: '', listeners: {},
    appendChild(child) { this.children.push(child); return child; },
    prepend(child) { this.children.unshift(child); return child; },
    setAttribute(name, value) { this.attrs[name] = value; },
    addEventListener(type, fn) { this.listeners[type] = fn; },
    querySelector(selector) {
      let found = null;
      walk(this, (n) => {
        if (found) return;
        if (selector === '.ask-body' && String(n.attrs?.class || '').split(/\s+/).includes('ask-body')) found = n;
      });
      return found;
    },
  };
  if (typeof attrs.onclick === 'function') node.onclick = attrs.onclick;
  return node;
}

// 1. The Connections import-error control delegates the already-redacted text to the ONE shared
// copier, instead of using navigator.clipboard directly and claiming success before it resolves.
{
  const copied = [];
  const context = vm.createContext({
    el: tinyEl,
    t: (s) => s,
    toast: () => {},
    redactSecrets: (raw) => `safe:${raw}`,
    copyText: (value) => { copied.push(value); return Promise.resolve(false); },
  });
  vm.runInContext(`${functionSource(connections, 'friendlyImportError')}; globalThis.run = friendlyImportError;`, context);
  const box = context.run('unsupported secret-value', null);
  let button = null;
  walk(box, (n) => {
    if (n.tag === 'button' && n.children.includes('Copy technical details')) button = n;
  });
  check(!!button, 'Connections renders Copy technical details on an import error');
  if (button) button.attrs.onclick();
  check(copied.length === 1 && copied[0] === 'safe:unsupported secret-value',
    'Copy technical details passes only redacted text to copyText', JSON.stringify(copied));
}

// Exercise copyText itself in the router's real browser shape: plain HTTP means no Clipboard API.
// execCommand is allowed to fail; the honest outcome is a manual-copy field, never a Copied toast.
{
  const events = { appended: 0, removed: 0, manual: [], toasts: [] };
  const document = {
    body: {
      appendChild(node) { events.appended++; node.parentNode = this; },
      removeChild(node) { events.removed++; node.parentNode = null; },
    },
    execCommand(command) { check(command === 'copy', 'fallback attempts only the copy command'); return false; },
  };
  const context = vm.createContext({
    navigator: {}, document, Promise,
    el: () => ({ value: '', focus() {}, select() {} }),
    t: (s) => s,
    toast: (message, kind) => events.toasts.push({ message, kind }),
    copyManualModal: (value) => events.manual.push(value),
  });
  vm.runInContext(`${functionSource(app, 'copyText')}\n${functionSource(app, 'execCopy')};`
    + 'globalThis.run = copyText;', context);
  const automatic = await context.run('redacted diagnostics');
  check(automatic === false, 'plain-HTTP fallback reports that automatic copy did not succeed');
  check(events.appended === 1 && events.removed === 1,
    'plain-HTTP fallback cleans up its temporary textarea', JSON.stringify(events));
  check(events.manual[0] === 'redacted diagnostics',
    'plain-HTTP clipboard failure opens the manual-copy fallback', JSON.stringify(events.manual));
  check(events.toasts.length === 0,
    'plain-HTTP clipboard failure never claims Copied', JSON.stringify(events.toasts));

  // A Clipboard API can exist and still reject (permissions, browser policy, extension). The old
  // Connections handler showed Copied synchronously in exactly this case.
  events.manual.length = 0;
  events.toasts.length = 0;
  context.navigator.clipboard = { writeText: () => Promise.reject(new Error('denied')) };
  const rejected = await context.run('still redacted');
  check(rejected === false, 'a rejected Clipboard API write reports no automatic-copy success');
  check(events.manual[0] === 'still redacted',
    'a rejected Clipboard API write continues through the manual fallback', JSON.stringify(events.manual));
  check(events.toasts.length === 0,
    'a rejected Clipboard API write never claims Copied', JSON.stringify(events.toasts));

  // An embedded browser/extension may throw synchronously inside execCommand. The temporary field
  // still has to be detached before the manual fallback opens.
  events.manual.length = 0;
  events.appended = 0;
  events.removed = 0;
  context.navigator.clipboard = {};
  document.execCommand = () => { throw new Error('copy unavailable'); };
  const thrown = await context.run('throw path');
  check(thrown === false && events.appended === 1 && events.removed === 1,
    'a thrown execCommand cleans up its temporary textarea', JSON.stringify(events));
}

check(functionSource(app, 'copyManualModal').includes('"aria-label": t("Text to copy")'),
  'manual-copy fallback gives its focused textarea an accessible name');

// 2. Reclassification belongs to the historical answer whose chip was clicked. Change the live input
// after the first Ask, then invoke the first result's callback and observe which value is classified.
{
  const classified = [];
  const entries = [];
  const runs = [];
  const context = vm.createContext({
    el: tinyEl,
    t: (s) => s,
    askClassify: (raw) => { classified.push(raw); return { kind: 'domain', value: String(raw).trim() }; },
    askEntry: (value, kind, reask) => {
      const body = tinyEl('div', { class: 'ask-body' });
      const entry = tinyEl('div', {}, body);
      entry.record = { value, kind, reask, body };
      entries.push(entry.record);
      return entry;
    },
    askRun: (kind, value, body) => runs.push({ kind, value, body }),
  });
  vm.runInContext(`${functionSource(app, 'askCard')}; globalThis.run = askCard;`, context);
  const card = context.run();
  let input = null, askButton = null;
  walk(card, (n) => {
    if (n.tag === 'input' && String(n.attrs?.class || '').includes('ask-in')) input = n;
    if (n.tag === 'button' && n.children.includes('Ask')) askButton = n;
  });
  check(!!input && !!askButton, 'Diagnostics Ask input and button render in the harness');
  input.value = 'first.example';
  askButton.attrs.onclick();
  input.value = 'second.example';
  entries[0].reask('ip');
  check(classified.length === 2 && classified[0] === 'first.example' && classified[1] === 'first.example',
    'historical reclassification classifies its captured query, not current input', JSON.stringify(classified));
  check(runs.length === 2 && runs[1].kind === 'ip' && runs[1].value === 'first.example',
    'historical reclassification runs the chosen kind against the captured query', JSON.stringify(runs));
}

function languageContext({ dirty = false, confirmLeave = true, stored = 'auto' } = {}) {
  const values = new Map(stored === 'auto' ? [] : [['wr-lang', stored]]);
  const events = { reloads: 0, discards: [], confirms: 0, toasts: [] };
  const context = vm.createContext({
    I18N_LANGS: [{ code: 'auto' }, { code: 'en' }, { code: 'ru' }],
    LANG_KEY: 'wr-lang',
    location: { hash: '#settings', reload() { events.reloads++; } },
    localStorage: {
      getItem: (key) => values.has(key) ? values.get(key) : null,
      setItem: (key, value) => values.set(key, value),
      removeItem: (key) => values.delete(key),
    },
    hasUnsavedPageEdits: () => dirty,
    discardPageEdits: (hash) => events.discards.push(hash),
    confirm: () => { events.confirms++; return confirmLeave; },
    t: (s) => s,
    toast: (message, kind) => events.toasts.push({ message, kind }),
  });
  vm.runInContext(`${functionSource(app, 'setLang')}; globalThis.run = setLang;`, context);
  return { context, values, events };
}

// 3. A non-English dictionary is intentionally absent until the bootstrap reload. Persist the exact
// requested code first, then reload; do not reinterpret absence as Auto.
{
  const { context, values, events } = languageContext();
  check(context.run('ru') === true, 'a supported non-English language selection is accepted');
  check(values.get('wr-lang') === 'ru',
    'non-English selection is persisted and never rewritten as Auto', JSON.stringify([...values]));
  check(events.reloads === 1, 'language selection reloads through the one-dictionary bootstrap');
}

// The reload must keep the existing dirty-page contract: cancel means no persistence or navigation;
// confirm discards through the registry before reload so beforeunload does not double-prompt.
{
  const cancelled = languageContext({ dirty: true, confirmLeave: false, stored: 'en' });
  check(cancelled.context.run('ru') === false, 'dirty-page cancellation rejects a language change');
  check(cancelled.values.get('wr-lang') === 'en' && cancelled.events.reloads === 0
      && cancelled.events.discards.length === 0 && cancelled.events.confirms === 1,
    'dirty-page cancellation preserves edits and previous language', JSON.stringify(cancelled.events));

  const confirmed = languageContext({ dirty: true, confirmLeave: true, stored: 'en' });
  check(confirmed.context.run('ru') === true, 'confirmed dirty-page language change proceeds');
  check(confirmed.values.get('wr-lang') === 'ru' && confirmed.events.reloads === 1
      && confirmed.events.discards[0] === '#settings' && confirmed.events.confirms === 1,
    'confirmed language change discards through the registry before reload', JSON.stringify(confirmed.events));
}

// The live-pill cache must never memoize an EMPTY reading of the page.
//
// route() bumps pillGen and empties #view before awaiting the render, so the window between "the old
// DOM is gone" and "the new DOM is appended" is a network round trip wide. The 5-second health tick
// lands in it routinely, and the previous cache pinned five empty NodeLists to that generation with
// nothing to clear them until the next navigation: every pill, per-tunnel rate and cause line froze
// on the page the operator was watching, while the daemon kept answering. Measured on the router —
// the cache held 0 exits against 6 in the DOM.
{
  const dom = { nodes: [] };
  const document = {
    querySelectorAll(selector) { return selector === '[data-health]' ? dom.nodes : []; },
  };
  const context = vm.createContext({ document });
  vm.runInContext(
    'let pillGen = 0, pillCacheGen = -1, pillCache = null;\n'
    + `${functionSource(app, 'pillNodes')}\n`
    + 'globalThis.tick = () => pillNodes();\n'
    + 'globalThis.navigate = () => { pillGen++; };',
    context);

  // A tick during the navigation window sees nothing — correct, there is nothing on screen yet.
  context.navigate();
  check(context.tick().health.length === 0, 'a tick mid-navigation reports no pills');
  // The render lands. The very next tick must SEE the new nodes rather than the cached emptiness.
  dom.nodes = [{ id: 'wg1' }, { id: 'wg2' }, { id: 'wg3' }, { id: 'wg4' }, { id: 'wg5' }, { id: 'wg6' }];
  check(context.tick().health.length === 6,
    'the first tick after the render sees the freshly appended pills');
  // Once a non-empty reading exists it IS cached, so the six full-tree scans stay off the 5 s path.
  dom.nodes = [];
  check(context.tick().health.length === 6,
    'a non-empty reading is memoized for the generation');
  // …until the page is rebuilt, which is what the generation counter is for.
  context.navigate();
  check(context.tick().health.length === 0, 'a new generation drops the memoized reading');
}

// The Failover chain must not promise a switch nobody performs, and must not credit a measurement
// nobody takes. Both claims changed meaning when a group of native tunnels stopped needing the proxy
// core: the ROUTER now walks the `ip global` ladder (measured on a live box — Wireguard3 down,
// default moved to Wireguard5), but only for the group carrying the DEFAULT route, and nothing in the
// daemon sets CompileOptions.GroupElection, so no latency is measured on that path at all.
{
  const endpoints = {
    'wg-a': { id: 'wg-a', engine: 'external' },
    'wg-b': { id: 'wg-b', engine: 'amneziawg' },
    'vless-a': { id: 'vless-a', engine: 'singbox' },
  };
  // The daemon names the groups whose routing-list tables it re-points; the page reads that rather
  // than guessing. Default: it owns nothing, which is the state on a platform where that loop does
  // not run — and the state this gate's original assertions were written against.
  const failoverState = { elected: {}, local_fault: false, known: true, self_switching: [] };
  const context = vm.createContext({
    t: (s) => s,
    findEndpoint: (id) => endpoints[id] || null,
    failoverState,
  });
  vm.runInContext(
    `${functionSource(app, 'foGroupNeedsCore')}\n`
    + `${functionSource(app, 'foSwitchesItself')}\n`
    + `${functionSource(app, 'foOrderNote')}\n`
    + 'globalThis.switches = foSwitchesItself; globalThis.orderNote = foOrderNote;',
    context);

  const native = (type) => ({ id: 'g', type, members: ['wg-a', 'wg-b'] });
  const proxy = (type) => ({ id: 'g', type, members: ['wg-a', 'vless-a'] });

  check(context.switches(native('fallback'), true) === true,
    'a native fallback group carrying the default route switches itself — the router walks the ladder');
  check(context.switches(native('fallback'), false) === false,
    'a native group that is NOT the default route and that the daemon does not own stays put');
  // Updated when the routing-list failover owner landed. A native group backing routing lists IS
  // re-pointed automatically now (listfailover.go; measured on the router, nwg3 to nwg5 in 15s), and
  // the card denied it — sending the operator to switch by hand what the daemon had already switched.
  // The claim follows the daemon's own list of owned groups, so it is empty where that loop does not
  // run rather than promising a feature the platform does not have.
  failoverState.self_switching = ['g'];
  check(context.switches(native('fallback'), false) === true,
    'a native group whose list tables the daemon re-points does say it switches itself');
  check(context.switches(native('selector'), false) === true,
    'and the type does not matter for that — the owner elects for any group it owns');
  failoverState.self_switching = [];
  check(context.switches(native('urltest'), false) === false,
    'a native urltest group off the default route does not switch itself either');
  // A managed selector gets nothing on a coreless router: no prober, and the control loop speaks Clash.
  check(context.switches({ id: 'g', type: 'selector', managed: true, members: ['wg-a', 'wg-b'] }, true) === false,
    'a managed selector on native tunnels does not claim to switch itself');
  // With the core in the group, the old answers stand: sing-box probes, or the daemon drives it.
  check(context.switches(proxy('urltest'), false) === true,
    'a proxy urltest group still switches itself through sing-box');
  check(context.switches({ id: 'g', type: 'selector', managed: true, members: ['wg-a', 'vless-a'] }, false) === true,
    'a managed proxy group is still driven by the daemon control loop');

  check(/nothing measures their latency/.test(context.orderNote(native('urltest'))),
    'a native urltest group says its latency is not measured', context.orderNote(native('urltest')));
  check(/picks the fastest working member/.test(context.orderNote(proxy('urltest'))),
    'a proxy urltest group keeps the sing-box wording', context.orderNote(proxy('urltest')));
}

// The Components section (formerly "Updater") must read this router's ordinary state as ordinary.
//
// Nothing is installed here and nothing needs to be: WayHop routes with the kernel and the router's
// own tunnels. Two separate things used to shout about that anyway — the WayHop row reported the
// private repository's 404 as "Update check refused by the server" with a three-source failure report
// under it, and the verdict counted that unchecked build among the components it had compared, so a
// page where nothing had been compared announced "Everything is current · 1 component checked".
{
  const context = vm.createContext({ t: (s, ...a) => s.replace(/\{(\d)\}/g, (_, i) => a[i]) });
  vm.runInContext(
    'let updRows = new Map();\n'
    + `${functionSource(updater, 'updVerdict')}\n`
    + `${functionSource(updater, 'usageNote')}\n`
    + 'globalThis.setRows = (rows) => { updRows = new Map(rows.map((r) => [r.id, r])); };\n'
    + 'globalThis.verdict = () => updVerdict();\n'
    + 'globalThis.usage = (usedBy, installed) => usageNote(usedBy, installed).children.join("");',
    context);
  // Give usageNote the one DOM helper it uses; it returns a single element with text children.
  context.el = (tag, attrs, ...children) => ({ tag, attrs, children: children.filter((c) => c != null) });

  // This router, exactly: a WayHop build with no release channel, and sing-box absent-and-optional.
  context.setRows([
    { id: 'wayhop', state: 'channel_missing', noChannelBuild: true },
    { id: 'sing-box', state: 'absent', optional: true },
  ]);
  let v = context.verdict();
  check(v.level === 'muted', 'a build with no update channel is not a warning', JSON.stringify(v));
  check(!/Everything is current/.test(v.word) && !/component checked/.test(v.sub),
    'a build nobody could compare is never counted as compared', JSON.stringify(v));
  check(/does not self-update/.test(v.sub),
    'the verdict states the reason instead of hiding it', JSON.stringify(v));

  // The package-catalog case keeps its own headline: that one IS actionable — add a repository.
  context.setRows([{ id: 'sing-box', state: 'channel_missing', managed: true }]);
  v = context.verdict();
  check(v.level === 'warn' && /without an update channel/.test(v.word),
    'a package with no repository still leads with its own headline', JSON.stringify(v));

  // A component that is behind must outrank everything, including the quiet build row.
  context.setRows([
    { id: 'wayhop', state: 'channel_missing', noChannelBuild: true },
    { id: 'sing-box', state: 'behind' },
  ]);
  v = context.verdict();
  check(v.level === 'err' && /1 behind/.test(v.word), 'a behind component still leads', JSON.stringify(v));

  // usageNote decides both questions the section exists for, and the two absences are NOT the same
  // sentence: an unused installed engine is flash to reclaim, an absent unneeded one is normal.
  check(/normal state here/.test(context.usage([], false)),
    'an absent engine nothing needs reads as normal', context.usage([], false));
  check(/Removing it frees the space/.test(context.usage([], true)),
    'an installed engine nothing uses is reported as reclaimable', context.usage([], true));
  check(/will not work until it is installed/.test(context.usage(['Frankfurt VLESS'], false)),
    'an absent engine something needs names what is waiting on it', context.usage(['Frankfurt VLESS'], false));
  check(/In use by: Frankfurt VLESS/.test(context.usage(['Frankfurt VLESS'], true)),
    'an installed engine in use names its dependents', context.usage(['Frankfurt VLESS'], true));
}

// The install-target card is the one place a small-flash router is protected from its own Install
// button, so what it claims has to be true on all three shapes that occur in the field.
{
  // A DOM double that honours innerHTML = "" — the card clears its placeholder that way, and a
  // double that ignored it would leave "reading storage…" in every assertion below.
  const el = (tag, attrs = {}, ...children) => {
    const node = { tag, attrs, children: children.filter((c) => c != null) };
    node.appendChild = (child) => { node.children.push(child); return child; };
    node.addEventListener = () => {};
    Object.defineProperty(node, 'innerHTML', { set(v) { if (v === '') node.children.length = 0; }, get() { return ''; } });
    return node;
  };
  const text = (node) => {
    if (node == null) return '';
    if (typeof node !== 'object') return String(node);
    return (node.children || []).map(text).join('');
  };
  const cardFor = async (storage) => {
    const context = vm.createContext({
      el,
      t: (s, ...a) => s.replace(/\{(\d)\}/g, (_, i) => a[i]),
      fmtBytes: (b) => `${Math.round((b / (1024 * 1024)) * 10) / 10} MB`,
      api: { get: () => Promise.resolve(storage) },
      state: { profile: { endpoints: [], groups: [] } },
      toast: () => {},
      Promise,
    });
    vm.runInContext(`${functionSource(updater, 'installTargetCard')}\n`
      + `${functionSource(updater, 'downloadPathRow')}\n`
      + 'globalThis.run = installTargetCard;', context);
    const card = context.run();
    await new Promise((r) => setTimeout(r, 0));
    return text(card);
  };

  const overlay = { path: '/', filesystem: 'overlayfs:/overlay', free_bytes: 9 << 20, free_known: true, external: false };
  const stick = { path: '/mnt/sda1', filesystem: '/dev/sda1', free_bytes: 7 << 30, free_known: true, external: true };
  // The threshold is the daemon's componentInstallFloor, sent as install_floor_bytes. The page used
  // to hold its own 32 MB literal and drifted away from the Diagnostics battery, which judged the
  // same disk by a different number; the copy is gone, so every fixture has to supply the field the
  // way the server does. A fixture that omits it is what caught this: the warning silently vanished.
  const FLOOR = 32 << 20;

  // OpenWrt on internal flash with a USB disk already mounted: the advice must name that disk and
  // the setting that moves engines onto it, not tell the operator to attach what is attached.
  let body = await cardFor({
    packages: overlay, engines: overlay, same_disk: true, roomier: [stick], engine_setting: 'sing-box binary',
    install_floor_bytes: FLOOR,
  });
  check(/Little room on internal flash/.test(body), 'a small overlay is warned about', body.slice(0, 120));
  check(/There is room on \/mnt\/sda1/.test(body) && /\/dev\/sda1/.test(body),
    'the mounted disk with room is named', body);
  check(/sing-box binary/.test(body), 'the setting that relocates engines is named', body);
  check(!/Attach a USB disk/.test(body), 'a router that already has a disk is not told to attach one', body);

  // The same router with nothing else mounted keeps the general advice.
  body = await cardFor({ packages: overlay, engines: overlay, same_disk: true, roomier: [], install_floor_bytes: FLOOR });
  check(/Attach a USB disk/.test(body), 'with no roomier disk the general advice stands', body);

  // The number has to be the SERVER's, not one this file happens to agree with. Same 9 MB overlay,
  // a floor it clears: no warning. If the page ever reintroduces a private constant, this is the
  // check that fails while every other storage assertion still passes.
  body = await cardFor({ packages: overlay, engines: overlay, same_disk: true, roomier: [], install_floor_bytes: 4 << 20 });
  check(!/Little room on internal flash/.test(body),
    'the warning follows the floor the daemon sent, not a threshold written into the page', body);

  // Engines already relocated onto the stick, packages still on flash: two targets, each with its
  // own free space. One figure for both would describe a directory half the installs never touch.
  body = await cardFor({
    packages: overlay,
    engines: { path: '/mnt/sda1/sbin', filesystem: '/dev/sda1', free_bytes: 7 << 30, free_known: true, external: true },
    same_disk: false,
  });
  check(/Packages install into/.test(body) && /Downloaded engines install into/.test(body),
    'two distinct targets are reported separately', body);
  check(/attached storage/.test(body), 'the relocated engine directory reads as attached storage', body);

  // Space that could not be measured must never render as space, and must never warn about a number
  // nobody has.
  body = await cardFor({
    packages: { path: '/', filesystem: '', free_bytes: 0, free_known: false, external: false },
    engines: { path: '/opt/sbin', filesystem: '', free_bytes: 0, free_known: false, external: false },
    same_disk: false, install_floor_bytes: FLOOR,
  });
  check(/free space not measured/.test(body), 'an unmeasured target says so', body);
  check(!/Little room on internal flash/.test(body),
    'an unmeasured target never triggers the low-space warning', body);
}

// Which connection component downloads leave through.
//
// The setting exists for the router whose ordinary path to the release is blocked: nothing can be
// installed there, including the engine that would have carried the traffic around the block. So the
// row has to state what is IN FORCE, not what was saved — a saved tunnel that the daemon could not
// resolve means the download silently takes the blocked path, and an operator who reads that as "it
// goes through the tunnel" will keep pressing Install and keep failing.
{
  const listeners = [];
  const el = (tag, attrs = {}, ...children) => {
    const node = { tag, attrs, children: children.filter((c) => c != null) };
    node.appendChild = (child) => { node.children.push(child); return child; };
    node.addEventListener = (type, fn) => { listeners.push({ node, type, fn }); };
    // A <select> only takes a value it has an option for; assigning an absent one leaves it empty.
    // The row detects a vanished choice exactly that way, so the double has to behave the same or the
    // assertion below would pass against a double that accepts anything.
    if (tag === 'select') {
      let want = '';
      Object.defineProperty(node, 'value', {
        set(v) { want = String(v); },
        get() { return node.children.some((c) => c.tag === 'option' && c.attrs.value === want) ? want : ''; },
      });
    }
    return node;
  };
  const text = (node) => {
    if (node == null) return '';
    if (typeof node !== 'object') return String(node);
    return [node.textContent || '', ...(node.children || []).map(text)].join('');
  };
  const options = (node) => {
    if (node == null || typeof node !== 'object') return [];
    if (node.tag === 'option') return [{ value: node.attrs.value, label: text(node) }];
    return (node.children || []).flatMap(options);
  };
  const puts = [];
  const toasts = [];
  // `fresh` is what the row re-reads from /api/updater/storage after saving. It is a parameter
  // because the outcome the operator is told about lives there, not in the save.
  const rowFor = (storage, fresh = {}) => {
    listeners.length = 0;
    puts.length = 0;
    toasts.length = 0;
    const context = vm.createContext({
      el,
      t: (s, ...a) => s.replace(/\{(\d)\}/g, (_, i) => a[i]),
      toast: (msg, kind) => { toasts.push({ msg, kind }); },
      // Deliberately NO state.profile: the row must render from the daemon's answer alone. When it
      // read the profile, arriving at Components cold — with nothing loaded yet — offered only the
      // ordinary path and hid every tunnel, which is the one moment the control exists for.
      state: {},
      api: {
        get: () => Promise.resolve(fresh),
        put: (u, body) => { puts.push({ u, body }); return Promise.resolve({}); },
      },
      Promise,
    });
    vm.runInContext(`${functionSource(updater, 'downloadPathRow')}\nglobalThis.run = downloadPathRow;`, context);
    return context.run(storage);
  };

  const PATHS = [
    { id: 'external-nwg3', name: 'Home WG', iface: 'nwg3' },
    { id: 'grp', name: 'Main', group: true, iface: 'nwg3' },
  ];
  let row = rowFor({ download_via: '', download_iface: '', download_paths: PATHS });
  let opts = options(row);
  check(opts[0].value === '', 'the ordinary path is the first choice', JSON.stringify(opts[0]));
  check(opts.some((o) => o.value === 'external-nwg3') && opts.some((o) => o.value === 'grp'),
    'enabled tunnels and groups are offered', JSON.stringify(opts.map((o) => o.value)));
  check(opts.length === PATHS.length + 1,
    'the page offers exactly what the daemon listed, plus the ordinary path', JSON.stringify(opts.map((o) => o.value)));
  check(!opts.some((o) => o.value === 'vless-de'),
    'nothing the daemon withheld appears', JSON.stringify(opts.map((o) => o.value)));
  check(/routes everything else/.test(text(row)),
    'with nothing chosen the row says downloads follow ordinary routing', text(row));

  // Saved AND resolved: the row names the interface the daemon will actually bind the socket to,
  // because an interface name is the only thing an operator can check against the router.
  row = rowFor({ download_via: 'external-nwg3', download_iface: 'nwg3', download_paths: PATHS });
  check(/in force: through nwg3/.test(text(row)), 'a working choice names the bound interface', text(row));

  // Saved but NOT resolved — the failure this row exists to make visible.
  row = rowFor({ download_via: 'grp', download_iface: '', download_paths: PATHS });
  check(/not in force/.test(text(row)) && /ordinary path/.test(text(row)),
    'an unresolvable choice says the download takes the ordinary path anyway', text(row));

  // A choice the profile no longer contains stays selected and says so, rather than reading as the
  // ordinary path — the operator picked something, and it disappearing is the news.
  row = rowFor({ download_via: 'external-gone', download_iface: '', download_paths: PATHS });
  opts = options(row);
  check(opts.some((o) => o.value === 'external-gone' && /no longer in the profile/.test(o.label)),
    'a vanished choice is still shown, marked as gone', JSON.stringify(opts.map((o) => o.label)));

  // Saving must go through the config write path, not some updater-only side door: the daemon re-binds
  // the updater after every config write, and a setting stored anywhere else would never take effect.
  const change = listeners.find((l) => l.type === 'change');
  check(!!change, 'the row saves on change');
  if (change) {
    change.node.value = 'grp';
    await change.fn();
    check(puts.length === 1 && puts[0].u === '/api/config',
      'the choice is written through /api/config', JSON.stringify(puts.map((p) => p.u)));
    check(puts[0] && puts[0].body.updater && puts[0].body.updater.download_via === 'grp',
      'the chosen tag lands in updater.download_via', JSON.stringify(puts[0] && puts[0].body.updater));
    // The save succeeded and the choice did NOT take effect — the mocked re-read returns no
    // interface. What the operator is TOLD has to be about the outcome, not about the write.
    // Measured wording before this: the success-styled "Downloads now go through the router's
    // ordinary path", beside a note that read "not in force". A group is offered on member kind
    // rather than member health, so an all-down group is reachable by clicking alone, and that is
    // precisely the operator who was trying to route around a blocked ordinary path.
    check(toasts.length === 1 && toasts[0].kind === 'err',
      'a choice that did not take effect is not reported in the success style', JSON.stringify(toasts));
    check(toasts[0] && /not in force/.test(toasts[0].msg),
      'and says so in words', JSON.stringify(toasts));
  }

  // The positive control: when the choice DOES resolve, the row still says so plainly and in the
  // success style. Without this, silencing the success toast entirely would pass the checks above.
  rowFor({ download_via: '', download_iface: '', download_paths: PATHS },
    { download_via: 'grp', download_iface: 'nwg3' });
  const okChange = listeners.find((l) => l.type === 'change');
  if (okChange) {
    okChange.node.value = 'grp';
    await okChange.fn();
    check(toasts.length === 1 && toasts[0].kind === 'ok' && /nwg3/.test(toasts[0].msg),
      'a choice that took effect names the interface it now uses', JSON.stringify(toasts));
  }
}

// The offer for a router that needs nothing must cost nothing until it is opened.
//
// Measuring the download makes the daemon call api.github.com directly — mirrors are not allowed to
// define the release metadata a digest is checked against — so building the panel eagerly meant one
// such call per visit to this page, on a router whose answer is "you need nothing". Where GitHub is
// unreachable that is a request that hangs for the whole 20-second timeout and then fills a panel
// nobody opened.
{
  const requested = [];
  const listeners = [];
  const el = (tag, attrs = {}, ...children) => {
    const node = { tag, attrs, children: children.filter((c) => c != null), open: false };
    node.appendChild = (child) => { node.children.push(child); return child; };
    node.addEventListener = (type, fn) => { listeners.push({ node, type, fn }); };
    Object.defineProperty(node, 'innerHTML', { set(v) { if (v === '') node.children.length = 0; }, get() { return ''; } });
    return node;
  };
  const context = vm.createContext({
    el,
    t: (s) => s,
    fmtBytes: () => '0 B',
    PROTO_LABEL: {},
    api: { get: (u) => { requested.push(u); return Promise.resolve({ singbox_required: [], native: {} }); } },
    Promise,
  });
  vm.runInContext(
    `${functionSource(updater, 'collapsedOffer')}\n`
    + `${functionSource(updater, 'unlockNote')}\n`
    + `${functionSource(updater, 'installCostNote')}\n`
    + 'globalThis.run = collapsedOffer;',
    context);

  const det = context.run({ id: 'sing-box' });
  check(requested.length === 0,
    'a collapsed offer asks the daemon for nothing at render', JSON.stringify(requested));
  check((det.children[0] || {}).tag === 'summary', 'the collapsed offer still renders its summary');

  const toggle = listeners.find((l) => l.type === 'toggle');
  check(!!toggle, 'the collapsed offer fills on toggle');
  // A toggle that CLOSED the panel must not fetch either.
  det.open = false;
  if (toggle) toggle.fn();
  check(requested.length === 0, 'closing the panel fetches nothing', JSON.stringify(requested));

  det.open = true;
  if (toggle) toggle.fn();
  check(requested.some((u) => u.includes('/fit')) && requested.some((u) => u.includes('/native/capabilities')),
    'opening it asks for the size and for what it would unlock', JSON.stringify(requested));

  // Closing and reopening must not stack a second copy of both notes, nor repeat both requests.
  const afterFirstOpen = requested.length;
  const childrenAfterFirstOpen = det.children.length;
  det.open = false;
  if (toggle) toggle.fn();
  det.open = true;
  if (toggle) toggle.fn();
  check(requested.length === afterFirstOpen && det.children.length === childrenAfterFirstOpen,
    'reopening the panel neither refetches nor duplicates its notes',
    `${requested.length} requests, ${det.children.length} children`);
}

// What the member ORDER buys must match who carries the group — the panel said three things about it.
//
// The New-group dialog offers "fallback — strict order"; its footer said "urltest/fallback auto-pick
// the fastest working member and use your order as a tiebreak"; and the group card afterwards said
// fallback follows the order top to bottom. Both blanket claims are wrong for some group, because an
// UNMANAGED fallback group is compiled to a sing-box urltest outbound (generator/singbox.go shares
// that branch — sing-box has no strict-order outbound), while a kernel-carried or managed one really
// is elected in the operator's order.
{
  // foOrderNote now reads failoverState to tell a group the kernel routes from one only the core
  // carries, so the sandbox has to carry it too. Empty by default: that is the core-only case.
  const context = vm.createContext({ failoverState: { kernel_members: {} }, t: (s2, ...a) => s2.replace(/\{(\d)\}/g, (_, i) => a[i]) });
  const findEndpointStub = 'globalThis.findEndpoint = (id) => ({ id, engine: /^native-/.test(id) ? "external" : "singbox" });';
  vm.runInContext([
    functionSource(app, 'foGroupNeedsCore'),
    functionSource(app, 'foOrderNote'),
    findEndpointStub,
    'globalThis.note = foOrderNote;',
  ].join('\n'), context);

  const nativeFallback = context.note({ type: 'fallback', members: ['native-a', 'native-b'] });
  check(/strictly, top to bottom/.test(nativeFallback),
    'a fallback group on router tunnels promises strict order', nativeFallback);

  const coreFallback = context.note({ type: 'fallback', members: ['vless-a', 'native-b'] });
  check(/fastest working member/.test(coreFallback) && !/strictly/.test(coreFallback),
    'a fallback group the core carries says the fastest wins instead', coreFallback);

  // A group can be carried BOTH ways at once, and on a live AX3000T group-failover is: its
  // prefix lists are routed by the kernel, which elects in his order and takes the first healthy
  // member, while everything else goes through the core, which has no strict-order outbound. The
  // note answered with the core's half alone - one of two truths stated as the whole one, the same
  // mistake this note was written to fix, taken in the other direction.
  context.failoverState.kernel_members = { split: ['native-b'] };
  const bothWays = context.note({ id: 'split', type: 'fallback', members: ['vless-a', 'native-b'] });
  check(/kernel carries follow your order strictly/.test(bothWays),
    'a group carried both ways says the kernel half follows the order', bothWays);
  check(/tiebreak/.test(bothWays),
    'and says in the same sentence that the core half does not');
  context.failoverState.kernel_members = {};

  const managedFallback = context.note({ type: 'fallback', members: ['vless-a'], managed: true });
  check(/strictly, top to bottom/.test(managedFallback),
    'a managed group gets its strict order from the daemon and says so', managedFallback);

  // And the dialog footer must stop making a blanket claim that contradicts the card.
  const hint = (app.match(/const MEMBER_ORDER_HINT = "([^"]*)"/) || [])[1] || '';
  check(!/urltest\/fallback auto-pick the fastest/.test(hint),
    'the dialog no longer tells every fallback group the fastest wins', hint.slice(0, 90));
  check(/strictly on router tunnels/.test(hint) && /tiebreak/.test(hint),
    'it names both answers and points at the card for which applies', hint.slice(0, 120));
}

// A form that draws "✗ not a valid x25519 key" must not then save the value.
//
// Measured by importing a Reality link whose public key was 3 characters: the field validated as you
// type, painted the error red, and Save wrote it into the profile anyway with an "Added" toast. The
// Apply preflight has no opinion about key material either, so the first thing that would notice is
// the tunnel failing to come up, a long way from the field that already knew.
{
  const seen = [];
  const input = {
    tagName: 'INPUT', dataset: { invalid: '1', invalidLabel: 'Reality public key', invalidWhy: 'not a valid x25519 key (base64 of 32 bytes)' },
    focus() { seen.push('focused'); },
  };
  const form = {
    el: { querySelectorAll: (sel) => (sel === '[data-invalid="1"]' ? [input] : []) },
  };
  const context = vm.createContext({ t: (s2, ...a) => s2.replace(/\{(\d)\}/g, (_, i) => a[i]) });
  vm.runInContext(`${functionSource(connections, 'invalidFieldError')}
globalThis.run = invalidFieldError;`, context);

  const msg = context.run(form);
  check(/Reality public key/.test(msg) && /x25519/.test(msg),
    'a refused save names the field and the reason', msg);
  check(seen.includes('focused'), 'and puts the cursor on the offending field', JSON.stringify(seen));

  // A clean form must not be refused — a guard that always fires is a form nobody can save.
  const clean = { el: { querySelectorAll: () => [] } };
  check(context.run(clean) === '', 'a clean form saves', JSON.stringify(context.run(clean)));

  // Both save paths have to consult it, not just the one that was easy to reach. Counting call sites
  // was the first attempt and it could not tell them apart: with the definition and two guards in the
  // file, deleting one still left "at least two". Assert each save path's OWN body instead.
  const addSave = functionSource(connections, 'openAddConnection');
  const editSave = functionSource(connections, 'openEditEndpoint');
  check(/invalidFieldError\(/.test(addSave), 'the add-connection save path refuses an invalid field');
  check(/invalidFieldError\(/.test(editSave), 'the edit-connection save path refuses an invalid field');
}

// A check that DID NOT RUN must never render as a failure, on any page that shows one.
//
// The battery gained a fourth status when "nothing was checked" stopped being reported as a verdict.
// Every consumer maps status -> pill class with a fall-through, and the fall-through is the RED pill:
// the DNS page's leak widget mapped pass and warn and sent everything else to "err", so the moment
// `na` existed, a check that simply had nothing to read rendered as a leak. Its own comment had been
// written after the SAME bug turned a leak-free result red. One unnamed value is all it takes.
{
  const seen = [];
  const el = (tag, attrs = {}, ...children) => {
    const node = { tag, attrs, children: children.filter((c) => c != null), textContent: '' };
    node.appendChild = (c) => { node.children.push(c); return c; };
    Object.defineProperty(node, 'innerHTML', { set(v) { if (v === '') node.children.length = 0; }, get() { return ''; } });
    return node;
  };
  const classesOf = (node, out = []) => {
    if (node && typeof node === 'object') {
      if (node.attrs && typeof node.attrs.class === 'string' && node.attrs.class.startsWith('pill ')) out.push(node.attrs.class);
      (node.children || []).forEach((c) => classesOf(c, out));
    }
    return out;
  };
  const rows = [
    { id: 'dns', label: 'Encrypted DNS', status: 'na', summary: 'this host has no connection table to read', fix: 'do not show me' },
    { id: 'ipv6', label: 'IPv6', status: 'pass', summary: 'no global IPv6' },
  ];
  const body = el('div');
  const context = vm.createContext({
    el,
    t: (s2) => s2,
    api: { get: () => Promise.resolve({ checks: rows }) },
    Promise,
  });
  vm.runInContext(`${functionSource(dns, 'runDNSLeak')}
globalThis.run = runDNSLeak;`, context);
  await context.run(body);
  await new Promise((r) => setTimeout(r, 0));
  const pills = classesOf(body);
  check(!pills.includes('pill err'),
    'a check that did not run is never painted as a failure', JSON.stringify(pills));
  check(pills.some((c) => c === 'pill muted'), 'it is painted neutral instead', JSON.stringify(pills));
  check(pills.includes('pill ok'), 'a passing row beside it still reads as passing', JSON.stringify(pills));

  // The same rule on the page the battery belongs to. Both halves matter: the colour, and the name
  // assistive tech reads out — "fail" spoken over a check that never ran is the same false alarm
  // without the pixels.
  // A row with a reason to show grows a disclosure, so the double needs insertBefore as well as
  // appendChild — the shipped function is the subject, not a re-implementation of it.
  const rowEl = (tag, attrs = {}, ...children) => {
    const node = el(tag, attrs, ...children);
    node.insertBefore = (child, before) => {
      const at = node.children.indexOf(before);
      node.children.splice(at < 0 ? node.children.length : at, 0, child);
      return child;
    };
    node.style = {};
    node.setAttribute = (k, v) => { node.attrs[k] = v; };
    return node;
  };
  const rowCtx = vm.createContext({
    el: rowEl,
    t: (s2) => s2,
    hcLabel: (id) => id,
    recheckOne: () => {},
    copyText: () => {},
    mono: (v) => rowEl('pre', {}, v),
    kbCard: () => rowEl('div'),
    a11yClick: () => {},
    HC_DEEP: {},
  });
  vm.runInContext(`${functionSource(diagnostics, 'healthRowEl')}
globalThis.row = healthRowEl;`, rowCtx);
  const chipOf = (node) => {
    let found = null;
    const walkNode = (n) => {
      if (!n || typeof n !== 'object' || found) return;
      if (n.attrs && String(n.attrs.class || '').startsWith('pill')) { found = n; return; }
      (n.children || []).forEach(walkNode);
    };
    walkNode(node);
    return found;
  };
  const naRow = rowCtx.row('dns', { status: 'na', summary: 'nothing to read here' }, false, false, {});
  const naChip = chipOf(naRow);
  check(naChip && naChip.attrs.class === 'pill muted',
    'the battery paints a check that did not run neutral', naChip && naChip.attrs.class);
  check(naChip && naChip.attrs['aria-label'] === 'not checked',
    'and names it "not checked" rather than fail', naChip && naChip.attrs['aria-label']);
  const failRow = rowCtx.row('dns', { status: 'fail', summary: 'broken' }, false, false, {});
  const failChip = chipOf(failRow);
  check(failChip && failChip.attrs.class === 'pill err' && failChip.attrs['aria-label'] === 'fail',
    'a real failure still reads as one', failChip && failChip.attrs.class);
  const text = JSON.stringify(body);
  check(!text.includes('do not show me'),
    'a check that did not run offers no advice to act on');
  seen.push(pills.length);
}

// Removing the core is a question the operator has to be able to answer.
//
// The daemon refuses the first DELETE while sing-box is running, because deleting it takes the
// router's datapath with it. That refusal reached the panel as the literal sentence "resend with
// stop:true" — an instruction to a program, shown to a person holding a mouse, on a control with no
// other way forward. Measured on a live Keenetic: Remove, confirm, and a red toast telling
// them to do something a browser cannot do. The flag was already in the response and the package path
// already branched on it; this path threw it away.
{
  const calls = [];
  const asked = [];
  const mkContext = (answers) => {
    const context = vm.createContext({
      t: (s, ...a) => s.replace(/\{(\d)\}/g, (_, i) => a[i]),
      toast: (m) => calls.push({ toast: m }),
      route: () => calls.push({ route: true }),
      modalConfirm: (q) => { asked.push(q); return Promise.resolve(answers.shift()); },
      api: {
        del: (p, body) => {
          calls.push({ del: p, body });
          if (!body || !body.stop) {
            const e = new Error('sing-box is running, and removing it deletes the binary the router '
              + 'is using right now. That stops the VPN datapath until sing-box is installed again.');
            e.status = 409;
            e.data = { needs_stop: true };
            return Promise.reject(e);
          }
          return Promise.resolve({ removed: 'sing-box', stopped: true });
        },
      },
      Promise,
    });
    vm.runInContext(`${functionSource(updater, 'removeEngine')}\nglobalThis.run = removeEngine;`, context);
    return context;
  };
  const btn = { attrs: {}, textContent: '', setAttribute(k, v) { this.attrs[k] = v; }, removeAttribute(k) { delete this.attrs[k]; } };

  // Yes to the first confirmation, yes to the refusal: the SAME request goes back with stop:true.
  let context = mkContext([true, true]);
  await context.run({ id: 'sing-box', name: 'sing-box', used_by: ['encrypted DNS'] }, btn);
  const dels = calls.filter((c) => c.del);
  check(dels.length === 2 && !dels[0].body && dels[1].body && dels[1].body.stop === true,
    'a refused core removal is retried with the stop the daemon asked for', JSON.stringify(dels));
  check(dels[0].del === dels[1].del, 'the retry is the same request, not a different one', JSON.stringify(dels));
  check(asked.length === 2 && /stops the VPN datapath/.test(asked[1]),
    'the operator is asked the daemon\'s own question, not shown an API instruction', JSON.stringify(asked));
  check(calls.some((c) => c.toast && /stopped and removed/.test(c.toast)),
    'the outcome says the core was stopped, not just removed', JSON.stringify(calls.filter((c) => c.toast)));
  check(calls.some((c) => c.route), 'the page re-reads itself after a removal');

  // No to the escalation: nothing is sent, and the button comes back.
  calls.length = 0; asked.length = 0;
  context = mkContext([true, false]);
  await context.run({ id: 'sing-box', name: 'sing-box', used_by: [] }, btn);
  check(calls.filter((c) => c.del).length === 1, 'declining the escalation sends no second request',
    JSON.stringify(calls));
  check(!calls.some((c) => c.route) && btn.attrs.disabled === undefined,
    'declining leaves the page alone and the button usable', JSON.stringify(btn.attrs));
}

// An operational row carries buttons, so only what this page may actually install gets one.
//
// Widening it to every engine that PROVIDES a protocol put AmneziaWG back with an install control
// beside "the userspace build is not needed here" — the row scripts/ui-kernel-carried.mjs exists
// because of, three true sentences that together tell an operator to fix a router whose kernel module
// was carrying their tunnel at that moment. The fact still has to reach the reader, so it is stated
// below the table as prose: an answer with nothing to click.
{
  const context = vm.createContext({
    el: (tag, attrs = {}, ...children) => ({ tag, attrs, children }),
    t: (s, ...a) => s.replace(/\{(\d)\}/g, (_, i) => a[i]),
  });
  vm.runInContext(`${functionSource(updater, 'componentsToShow')}\n`
    + `${functionSource(updater, 'kernelCarriedNote')}\n`
    + `const PROTO_LABEL = { amneziawg: 'AmneziaWG' };\n`
    + 'globalThis.run = componentsToShow;\nglobalThis.note = kernelCarriedNote;', context);
  const catalog = [
    { id: 'sing-box', role: 'core' },
    { id: 'amneziawg-go', name: 'AmneziaWG (userspace)', role: 'kernel-plugin', provides: 'amneziawg', carried_by_kernel: true },
    { id: 'mihomo', role: 'standalone' },
    { id: 'xray', role: 'standalone' },
    { id: 'hysteria', role: 'standalone' },
    { id: 'dnscrypt-proxy', role: 'standalone' },
    { id: 'olcrtc', name: 'olcRTC', role: 'socks-plugin', native_managed: true, installed: { present: true } },
  ];
  const shown = context.run(catalog).map((e) => e.id);
  check(shown.includes('sing-box'), 'the core is listed', JSON.stringify(shown));
  check(!shown.includes('amneziawg-go'),
    'an engine the kernel already carries gets no installable row', JSON.stringify(shown));
  check(!shown.includes('olcrtc'),
    'an engine the package manager owns gets no installable row', JSON.stringify(shown));
  // A standalone binary WayHop's datapath never runs would be a row whose install changes no routing.
  check(!shown.includes('mihomo') && !shown.includes('xray') && !shown.includes('hysteria')
    && !shown.includes('dnscrypt-proxy'),
    'catalog binaries the datapath cannot use stay out', JSON.stringify(shown));
  check(context.run(undefined).length === 0, 'a missing engine list is not a crash');

  // What left the table has to arrive somewhere: the answer to "where is AmneziaWG" is the reason
  // this page shows it at all.
  const text = (n) => (n == null ? '' : typeof n !== 'object' ? String(n)
    : (n.children || []).map(text).join(''));
  const note = text(context.note(catalog));
  check(/AmneziaWG/.test(note) && /nothing to install/.test(note),
    'the kernel-carried protocol is named, with nothing to install', note);
  check(/olcRTC/.test(note) && /package manager/.test(note),
    'a package-manager-owned engine says where it is updated', note);
  check(context.note([{ id: 'sing-box', role: 'core' }]) === null,
    'an ordinary router gets no such note at all');

  // "The kernel carries AmneziaWG itself" stood over a generation-2 module that cannot carry a 3.x
  // setting. The daemon now reports carried_by_kernel only for the newest generation, names it, and a
  // router behind it gets the component offered as optional instead of the prose.
  const gen = (builtin, extra = {}) => ({ id: 'amneziawg-go', name: 'AmneziaWG (userspace)', role: 'kernel-plugin',
    provides: 'amneziawg', awg: { builtin, newest: '3.1', needed: false, ...extra }, ...extra.row });
  check(context.run([gen('2', { optional: true })]).length === 1,
    'an AmneziaWG older than amneziawg-go gets its row, as an offer');
  check(context.run([gen('3.1', { row: { carried_by_kernel: true } })]).length === 0,
    'the newest AmneziaWG in the kernel still gets no row');
  const newest = text(context.note([gen('3.1', { row: { carried_by_kernel: true } })]));
  check(/AmneziaWG 3\.1 itself/.test(newest), 'the note names the generation the kernel carries', newest);
}

// The AmneziaWG row sets the router's own generation against amneziawg-go's, and when nothing needs
// the component says it is optional and what it is for, so its Install reads as an offer.
{
  const context = vm.createContext({
    el: (tag, attrs = {}, ...children) => ({ tag, attrs, children }),
    t: (s, ...a) => s.replace(/\{(\d)\}/g, (_, i) => a[i]),
  });
  vm.runInContext(`${functionSource(updater, 'awgBuiltinLine')}\nglobalThis.line = awgBuiltinLine;`, context);
  const text = (n) => (n == null ? '' : typeof n !== 'object' ? String(n) : (n.children || []).map(text).join(''));
  const offer = text(context.line({ builtin: '2', newest: '3.1', optional: true }));
  check(/up to generation 2; amneziawg-go runs generation 3\.1/.test(offer) && /^.*Optional: no connection needs it yet/.test(offer),
    'a generation-2 router is told what it has, what amneziawg-go adds, and that it is optional', offer);
  const needed = text(context.line({ builtin: '2', newest: '3.1', optional: false }));
  check(/generation 2/.test(needed) && !/Optional/.test(needed),
    'a router that needs amneziawg-go is not told it is optional', needed);
  check(context.line({ builtin: '3.1', newest: '3.1', optional: false }) === null,
    'the newest generation needs no such line');
  check(!/generation none/.test(text(context.line({ builtin: 'none', newest: '3.1', optional: true }))),
    'a router with no AmneziaWG of its own is not given a generation');
}

// The connection editor's engine choice: collect() builds the endpoint from the form alone, so a
// field without a control is lost on the first save. awg_userspace has one, is read back into it, and
// is sent only for an AmneziaWG connection.
{
  const awgBranch = conns.slice(conns.indexOf('if (proto === "amneziawg") {\n      // Same typing rule'),
    conns.indexOf('if (["socks", "http"].includes(proto) && g("f-user"))'));
  check(/g\("f-awg-engine"\) === "userspace"\) out\.awg_userspace = true/.test(awgBranch),
    'collect() carries the engine choice, inside the AmneziaWG branch', awgBranch.slice(-200));
  check(/eng\.value = ep\.awg_userspace \? "userspace" : "auto"/.test(conns),
    'the editor opens on the stored choice');
}

// No user-visible string may send the reader to a section that is not in the navigation.
//
// Renaming "Updater" to "Components" left two hints on the Routing page saying "install it in
// Updater" and three labels in Settings called "Updater mirrors". Every word of them had been true
// for a year, and after the rename they pointed at a nav item nobody can find — which is worse than
// vague, because the reader goes looking. A rename is not finished when the nav label changes; it is
// finished when nothing else still says the old name.
//
// Add the old name here when renaming a section, and this fails until the last reference is gone.
{
  const RETIRED_SECTION_NAMES = ['Updater'];
  const shipped = ['web/dist/app.js', ...fs.readdirSync('web/dist')
    .filter((f) => /^page-.*\.js$/.test(f)).map((f) => `web/dist/${f}`)];
  // Only what the operator can READ: the argument of a t(…) call, not comments or identifiers.
  const uiStrings = [];
  for (const file of shipped) {
    const text = fs.readFileSync(file, 'utf8');
    for (const m of text.matchAll(/\bt\(\s*"((?:[^"\\]|\\.)*)"/g)) uiStrings.push({ file, s: m[1] });
  }
  check(uiStrings.length > 200, 'the UI-string scan found strings to check', String(uiStrings.length));
  for (const name of RETIRED_SECTION_NAMES) {
    const offenders = uiStrings.filter((u) => u.s.includes(name));
    check(offenders.length === 0,
      `no shipped UI string names the retired section "${name}"`,
      offenders.slice(0, 3).map((o) => `${o.file}: ${o.s.slice(0, 60)}`).join(' | '));
  }
  // And the names it DOES use must be real: every nav label in app.js is a section that exists.
  const navLine = fs.readFileSync('web/dist/app.js', 'utf8').match(/const NAV_LABELS = \{([^}]*)\}/);
  check(!!navLine && /updater:\s*"Components"/.test(navLine[1]),
    'the components route still carries the Components label', navLine ? navLine[1].slice(0, 80) : 'not found');
}

// What an install COSTS must be on screen wherever an install can be started, not only where the
// engine is absent.
//
// installCostNote was rendered for the not-installed row alone. An engine that IS installed still
// carries a version picker and an "Install selected" button, and pressing it downloads and writes
// exactly as much as a first install — ~69 MB for sing-box. On a live AX3000T, whose overlay
// has under 13 MB free, that refusal arrived only after the click, which is the failure /fit exists
// to prevent. Measured on the Keenetic: the picker offered fifteen versions with no cost anywhere.
{
  const src = fs.readFileSync('web/dist/page-updater.js', 'utf8');

  // The note has to be able to answer for a chosen version, not just "latest".
  check(/function installCostNote\(e, version\)/.test(src),
    'the cost note takes a version');
  const note = src.slice(src.indexOf('function installCostNote(e, version)'), src.indexOf('function installCostNote(e, version)') + 700);
  check(/\?version=" \+ encodeURIComponent\(version\)/.test(note),
    'and asks the daemon about that version', note.slice(0, 200));
  check(/version \?/.test(note),
    'while still asking about the default when no version is given');

  // It must be beside the picker, and it must follow the selection: the answer is per-version.
  const picker = src.slice(src.indexOf('Install selected version of'), src.indexOf('Install selected version of') + 1200);
  check(/installCostNote\(e, sel\.value\)/.test(picker),
    'the picker shows the cost of the selected version', picker.slice(0, 200));
  check(/sel\.addEventListener\("change"/.test(picker) && /replaceWith/.test(picker),
    'and re-measures when the selection changes');

  // The original call site must survive: an absent engine still states its cost.
  check(/p\.vbox\.appendChild\(installCostNote\(e\)\);/.test(src),
    'an absent engine still states what installing it would cost');
}

// A package-managed engine that offers NO action must say why it offers none.
//
// The managed branch explains itself for behind / catalog_error / channel_missing / ahead, and fell
// through to silence for "unknown". Reproduced with a binary the package does not list among its
// files — the daemon's own guard against operating on a package that would not act on the binary in
// use, which is what stops a remove taking out the wrong thing. The row then read "Installed as apk
// package sing-box." with no Update, no Remove, no Roll back and not a word about it.
{
  const src = fs.readFileSync('web/dist/page-updater.js', 'utf8');
  const managed = src.slice(src.indexOf('if (managed) {'), src.indexOf('} else if (!installed.present'));

  check(/pkg\.state === "behind"/.test(managed), 'the behind state still offers the update path');
  check(/pkg\.state === "catalog_error"/.test(managed), 'an unreadable catalog still explains itself');
  check(/pkg\.state === "channel_missing"/.test(managed), 'a missing repository still explains itself');
  check(/pkg\.state === "ahead"/.test(managed), 'an ahead package still explains itself');
  // "current" was the last silent state, found on a live AX3000T: an apk-owned sing-box at
  // 1.12.17 against a 1.12.17-r1 catalog rendered "Installed as apk package sing-box · 1.12.17-r1."
  // and stopped — no Update (right, there is nothing to update to), but also no Remove, no Roll back
  // and no reason. The first fix stated the policy: the panel does not operate over a package manager
  // that owns the binary. The policy itself was then wrong — the daemon has carried a tested `apk del`
  // plan, its collateral list and its stop gate all along, and nothing led to them — so the row now
  // says there is nothing to UPDATE and points at the actions it does offer.
  check(/pkg\.state === "current"/.test(managed),
    'an up-to-date package says why it offers no update');
  const currentBranch = managed.slice(managed.indexOf('pkg.state === "current"'));
  check(/nothing to update/.test(currentBranch) && /going back to an older build/.test(currentBranch),
    'and names both halves: nothing to update, and where removing or rolling back happens',
    currentBranch.slice(0, 200));
  // The controls themselves, which is the half a sentence cannot stand in for. Every package-owned
  // row gets the delegation box — "owned" when the feed has something newer, "managed" when it does
  // not — and the mode that carries Update is the only one gated on being behind. This is the check
  // that would have caught the original defect: `pmDelegation` had an "owned" mode with Remove and
  // Roll back in it that no call site ever passed.
  check(/pmDelegation\(e, pmKind, pkg\.state === "behind" \? "owned" : "managed"\)/.test(managed),
    'and every package-owned row gets the delegation, not only one with an update waiting');
  const delegation = src.slice(src.indexOf('function pmDelegation'));
  check(/mode === "owned"[\s\S]{0,120}act\(t\("Update"\), "upgrade"\)/.test(delegation),
    'Update is offered only where there is something to update to');
  check(/acts\.appendChild\(act\(t\("Remove"\), "remove"\)\)/.test(delegation) &&
    !/mode === "update"/.test(delegation),
    'Remove is reachable in both owned modes rather than returned past');
  // The case this exists for: anything else with a reason attached must surface that reason.
  check(/else if \(pkg\.error\)/.test(managed),
    'any other state surfaces the daemon reason instead of going quiet');
  check(/No package actions are offered for this one/.test(managed),
    'and names what is missing rather than only why');
  // The reason must be the daemon's sentence, not one invented by the page: the daemon sanitises it
  // (package-manager output can carry private feed URLs), and inventing one here would drift.
  const branch = managed.slice(managed.indexOf('else if (pkg.error)'));
  check(/el\("span", \{\}, pkg\.error\)/.test(branch),
    'the sentence shown is the daemon\'s own', branch.slice(0, 160));
}

// Making a DEAD group the default route asks first; making a live one does not.
//
// The control took effect silently, and the card afterwards stated only the general rule ("if it
// fails, traffic through this group stops") — never that the thing just chosen is down right now.
// Measured while testing group actions: a group whose two members both read "unusable / down" became
// the default route with no warning at any point.
//
// The question is asked only when the answer is KNOWN and bad. A member whose health has not been
// measured is not evidence of anything, and a confirmation on every click would be ceremony rather
// than information — which is how a panel teaches people to click through warnings.
{
  const run = async (health, members) => {
    const asked = [];
    const posted = [];
    const context = vm.createContext({
      t: (s2, ...a) => s2.replace(/\{(\d)\}/g, (_, i) => a[i]),
      healthMap: health,
      modalConfirm: (q) => { asked.push(q); return Promise.resolve(false); },
      api: { post: (u, b) => { posted.push({ u, b }); return Promise.resolve({}); } },
      loadProfile: () => Promise.resolve(),
      route: () => {},
      toast: () => {},
      Promise,
    });
    vm.runInContext(`${functionSource(app, 'setDefault')}\nglobalThis.run = setDefault;`, context);
    await context.run({ id: 'g', name: 'Main', members });
    return { asked, posted };
  };

  const allDown = await run({ a: { state: 'down' }, b: { state: 'down' } }, ['a', 'b']);
  check(allDown.asked.length === 1 && /down right now/.test(allDown.asked[0]),
    'a group with every member down asks before becoming the default route', JSON.stringify(allDown.asked));
  check(/ALL unmatched traffic/.test(allDown.asked[0] || ''),
    'and the question says what that costs', (allDown.asked[0] || '').slice(0, 90));
  check(allDown.posted.length === 0,
    'declining writes nothing', JSON.stringify(allDown.posted));

  const oneAlive = await run({ a: { state: 'down' }, b: { state: 'alive' } }, ['a', 'b']);
  check(oneAlive.asked.length === 0 && oneAlive.posted.length === 1,
    'one healthy member is enough to proceed without a question', JSON.stringify(oneAlive));

  // Unmeasured health is not evidence of failure: a fresh page must not accuse a working group.
  const unmeasured = await run({}, ['a', 'b']);
  check(unmeasured.asked.length === 0 && unmeasured.posted.length === 1,
    'unmeasured members do not trigger the warning', JSON.stringify(unmeasured));
}

// Nothing submitted is not the same answer as nothing found.
//
// The subscription tab answered an empty form with "No connections found." — a report on a search
// that never ran, in the same dialog whose Paste-link tab already distinguishes "The link is empty"
// from "This connection format is not supported". The daemon was not even asked.
{
  const src = fs.readFileSync('web/dist/page-connections.js', 'utf8');
  const fetchHandler = src.slice(src.indexOf('const fetchBtn = el("button"'), src.indexOf('const fetchBtn = el("button"') + 1400);
  check(/Nothing to fetch/.test(fetchHandler),
    'an empty subscription form says nothing was submitted');
  // The guard must come BEFORE the request: the point is not to ask at all.
  const guardAt = fetchHandler.indexOf('Nothing to fetch');
  const postAt = fetchHandler.indexOf('api.post("/api/subscription"');
  check(guardAt > 0 && postAt > 0 && guardAt < postAt,
    'and it refuses before calling the daemon, not after', `guard@${guardAt} post@${postAt}`);
  // Both inputs count: a URL alone or pasted text alone is a real submission.
  check(/!url\.value\.trim\(\) && !ta\.value\.trim\(\)/.test(fetchHandler),
    'either field alone still counts as something to fetch');
  // The button has to come back, or the empty case would disable the form permanently.
  const afterGuard = fetchHandler.slice(guardAt, guardAt + 260);
  check(/b\.disabled = false;/.test(afterGuard),
    'the Fetch button is re-enabled after the refusal', afterGuard.slice(0, 120));
  // "No connections found" must still exist for the case it is actually about.
  check(/No connections found/.test(src),
    'a real search that finds nothing still says so');
}

// "Install with opkg" must not be offered where the feed has no such package.
//
// The daemon already knows: PlanPM does the candidate lookup and the virtual-name resolution, and
// returns `blocked` with the checks it ran. The page drew the button regardless, so the check landed
// AFTER the click — measured on a live Keenetic, which answered "opkg has no package called
// \"sing-box\" and nothing provides it" only once pressed. Of the seven engines this panel knows, the
// AX3000T's feed carries two.
{
  const mk = () => {
    const node = { tag: 'div', attrs: {}, children: [], textContent: '' };
    node.appendChild = (c) => { node.children.push(c); return c; };
    node.remove = () => {};
    Object.defineProperty(node, 'innerHTML', { set(v) { if (v === '') node.children.length = 0; }, get() { return ''; } });
    return node;
  };
  const el = (tag, attrs = {}, ...children) => {
    const node = mk();
    node.tag = tag;
    node.attrs = attrs;
    node.children = children.filter((c) => c != null);
    node.addEventListener = () => {};
    return node;
  };
  const text = (n) => {
    if (n == null) return '';
    if (typeof n !== 'object') return String(n);
    return [n.textContent || '', ...(n.children || []).map(text)].join('');
  };
  const buttons = (n, out = []) => {
    if (n && typeof n === 'object') {
      if (n.tag === 'button') out.push(text(n));
      (n.children || []).forEach((c) => buttons(c, out));
    }
    return out;
  };

  const run = async (planAnswer) => {
    const asked = [];
    const context = vm.createContext({
      el,
      t: (s2, ...a) => s2.replace(/\{(\d)\}/g, (_, i) => a[i]),
      toast: () => {},
      modalConfirm: () => Promise.resolve(true),
      route: () => {},
      api: {
        get: (u) => { asked.push(u); return planAnswer instanceof Error ? Promise.reject(planAnswer) : Promise.resolve(planAnswer); },
        post: () => Promise.resolve({}),
      },
      Promise,
    });
    vm.runInContext(`${functionSource(updater, 'pmDelegation')}\nglobalThis.run = pmDelegation;`, context);
    const box = context.run({ id: 'sing-box', name: 'sing-box' }, 'opkg', 'install');
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
    return { box, asked, labels: buttons(box), body: text(box) };
  };

  // The feed does not carry it: no button, and the reason plus the evidence in its place.
  const blocked = await run({
    blocked: 'opkg has no package called "sing-box" and nothing provides it',
    checks: [{ name: 'the feed has this package', ok: false, note: 'nothing provides it' }],
  });
  check(blocked.asked.some((u) => /\/pm\/plan\?action=install/.test(u)),
    'the row asks the daemon whether an install is possible', JSON.stringify(blocked.asked));
  check(!blocked.labels.some((l) => /Install with/.test(l)),
    'a package the feed does not carry gets no install button', JSON.stringify(blocked.labels));
  check(/no package called/.test(blocked.body), 'the reason takes its place', blocked.body.slice(0, 120));
  check(/What was checked/.test(blocked.body), 'with the evidence that used to appear only after clicking');

  // The feed does carry it: the button appears.
  const ok = await run({ runnable: true, argv: ['opkg', 'install', 'sing-box'], checks: [] });
  check(ok.labels.some((l) => /Install with opkg/.test(l)),
    'an installable package still gets its button', JSON.stringify(ok.labels));

  // The lookup itself failed — a locked package database is not proof of absence, so refusing here
  // would hide a working install behind a transient error.
  const errored = await run(new Error('database is locked'));
  check(errored.labels.some((l) => /Install with opkg/.test(l)),
    'a failed lookup still offers the button rather than refusing on unknown', JSON.stringify(errored.labels));
  check(/could not be checked first/.test(errored.body), 'and says the check did not happen', errored.body.slice(0, 140));
}

// Installing a core used to end at a dead end: the applied plan was compiled while the core was
// absent, so the connections it was installed FOR stayed dark, and the line said "Open Review &
// Apply" — over a panel where nothing was pending (installing a binary changes neither profile nor
// config), so no Apply control existed and there was nothing to click. Measured on a live
// Keenetic: only restarting the daemon fixed it, because a restart converges to the committed
// materialization. The daemon now does that itself on install, so the line reports an OUTCOME.
{
  const el = (tag, attrs = {}, ...children) => ({ tag, attrs, children: children.filter((c) => c != null) });
  const text = (n) => (n == null ? '' : typeof n !== 'object' ? String(n) : (n.children || []).map(text).join(''));
  const context = vm.createContext({ el, t: (s, ...a) => s.replace(/\{(\d)\}/g, (_, i) => a[i]) });
  vm.runInContext(`${functionSource(updater, 'installedNextStep')}\nglobalThis.run = installedNextStep;`, context);

  // The ordinary case: the daemon converged, so the thing that was dark is carried again.
  const converged = text(context.run(['Frankfurt VLESS', 'encrypted DNS (dns_secure)'], true));
  check(/running/i.test(converged), 'a converged install reports that it is running', converged);
  check(/Frankfurt VLESS/.test(converged) && /encrypted DNS/.test(converged),
    'and names what is carried again rather than saying "something"', converged);
  check(!/Review & Apply/.test(converged),
    'it no longer sends the operator to a control that does not exist', converged);

  // Not converged: the applied plan does not run this engine, so there is a wait — but the line must
  // describe it truthfully instead of pointing at an absent button.
  const waiting = text(context.run(['Frankfurt VLESS'], false));
  check(/next time the configuration is applied/.test(waiting),
    'an install the plan does not yet use says when it starts counting', waiting);
  check(!/Review & Apply/.test(waiting), 'and still points at no phantom control', waiting);

  const anonymous = text(context.run([], false));
  check(/Nothing is waiting on it/.test(anonymous),
    'with no dependents it says so instead of inventing a next step', anonymous);

  // The line must be a ONE-SHOT: it is a fact about the action just taken, not a standing state, and
  // a nag that reappears on every visit is how a page teaches people to stop reading it.
  const src = fs.readFileSync('web/dist/page-updater.js', 'utf8');
  check((src.match(/updJustInstalled = e\.id;/g) || []).length === 2,
    'the direct and the package-manager install path both record which engine was installed',
    String((src.match(/updJustInstalled = e\.id;/g) || []).length));
  check(/updJustInstalled = null;\s*\n\s*updJustConverged = false;/.test(src),
    'the row clears both flags as it renders the line, so it shows once');
  // The outcome has to travel from the daemon's answer, not be assumed by the page.
  check(/updJustConverged = !!r\.converged;/.test(src),
    'the page takes the converge outcome from the daemon response');
}

// Opening Components must not re-ask GitHub for an answer that belongs to the BUILD.
//
// The WayHop row checks itself on every render, and the daemon answers by calling api.github.com.
// For this build the reply is 404 forever (private repository), so the call buys nothing per visit
// and costs the full 20-second timeout on a router where GitHub is unreachable. Only that verdict is
// cached; a live comparison is not, because it changes under the operator's feet.
{
  const src = fs.readFileSync('web/dist/page-updater.js', 'utf8');
  check(/let updSelfNoChannel = null;/.test(src), 'the no-channel verdict has a session cache');
  check(/if \(s\.no_channel\) updSelfNoChannel = s; else updSelfNoChannel = null;/.test(src),
    'only the no-channel verdict is cached, and any other answer clears it');
  check(/const s = \(!force && updSelfNoChannel\) \? updSelfNoChannel : await api\.get\("\/api\/updater\/self"\);/.test(src),
    'the cache is bypassed whenever the caller forces a fresh check');
  // The render must NOT force (that is the visit-cost this removes); every explicit refresh must.
  check(/rec\.check\(\)\.then\(paintUpdVerdict\);/.test(src),
    'the render-time check does not force a network round trip');
  check(/await r\.check\(true\)/.test(src), 'the sweep forces a fresh check');
  check(/await rec\.check\(true\); paintUpdVerdict\(\)/.test(src),
    "the row's own Check updates button forces a fresh check");
}

// The settings index is one searchable list — that is its whole premise, the reason the page dropped
// tabs. So it has to be searchable by what the reader can SEE: the haystack was name + card + section
// + config path, and any word appearing only in a setting's explanation matched nothing. Measured on
// a live router: "dev-no-auth" reported "0 of 26 settings" with that exact word on screen.
{
  const src = fs.readFileSync('web/dist/app.js', 'utf8');
  check(/r\.hay = \(r\.name \+ " " \+ r\.card \+ " " \+ r\.section \+ " " \+ \(r\.meta\.cfg \|\| ""\) \+ " "\s*\n\s*\+ \(r\.node\.textContent \|\| ""\)\)/.test(src),
    "the settings haystack includes each row's own visible text");
  check(/let ok = !q \|\| r\.hay\.includes\(q\);/.test(src),
    'the filter searches that haystack rather than rebuilding a narrower one');
  // Built once at index time, not per keystroke: the rows carry live controls and the list is
  // re-filtered on every character.
  //
  // The window is the WHOLE function, found by its closing brace at column 0. A fixed character
  // budget was the first cut and it broke the moment the function grew: inserting the row sort
  // pushed `const apply` past the slice, and the check reported a regression that had not happened.
  const indexStart = src.indexOf('function settingsIndex(');
  const indexEnd = src.indexOf('\n}\n', indexStart);
  const indexBody = src.slice(indexStart, indexEnd > 0 ? indexEnd : undefined);
  check(indexBody.indexOf('r.hay =') < indexBody.indexOf('const apply = ()'),
    'the haystack is computed while indexing, before the filter closure');
  // textContent, never the control VALUES — a typed password must not be matchable, nor revealed by
  // the fact that it matched.
  check(!/r\.hay[^\n]*settingValueOf/.test(src), 'the haystack never carries a control value');
}

// Every config path the Settings index claims must exist in the daemon's config struct.
//
// The page answers "is this still the default" by looking a field up by its dotted json path. A path
// that matches nothing does not fail loudly — the row simply reports that it cannot be compared and
// drops out of the filter, which reads like a property of the setting rather than a typo. Measured on
// a live router: "Flow offload" and "Offload devices" pointed at `flow_offload` and
// `flow_offload_devices` while the daemon calls them `offload` and `offload_devices`, so the two
// noisiest performance settings on the page had silently sat out the filter.
{
  const goSrc = fs.readFileSync('internal/config/config.go', 'utf8');
  // Map each Go struct to the json names it declares, and which of those are themselves structs.
  const structs = {};
  for (const m of goSrc.matchAll(/type\s+(\w+)\s+struct\s*\{([\s\S]*?)\n\}/g)) {
    const fields = {};
    for (const f of m[2].matchAll(/^\s*(\w+)\s+([\w\[\]\*\.]+)\s+`[^`]*json:"([^",]+)/gm)) {
      fields[f[3]] = f[2].replace(/^[\[\]\*]+/, '');
    }
    structs[m[1]] = fields;
  }
  check(!!structs.Config && Object.keys(structs.Config).length > 10,
    'the config struct was parsed', String(Object.keys(structs.Config || {}).length));

  const resolves = (path) => {
    let type = 'Config';
    for (const part of path.split('.')) {
      const fields = structs[type];
      if (!fields || !(part in fields)) return false;
      type = fields[part];
    }
    return true;
  };

  const app = fs.readFileSync('web/dist/app.js', 'utf8');
  const metaStart = app.indexOf('const SETTING_META = {');
  const metaBody = app.slice(metaStart, app.indexOf('\n};', metaStart));
  const paths = [...metaBody.matchAll(/cfg:\s*"([^"]+)"/g)].map((m) => m[1]);
  check(paths.length > 8, 'the settings metadata declares config paths', String(paths.length));
  const broken = paths.filter((p) => !resolves(p));
  check(broken.length === 0,
    'every settings config path resolves in internal/config', broken.join(', '));
}

// Two settings must not share a display name.
//
// The settings index keys each row's metadata BY NAME, so a duplicate makes one setting inherit the
// other's config path — and then it is compared against a default that belongs to something else.
// Measured on a live router: the Reliability card holding the Demo-mode checkbox was titled
// "Mode", the routing-mode field is also "Mode", and the checkbox was compared against a
// routing-mode string. It can never match one, so the page reported "not default" for it forever,
// whatever the operator had actually set.
{
  const app = fs.readFileSync('web/dist/app.js', 'utf8');
  const start = app.indexOf('async function renderSettings(');
  check(start > 0, 'renderSettings was located');
  const body = app.slice(start, app.indexOf('\n}\n', app.indexOf('settingsIndex(view', start)));
  // The two things that become a row NAME: a field's label, and a card's title.
  const names = [
    ...[...body.matchAll(/\bfield\(\s*t\("((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]),
    ...[...body.matchAll(/class:\s*"card-title[^"]*"[^)]*\},\s*t\("((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]),
  ];
  check(names.length > 12, 'the settings page declares field and card names', String(names.length));
  const seen = new Map();
  const dupes = [];
  for (const n of names) {
    if (seen.has(n)) dupes.push(n);
    else seen.set(n, true);
  }
  check(dupes.length === 0,
    'no two settings share a display name, which the index keys metadata by',
    [...new Set(dupes)].join(', '));
}

// A depth guarantee must be true for the plane it is offered to.
//
// The Failover card counted every member and printed "N exits deep". For routing lists the KERNEL
// carries, only a member with a real link counts: electMember skips the rest, so a group mixing a
// native tunnel with an engine-carried one has fewer exits than names. Measured on a live
// AX3000T — group-failover [tunnel-a → awg1, proxy-member → socks] reading "2 exits deep" while the
// kernel could elect exactly one — and reproduced on the demo, where the card now adds
// "1 of 3 usable for routing lists".
{
  const src = fs.readFileSync('web/dist/app.js', 'utf8');

  // The fact is the daemon's, not a guess from endpoint shapes in the page.
  check(/failoverState\.kernel_members/.test(src),
    'the card reads the daemon\'s kernel-routable member list');
  // Carried through the loader: dropping it there would leave the card reading undefined forever,
  // which fails silently as "nothing to correct" — the exact defect, restored invisibly.
  const loader = functionSource(src, 'loadFailoverState');
  check(/kernel_members:\s*\(fs && fs\.kernel_members\) \|\| \{\}/.test(loader),
    'loadFailoverState carries the field through', loader.slice(0, 240));
  check(/kernel_members: \{\}/.test(src.slice(src.indexOf('} catch (e) { failoverState'), src.indexOf('} catch (e) { failoverState') + 200)),
    'and resets it when the daemon could not be read, rather than keeping a stale claim');

  // Silent when there is nothing to correct: every member routable, or no kernel table for the group.
  const block = src.slice(src.indexOf('const kernelIDs = (failoverState.kernel_members || {})'),
    src.indexOf('const kernelIDs = (failoverState.kernel_members || {})') + 1400);
  check(/if \(kernelIDs && kernelIDs\.length < members\.length\)/.test(block),
    'the line appears only where the counts disagree', block.slice(0, 200));
  // The number must count kernel-routable AND up — either half alone is a different, wrong claim.
  check(/kernelIDs\.includes\(id\)/.test(block) && /state !== "down"/.test(block),
    'the count is of members that are both kernel-routable and up');
  // What happens at exhaustion depends on the kill switch, and both branches must exist: without one
  // the traffic leaves through the provider, with one it is dropped.
  check(/g\.kill_switch/.test(block), 'the exhaustion sentence branches on the kill switch');
  check(/leaves through the provider/.test(block) && /traffic is dropped/.test(block),
    'and names both outcomes', block.slice(block.indexOf('kill_switch'), block.indexOf('kill_switch') + 220));
}


// The demo fixture must be in the shape the PRODUCT writes, or every UI gate rehearses a connection
// that could not exist.
//
// seed-demo.mjs carried TLS settings as loose params (security/pbk/sni/fp). Nothing writes that:
// every importer fills endpoint.tls, the sing-box generator reads endpoint.tls and nothing else for
// TLS, and the editor renders from it. Measured on the seeded demo before the fix — the Edit form for
// "Frankfurt VLESS" showed TLS: none with an empty SNI and empty key, and generating from that
// profile produced an outbound with no tls object at all (tls=false, reality=false). A fixture that
// disagrees with the product turns every gate built on it into a rehearsal of the wrong thing.
{
  const seed = fs.readFileSync('scripts/seed-demo.mjs', 'utf8');
  const endpointBlock = seed.slice(seed.indexOf('const endpoints = ['), seed.indexOf('const groups = ['));

  // The Reality connection must declare it structurally.
  check(/tls: \{ enabled: true, type: 'reality'/.test(endpointBlock),
    'the seeded Reality connection carries a structured tls block');
  check(/public_key: '[A-Za-z0-9_-]{43}'/.test(endpointBlock),
    'with a key of the length the validator accepts (43 chars = 32 bytes base64)');

  // TLS-only protocols must not leave their SNI where the generator will not look.
  check(!/params: \{[^}]*\bsni:/.test(endpointBlock),
    'no endpoint hides an SNI in params, where the generator does not read it',
    (endpointBlock.match(/params: \{[^}]*\bsni:[^}]*\}/) || [''])[0].slice(0, 120));
  check(!/params: \{[^}]*\b(security|pbk|fp):/.test(endpointBlock),
    'and none hides reality settings there either',
    (endpointBlock.match(/params: \{[^}]*\b(security|pbk|fp):[^}]*\}/) || [''])[0].slice(0, 120));

  // The uuid/flow/password ARE params — this is a rule about TLS, not a ban on params.
  check(/params: \{ uuid: '[0-9a-f-]+', flow:/.test(endpointBlock),
    'protocol credentials stay in params, which is where the product puts them');

  // An ADOPTED native tunnel must be in the seed, because it is the shape live routers are
  // actually built from — five of five connections on the Keenetic — and it has its own dialog
  // (externalForm), its own save path and the health-target picker inside it. Without one here, none
  // of that is rendered by any gate on any page: it could only be checked by hand on a live router.
  check(/engine: 'external'/.test(endpointBlock),
    'the seed carries an adopted native connection, so externalForm is exercised');
  check(/params: \{ interface: '[a-z0-9-]+'/.test(endpointBlock),
    'and it is bound to an interface, which is what makes it external rather than a blank endpoint');
}


// The manual-copy dialog must name the reason the copy actually failed.
//
// It blamed plain HTTP unconditionally. Over the SSH tunnel this project and the operator both use,
// the panel is served from 127.0.0.1, which the browser treats as a SECURE context: measured with the
// dialog open on the live router, isSecureContext true and navigator.clipboard present, while the
// real refusal was the page not being focused (the browser pane was hidden). That sentence sends
// someone to fix TLS over a problem a click solves, and it is equally wrong for a denied clipboard
// permission. Three causes, three sentences, and only one of them is about HTTP.
{
  const src = fs.readFileSync('web/dist/app.js', 'utf8');
  const reason = functionSource(src, 'copyBlockedReason');

  check(/isSecureContext/.test(reason) && /navigator\.clipboard/.test(reason),
    'the HTTP sentence is gated on the context actually being insecure', reason.slice(0, 200));
  check(/document\.hasFocus\(\)/.test(reason),
    'an unfocused window gets its own sentence');
  check(/clipboard permission/.test(reason),
    'and a refused permission gets a third, rather than inheriting either');

  // Order matters: focus is checked only AFTER the context, so an insecure context still reports the
  // scheme even when the window also happens to be unfocused — the scheme is the blocking cause there.
  const secureAt = reason.indexOf('isSecureContext');
  const focusAt = reason.indexOf('document.hasFocus()');
  check(secureAt > 0 && focusAt > secureAt,
    'the insecure-context case is decided first', `secure@${secureAt} focus@${focusAt}`);

  // The dialog must call it rather than embedding one of the strings itself.
  const dialog = functionSource(src, 'copyManualModal');
  check(/copyBlockedReason\(\)/.test(dialog),
    'the dialog asks for the reason instead of asserting one', dialog.slice(0, 200));
  check(!/runs over plain HTTP/.test(dialog),
    'and no longer carries the unconditional sentence');
}


// The Flight recorder is a live view and must not freeze at page-open.
//
// It rendered once. Measured on a live Keenetic twenty minutes after a daemon restart: the
// card still showed a nine-probe window with "partial" beside all six exits, while /api/health/history
// answered thirty samples with full:true. Navigating away and back replaced 9 cells with 30 and
// dropped every "partial" — so the data path was right and only the refresh was missing. The cost of
// that is not cosmetic: an outage occurring while the page is open never reaches the one card whose
// purpose is to show outages.
{
  const src = fs.readFileSync('web/dist/page-diagnostics.js', 'utf8');
  const card = functionSource(src, 'flightRecorderCard');

  check(/const paint = async \(\)/.test(card),
    'the render is a function that can run more than once', card.slice(0, 200));
  check(/setInterval\(/.test(card) && /FR_REFRESH_MS/.test(card),
    'and it is driven on a timer');
  // The stop condition must be the card leaving the page, not a fixed number of ticks.
  check(/if \(!card\.isConnected\) \{ clearInterval\(iv\); return; \}/.test(card),
    'the timer retires when the card is detached', card.slice(card.indexOf('setInterval'), card.indexOf('setInterval') + 220));
  // A repaint rebuilds the <details>; losing their state under a reader is worse than the staleness.
  check(/rememberDisclosures\(\)/.test(card) && /openBands/.test(card) && /openEvents/.test(card),
    'expanded disclosures survive a repaint');
  check(/d\.open = true/.test(card),
    'and are actually re-opened after the rebuild');

  // Cadence: the probes are ~10s apart, so the floor must not be sub-probe.
  const ms = /const FR_REFRESH_MS = (\d+);/.exec(src);
  check(ms && Number(ms[1]) >= 10000,
    'the refresh is no faster than the probe cadence', ms ? ms[1] : '(not found)');
}


// A latency on the Failover card must say what it was measured against.
//
// The card prints a time per member and marks one CURRENT, which reads as "this is the best exit".
// It is the best exit to the PROBE TARGET, and that is not what the group carries. Measured on the
// operator's router while diagnosing a slow Telegram: the elected member answered the probe in 83 ms
// and reached Telegram in 437 ms, while two other members reached Telegram in 216 and 219 ms. The
// election was working exactly as configured; nothing on the page said what it was optimising for.
{
  const src = fs.readFileSync('web/dist/app.js', 'utf8');
  const note = functionSource(src, 'foProbeNote');

  check(/g\.test && g\.test\.url/.test(note),
    'the note names the group\'s own probe URL', note.slice(0, 200));
  check(/if \(!url\) return null/.test(note),
    'and says nothing when there is no URL to name, rather than inventing the default');
  check(/g\.test && g\.test\.interval/.test(note),
    'the cadence comes from the group too');
  // The caveat is the whole point: without it the URL is trivia.
  check(/not to the sites this group carries/.test(note),
    'it states that the times are NOT to the traffic this group carries');
  // A selector elects nothing, so it must not claim an election.
  check(/switchesItself\s*\n?\s*\?/.test(note) || /switchesItself \?/.test(note),
    'a group that elects and one that does not are worded differently', note.slice(note.indexOf('switchesItself'), note.indexOf('switchesItself') + 160));
  check(/Health measured by/.test(note) && /Elected by/.test(note),
    'and both wordings exist');

  // Wired into the card, next to the order note.
  check(/foProbeNote\(g, switchesItself\)/.test(src),
    'the card renders it with the election fact it already computed');
}


// Choosing a health-check target is a measurement, and it must be measured THROUGH the connection.
//
// The probe decides whether a tunnel counts as alive, and an anycast target answers from the edge
// nearest the EXIT, so it says little about the path to what the tunnel carries. Measured on the
// operator's router: through Armenia, Cloudflare answered in 174 ms and Telegram in 448 ms; through
// the Netherlands the same pair was 144 and 210 ms. So the field offers a shortlist that can be
// ordered by real numbers instead of a default nobody revisits.
//
// The shortlist itself was measured before it shipped: www.kaspi.kz was tried and dropped (718–1961
// ms through the tunnels, unreachable through one) because it is a website, not a probe endpoint.
{
  // These three live in the CONNECTIONS CHUNK, not app.js: every caller is on that page, and together
  // they were ~9 KB gzip of an initial payload that had reached 99% of its budget. Moving them back
  // would silently spend that headroom again, so the location is asserted here alongside the
  // behaviour — and app.js is checked for their ABSENCE rather than trusted to stay clean.
  const app = fs.readFileSync('web/dist/app.js', 'utf8');
  const src = fs.readFileSync('web/dist/page-connections.js', 'utf8');
  for (const name of ['healthTargetPicker', 'manualForm', 'externalForm']) {
    check(!new RegExp('^function ' + name + '\\(', 'm').test(app),
      `${name} stays out of the eagerly-loaded app.js`);
    check(new RegExp('^function ' + name + '\\(', 'm').test(src),
      `${name} is defined in the connections chunk`);
  }
  const picker = functionSource(src, 'healthTargetPicker');

  // Free text must survive: a select would delete the ability to keep a target already relied on.
  check(/setAttribute\("list", "f-health-list"\)/.test(picker),
    'the field stays a text input with a datalist, so any target can still be typed', picker.slice(0, 220));
  check(/el\("datalist"/.test(picker), 'and the shortlist is a datalist');

  // The measurement must go through THIS connection, or the numbers describe the WAN.
  check(/egress: endpointID/.test(picker),
    'each probe is sent through the connection being edited');
  check(/if \(!endpointID\)/.test(picker) && /btn\.disabled = true/.test(picker),
    'and the button is refused for a connection with no id yet, rather than silently measuring the WAN');

  // The daemon answers {reachable, latency_ms}. Reading `ok` made every target read "unreachable" on
  // a router where all six answered — caught on hardware, so it is pinned here.
  check(/r\.reachable != null \? r\.reachable : r\.ok/.test(picker),
    'success is read from the field the daemon actually sends (reachable)', picker.slice(picker.indexOf('reachable'), picker.indexOf('reachable') + 160));
  check(/latency_ms/.test(picker), 'and the latency comes from latency_ms');

  // Sorting: fastest first, and anything without a number sinks rather than sorting as zero.
  check(/\(a\.ms == null\) - \(b\.ms == null\)/.test(picker),
    'targets with no answer sort last instead of first');
  // A failed request is not evidence about the target.
  check(/failed: true/.test(picker) && /not measured/.test(picker),
    'a request that never completed is labelled apart from an unreachable target');

  // The shortlist must be the measured one, not an arbitrary list.
  const cat = src.slice(src.indexOf('const HEALTH_TARGETS = ['), src.indexOf('const HEALTH_TARGETS = [') + 900);
  check(/cp\.cloudflare\.com\/generate_204/.test(cat) && /web\.telegram\.org/.test(cat),
    'the shortlist holds the verified entries');
  check(!/kaspi\.kz/.test(cat),
    'and not the one that measured 718-1961 ms and was rejected');

  // The native-connection dialog is where live routers actually live, and it had no field
  // at all — while the monitor has always read Health.URL for every enabled endpoint.
  const ext = functionSource(src, 'externalForm');
  check(/id: "f-health"/.test(ext), 'an external connection has the health field too', ext.slice(0, 200));
  check(/healthTargetPicker\(health, ep\.id \|\| ""\)/.test(ext), 'with the same measured picker');
  check(/out\.health = \{ url: hv/.test(ext) && /else delete out\.health/.test(ext),
    'and its save path writes the target, and clears it when emptied');
}


// The failover member list is the one screen where ORDER is the configuration, and both of its end
// controls were live-looking and inert: the top row's up arrow and the bottom row's down arrow moved
// nothing, said nothing, and left the operator to guess whether the arrows work at all. move() has
// always guarded on the sibling, so the clicks were harmless - the defect is that they looked like
// actions. Measured on the demo: clicking each left the row order byte-identical with no feedback.
{
  const picker = functionSource(app, 'memberPicker');
  check(picker.includes('_up.disabled = i === 0'),
    'the top member cannot be moved up, and its arrow says so', picker.slice(0, 120));
  check(picker.includes('_dn.disabled = i === rows.length - 1'),
    'and the bottom member cannot be moved down');
  // Which row sits at an end changes with every move, so a one-time pass would leave the disabled
  // state pinned to whoever happened to start there.
  const move = picker.slice(picker.indexOf('const move ='), picker.indexOf('up.onclick'));
  check(move.includes('syncEnds()'), 'the end state is recomputed after each move', move.slice(0, 160));
  const built = picker.lastIndexOf('syncEnds();');
  check(built > 0 && built < picker.lastIndexOf('return box'),
    'and is applied once when the list is first built');
}

// "Break hardcoded encrypted resolvers" does nothing until "Intercept clients' DNS" is on:
// keeneticPBROptionsFor only passes DNSRejectEncrypted through inside `if p.DNS.Intercept`, so on its
// own the switch stored true and installed no rule - while its own hint promised those clients "fall
// back to plain DNS and are intercepted", which cannot happen without interception. Measured on the
// demo: flipping it alone toasted a plain confirmation and saved intercept_reject_encrypted:true
// against intercept:false.
{
  const dnsSrc = fs.readFileSync('web/dist/page-dns.js', 'utf8');
  const row = functionSource(dnsSrc, 'dnsToggleRow');
  check(row.includes('if (blocked && !dnsState[key])'),
    'a gated switch refuses only the ON direction', row.slice(0, 140));
  // Locking it in the state it should not be in would be a worse trap than the silent no-op.
  check(row.includes('setGateLook(s, !want, blocked)'),
    'and re-reads as unavailable the moment it is switched off, not at the next render');
  check(row.includes('DNS_GATE_KEYS.has(key)'),
    'flipping the gate itself redraws the page so the dependent row stops lying');
  check(dnsSrc.includes('DNS_GATE_KEYS = new Set(["intercept"])'),
    'and interception is the gate the DNS page declares');
  // The dependency has to be declared where the row is built, or the gate above guards nothing.
  check(app.includes('{ key: "intercept", reason: t('),
    'the reject-encrypted row names interception as its gate, with a reason');
}

// The copied diagnostics report is the one artefact meant to be handed to somebody else, so what it
// says was removed has to be what was removed. A MAC is six hex pairs joined by colons, which the
// full-form IPv6 pattern matched first: aa:bb:cc:dd:ee:ff was reported as "[ipv6]". The value was
// hidden either way - the defect is the label, on the page whose whole job is an accurate picture.
{
  const context = vm.createContext({});
  vm.runInContext(functionSource(diagnostics, 'isPrivIP') + ';'
    + functionSource(diagnostics, 'scrubText') + '; globalThis.run = scrubText;', context);
  const scrub = (x) => context.run(x);
  check(scrub('mac aa:bb:cc:dd:ee:ff') === 'mac [mac]',
    'a MAC is reported as a MAC, not as an IPv6 address', scrub('mac aa:bb:cc:dd:ee:ff'));
  // The rule that used to swallow it must still do its own job, in both IPv6 spellings.
  check(scrub('v6 2001:db8::dead:beef') === 'v6 [ipv6]',
    'a compressed IPv6 address is still masked', scrub('v6 2001:db8::dead:beef'));
  check(scrub('v6 2606:4700:4700:1111:2222:3333:4444:5555') === 'v6 [ipv6]',
    'and a full-form one too', scrub('v6 2606:4700:4700:1111:2222:3333:4444:5555'));
  // Unchanged either way: public addresses lose their middle, LAN addresses are kept on purpose.
  check(scrub('exit 203.0.113.45') === 'exit 203.x.x.45', 'a public IPv4 keeps only its ends');
  check(scrub('client 192.168.1.77') === 'client 192.168.1.77', 'a LAN address is kept for debugging');
  check(scrub('id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee') === 'id [uuid]', 'and a uuid is masked');
}

// A daemon started with --listen host:PORT keeps serving that port, while Ports -> Web UI still holds
// the config's value and reconcileListen rewrites Listen's port from that field on the next save.
// Measured while testing: an AX3000T panel launched on 8089 read "Web UI 8088" here, and saving an
// unrelated setting moved the panel to 8088 and took LAN access with it. The number is not wrong - it
// is what the next save will bind - but the page reads as a description of the running daemon.
{
  const sv = functionSource(app, 'renderSettings');
  check(sv.includes('const portDrift = boundPort && uiPort && boundPort !== uiPort'),
    'the settings page compares the port the daemon bound against the one it is about to bind');
  check(sv.includes('answering on port {0} right now'),
    'and says so where the operator can still act on it');
  // The notice has to sit INSIDE the .field: settingsIndex re-renders each field as one row and
  // drops leftover card content that carries no control, so a sibling hint is never seen. This is
  // not a style preference - the first cut put it on the card and it rendered nowhere.
  const ports = sv.slice(sv.indexOf('field(t("Web UI")'), sv.indexOf('field(t("Clash API")'));
  check(ports.includes('answering on port'),
    'and it travels inside the Web UI field, which is the only part the settings index keeps', ports.slice(0, 160));
}

// Reachability against a dead host takes about 12 seconds - ping timeout plus the TCP connect -
// and the only sign of life was a greyed button. The Set up button one handler below has always
// said "Working…" for exactly this reason, so the slower of the two buttons in one dialog was the
// silent one. Measured against the fixture's 198.51.100.21: 11.6s to "unreachable".
{
  const srv = fs.readFileSync('web/dist/page-server.js', 'utf8');
  const i = srv.indexOf('checkBtn.addEventListener'), j = srv.indexOf('previewBtn.addEventListener');
  const handler = srv.slice(i, j);
  check(handler.includes('checkBtn.textContent = t("Checking…")'),
    'the reachability button says it is working, not just goes grey', handler.slice(0, 200));
  // Restoring the label matters as much: a button stuck on "Checking…" after the answer arrived
  // reads as a probe that never finished.
  check(handler.includes('checkBtn.textContent = checkLabel'),
    'and puts its own label back when the answer arrives');
}

// Counts that read as their own contradiction. The dashboard said "1 failover groups" beside
// "7 route(s) via a tunnel" on the same line, and a one-member group card said "1 members". The Go
// side already spells out why this matters at countWordLists: a router that writes "1 lists in
// force" invites the reader to doubt the number next to it.
{
  // These pinned the "(s)" form, which was the best answer available when they were written: it at
  // least stopped the dashboard reading "1 failover groups". tn supersedes it — a real singular
  // instead of a parenthesis — so the assertions move with the behaviour rather than holding the
  // page at the older fix.
  check(!app.includes('t("{0} failover groups"') && !app.includes('t("{0} failover group(s)"'),
    'the dashboard no longer writes "1 failover groups", nor fakes it with "(s)"');
  check(app.includes('tn("{0} failover group|{0} failover groups"'),
    'and picks a real form from the count');
  check(app.includes('tn("{0} member|{0} members"'),
    'a one-member group card counts members the same way');
}

// A group is not a proxy. On a live Keenetic, selecting the one group swapped Ping /
// Traceroute / Resolve for a single "Reachability" under "ICMP can't traverse a proxy" - false about
// a group whose five members are all native tunnels, and it withheld two tools that work through the
// elected member. The election is read from the Failover page's own helper so the two screens cannot
// disagree; re-deriving it here is exactly the second opinion this codebase avoids.
{
  const dg = functionSource(diagnostics, 'renderDiagnostics');
  const src = dg || diagnostics;
  check(src.includes('const g = (state.profile.groups || []).find(x => x.id === egress.value)'),
    'the egress resolver looks past endpoints to groups');
  check(src.includes('ifaceOfEndpoint(foElected(g))'),
    'and binds to the interface of the member the group elected, read from foElected');
}

// The Failover card's depth caveat and the group_depth battery row both exist for one hazard: a
// group that reads as a redundant pair while the kernel can only fall to one of its members. Both
// were written from a live AX3000T and neither was rendered by any fixture - /api/failover/
// state answered kernel_members: {} on the demo - so no UI gate had ever drawn either of them.
//
// Two things make it reachable, and both must stay: a group mixing a native tunnel with a
// core-carried one, and a list of plain PREFIXES pointing at that group. Domains alone would not do
// it, because the resolver carries those and the kernel compiles no table for the group.
{
  const seed = fs.readFileSync('scripts/seed-demo.mjs', 'utf8');
  check(seed.includes("id: 'seed-grp-mixed'"),
    'the demo seeds a group the kernel routes with one member it cannot elect');
  check(seed.includes("members: ['seed-ext-awg', 'seed-hy2-nl']"),
    'and that group mixes a native tunnel with a core-carried one');
  check(seed.includes("outbound: 'seed-grp-mixed'") && seed.includes("'203.0.113.0/24'"),
    'and a prefix list points at it, which is what makes the kernel compile its table');
}

// A device-group member that is not a 6-byte MAC was filed as an IP whatever it was: typing
// "not-a-device" added a chip, the field said nothing, and only Save came back with the server's
// "invalid IP/CIDR". Measured on the demo. The rule is checkable where it is typed, and the
// connection dialog already marks a bad Reality key that way instead of waiting for the save.
//
// The address check is deliberately permissive about IPv6 - any hex-and-colon form passes - because
// rejecting an address the router would have accepted is the worse failure, and the server stays
// the authority either way. Both directions are pinned below.
{
  const context = vm.createContext({});
  const body = app.slice(app.indexOf('const looksLikeAddress ='), app.indexOf('const addManual ='));
  check(body.length > 0, 'the device-member address check is present at all');
  vm.runInContext(body + '; globalThis.ok = looksLikeAddress;', context);
  for (const good of ['192.168.1.5', '10.0.0.0/8', '2001:db8::1', 'fe80::1/64', '::1']) {
    check(context.ok(good), 'a real address is accepted where it is typed: ' + good);
  }
  for (const bad of ['not-a-device', '999.1.1.1', '192.168.1.5/99', 'hello world', '']) {
    check(!context.ok(bad), 'and a non-address is refused before the save: ' + JSON.stringify(bad));
  }
  // The MAC branch must keep matching what the server accepts: a 6-byte EUI-48 and nothing longer,
  // because the kernel planes render ether saddr and a longer address fails the whole apply.
  check(app.includes('([:-][0-9a-fA-F]{2}){5}'),
    'the MAC shape stays the 6-byte one the kernel plane can render');
}

// rlUniqueId promises an id unique across the whole profile, and device groups were not in the set
// it checked - while the device-group dialog mints its id with that very function. Measured on the
// demo: a second device group named "Kids devices" produced ONE group at rl-kids-devices holding
// only the second device, the first group's member silently gone. A routing list scoped to it then
// applies to a different set of devices than the operator configured.
{
  const context = vm.createContext({ state: { profile: {
    endpoints: [{ id: 'e' }], groups: [{ id: 'g' }], rules: [{ id: 'r' }],
    routing_lists: [{ id: 'rl-work' }], device_groups: [{ id: 'rl-kids-devices' }] } } });
  vm.runInContext(functionSource(app, 'rlUniqueId') + '; globalThis.uid = rlUniqueId;', context);
  check(context.uid('rl-kids-devices') !== 'rl-kids-devices',
    'a new id never lands on an existing device group', context.uid('rl-kids-devices'));
  // The four it always covered must stay covered.
  for (const taken of ['e', 'g', 'r', 'rl-work']) {
    check(context.uid(taken) !== taken, 'and still never lands on an existing ' + taken);
  }
  check(context.uid('rl-fresh') === 'rl-fresh',
    'while a free id is handed back unchanged');
}


// A detected native tunnel must be identified by the name the ROUTER gives it. The row rendered
// [iface, type, public_key], and on the KeeneticOS discovery path there is no public key at all —
// `ndmc show interface` does not expose one — so every row collapsed to "<iface> · <type>".
// Measured on a live Keenetic: /api/vpn/discover returned name "LanAccessTunnel" for nwg2
// (and five more named WgProvider_*), the page showed "nwg2 · amneziawg", and that row is the
// Adopt button — he had to guess which of six tunnels he was adding. The daemon already knew: adopt
// names the created endpoint with that very string.
{
  const row = diagnostics.slice(diagnostics.indexOf('const parts = [v.iface'), diagnostics.indexOf('const parts = [v.iface') + 90);
  check(row.includes('v.name'),
    'the detected-tunnel row identifies the tunnel by the name the router gives it', row.trim());
  check(!/const parts = \[v\.iface, v\.type, v\.public_key\]/.test(diagnostics),
    'and does not fall back to the key as the sole identity, which is empty on the KeeneticOS path');
}


// An install that did not happen must not report itself as one. Demo mode's package manager returns
// the command it WOULD have run and changes nothing on purpose ("so nobody reads the output as a
// real install"), but the page had only the HTTP status to go on and rendered the same "Installed."
// block as a real install. Measured on the demo: pressing Run it under `apk add sing-box` produced
// "Installed. ... will use it the next time the configuration is applied" directly above a State
// column reading "not installed", with the toast for the same click saying nothing was installed.
{
  check(updater.includes("installedNextStep(usedBy, converged, demo)"),
    'the after-install block is told whether the install was simulated');
  // Both install paths must carry it, and an earlier version of this check passed while the
  // package-manager path had lost it — the string still existed on the version-install path below.
  const pmLine = updater.split('\n').find(l => l.includes('mode === "install"') && l.includes('updJustInstalled')) || '';
  check(pmLine.includes('updJustDemo = !!r.demo'),
    'the package-manager path takes it from the daemon rather than parsing the manager output', pmLine.trim());
  check((updater.match(/updJustDemo = !!r.demo/g) || []).length === 2,
    'and so does the version-install path — both report the same outcome');
  const fn = functionSource(updater, 'installedNextStep');
  const demoBranch = fn.indexOf('if (demo)');
  check(demoBranch > 0 && demoBranch < fn.indexOf('t("Installed.")'),
    'and answers the simulated case before it can claim "Installed."');
}


// The kernel band counts out of the members the KERNEL can elect, not out of every name in the
// group. This block exists precisely because "a group mixing a native tunnel with an engine-carried
// one has fewer exits than names" — and it printed members.length as the denominator, the number it
// was written to correct. Measured on the demo: "Mixed depth (native + proxy)" holds one native
// tunnel (down) and one Hysteria2 exit, and the card read "0 of 2 usable for routing lists" — which
// reads as "both are down right now" when one of them can never carry a kernel-routed list at all.
{
  // Anchored on the placeholder form, which appears only in the call — the prose above says the
  // same words and a plain-text search lands in this comment instead.
  const i = app.indexOf('{0} of {1} usable for routing lists');
  const line = app.slice(i, app.indexOf(')', i) + 1);
  check(line.includes('kernelIDs.length'),
    'the kernel band counts out of the kernel-electable members', line.trim());
  check(!line.includes('members.length'),
    'and not out of every member, which is the count this band exists to correct');
}


// The chain's guess and the card's own order note must state ONE rule. foOrderNote already tells the
// operator that a fallback group the core elects "keeps the fastest working member and uses your
// order only as a tiebreak"; foElection guessed by strict order regardless, so the same card said
// both. Measured on the demo with a fallback of three core-carried exits deliberately ordered
// against their latency: the note said fastest-wins while the chain named "#1 current Helsinki
// Trojan 87 ms" with Frankfurt VLESS alive at 40 ms. The split case (kernel carries some lists) is
// excluded on purpose — there the kernel does walk the order.
{
  const fn = functionSource(app, 'foElection');
  check(fn.includes('coreElectsAlone'),
    'the election guess asks whether the core alone elects this group');
  check(fn.includes('foGroupNeedsCore(g)') && fn.includes('!g.managed'),
    'and that question is the same one the order note branches on (needs core, unmanaged)');
  check(fn.includes('kernel_members') && fn.includes('.length'),
    'and leaves the split group on its order guess, where the kernel really walks the list');
  const guardAt = fn.indexOf('coreElectsAlone)');
  const firstAt = fn.indexOf('const first =');
  check(guardAt > 0 && firstAt > guardAt,
    'the order walk runs only after that question is answered');
}


// A target the provider blocks is not a broken uplink. The reachability table's closing note fired
// on "WAN (direct) failed" alone and said "the router itself can't reach this target; check the
// uplink/DNS" — advice contradicted by the same table directly above it. Measured on a live
// Keenetic asking about youtube.com: WAN unreachable, five native tunnels AND the group reachable at
// 291-641 ms, and the page sent him to check an uplink his own six successful probes had exercised.
// The word "too" says what the sentence was for: the run where everything failed.
{
  const i = app.indexOf('const wan = rows.find(x => x.egress === "direct")');
  const seg = app.slice(i, i + 1200);
  check(seg.includes('const tunnelsReach = rows.some(x => x.egress !== "direct" && x.reachable);'),
    'the WAN-failed note asks whether any exit reached the target');
  // The BRANCH, not the order of two strings in the file: inverting the ternary leaves both
  // sentences exactly where they were and swaps what the operator is told.
  const blockedAt = seg.indexOf('? t("The direct path');
  const guard = seg.slice(Math.max(0, blockedAt - 40), blockedAt).trim();
  check(blockedAt > 0 && guard.endsWith('tunnelsReach') && !guard.endsWith('!tunnelsReach'),
    'and gives the blocked-target sentence when an exit DID reach it', guard);
  check(seg.indexOf('check the uplink/DNS') > blockedAt,
    'leaving the broken-uplink sentence for the run where nothing reached it');
  check(/tunnelsReach ? ""/.test(seg) || seg.includes('(tunnelsReach ? "" : ";color:var(--warn)")'),
    'and does not colour the ordinary blocked-target case as a fault');
}


// "one tool, one exit" was true of three of the four tools listed. Ping and traceroute take the
// selected egress (-I/-i); the DNS lookup resolves through the router's own resolver whatever is
// picked, so listing it among them made an answer from the WAN read as an answer from a tunnel.
// Measured on a live Keenetic with the egress set to WgProvider_SiteB. The daemon now
// says so per run (see TestDNSToolSaysItIgnoresTheExit); the header must not undo that.
{
  const i = diagnostics.indexOf('Advanced — one tool, one exit');
  check(i > 0, 'the Advanced tools section still exists');
  const header = diagnostics.slice(i, i + 200);
  check(!header.includes('traceroute · DNS ·'),
    'the header does not list DNS among the tools that take the selected exit', header.slice(0, 110));
  check(header.includes("DNS answers from the router"),
    'and says where the DNS answer does come from');
}


// Scan's report names things the way the operator named them. Two literals in one renderer said
// otherwise, both measured on a live Keenetic:
//   • a device with no DHCP lease name rendered as "(192.168.50.11)" — parentheses wrapped around the
//     only thing present, which reads as a name that failed to load. All three devices Scan found
//     there are nameless, so every heading was bracketed.
//   • the exit badge printed the raw outbound tag: "via grp-primary", while the Failover page
//     calls that same group "Primary group". nameOf() resolves endpoint or group and falls back to
//     the id, so a stale tag still renders something.
{
  const fn = functionSource(app, 'renderClientDests');
  check(!fn.includes('(c.name ? c.name + " " : "") + "(" + c.ip + ")"'),
    'a nameless device is not wrapped in empty parentheses');
  check(fn.includes('c.name ? c.name + " (" + c.ip + ")" : c.ip'),
    'and renders as its bare address');
  check(fn.includes('nameOf(d.exit)'),
    'the exit badge names the exit the way the operator named it');
  check(!fn.includes(String.fromCharCode(34) + 'via {0}' + String.fromCharCode(34) + ', d.exit || '),
    'and no longer prints the raw outbound tag');
}


// The Routing page states the precedence for BOTH planes, not just the one that reads a rule list.
// "Evaluated top to bottom: the first list that matches wins" is true of the core; the kernel plane
// sorts zones (blocks last, then by NAME) and emits one non-terminating mark each, so an overlap
// takes the LAST zone emitted — see orderZonesForEmit and TestZoneOrderIsNotTheOperatorOrder.
// Measured on a live Keenetic: panel order Telegram, Antifilter, Meta, Twitter, Re:filter,
// TeamViewer, GitHub; mangle chain alphabetical. Both sentences must actually reach the card — the
// first attempt passed the second one as a second argument to appendChild, which takes one, so it
// rendered nowhere and no gate noticed.
{
  const notes = app.split('class: "hint rl-order-note"').length - 1;
  check(notes === 2, 'the Routing order note covers both planes', notes + ' note(s)');
  const appended = app.split('card.appendChild(el("div", { class: "hint rl-order-note"').length - 1;
  check(appended === 2, 'and each one is appended by its own call, not passed as a spare argument');
  check(app.includes('a block always wins'),
    'the kernel sentence names what actually decides an overlap there');
}


// The write-back preview says what it does NOT touch. The plan renders 00-upstream.conf inside the
// conf-dir and dnsmasq merges that directory into the main config, so an upstream already present
// there gains a second copy instead of being replaced — together with a second strict-order and
// no-resolv. Measured on a live Keenetic: the plan proposes exactly the four directives his
// /opt/etc/dnsmasq.conf already carries. The count comes from the reader's provenance tag, which is
// why this could not be asked before every upstream stopped claiming to come from the conf-dir.
{
  check(dns.includes('function mainConfUpstreams(nat)'),
    'the preview can count upstreams that came from the main config');
  check(dns.includes('startsWith("dnsmasq.conf")'),
    "and it asks the reader provenance tag rather than guessing");
  const at = dns.indexOf('mainConfUpstreams(nat) && r.platform !== "openwrt"');
  check(at > 0, 'the caveat is shown only when there is a collision, and only on the platform that has one');
  const contentAt = dns.indexOf('t("dnsmasq.d content")');
  check(at > 0 && contentAt > at,
    'and it appears above the content it qualifies, not under it');
}


// A verdict that took 12 seconds to obtain must not expire. The reachability probe reported ONLY
// through a toast: the code's own comment records the measurement — 11.6s to "unreachable" against a
// dead host — and a wait that long is exactly when the operator looks away. Measured on the demo
// against 203.0.113.10: press, wait, and the dialog holds nothing about whether the host answered.
// The toast stays (page-level, survives a re-render); the dialog now keeps the same sentence.
{
  check(server.includes('const checkOut ='),
    'the reachability dialog has somewhere to keep its answer');
  check(server.includes('checkOut, ') || server.includes(', checkOut)'),
    'and that element is actually mounted in the dialog');
  const fn = server.slice(server.indexOf('checkBtn.addEventListener'), server.indexOf('checkBtn.addEventListener') + 1600);
  check(fn.includes('checkOut.textContent = verdict'),
    'the verdict is written to it, not only toasted');
  check(fn.includes('checkOut.textContent = e.message'),
    'and so is a failure, which is the case most worth not losing');
  check((fn.match(/const verdict =/g) || []).length === 1 && fn.includes('toast(verdict,'),
    'the toast and the dialog say the same sentence, composed once');
}


// A field that edits PART of a config value must be compared against the same part. The Listen host
// row edits the host half of cfg.listen ("" = all interfaces; the port lives under Ports → Web UI)
// and the badge compared it against the whole "host:port" default. Measured on a live
// Keenetic: /api/config/defaults listen ":8088", /api/config listen ":8088" — untouched — and the
// row still read "not default", with a tooltip saying "Default is :8088" over a field where that
// string is not a valid entry.
{
  check(app.includes('function hostOfListen(v)'),
    'the host half of a listen string is one shared projection');
  check(app.includes('"Listen host": { cfg: "listen", project: hostOfListen'),
    'and the Listen host row declares that its field edits that projection');
  check(app.includes('const projected = meta.project ? meta.project(d) : d;'),
    'the default is put through the same projection before the comparison');
  const fieldUse = app.indexOf('const listenHost = hostOfListen(cfg.listen);');
  check(fieldUse > 0,
    'and the field itself uses it too, so the two cannot drift apart');
}


// A conntrack egress tag names an endpoint OR a group, and exitLabel looked up only endpoints — so
// every connection a failover group carried printed its raw tag. Measured on a live
// Keenetic: the Dashboard's Live connections summary read "grp-primary 94.0 MB" while the
// Routing lists card on the same page called that group "Primary group". Both call sites — the
// per-connection "via X" and the per-egress byte summary — go through this one function.
{
  const fn = functionSource(app, 'exitLabel');
  check(fn.includes('findGroup(tag)'),
    'exitLabel resolves a group tag, not just an endpoint id', fn.trim().slice(0, 120));
  check(fn.includes('findEndpoint(tag)'),
    'and still resolves an endpoint id');
  check(fn.includes('return tag') || fn.includes(': tag'),
    'and falls back to the raw tag rather than rendering nothing for an outbound the profile lost');
  // Both consumers must keep going through it: the summary line is where the id was actually seen.
  check(app.split('exitLabel(').length - 1 >= 3,
    'the per-connection row and the byte summary both use it');
}


// "Ask the router" accepts a pasted log — including ONE line, which is how people actually ask: they
// copy the single line that looks wrong. The paste test only caught multi-line or >160-char input,
// so an 84-character sing-box FATAL fell through every branch and the answer was "could not tell
// what this is", followed by advice to "…paste a log". Measured on a live Keenetic with
// "2026-08-20 07:11:02 FATAL start service: configure tun interface: invalid argument" — a line the
// knowledge base has an entry for.
{
  const priv = app.slice(app.indexOf('function isPrivateIPv4'), app.indexOf('// askRun answers'));
  const cls = diagnostics.slice(diagnostics.indexOf('function looksLikeLogLine'), diagnostics.indexOf('// ── Flight recorder'));
  const ctx = vm.createContext({ state: { profile: {
    endpoints: [{ id: 'e1', name: 'Frankfurt VLESS' }], groups: [{ id: 'g1', name: 'Primary group' }] } } });
  vm.runInContext(priv + cls + ';globalThis.k = (q) => (askClassify(q) || {}).kind;', ctx);
  const k = ctx.k;
  check(k('2026-08-20 07:11:02 FATAL start service: configure tun interface: invalid argument') === 'log',
    'a single timestamped FATAL line is read as a log');
  check(k('+0000 2026-08-20 06:24:54 WARN inbound/tun[tun-in]: enable offload') === 'log',
    "and so is the router's own \"+0000 <date>\" log form");
  check(k('ERROR outbound/vless: dial failed') === 'log',
    'and a line that leads with a severity token');
  // The narrow shape matters as much as the wide one: these must NOT become logs.
  check(k('error.example.com') === 'domain', 'a domain containing a severity word stays a domain');
  check(k('Frankfurt VLESS') === 'exit', 'an exit name with a space stays an exit');
  check(k('192.168.0.20') === 'device', 'a LAN address stays a device');
  check(k('INFO') === 'unknown', 'a bare word is a name, not a log line');
  // The whitespace guard is what makes that true of a token that DOES carry the severity shape:
  // "ERROR:" is one word, and reading it as a log would run the analyzer over a single token.
  check(k('ERROR:') === 'unknown', 'including one that ends in a colon');
}


// The Failover page reads healthMap, so it has to be one of the pages that REFRESHES it. pollHealth
// filled that map only on dashboard/connections; the failover repaint refreshes the daemon's
// election and then re-renders the same stale snapshot. Measured on a live Keenetic sixteen
// minutes after opening the page: healthMap uptime_s = 13 against the API's 972 — the Exit capacity
// card read "up 13s" and "12.2 MB transferred" for a tunnel that had carried 943 MB.
{
  const line = app.split(String.fromCharCode(10)).find(l => l.includes('const onHealth = () =>')) || '';
  check(line.includes('"failover"'),
    'the health poll runs on the Failover page, whose cards read healthMap', line.trim());
  check(line.includes('"dashboard"') && line.includes('"connections"'),
    'and still on the two pages that had it');
  // The repaint alone is not enough — it re-renders whatever the map holds.
  const rp = app.indexOf('await loadFailoverState(); // the daemon');
  check(rp > 0, 'the failover repaint still refreshes the election');
}




// A self-update refusal has to survive being read. On a small-flash router it is the ROUTINE
// outcome: measured on a live AX3000T (OpenWrt, /overlay 13 MiB free), WayHop's own update
// needs ~27 MiB — the new binary plus the mandatory rollback backup plus slack — so the daemon
// answers a paragraph naming the shortfall and the ways out (free space, mount storage, update over
// SSH). That paragraph lived only in a toast, which expires while the operator is still deciding
// what to free. The engine rows already write their failures into the row through updRowErr; the
// self row now does the same, with the sentence composed once so both halves say it identically.
{
  const fn = functionSource(updater, 'selfUpdate');
  check(fn.includes('const failed = t("Update failed: {0}", e.message)'),
    'the self-update failure sentence is composed once');
  check(fn.includes('updRowErr(selfRow && selfRow.querySelector(".upd-detail"), failed)'),
    'and is written into the row, not only toasted');
  check(fn.includes('toast(failed, "err")'),
    'while the toast keeps saying the same thing');
  check(fn.includes('btn.closest(".upd-item")'),
    'and the row is found from the button, never from the shared card');
}

// A blocking finding whose object has no page must offer the ACTION, not an instruction.
//
// profile.rules is read in five places in the panel and rendered as an editable row in none, so a
// rule with a broken reference blocked every Apply while "Correct or disable the affected object"
// named a control that exists on no screen. The daemon now names the way out in a closed vocabulary
// (finding.fix) and this row renders it. Measured on the demo before the fix: rule "st-rule-6"
// pointing at a group that is not in the profile, Apply blocked, and neither that rule nor
// "st-rule-12" present anywhere in the DOM.
{
  const listeners = [];
  const deleted = [];
  const toasts = [];
  const reloaded = [];
  const el = (tag, attrs = {}, ...children) => {
    const node = { tag, attrs, children: children.filter((c) => c != null), textContent: '' };
    if (typeof children[0] === 'string') node.textContent = children[0];
    node.appendChild = (child) => { node.children.push(child); return child; };
    node.addEventListener = (type, fn) => { listeners.push({ node, type, fn }); };
    node.querySelectorAll = () => [];
    return node;
  };
  const text = (node) => {
    if (node == null) return '';
    if (typeof node !== 'object') return String(node);
    return [node.textContent || '', ...(node.children || []).map(text)].join(' ');
  };
  const rowFor = (finding, confirmAnswer = true) => {
    listeners.length = 0; deleted.length = 0; toasts.length = 0; reloaded.length = 0;
    const context = vm.createContext({
      el,
      t: (s, ...a) => String(s).replace(/\{(\d)\}/g, (_, i) => a[i]),
      toast: (msg, kind) => { toasts.push({ msg, kind }); },
      // Auto-answering the confirm is what lets the click be exercised; the assertion that a confirm
      // is ASKED at all is separate, because deleting is not reversible.
      modalConfirm: (msg) => { toasts.push({ confirm: msg }); return Promise.resolve(confirmAnswer); },
      api: { del: (u) => { deleted.push(u); return Promise.resolve({}); } },
      refreshBehindReview: () => Promise.resolve(),
      load: (v) => { reloaded.push(v); return Promise.resolve(); },
      findingStatus: () => ['err', 'blocked'],
      ackedFindings: new Set(),
      updateActions: () => {},
      encodeURIComponent,
      Promise,
    });
    vm.runInContext(`${arrowSource(app, 'findingRow')}
globalThis.run = findingRow;`, context);
    return context.run(finding, 'blocked');
  };

  const RULE = { id: 'profile.invalid', code: 'PROFILE_INVALID', title: 'The configuration is invalid',
    detail: 'rule "st-rule-6": outbound "st-grp-0" does not resolve',
    remedy: 'This rule has no row on any page, so no screen can correct it.',
    count: 1, items: ['rule "st-rule-6"'], fix: { action: 'delete_rule', id: 'st-rule-6', label: 'st-rule-6' } };

  let row = rowFor(RULE);
  check(/Remove st-rule-6/.test(text(row)), 'the finding offers the action as a button', text(row));

  let click = listeners.find((l) => l.type === 'click');
  check(!!click, 'the button is wired');
  if (click) {
    await click.fn();
    check(toasts.some((x) => x.confirm && /st-rule-6/.test(x.confirm)),
      'deleting asks first, naming what it will remove', JSON.stringify(toasts));
    check(deleted.length === 1 && deleted[0] === '/api/rules/st-rule-6',
      'and deletes exactly that rule through the rules route', JSON.stringify(deleted));
    check(reloaded.length === 1,
      'then re-reviews, so the operator sees what is left rather than a stale blocker', JSON.stringify(reloaded));
    check(toasts.some((x) => x.kind === 'ok'), 'and says it happened', JSON.stringify(toasts));
  }

  // Cancelling must do nothing at all. A confirm that deletes anyway is worse than no confirm.
  row = rowFor(RULE, false);
  click = listeners.find((l) => l.type === 'click');
  if (click) {
    await click.fn();
    check(deleted.length === 0 && reloaded.length === 0,
      'cancelling the confirm removes nothing and reloads nothing', JSON.stringify({ deleted, reloaded }));
  }

  // The negative control: every other finding names an object that HAS a page, so no button. Without
  // this, rendering the button unconditionally would pass every assertion above.
  const NOFIX = { id: 'profile.invalid', code: 'PROFILE_INVALID', title: 'The configuration is invalid',
    detail: 'routing list "rl-1": outbound "gone" does not resolve',
    remedy: 'Routing list "rl-1" points at "gone".', count: 1, items: ['routing list "rl-1"'] };
  row = rowFor(NOFIX);
  check(!/Remove /.test(text(row)),
    'a finding whose object has its own page gets no button here', text(row));
  check(!listeners.some((l) => l.type === 'click'), 'and nothing is wired');

  // The vocabulary is CLOSED. An action this panel does not implement must render nothing rather
  // than a button that does something approximate — a finding is data from the daemon, and a newer
  // daemon naming an action an older panel never learned is the ordinary case, not an error.
  //
  // This fixture is what makes the guard testable at all: mutating it away with a fix absent simply
  // threw on f.fix.label, which reddens the gate by crashing instead of by the assertion that is
  // supposed to be doing the work.
  row = rowFor(Object.assign({}, NOFIX, { fix: { action: 'open_page', id: 'rl-1', label: 'rl-1' } }));
  check(!/Remove /.test(text(row)),
    'an action this panel does not implement renders nothing', text(row));
  check(!listeners.some((l) => l.type === 'click'), 'and wires nothing');
}

// A counter's wording follows its COUNT, in every language the panel ships.
//
// Measured on a live router: the review header read "1 pending changes". German, Spanish,
// French and Portuguese carried the same fault in their own words; the Slavic dictionaries had
// already dodged it by rewriting the phrase so no form is needed, which is a workaround per string
// and is why it never generalised. tn() picks a form out of the translation, so the rule lives in
// one place and a translator supplies as many forms as their language actually takes.
{
  const forms = {
    "{0} pending change|{0} pending changes": {
      en: "{0} pending change|{0} pending changes",
      ru: "Ожидает: {0}|Ждут: {0}|Ждёт: {0}",
      tr: "{0} bekleyen",
    },
  };
  let active = "en";
  const context = vm.createContext({
    lang: () => active,
    t: (key) => (forms[key] && forms[key][active]) || key,
    String, Math, Number,
  });
  vm.runInContext(`${functionSource(app, 'pluralIndex')}
${functionSource(app, 'tn')}
globalThis.pi = pluralIndex; globalThis.tn = tn;`, context);
  const pi = (code, n) => context.pi(code, n);

  // Two-form languages: only ONE is singular.
  for (const code of ['en', 'de', 'es', 'pt']) {
    check(pi(code, 1) === 0 && pi(code, 0) === 1 && pi(code, 2) === 1 && pi(code, 11) === 1,
      `${code} makes exactly 1 singular`, [0, 1, 2, 11].map((n) => pi(code, n)).join(','));
  }
  // French counts 0 as singular; that is a rule, not a rounding.
  check(pi('fr', 0) === 0 && pi('fr', 1) === 0 && pi('fr', 2) === 1,
    'French treats zero as singular', [0, 1, 2].map((n) => pi('fr', n)).join(','));
  // Turkish does not pluralise a noun that already carries a number.
  check([0, 1, 2, 5, 21].every((n) => pi('tr', n) === 0), 'Turkish has one form');

  // The Slavic rule, including the teens exception that a naive "last digit" version gets wrong:
  // 11..14 are MANY even though their last digits look like one/few.
  for (const code of ['ru', 'uk', 'be']) {
    check([1, 21, 101].every((n) => pi(code, n) === 0), `${code}: 1, 21, 101 take the one-form`);
    check([2, 3, 4, 22, 34].every((n) => pi(code, n) === 1), `${code}: 2-4 take the few-form`);
    check([0, 5, 11, 12, 13, 14, 25, 111].every((n) => pi(code, n) === 2),
      `${code}: 0, 5+, and the teens take the many-form`,
      [0, 5, 11, 12, 13, 14, 25, 111].map((n) => pi(code, n)).join(','));
  }

  // tn itself: the form is chosen, then the count is interpolated.
  check(context.tn("{0} pending change|{0} pending changes", 1) === '1 pending change',
    'one thing reads as one thing', context.tn("{0} pending change|{0} pending changes", 1));
  check(context.tn("{0} pending change|{0} pending changes", 3) === '3 pending changes',
    'several read as several', context.tn("{0} pending change|{0} pending changes", 3));

  // A translation with FEWER forms than the language asks for falls back to its last one rather
  // than rendering undefined. Turkish supplies one form and asks for index 0; the guard is for a
  // Slavic entry that supplies two, which is a plausible translator mistake and must not crash.
  active = 'tr';
  check(context.tn("{0} pending change|{0} pending changes", 5) === '5 bekleyen',
    'a single-form language uses its single form', context.tn("{0} pending change|{0} pending changes", 5));
  active = 'ru';
  check(context.tn("{0} pending change|{0} pending changes", 5) === 'Ждёт: 5',
    'the Slavic many-form is the third one', context.tn("{0} pending change|{0} pending changes", 5));
  // Both of the too-few-forms cases go through a catch: without the clamp they THROW, and a
  // mutation that kills the runner reddens for the wrong reason and proves nothing about the rule.
  const call = (key, n) => {
    try { return context.tn(key, n); } catch (e) { return 'threw: ' + ((e && e.message) || e); }
  };
  check(call("only one form", 7) === 'only one form',
    'a key with no forms at all still renders', call("only one form", 7));
  // The case the clamp exists for, and the one an earlier version of this block only DESCRIBED: a
  // Slavic language asks for index 2 while the translation supplies two forms.
  // Every counter this page converts must go through tn, not t. A counter left on t renders its
  // plural form at one — "Log (1 lines)" and "1 known issue(s) detected" were both measured that
  // way on a live router, and the second was carrying the "(s)" dodge into German and
  // French as "{0} bekannte(s) Problem(e)". Pinned by SHAPE rather than by listing the strings: a
  // list would have to be extended by the same person who forgot to use tn.
  {
    // Every counter must go through tn, not t. A counter left on t renders its plural form at one:
    // "Log (1 lines)" and "1 known issue(s) detected" were both measured that way on the operator's
    // router, and the second carried the "(s)" dodge into German and French as "bekannte(s)
    // Problem(e)". Pinned by SHAPE, not by listing the strings — a list would have to be extended by
    // the same person who forgot to use tn, and widening this to a new file found three more
    // counters than the author had set out to fix.
    //
    // Only strings carrying a COUNT are judged: "Probe interval (s)" and "Persistent keepalive (s)"
    // are seconds, not plurals, and a rule that cannot tell a unit from a plural would demand two
    // forms for a field label.
    //
    // buildReport is excluded, and deliberately: it renders a Markdown report for pasting into a
    // support chat, every line of it raw English on purpose, because a report read by someone else
    // should be in one language rather than the reporter's. Scanning it would demand translating an
    // artifact whose whole point is not to be translated.
    //
    // Every panel file is converted now, so the list is the whole set and the ceiling mechanism is
    // gone with the last file it guarded. It earned its keep: while app.js still held fifteen
    // counters on t(), a ceiling that could only go down was the only thing standing between a
    // sixteenth and nobody noticing. Bring it back the moment a new file arrives unconverted rather
    // than leaving that file out of the list, which is silence dressed as green.
    const CONVERTED = ['web/dist/app.js', 'web/dist/page-diagnostics.js', 'web/dist/page-updater.js',
      'web/dist/page-connections.js', 'web/dist/page-routing.js', 'web/dist/page-server.js',
      'web/dist/nav.js'];
    for (const file of CONVERTED) {
      const all = fs.readFileSync(file, 'utf8');
      const body = file.endsWith('page-diagnostics.js')
        ? all.replace(functionSource(all, 'buildReport'), '')
        : all;
      const dodges = (body.match(/t\("[^"]*\{0\}[^"]*\(s\)[^"]*"/g) || []);
      check(dodges.length === 0,
        `${file}: no counter fakes a plural with "(s)"`, dodges.join(' | '));
      const rawCount = (body.match(/"[^"]*" \+ [a-zA-Z_.]+\.length \+ "[^"]*"/g) || []);
      check(rawCount.length === 0,
        `${file}: no counter is concatenated past the translator`, rawCount.join(' | '));
    }
  }

  const tooFew = call("A {0}|B {0}", 5);
  check(tooFew === 'B 5', 'a translation with fewer forms than the language asks for uses its last', tooFew);
}

// The Failover page's filter and its fold must agree about when the page needs help.
//
// The fold appears above GROUPS_VISIBLE groups and the filter appeared above four, so at exactly
// four there was a "Show all 4 groups" summary and no way to narrow what it opened. Measured on the
// seeded demo: 1616px against a 720px viewport, 2.24 screens, five cards, zero filters. The density
// gate reported it as a route taller than two screens with no in-page filter — and did so
// intermittently, because the page's height also swings with health text, so the same tree passed
// and failed on consecutive full runs. A gate that reports a real defect only sometimes is a gate
// people learn to re-run instead of read.
//
// Pinned as ONE threshold rather than two equal numbers: two constants that happen to match today
// are the same defect waiting to come back.
{
  const src = functionSource(app, 'renderFailover');
  const foldAt = src.match(/const GROUPS_VISIBLE = (\d+);/);
  check(!!foldAt, 'the fold still declares its threshold as a named constant');
  check(/if \(groups\.length > GROUPS_VISIBLE\) \{/.test(src),
    'the filter is gated on the fold threshold, not on a number beside it');
  check(!/if \(groups\.length > \d+\) \{/.test(src),
    'no literal group threshold remains in the page', (src.match(/groups\.length > \d+/g) || []).join(','));
}

// Deleting a failover group must ask BEFORE it offers the destructive confirm.
//
// Store.DeleteGroup refuses on exactly two conditions — a rule whose outbound is this group, and
// another group for which this one is the only member. Both are in the profile the browser already
// holds, and the dialog asked neither: measured on the demo, pointing the default route at a group
// and pressing Delete gave "Delete group Order probe?", took OK, and only then produced an error
// toast reading `group "grp-order-probe" is used by rule "default"; repoint it first`. The store was
// right to refuse; the panel spent the operator's decision on a question it could have answered.
{
  const src = functionSource(app, 'delGroup');
  check(/blockingGroupRefs\(g\)/.test(src),
    'the delete flow consults the references before asking to delete');
  const asksFirst = src.indexOf('blockingGroupRefs') < src.indexOf('Delete group {0}?');
  check(asksFirst, 'and does so BEFORE the destructive confirm, not after it');
  // Defence in depth: the pre-check can only know the conditions someone wrote into it, so the
  // refusal path has to be readable too. It used to print err.message raw — measured on the demo as
  // the toast `group "grp-order-probe" is used by rule "default"; repoint it first`, with nothing to
  // act on. The daemon now answers GROUP_IN_USE with its dependents, the same shape the endpoint
  // path has used for a long time, and this renders them.
  check(/GROUP_IN_USE/.test(src) && /data\.dependents/.test(src),
    'the refusal path reads the structured dependents rather than printing the raw error');
  check(/acknowledgeOnly/.test(src),
    'and states them, rather than offering OK on a message that is not a choice');
  // All FOUR conditions Store.DeleteGroup refuses on, pinned individually. The first cut of this
  // gate checked two, and the pre-check quietly shipped knowing only those two: deleting a group a
  // DNS server detoured through asked first and refused afterwards anyway. A gate that names the
  // conditions one by one cannot go green on a check that has lost one of them.
  const refs = functionSource(app, 'blockingGroupRefs');
  check(/r\.outbound === g\.id/.test(refs),
    'it checks the rule reference the store refuses on');
  check(/\.length === 1/.test(refs) && /members/.test(refs),
    'and the only-member parent group');
  check(/rl\.outbound === g\.id \|\| rl\.download_via === g\.id/.test(refs),
    'and a routing list routing or downloading through it');
  check(/ds\.detour === g\.id/.test(refs),
    'and a DNS server detouring through it');
}

// A delete confirm may state a consequence only when it IS one.
//
// "Delete connection X? It will also be removed from every failover group that uses it." was
// unconditional, so it fired for a connection belonging to no group — measured on the demo with a
// freshly added trojan whose membership count was zero. A warning that goes off on nothing is how a
// reader learns to skim the one that goes off on something, and the switch-off dialog one click away
// already sets the standard: it lists each dependent group by name.
{
  const src = functionSource(conns, 'delEndpoint');
  check(/state\.profile\.groups/.test(src) && /includes\(e\.id\)/.test(src),
    'the confirm looks at which groups actually hold this connection');
  check(/inGroups\.length/.test(src),
    'and states the consequence only when there is one');
  check(/tn\("It will also be removed from this failover group/.test(src),
    'naming the groups, in a form that agrees with how many there are');
  check(!/It will also be removed from every failover group that uses it/.test(src),
    'the unconditional sentence is gone');
}

// The flight recorder shows probes; the feed beside it reports outages. Only one arrangement of the
// data makes the difference matter, and that is the one it must explain.
//
// Measured on a live Keenetic: one exit at 29/30 with a single failed probe, and the feed
// reading "No outage or switch since the daemon started (25m ago)". Both statements are true — a
// cell is one probe, an outage is a committed state change the monitor's fast-out hysteresis only
// promotes after consecutive failures — but a reader has to know the hysteresis exists to reconcile
// them. Said only when a band actually holds a failure, because on a clean ribbon it explains
// something nobody is looking at.
{
  const src = functionSource(diag, 'flightRecorderCard');
  check(/samples \|\| \[\]\)\.some\(ok => !ok\)/.test(src),
    'the note is conditioned on a band actually holding a failed probe');
  check(/not an outage on its own/.test(src),
    'and says what separates a probe from an outage');
  const noteAt = src.indexOf('not an outage on its own');
  const emptyAt = src.indexOf('No outage or switch since');
  check(emptyAt >= 0 && noteAt > emptyAt,
    'and sits with the no-events line it qualifies, not somewhere else on the card');
}

// The throughput card must not name a path its own result contradicts.
//
// The title said "Throughput (through active proxy)" unconditionally while the result line prints
// the server's `via` — derived from singbox.Running(), i.e. from what actually happened. Measured on
// the demo, where no core runs: "Throughput (through active proxy)  ↓ 772.26 Mbps ↑ 319.43 Mbps ·
// 227 ms (direct)" — a claim and its refutation on one line. The title is now the measurement, and
// the path stays with the number that was measured through it.
{
  // Comment lines are dropped before scanning: the fix records the old wording in a comment right
  // above the line it replaced, and a scan over the whole file found it there and failed on the very
  // tree that fixed it. Prose that documents a defect is not the defect.
  const diagCode = diag.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  check(!/Throughput \(through active proxy\)/.test(diagCode),
    'the title no longer promises a path the result may contradict');
  const run = functionSource(diag, 'runSpeedtest');
  check(/r\.via/.test(run),
    'and the result still names the path the server actually used');
}

// DNS rule ORDER is meaning - sing-box takes the first match - so a reorder is a real config write.
// Both copies of the row (app.js and the page-dns chunk) used to PUT directly, outside the
// dnsSaveChain every other DNS write goes through. Replayed against a rev-checking double, two quick
// arrow clicks left the panel showing C,A,B while the server held A,C,B: both writes carried the
// same rev, the second was refused as stale, and its rollback restored a snapshot the first had
// already superseded. Serializing converges both; this pins that neither copy regresses to a bare PUT.
{
  // page-dns.js ONLY. app.js carried a second copy of this row - dnsRuleRow - that nothing called:
  // residue from moving the DNS page into its route chunk. The reorder fix was applied to both,
  // and the app.js half was a no-op nobody could reach; the dead copy is gone, so asserting on it
  // would pin a file that no longer has the row.
  for (const [name, src] of [['page-dns.js', dns]]) {
    const at = src.indexOf('"DNS rule " + match');
    check(at > 0, `${name}: the DNS rule row still carries an order control`);
    if (at < 0) continue;
    const handler = src.slice(at, at + 700);
    check(/dnsSaveChain = dnsSaveChain\.then/.test(handler),
      `${name}: the DNS reorder serializes through dnsSaveChain instead of racing a concurrent save`);
    check(!/try \{ await dnsPut\(\); route\(\); \}/.test(handler),
      `${name}: the DNS reorder no longer PUTs directly from the click handler`);
    check(/if \(r && r\.dns\) dnsState = r\.dns/.test(handler),
      `${name}: the DNS reorder adopts the server echo like every other DNS write`);
  }
}
// Pasting a second link before the first parse answers must not resurrect the first. /api/import
// can answer out of order, and the late answer used to overwrite the newer confirmation form -
// Save then wrote the endpoint from link A while the textarea above it still read link B. Both
// exits need the guard: the success path (a stale form) and the error path (a stale error
// replacing a good form). Same shape as the router's routeGen.
{
  const parse = conns.slice(conns.indexOf('async function parse()'), conns.indexOf('async function parse()') + 4200);
  check(parse.length > 100, 'the paste tab still has a parse function');
  check(/const gen = \+\+parseGen/.test(parse),
    'each paste parse takes a generation number');
  const guards = (parse.match(/gen !== parseGen/g) || []).length;
  check(guards >= 2,
    'both the success and the error path discard a superseded parse', `guards=${guards}`);
}
// Adding a connection by hand for a host that already has one used to overwrite it in silence: the
// id is protocol+server+port and POST /api/endpoints is an UPSERT, so the manual tab replaced the
// old keys and still toasted "Added". The paste tab had grown a confirm-first check; the manual tab
// posted blind. Both now call ONE helper, so they cannot drift apart again - that is what is pinned
// here: the helper exists, both save handlers go through it, and neither posts unguarded.
{
  const add = conns.slice(conns.indexOf('function openAddConnection()'));
  check(/async function confirmEndpointReplace\(e\)/.test(add),
    'one helper owns the "this id already exists" check');
  const calls = (add.match(/await confirmEndpointReplace\(e\)/g) || []).length;
  check(calls === 2, 'both the paste tab and the manual tab ask before overwriting', `calls=${calls}`);
  const manual = add.slice(add.indexOf('function manualTab()'), add.indexOf('function subTab()'));
  check(/confirmEndpointReplace/.test(manual),
    'the manual tab specifically no longer posts an endpoint blind');
  check(/replacing \? t\("Replaced \{0\}"/.test(manual),
    'and it reports a replacement as a replacement, not as "Added"');
}
// The routing-list editor submits the WHOLE struct, and the store reads a missing domain_source as
// a CHANGED one - which also drops domain_cache and domain_refreshed. The form has no input for the
// domain feed, so renaming a list, or changing its outbound, deleted the feed URL and every domain
// it had fetched: the list stayed in the panel and quietly stopped matching anything. The editor
// must carry the field through, exactly as it already does for cidr_source and format.
{
  const routing = fs.readFileSync('web/dist/page-routing.js', 'utf8');
  const save = routing.slice(routing.indexOf('async function save(btn)'), routing.indexOf('async function save(btn)') + 3000);
  check(save.length > 100, 'the routing-list editor still has a save function');
  check(/body\.domain_source = rl\.domain_source|body\.domain_source =/.test(save),
    'the list editor carries the domain feed through an edit instead of erasing it');
  check(/body\.cidr_source = cidrSrc\.value\.trim\(\)/.test(save),
    'and still carries the CIDR feed, the sibling this was modelled on');
}
// "Depended on by" is ONE line per dependent, not one per relationship. A routing list normally
// both routes and downloads through the same exit, and emitting a row for each printed every list
// twice under the same name — the panel looked like it was double-rendering. The fetch row also
// dropped the "via <group>" qualifier the routing row carried, so the pair read as a bare
// duplicate rather than two facts. Executed here against real profile shapes, not grepped.
{
  const t2 = (str, ...a) => a.length ? str.replace(/\{(\d+)\}/g, (_, i) => a[+i]) : str;
  const tn2 = (str, n) => str.split("|")[n === 1 ? 0 : 1].replace("{0}", n);
  const nameOf2 = (id) => ({ grp: "Primary group", cy: "Cyprus" })[id] || id;
  const deps = (lists, who = "cy") => {
    const st = { profile: { groups: [{ id: "grp", name: "Primary group", members: ["cy", "by"] }],
      routing_lists: lists, dns: {} } };
    const fn = new Function("state", "t", "tn", "nameOf",
      functionSource(app, "dependentsOf") + "; return dependentsOf;")(st, t2, tn2, nameOf2);
    return fn(who).filter((r) => r.icon !== "⇄");
  };

  const both = deps([{ id: "tg", name: "Telegram", outbound: "grp", download_via: "grp", enabled: true }]);
  check(both.length === 1,
    "a list that routes AND downloads through one exit is one line, not two", `rows=${both.length}`);
  check(/routing list/.test(both[0]?.note || "") && /downloads its list/.test(both[0]?.note || ""),
    "and that one line names both roles", both[0]?.note);
  check(/via Primary group/.test(both[0]?.note || ""),
    "and still says which group stands between them", both[0]?.note);

  const fetchOnly = deps([{ id: "y", name: "Fetch only", outbound: "direct", download_via: "grp", enabled: true }]);
  check(fetchOnly.length === 1 && /via Primary group/.test(fetchOnly[0]?.note || ""),
    "a fetch-only dependency carries the via-qualifier the routing row always had", fetchOnly[0]?.note);

  // A direct role pins this exit; only an all-indirect dependency may be drawn as weak.
  const mixed = deps([{ id: "x", name: "Split", outbound: "grp", download_via: "cy", enabled: true }]);
  check(mixed.length === 1 && mixed[0]?.weak === false,
    "a list downloading DIRECTLY through this exit is not a weak dependency", String(mixed[0]?.weak));
  check(both[0]?.weak === true,
    "while an all-via-group dependency still is");
}
if (failures.length) {
  console.error(`interaction regressions FAILED (${failures.length}/${checks}):\n  - ${failures.join('\n  - ')}`);
  process.exit(1);
}
console.log(`interaction regressions OK: ${checks} assertions; plain-HTTP copy fallback, captured-query reclassification, safe language reload, the live-pill cache never memoizing an empty page, the Failover chain promising only switches something actually performs, and the Components section reading an ordinary router as ordinary`);
