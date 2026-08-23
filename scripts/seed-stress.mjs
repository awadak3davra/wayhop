// seed-stress.mjs — a profile deliberately larger than any real one, to answer a question the
// density gate keeps answering one page at a time and too late.
//
// Five separate times a page has broken its height budget for the same reason: it draws one row per
// configured object, and every profile used during design was smaller than a real one. Routing's 29
// chips, the Diagnostics protocol matrix, the dashboard exit grid, Top talkers, the Failover capacity
// bands. Each was found only because some profile happened to be big enough that day — the Keenetic's,
// or the seeded demo's. That is whack-a-mole: it finds the instances you get lucky with, never the
// class, and it silently regresses the moment the test profile shrinks.
//
// So: seed a profile past any plausible deployment and measure. What stays flat is genuinely bounded.
// What grows is unbounded, and the gate says so now instead of a user finding out.
//
// Demo only, same refusal as seed-demo.mjs — this writes a fake profile and must never touch a router.
//
//   node scripts/seed-stress.mjs http://127.0.0.1:8097/

const BASE = (process.argv[2] || 'http://127.0.0.1:8097/').replace(/\/$/, '');
const SKIP_IF_NOT_DEMO = process.argv.includes('--skip-if-not-demo');

// Sized past the largest real profile seen (the Keenetic: 8 exits, 29 routing lists) with headroom,
// so a pass here means "bounded", not "bounded up to today's biggest router".
const N_ENDPOINTS = 24;
const N_GROUPS = 6;
const N_LISTS = 60;
const N_RULES = 24;
const N_DNS = 20;

const post = async (p, body) => {
  const r = await fetch(BASE + p, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: BASE },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`POST ${p} -> ${r.status} ${(await r.text()).slice(0, 160)}`);
  return r;
};

const ver = await (await fetch(BASE + '/api/health')).json();
if (!ver.demo) {
  if (SKIP_IF_NOT_DEMO) {
    console.log(`${BASE} is not a demo instance — not seeding.`);
    process.exit(0);
  }
  console.error(`${BASE} does not report demo mode (version ${ver.version}). Refusing to seed a real
instance — this script writes a fake profile and would overwrite a working configuration.`);
  process.exit(2);
}

// Long names on purpose. A row that fits at "Work tools" can still wrap at a name someone actually
// types, and wrapped rows are how a bounded-looking list stops being bounded.
const PROTOS = ['vless', 'hysteria2', 'trojan', 'vmess', 'shadowsocks', 'tuic'];
const CITIES = ['Frankfurt', 'Amsterdam', 'Helsinki', 'Stockholm', 'Warsaw', 'Vilnius', 'Riga',
  'Tallinn', 'Prague', 'Vienna', 'Zurich', 'Milan'];

const endpoints = [];
for (let i = 0; i < N_ENDPOINTS; i++) {
  const proto = PROTOS[i % PROTOS.length];
  const city = CITIES[i % CITIES.length];
  const base = {
    id: `st-ep-${i}`,
    name: `${city} ${proto.toUpperCase()} node ${i} (stress)`,
    engine: 'singbox', protocol: proto,
    enabled: i % 7 !== 0,                       // a few disabled, as real profiles have
    server: `198.51.100.${(i % 200) + 10}`, port: 443 + i,
  };
  if (proto === 'vless') base.params = { uuid: '2f1b7c94-6d3a-4f5e-8b12-0a9c7e4d1f60', security: 'none' };
  else if (proto === 'vmess') base.params = { uuid: '2f1b7c94-6d3a-4f5e-8b12-0a9c7e4d1f60' };
  else if (proto === 'shadowsocks') base.params = { method: 'aes-128-gcm', password: 'stress-pw' };
  else if (proto === 'tuic') base.params = { uuid: '2f1b7c94-6d3a-4f5e-8b12-0a9c7e4d1f60', password: 'stress-pw' };
  else base.params = { password: 'stress-pw', sni: `n${i}.example.net` };
  endpoints.push(base);
}

const groups = [];
for (let i = 0; i < N_GROUPS; i++) {
  groups.push({
    id: `st-grp-${i}`,
    name: `Failover group ${i} with a deliberately long label (stress)`,
    type: i % 2 ? 'urltest' : 'selector',
    members: endpoints.slice(i * 3, i * 3 + 4).map((e) => e.id).filter(Boolean),
  });
}

const OUTS = (i) => {
  if (i % 9 === 0) return 'direct';
  if (i % 11 === 0) return 'block';
  if (i % 3 === 0) return `st-grp-${i % N_GROUPS}`;
  return `st-ep-${i % N_ENDPOINTS}`;
};
const lists = [];
for (let i = 0; i < N_LISTS; i++) {
  const l = { id: `st-rl-${i}`, name: `Routing list ${i} — a realistically long list name (stress)`,
    outbound: OUTS(i), enabled: i % 8 !== 0 };
  if (i % 4 === 0) { l.source = `https://example.invalid/rule-set/list-${i}.srs`; l.format = 'binary'; l.refresh_hours = 24; }
  else if (i % 4 === 1) l.manual = [`site${i}.example`, `cdn${i}.example`, `api${i}.example`];
  else if (i % 4 === 2) { l.manual = [`local${i}.example`]; l.cidr_source = 'asn:13238'; l.refresh_hours = 12; }
  else l.manual = [`only${i}.example`];
  lists.push(l);
}

const rules = [];
for (let i = 0; i < N_RULES; i++) {
  const r = { id: `st-rule-${i}`, outbound: OUTS(i) };
  if (i % 3 === 0) r.domain_suffix = [`rule${i}.example`, `alt${i}.example`];
  else if (i % 3 === 1) r.ip_cidr = [`203.0.${i}.0/24`];
  else r.port = [1000 + i, 2000 + i];
  rules.push(r);
}

let made = 0;
const put = async (label, path, items) => {
  let failed = 0;
  for (const it of items) {
    try { await post(path, it); made++; } catch (e) { failed++; if (failed <= 2) console.error(`  ${label} ${it.id}: ${e.message.split('\n')[0]}`); }
  }
  console.log(`  ${label}: ${items.length - failed}/${items.length} accepted`);
};

await put('endpoints', '/api/endpoints', endpoints);
await put('groups', '/api/groups', groups);
await put('routing lists', '/api/routing', lists);
await put('rules', '/api/rules', rules);

// DNS rules go through the whole-document PUT, like seed-demo does.
{
  const cur = await (await fetch(BASE + '/api/dns')).json();
  const dns = cur.dns || cur;
  const rev = cur.rev;
  const secure = (dns.servers || []).find((s) => /secure/.test(s.tag)) || (dns.servers || [])[0];
  const local = (dns.servers || []).find((s) => /local/.test(s.tag)) || secure;
  if (secure) {
    // Must be an ENABLED endpoint: the daemon refuses a detour that targets a disabled one, with
    // `detour "st-ep-0" targets a disabled endpoint`. st-ep-0 is disabled by the i % 7 pattern above,
    // so the first attempt at this seed was refused — correctly, and with a message that named the
    // exact cause.
    const enabledEp = endpoints.find((e) => e.enabled);
    secure.detour = enabledEp ? enabledEp.id : undefined;
    dns.rules = [];
    for (let i = 0; i < N_DNS; i++) {
      dns.rules.push({ id: `st-dns-${i}`, domain_suffix: [`dns${i}.example`, `alt-dns${i}.example`],
        server: i % 5 === 0 ? 'reject' : (i % 2 ? local.tag : secure.tag), disabled: i % 9 === 0 });
    }
    const r = await fetch(BASE + '/api/dns', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', origin: BASE, ...(rev == null ? {} : { 'If-Match': String(rev) }) },
      body: JSON.stringify(dns),
    });
    console.log(r.ok ? `  dns rules: ${dns.rules.length} written` : `  dns rules: PUT -> ${r.status}`);
  }
}

// The hard server records. The two ordinary ones live in seed-demo.mjs, which runs early enough that
// every gate sees a populated Set-up-Server page; these two are the cases only this file should own:
// a name long enough to wrap a card, and an IPv6 address, because a layout that holds `1.2.3.4` proves
// nothing about the address a real deployment carries.
const SERVERS = [
  { name: 'Helsinki backup box with a deliberately long label (stress)', host: '198.51.100.77', port: 22, user: 'root' },
  { name: 'tokyo-01', host: '2001:db8:4860:4860:0000:0000:0000:8888', port: 22, user: 'admin' },
];
{
  let ok = 0;
  for (const s of SERVERS) {
    try { await post('/api/servers', s); ok++; made++; }
    catch (e) { console.log(`  server ${s.name.slice(0, 28)}: ${e.message.slice(0, 90)}`); }
  }
  const list = await (await fetch(BASE + '/api/servers')).json();
  const n = Array.isArray(list) ? list.length : (list.servers || []).length;
  console.log(`  servers: ${ok}/${SERVERS.length} accepted, page now lists ${n}`);
}

const prof = await (await fetch(BASE + '/api/profile')).json();
const p = prof.profile || prof;
const srv = await (await fetch(BASE + '/api/servers')).json();
console.log(`seeded ${made} object(s); profile now holds ${(p.endpoints || []).length} endpoints, ` +
  `${(p.groups || []).length} groups, ${(p.routing_lists || []).length} routing lists, ` +
  `${(p.rules || []).length} rules, ` +
  `${(Array.isArray(srv) ? srv.length : (srv.servers || []).length)} servers`);
