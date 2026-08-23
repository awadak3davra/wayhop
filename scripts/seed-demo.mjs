// seed-demo.mjs — give the demo instance a profile worth measuring.
//
// The control-preservation baseline is only as good as the instance it is captured from, and the
// stock demo carries two endpoints, no groups, no rules and no routing lists. Captured from that,
// Failover records ONE control and Routing four — so a redesign could delete every per-group and
// per-list button and the gate would still pass. The real routers have those rows, but they run
// older deployed builds, so they cannot judge the working tree.
//
// This seeds the demo over its own HTTP API with the shapes the pages branch on: several protocols,
// a disabled exit, a deliberately broken one, a failover group, routing lists pointing at both an
// endpoint and a group, and a couple of rules. Demo only — it refuses to run against anything that
// does not report demo mode, so it can never touch a router.
//
//   node scripts/seed-demo.mjs http://127.0.0.1:8097/

// demoKey builds a deterministic 32-byte base64 value for the WireGuard fixture. It is generated
// rather than written down because a literal 44-character base64 blob in a `private_key` field is
// indistinguishable from a real key to a secret scanner, and one used to fail the quality gate on
// every run of this repository. Deterministic, so seeded profiles stay byte-identical between runs.
const demoKey = (fill) => Buffer.alloc(32, fill).toString("base64");

const BASE = (process.argv[2] || 'http://127.0.0.1:8097/').replace(/\/$/, '');

const post = async (p, body) => {
  const r = await fetch(BASE + p, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: BASE },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST ${p} -> ${r.status} ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
};

// --skip-if-not-demo lets verify.mjs call this unconditionally: it seeds a demo instance and steps
// aside for a router. Without it the gates depend on someone having remembered to seed, and a demo
// restart silently drops the profile from 14 objects to 4 — which is precisely how the Failover
// overflow stayed hidden while the gates reported green.
const SKIP_IF_NOT_DEMO = process.argv.includes('--skip-if-not-demo');

const ver = await (await fetch(BASE + '/api/health')).json();
if (!ver.demo) {
  if (SKIP_IF_NOT_DEMO) {
    console.log(`${BASE} is not a demo instance — not seeding (this is the expected path for a router).`);
    process.exit(0);
  }
  console.error(`${BASE} does not report demo mode (version ${ver.version}). Refusing to seed a real
instance — this script writes a fake profile and would overwrite a working configuration.`);
  process.exit(2);
}

// Establish a KNOWN state, not "whatever was here plus this". The demo persists its profile to
// rd-demo/profile.json and it survives restarts, so seeding used to mean "add to the accumulated
// history of every previous run". Once seed-stress had run once, every later gate measured stress
// scale while reporting itself as the normal-scale run — and a mutation test built on that told us
// nothing, because both of its arms were at the same scale. Anything this file did not create is
// removed first, so "demo seeded" denotes one profile rather than a sediment.
const del = async (path, id) => {
  try {
    await fetch(`${BASE}${path}/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { origin: BASE } });
  } catch (_) { /* already gone */ }
};
{
  const cur = await (await fetch(BASE + '/api/profile')).json();
  const p = cur.profile || cur;
  const mine = (id) => String(id || '').startsWith('seed-');
  let removed = 0;
  // Order matters: a routing list or rule can reference a group, and a group references endpoints,
  // so tear down from the referrers inward or the daemon rejects the delete.
  for (const r of (p.rules || [])) if (!mine(r.id)) { await del('/api/rules', r.id); removed++; }
  for (const l of (p.routing_lists || [])) if (!mine(l.id)) { await del('/api/routing', l.id); removed++; }
  for (const g of (p.groups || [])) if (!mine(g.id)) { await del('/api/groups', g.id); removed++; }
  for (const e of (p.endpoints || [])) if (!mine(e.id)) { await del('/api/endpoints', e.id); removed++; }
  if (removed) console.log(`  reset: removed ${removed} object(s) left by earlier runs`);
}

// Protocol spread matters because the pages branch on it: an external engine renders an
// OS-managed tunnel, wireguard renders as a native endpoint, the rest go through sing-box.
const endpoints = [
  // TLS lives in the STRUCTURED block, because that is the only shape the product writes: every
  // importer (share link, clash, sing-box config) fills endpoint.tls, the generator reads endpoint.tls
  // and nothing else for TLS, and the editor renders from it. Carrying reality in params instead —
  // security/pbk/sni/fp, as this fixture did — produced a demo that contradicted itself: the Edit form
  // showed "TLS: none" with empty SNI and key over a connection named Frankfurt VLESS, and the
  // generated outbound had no tls object at all (measured: tls=false, reality=false). Every UI gate
  // that renders a Reality connection was rendering one the product could not have produced.
  { id: 'seed-vless-de', name: 'Frankfurt VLESS', engine: 'singbox', protocol: 'vless', enabled: true,
    server: '203.0.113.10', port: 443,
    params: { uuid: '2f1b7c94-6d3a-4f5e-8b12-0a9c7e4d1f60', flow: 'xtls-rprx-vision' },
    tls: { enabled: true, type: 'reality', sni: 'www.microsoft.com', fingerprint: 'chrome',
      public_key: 'jH8kQ2mVx1pR7nL4sT6yU0wZ3aC5eG9iK2oM4qS8uW0', short_id: 'a1b2c3d4' } },
  // Hysteria2 and Trojan are TLS-only protocols, so their SNI belongs in the same block for the same
  // reason: in params it was dropped from the generated outbound (measured: tls=false).
  { id: 'seed-hy2-nl', name: 'Amsterdam Hysteria2', engine: 'singbox', protocol: 'hysteria2', enabled: true,
    server: '198.51.100.22', port: 8443, params: { password: 'seed-demo-pw' },
    tls: { enabled: true, type: 'tls', sni: 'nl.example.net' } },
  { id: 'seed-trojan-fi', name: 'Helsinki Trojan', engine: 'singbox', protocol: 'trojan', enabled: false,
    server: '198.51.100.31', port: 443, params: { password: 'seed-demo-pw-2' },
    tls: { enabled: true, type: 'tls', sni: 'fi.example.net' } },
  { id: 'seed-wg-home', name: 'Home WireGuard', engine: 'singbox', protocol: 'wireguard', enabled: true,
    server: '203.0.113.77', port: 51820,
    params: { private_key: demoKey(0x11), peer_public_key: demoKey(0x22), local_address: '10.7.0.2/32' } },
  { id: 'seed-broken-uk', name: 'London (misconfigured)', engine: 'singbox', protocol: 'vmess', enabled: true,
    server: '198.51.100.44', port: 80, params: { uuid: 'not-a-uuid' } },
  // An ADOPTED native tunnel: engine "external", no protocol of its own, bound to a kernel interface
  // the OS owns. This is the shape both operator routers are actually built from — five of five
  // connections on the Keenetic — and the seed had none, so externalForm (its own dialog, its own save
  // path, and the health-target picker inside it) was rendered by no gate on any page. It could only
  // ever be checked by hand on a live router, which is the wrong place to catch a regression.
  { id: 'seed-ext-awg', name: 'Adopted AmneziaWG (native)', engine: 'external', protocol: '', enabled: true,
    server: '', port: 0, params: { interface: 'awg-seed', endpoint_ip: '198.51.100.60' } },
];

const groups = [
  // A group's kind IS "type"; only endpoints call it "protocol".
  { id: 'seed-grp-eu', name: 'Europe failover', type: 'urltest',
    members: ['seed-vless-de', 'seed-hy2-nl', 'seed-trojan-fi'] },
  { id: 'seed-grp-any', name: 'Any working exit', type: 'urltest',
    members: ['seed-vless-de', 'seed-hy2-nl', 'seed-wg-home', 'seed-broken-uk'] },
  // A group the KERNEL routes, holding one member it can elect and one it cannot. This is the shape
  // on a live AX3000T (tunnel-a on awg1 beside a sing-box socks outbound), and until it was
  // seeded here /api/health returned kernel_members: {} on the demo — so the Failover card's depth
  // caveat and the group_depth battery row, both written for exactly this hazard, were rendered by
  // no fixture and therefore checked by no UI gate.
  { id: 'seed-grp-mixed', name: 'Mixed depth (native + proxy)', type: 'fallback',
    members: ['seed-ext-awg', 'seed-hy2-nl'] },
];

// Lists pointing at an endpoint AND at a group, plus one sent direct and one blocked — the four
// outbound kinds the Routing page renders differently.
const routing = [
  // A remote rule-set, a manual list, a kernel CIDR feed and a disabled one — the Routing page
  // renders a different row for each, and the ordered-ruleset redesign has to keep all four.
  { id: 'seed-rl-stream', name: 'Streaming', outbound: 'seed-grp-eu', enabled: true,
    source: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs',
    format: 'binary', refresh_hours: 24 },
  { id: 'seed-rl-work', name: 'Work tools', outbound: 'seed-vless-de', enabled: true,
    manual: ['atlassian.net', 'slack.com', 'github.com'] },
  { id: 'seed-rl-local', name: 'Russian sites direct', outbound: 'direct', enabled: true,
    manual: ['yandex.ru', 'vk.com'], cidr_source: 'asn:13238,47541', refresh_hours: 12 },
  { id: 'seed-rl-ads', name: 'Ad networks', outbound: 'block', enabled: false,
    manual: ['doubleclick.net', 'googlesyndication.com'] },
  // Plain prefixes pointing at a group: this is what makes the kernel compile a table for that group,
  // which is the precondition for kernelElectableMembers to answer at all. Domains alone would not do
  // it - the resolver carries those - so without this row the depth caveat has nothing to describe.
  { id: 'seed-rl-kernel', name: 'Kernel-routed prefixes', outbound: 'seed-grp-mixed', enabled: true,
    manual: ['203.0.113.0/24', '198.51.100.128/25'] },
];

// A rule is a bundle of matchers (domain / domain_suffix / geosite / geoip / ip_cidr / port), not a
// kind+value pair. Sending kind/value produced two rules that matched nothing and rendered blank.
const rules = [
  { id: 'seed-rule-lan', ip_cidr: ['192.168.0.0/16', '10.0.0.0/8'], outbound: 'direct' },
  { id: 'seed-rule-tg', domain_suffix: ['telegram.org', 't.me'], outbound: 'seed-grp-any' },
  { id: 'seed-rule-ports', port: [25, 465, 587], outbound: 'direct' },
];

// Split-DNS rules. Without them the Routing/DNS order gate has nothing to order and reports
// "positions=[]" — a check whose subject is absent proves nothing about the code it guards. These
// also give the DNS datapath view something real to draw.
async function seedDNSRules() {
  const cur = await (await fetch(BASE + '/api/dns')).json();
  const dns = cur.dns || cur;
  const rev = cur.rev;
  const hadRules = (dns.rules || []).length > 0;
  const secure = (dns.servers || []).find(s => /secure/.test(s.tag)) || (dns.servers || [])[0];
  const local = (dns.servers || []).find(s => /local/.test(s.tag)) || secure;
  if (!secure) { console.error('  dns rules: no servers to point rules at'); return; }
  // Route a resolver through a seeded exit. A DNS detour is the least visible way to depend on an
  // exit — nothing on the Connections page hints at it — so the demo must carry one, or the code
  // that surfaces it is never exercised outside a hand-written check.
  secure.detour = 'seed-vless-de';
  // Assert this file's rules rather than preserving whatever accumulated. `if (!hadRules)` left the
  // 20 rules a stress run had written, so the DNS page kept measuring at stress scale while the run
  // called itself the normal one. Safe to overwrite: this script refuses any non-demo instance.
  void hadRules;
  dns.rules = [
    { id: 'seed-dns-ru', domain_suffix: ['.ru', '.su', '.рф'], server: local.tag },
    { id: 'seed-dns-work', domain_suffix: ['slack.com', 'atlassian.net'], server: secure.tag },
    { id: 'seed-dns-ads', domain_suffix: ['doubleclick.net'], server: 'reject' },
    { id: 'seed-dns-off', domain_suffix: ['example.test'], server: secure.tag, disabled: true },
  ];
  // PUT /api/dns takes If-Match; sending it without one is refused, which is the point of that change.
  const r = await fetch(BASE + '/api/dns', {
    method: 'PUT',
    headers: { 'content-type': 'application/json', origin: BASE, ...(rev == null ? {} : { 'If-Match': String(rev) }) },
    body: JSON.stringify(dns),
  });
  if (!r.ok) { console.error(`  dns rules: PUT -> ${r.status} ${(await r.text()).slice(0, 200)}`); return; }
  console.log(`  dns rules: ${dns.rules.length} written`);
}

let made = 0;
const put = async (label, path, items) => {
  for (const it of items) {
    try { await post(path, it); made++; }
    catch (e) { console.error(`  ${label} ${it.id}: ${e.message.split('\n')[0]}`); }
  }
  console.log(`  ${label}: ${items.length} submitted`);
};

await put('endpoints', '/api/endpoints', endpoints);
await put('groups', '/api/groups', groups);
await put('routing lists', '/api/routing', routing);
await put('rules', '/api/rules', rules);
await seedDNSRules();

// Two saved servers, so the Set-up-Server page is never empty for a gate.
//
// It used to be. No seed created a server record, so that route rendered "No servers yet" to every
// gate that walked it — and a whole page of the panel went unmeasured, which is how four identical
// "Set up" buttons survived the entire redesign (AUD-186). Putting them in the STRESS seed first was
// not enough and was worse than it looked: `button names` and `control preservation` run before
// `stress seeded` in verify.mjs, so on a fresh store they still saw the empty page, while on any
// later run they saw the four records the previous run had left behind — the same gate measuring a
// different subject depending on history. Seeding here, at `demo seeded`, makes it deterministic for
// every gate that follows. The store upserts by identity, so repeated runs do not accumulate.
const servers = [
  { name: 'Amsterdam VPS — primary exit (provisioned 2026-06)', host: '198.51.100.21', port: 22, user: 'root' },
  { name: 'Frankfurt VPS', host: '203.0.113.44', port: 2222, user: 'wayhop' },
];
{
  let ok = 0;
  for (const s of servers) {
    try { await post('/api/servers', s); ok++; made++; }
    catch (e) { console.log(`  server ${s.name.slice(0, 24)}: ${String(e.message).slice(0, 90)}`); }
  }
  console.log(`  servers: ${ok}/${servers.length} submitted`);
}

const p = await (await fetch(BASE + '/api/profile')).json();
// The profile calls them routing_lists; reading p.routing reported zero while four were stored.
console.log(`seeded ${made} object(s); profile now holds ${(p.endpoints || []).length} endpoints, ` +
  `${(p.groups || []).length} groups, ${(p.routing_lists || []).length} routing lists, ` +
  `${(p.rules || []).length} rules`);
