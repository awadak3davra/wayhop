// seed-hostile.mjs — seed a profile whose TEXT is hostile, not whose counts are large.
//
// The stress profile answered "does the UI survive many objects". This answers a different and
// sharper question: what happens when the text inside those objects is markup, a javascript: URL, or
// a direction override.
//
// That is not hypothetical here. Endpoint names are not all typed by the user: the importer parses
// share links, and `subscription.go` FETCHES those links from a remote URL the user pastes once and
// then trusts forever. A hostile or compromised subscription therefore controls the `#name` fragment
// of every endpoint it ships. If any of that reaches the DOM as markup rather than text, the panel is
// owned by whoever runs the subscription — on the box that routes the household's traffic.
//
// So the payloads below are the ones that matter for a DOM built by hand: an <img onerror> (fires
// without a script tag and survives naive tag-stripping), an attribute breakout, a javascript: URL in
// case anything ever renders a name as a link, an RTL override that can make a name read as something
// else entirely, and a stored template-ish string in case any layer interpolates.
//
// Demo only, same refusal as the other seeds.
//
//   node scripts/seed-hostile.mjs http://127.0.0.1:8097/

const BASE = (process.argv[2] || 'http://127.0.0.1:8097/').replace(/\/$/, '');
const SKIP_IF_NOT_DEMO = process.argv.includes('--skip-if-not-demo');

// Each payload sets a window flag if it ever executes, so the checker can distinguish "rendered as
// text" (fine) from "rendered as markup that ran" (a finding).
export const PAYLOADS = [
  `<img src=x onerror="window.__xss=1">`,
  `"><img src=x onerror="window.__xss=2">`,
  `<script>window.__xss=3<\/script>`,
  `javascript:window.__xss=4`,
  `<svg/onload="window.__xss=5">`,
  `‮gnp.exe`,                       // RTL override: renders as "exe.png"
  `{{7*7}}`,                             // template interpolation, if any layer does it
  `' OR 1=1 --`,
];

const post = async (p, body) => {
  const r = await fetch(BASE + p, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: BASE },
    body: JSON.stringify(body),
  });
  return { ok: r.ok, status: r.status, text: r.ok ? '' : (await r.text()).slice(0, 200) };
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

// Remove anything a previous run of THIS script left, so it is idempotent like the others.
{
  const cur = await (await fetch(BASE + '/api/profile')).json();
  const p = cur.profile || cur;
  const del = async (path, id) => {
    try { await fetch(`${BASE}${path}/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { origin: BASE } }); }
    catch (_) { /* already gone */ }
  };
  const mine = (id) => String(id || '').startsWith('hx-');
  for (const r of (p.rules || [])) if (mine(r.id)) await del('/api/rules', r.id);
  for (const l of (p.routing_lists || [])) if (mine(l.id)) await del('/api/routing', l.id);
  for (const g of (p.groups || [])) if (mine(g.id)) await del('/api/groups', g.id);
  for (const e of (p.endpoints || [])) if (mine(e.id)) await del('/api/endpoints', e.id);
  // Saved provisioner records live outside the profile document.
  try {
    const sv = await (await fetch(BASE + '/api/servers')).json();
    for (const s of (sv.servers || sv || [])) if (mine(s.id)) await del('/api/servers', s.id);
  } catch (_) { /* endpoint absent on this build */ }
}

let accepted = 0, refused = 0;
const refusals = [];

// One endpoint per payload, name AND a free-text param carrying it.
for (let i = 0; i < PAYLOADS.length; i++) {
  const r = await post('/api/endpoints', {
    id: `hx-ep-${i}`, name: PAYLOADS[i], engine: 'singbox', protocol: 'trojan',
    enabled: true, server: '198.51.100.7', port: 443,
    params: { password: 'hostile-seed', sni: PAYLOADS[i] },
  });
  if (r.ok) accepted++; else { refused++; refusals.push(`endpoint ${i}: ${r.status} ${r.text}`); }
}
// A group and a routing list too — different pages render names through different code.
{
  const r = await post('/api/groups', {
    id: 'hx-grp-0', name: PAYLOADS[0], type: 'urltest', members: ['hx-ep-0', 'hx-ep-1'],
  });
  if (r.ok) accepted++; else { refused++; refusals.push(`group: ${r.status} ${r.text}`); }
}
{
  const r = await post('/api/routing', {
    id: 'hx-rl-0', name: PAYLOADS[1], outbound: 'hx-ep-0', enabled: true,
    manual: [PAYLOADS[0], 'plain.example'],
  });
  if (r.ok) accepted++; else { refused++; refusals.push(`routing list: ${r.status} ${r.text}`); }
}

// The DNS page and the Set-up-Server page render stored TEXT and saw no payload at all: measured
// `payload-as-text=0` on both while the injection gate still certified "all 9 routes". Endpoints,
// groups, routing lists and rules were the only things seeded, and neither page renders any of them.
// Both surfaces accept markup (measured: the daemon stores it), so plant one in each.
{
  const cur = await (await fetch(BASE + '/api/dns')).json();
  const dns = cur.dns || cur;
  const server = (dns.servers || [])[0];
  if (!server) {
    refusals.push('dns rule: no DNS server exists to point a rule at');
  } else {
    const rules = (dns.rules || []).filter((r) => !String(r.id || '').startsWith('hx-'));
    rules.unshift({ id: 'hx-dns-0', domain_suffix: [PAYLOADS[0], 'plain.example'], server: server.tag });
    // Whole-document PUT with If-Match, like the seeders: without the revision the daemon refuses,
    // and a body of the wrong SHAPE is a full replacement with an empty document — it answers 200 and
    // wipes every rule and server, which is how this file's author lost the demo's DNS once.
    const r = await fetch(BASE + '/api/dns', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', origin: BASE, ...(cur.rev == null ? {} : { 'If-Match': String(cur.rev) }) },
      body: JSON.stringify({ ...dns, rules }),
    });
    if (r.ok) accepted++; else { refused++; refusals.push(`dns rule: ${r.status} ${(await r.text()).slice(0, 160)}`); }
  }
}
{
  const r = await post('/api/servers', {
    id: 'hx-srv-0', name: PAYLOADS[1], host: '203.0.113.9', port: 22, user: 'root',
  });
  if (r.ok) accepted++; else { refused++; refusals.push(`server record: ${r.status} ${r.text}`); }
}

console.log(`  hostile objects: ${accepted} accepted, ${refused} refused by validation`);
// A refusal is a legitimate defence, not a failure of this script — but it has to be VISIBLE, because
// "the UI escaped it" and "the daemon never stored it" are different guarantees with different blast
// radii, and only the first survives an attacker who writes the profile some other way.
for (const r of refusals) console.log(`    refused: ${r}`);
if (!accepted) {
  console.log('  nothing was stored — the injection check below can only prove the daemon refuses it.');
}
