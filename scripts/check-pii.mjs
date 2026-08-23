// check-pii.mjs — does anything PERSONAL survive into the tree we would publish?
//
// The existing audit (publish/Audit-Clean.ps1) scans against `deny`, which is a list of SPECIFIC  (development repository)
// strings: this IP, that hostname, this key. That is exactly the right net for what is already known
// and exactly the wrong shape for what is not. A VPS added next month, a router renamed, a token
// pasted into a fixture — none of them are on the list, so none of them fail the audit, and the first
// time anyone finds out is after the push. A blocklist can only ever be as current as the last person
// who remembered to extend it.
//
// This is the other half: detectors for the SHAPE of personal data, with an allowlist for the values
// that are legitimately there. The default is "flag it"; every exception is a line in
// publish/pii-allow.json that has to carry a reason. That inverts the failure mode — forgetting to  (development repository)
// list something now means a red gate, not a leak.
//
// It audits the tree that WOULD be published: paths in dropExact/dropPrefix are skipped and the
// `replace` substitutions are applied in memory first, so it judges the published bytes rather than
// the working copy. Pass --tree <dir> to scan an already-built public tree instead.
//
//   node scripts/check-pii.mjs [--tree <dir>] [--verbose]

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const argv = process.argv.slice(2);
const treeArg = argv.indexOf('--tree');
const TREE = treeArg >= 0 ? argv[treeArg + 1] : '.';
const VERBOSE = argv.includes('--verbose');
const APPLY_RULES = treeArg < 0; // a prebuilt public tree is already scrubbed

// Both inputs live under publish/, which the published tree drops. In the public repo this script is
// therefore present but has nothing to read, and a stack trace there would look like a broken gate
// rather than a gate that belongs to the other repo. Say which it is, and exit 0: the published
// repo runs this workflow too, and a gate that cannot apply there is not a failure there. Exiting 2
// turned the public repo's own quality gate red on every push and blocked its releases, for a check
// whose entire subject is the transform that produced that tree. check-scrub-output.mjs, which has
// exactly the same dependency, already skips this way - the two must not disagree.
function readRules(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e && e.code === 'ENOENT') {
      console.log(`check-pii: ${file} is not in this tree. This gate audits the tree BEFORE publishing`);
      console.log('and runs in the development repository, where publish/ exists. There is nothing for');
      console.log('it to do in a published tree, which by construction is what it already approved.');
      process.exit(0);
    }
    throw e;
  }
}
const rules = readRules('publish/scrub-rules.json');
const allow = readRules('publish/pii-allow.json');

// --- what counts as text worth reading -------------------------------------------------------
const SKIP_DIR = new Set(['.git', 'node_modules', 'vendor', '.idea', '.vscode']);
// The publisher copies `git ls-files` (see publish/Publish-Public.ps1), so this reads exactly that  (development repository)
// set: an untracked build output is never published and must not be scanned. Reading the working
// tree instead produced three "WireGuard keys" that were bytes out of dist/wayhop.exe, a file no
// publish has ever touched.
const TEXT_EXT = new Set([
  '.go', '.js', '.mjs', '.cjs', '.ts', '.json', '.md', '.txt', '.yml', '.yaml', '.sh', '.ps1',
  '.html', '.css', '.conf', '.cfg', '.ini', '.sql', '.toml', '.mod', '.sum', '.gitignore', '',
]);

// --- address space that is documentation, private, or otherwise not a person's -----------------
//
// Anything OUTSIDE these ranges is somebody's real address until proven otherwise. RFC5737 (TEST-NET
// 1/2/3) and RFC3849 (2001:db8::/32) are what the scrub rewrites real addresses INTO, so seeing them
// is the success case.
const ipv4Doc = (a, b) =>
  a === 0 || a === 10 || a === 127 || a >= 224 ||                       // this-net, private, loopback, multicast/reserved
  (a === 169 && b === 254) ||                                            // link-local
  (a === 172 && b >= 16 && b <= 31) ||                                   // private
  (a === 192 && b === 168) ||                                            // private
  (a === 192 && b === 0) ||                                              // 192.0.0/24 + 192.0.2/24 TEST-NET-1
  (a === 198 && (b === 18 || b === 19)) ||                               // benchmarking
  (a === 198 && b === 51) ||                                             // TEST-NET-2
  (a === 203 && b === 0) ||                                              // TEST-NET-3
  (a === 100 && b >= 64 && b <= 127);                                    // CGNAT

const DETECTORS = [
  {
    id: 'ipv4',
    what: 'a public IPv4 address',
    re: /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g,
    keep: (m) => {
      const [a, b, c, d] = [m[1], m[2], m[3], m[4]].map(Number);
      if ([a, b, c, d].some((n) => n > 255)) return false;             // a version string, not an address
      return !ipv4Doc(a, b);
    },
  },
  {
    id: 'ipv6',
    what: 'a public IPv6 address',
    // Two or more groups with a real hex value; ::1 and bare :: are not addresses of anyone.
    re: /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g,
    keep: (m) => {
      const s = m[0].toLowerCase();
      // Six two-hex groups is a MAC, not an address: the mac detector owns those, and reporting them
      // twice would make the same fixture look like two different kinds of leak.
      const groups = s.split(':');
      if (groups.length === 6 && groups.every((g) => g.length === 2)) return false;
      if (groups.length === 8 && groups.every((g) => g.length === 2)) return false; // EUI-64
      // A clock reading (00:03:48, 21:03:45) and a MAC fragment (aa:bb:cc) are three two-digit
      // groups, which is the same shape as a truncated address. Requiring one group of three or
      // four hex digits keeps 2606:4700:4700 and drops both — measured: five of seventeen distinct
      // "addresses" in this tree were timestamps out of log fixtures.
      if (!groups.some((g) => g.length >= 3)) return false;
      // RFC3849 documentation space, in EITHER spelling. Matching only the compressed form was the
      // same defeat this tree just fixed in the DoH check: one address, two textual forms, compared
      // as strings. A comment written with the expanded 2001:0db8:… was reported as a real address.
      if (/^2001:0?db8(:|$)/i.test(s)) return false;                    // RFC3849 documentation
      if (/^fe[89ab]/.test(s) || /^f[cd]/.test(s)) return false;        // link-local / unique-local
      if (/^(0{1,4}:){2,}/.test(s)) return false;                       // ::-ish
      return true;
    },
  },
  {
    id: 'mac',
    what: 'a MAC address',
    re: /\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b/g,
    keep: (m) => {
      const s = m[0].toLowerCase();
      // The all-zero and the aa:bb:cc:dd:ee:ff placeholder are what documentation uses.
      return s !== '00:00:00:00:00:00' && s !== 'aa:bb:cc:dd:ee:ff' && s !== 'ff:ff:ff:ff:ff:ff';
    },
  },
  {
    id: 'email',
    what: 'an email address',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    // RFC2606 reserves .example/.test/.invalid/.localhost precisely so documentation can use them,
    // and the noreply form is what the publish identity commits as.
    keep: (m) => !/@(?:[A-Za-z0-9.-]*\.)?(?:example|test|invalid|localhost)(?:\.[A-Za-z]{2,})?$/i.test(m[0])
      && !/@users\.noreply\.github\.com$/i.test(m[0]),
  },
  {
    id: 'wg-key',
    what: 'a WireGuard-shaped key',
    re: /\b[A-Za-z0-9+/_-]{42}[A-Za-z0-9+/_-]=\B/g,
    keep: (m) => !/^A{4,}/.test(m[0]),                                  // the scrub rewrites keys to AAAA…
  },
  {
    id: 'secret-hex',
    what: 'a long hex secret',
    re: /\b(?:0x)?[0-9a-fA-F]{32,}\b/g,
    keep: (m) => {
      const hex = m[0].replace(/^0x/i, '').toLowerCase();
      if (/^(.)\1*$/.test(hex)) return false;                           // 1111…, the scrubbed placeholder
      if (/^(0123456789abcdef)+$/.test(hex)) return false;              // an obvious fixture
      return true;
    },
  },
  {
    id: 'token',
    what: 'a credential-shaped token',
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    keep: () => true,
  },
  {
    id: 'private-key',
    what: 'a private key block',
    re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/g,
    keep: () => true,
  },
  {
    id: 'hostname',
    what: 'a hostname that is not a documentation or public-project domain',
    // Lower-case only, no /i flag: `System.IO`, `version.Info` and `v.Connection.Org` are Go
    // identifiers, and a case-insensitive match reported all three as hostnames — noise a reviewer
    // learns to skim past, which is how the real one gets skimmed past too.
    //
    // The suffix list is wide enough that a personal VPS under .pw, .site or .cloud is caught, and
    // stops short of the zones that collide with code: .sh matches every shell script in scripts/,
    // .click matches btn.click, and .host/.to/.in/.link/.md match ordinary identifiers. Those four
    // hundred dismissals would train a reviewer to dismiss, so they are out of scope here BY NAME:
    // a personal domain in one of those zones is caught by the deny list, not by this detector.
    re: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|io|dev|me|xyz|top|info|biz|su|ua|by|kz|de|nl|uk|pl|cz|fi|se|fr|tr|ir|cn|jp|hk|sg|ca|au|tv|ge|lv|lt|ee|site|online|store|cloud|tech|space|pw)\b/g,
    // RFC2606 reserves example/test/invalid/localhost for documentation, which is what this tree
    // uses for its several hundred fixture hostnames. Anything else is a real name until reviewed.
    // A match followed by '(' is a method call, and a single-letter first label is a code fragment.
    keep: (m, line) => {
      if (/(?:^|\.)(?:example|test|invalid|localhost)(?:\.[a-z]{2,}){0,2}$/.test(m[0])) return false;
      if (line.charAt(m.index + m[0].length) === '(') return false;
      if (/^[a-z0-9]\./.test(m[0])) return false;
      return true;
    },
  },
];

// --- allowlist -------------------------------------------------------------------------------
//
// Each entry is {detector, pattern, why}. A bare string silences nothing on its own: it has to name
// the detector it applies to, so allowing a public DNS resolver cannot also allow a hostname.
const allowRe = new Map();
for (const entry of allow.allow) {
  if (!entry.why || !entry.why.trim()) {
    console.error(`pii allowlist entry without a reason: ${JSON.stringify(entry)}`);
    process.exit(2);
  }
  if (!allowRe.has(entry.detector)) allowRe.set(entry.detector, []);
  allowRe.get(entry.detector).push(new RegExp(entry.pattern));
}
const allowed = (id, text) => (allowRe.get(id) || []).some((re) => re.test(text));

// --- the tree we would publish ----------------------------------------------------------------
const dropExact = new Set(rules.dropExact || []);
const dropPrefix = rules.dropPrefix || [];
const dropped = (rel) => {
  const p = rel.split(path.sep).join('/');
  return dropExact.has(p) || dropPrefix.some((d) => p.startsWith(d));
};

const replacements = APPLY_RULES ? (rules.replace || []) : [];
const scrub = (text) => {
  let out = text;
  for (const r of replacements) out = out.split(r.from).join(r.to);
  return out;
};

// listPublishable yields exactly what a publish would carry: tracked files, minus the drop lists.
//
// git ls-files rather than a directory walk, because that is what publish/Publish-Public.ps1 copies.  (development repository)
// A walk also reads build outputs, editor leftovers and anything else sitting in the tree, and every
// one of those is a hit the reviewer has to dismiss — noise that trains people to dismiss hits.
function listPublishable(root) {
  let tracked;
  try {
    tracked = execFileSync('git', ['ls-files', '-z'], { cwd: root, maxBuffer: 64 << 20 })
      .toString('utf8').split('\0').filter(Boolean);
  } catch {
    // A prebuilt public tree handed in with --tree may not be a repo yet. Fall back to a walk there,
    // where the whole directory IS the publishable set by construction.
    tracked = walkAll(root);
  }
  const out = [];
  for (const rel of tracked) {
    if (dropped(rel)) continue;
    if (rel.split('/').some((seg) => SKIP_DIR.has(seg))) continue;
    const ext = path.extname(rel);
    if (!TEXT_EXT.has(ext)) continue;
    const full = path.join(root, rel);
    let st;
    try { st = fs.statSync(full); } catch { continue; }
    if (!st.isFile() || st.size > 2 << 20) continue;
    out.push({ full, rel });
  }
  return out;
}

function walkAll(dir, base = dir, acc = []) {
  for (const name of fs.readdirSync(dir)) {
    if (SKIP_DIR.has(name)) continue;
    const full = path.join(dir, name);
    const st = fs.statSync(full);
    if (st.isDirectory()) walkAll(full, base, acc);
    else acc.push(path.relative(base, full).split(path.sep).join('/'));
  }
  return acc;
}

// --- scan --------------------------------------------------------------------------------------
const hits = new Map(); // detector id -> [{file, line, text}]
let scanned = 0;
for (const file of listPublishable(TREE)) {
  let raw;
  try { raw = fs.readFileSync(file.full, 'utf8'); } catch { continue; }
  if (raw.includes('\u0000')) continue; // binary that happens to carry a text extension
  scanned++;
  // go.sum is hashes by construction: every line is a base64 SHA-256 of a module, which is the
  // same 44-character shape as a WireGuard key and the same long-hex shape as a secret. Four of
  // the "keys" this detector first reported were module hashes. Skipping the file is honest — a
  // credential cannot be hidden there, because `go mod verify` would reject a hand-edited line.
  const isHashFile = /(?:^|\/)go\.sum$/.test(file.rel);
  const text = scrub(raw);
  const lines = text.split('\n');
  for (const det of DETECTORS) {
    if (isHashFile && (det.id === 'wg-key' || det.id === 'secret-hex')) continue;
    for (let i = 0; i < lines.length; i++) {
      det.re.lastIndex = 0;
      let m;
      while ((m = det.re.exec(lines[i])) !== null) {
        if (!det.keep(m, lines[i])) continue;
        if (allowed(det.id, m[0])) continue;
        if (!hits.has(det.id)) hits.set(det.id, []);
        hits.get(det.id).push({ file: file.rel, line: i + 1, text: m[0] });
      }
    }
  }
}

// --- report ------------------------------------------------------------------------------------
// --- names ------------------------------------------------------------------------------------
//
// The detectors above catch SHAPES. A name has no shape: "Primary group" and "WgProvider_SiteB"
// look exactly like any other words, and no pattern separates the operator's group from a fixture
// someone invented. Both of those were in this tree, in test fixtures and gate comments written
// from live measurements, and neither the deny list nor any detector saw them.
//
// So this half stays human, with a tool instead of a promise: paste the names your own profile uses
// (connection, group and routing-list names, router hostnames, provider names) one per line, and
// this reports which of them survive into the publishable bytes. What it finds becomes a replace +
// deny pair in scrub-rules.json.
//
//   node scripts/check-pii.mjs --names my-names.txt
// The list is the weak part, and it failed exactly the way a hand-written list fails. A first sweep
// was fed the names visible in one reading of the live profile; it scrubbed two members of a
// measured group and missed the third, which sat in a health check, two gates and a comment until a
// later sweep with a fuller list found it. The list is only as complete as whoever typed it.
//
// So --profile removes the typing. Point it at anything the box already emits that carries names --
// a config.json, an /api/state dump, a proxies dump -- and it harvests the operator-chosen strings
// out of that JSON and checks every one of them, whether or not anybody remembered it:
//
//   node scripts/check-pii.mjs --profile /tmp/proxies.json
//
// Over-harvesting is the safe direction here: a false positive costs one review, a miss ships.
// Only the product's own vocabulary is dropped, because those words are in the source by right.
const PROFILE_VOCABULARY = new Set([
  'direct', 'block', 'reject', 'global', 'proxy', 'proxies', 'default', 'auto', 'main', 'none',
  'fallback', 'selector', 'urltest', 'loadbalance', 'shadowsocks', 'vmess', 'vless', 'trojan',
  'hysteria', 'hysteria2', 'wireguard', 'socks', 'http', 'https', 'mixed', 'tun', 'dns', 'name',
  'type', 'history', 'udp', 'now', 'all', 'alive', 'delay', 'time', 'meanDelay', 'extra', 'id',
  'tag', 'kind', 'mode', 'state', 'status', 'enabled', 'disabled', 'true', 'false', 'null',
  'group', 'groups', 'rule', 'rules', 'list', 'lists', 'member', 'members', 'outbound', 'outbounds',
  'endpoint', 'endpoints', 'interface', 'server', 'port', 'host', 'address', 'domain', 'test',
  'interval', 'tolerance', 'timeout', 'url', 'version', 'platform', 'config', 'settings',
]);

// Harvest every string that could be a name: object keys and string values alike. A named map
// ({"proxies": {"group-failover": {...}}}) hides its names in the KEYS, so keys have to count.
function harvestNames(node, out) {
  if (Array.isArray(node)) {
    for (const v of node) harvestNames(v, out);
    return;
  }
  if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      out.add(k);
      harvestNames(v, out);
    }
    return;
  }
  if (typeof node === 'string') out.add(node);
}

function operatorChosen(s) {
  const t = s.trim();
  if (t.length < 4 || t.length > 120) return false;
  if (!/[A-Za-z]/.test(t)) return false;             // pure numbers, punctuation, empty shapes
  if (PROFILE_VOCABULARY.has(t.toLowerCase())) return false;
  return true;
}

// Both name modes ask the same question of the same bytes; only the list differs.
function scanNames(wanted) {
  const found = new Map();
  for (const file of listPublishable(TREE)) {
    let raw;
    try { raw = fs.readFileSync(file.full, 'utf8'); } catch { continue; }
    const text = scrub(raw);
    for (const name of wanted) {
      if (!text.includes(name)) continue;
      if (!found.has(name)) found.set(name, []);
      if (found.get(name).length < 5) found.get(name).push(file.rel);
    }
  }
  return found;
}

function reportNames(wanted, found, subject) {
  if (!found.size) {
    console.log(`${subject} OK: none of the ${wanted.length} name(s) survive into the publishable tree.`);
    process.exit(0);
  }
  for (const [name, where] of found) console.error(`  ${JSON.stringify(name)} -> ${where.join(', ')}`);
  console.error(`\n${subject} FAILED: ${found.size} of ${wanted.length} name(s) reach the public tree.`);
  console.error('Add each as a replace + deny pair in publish/scrub-rules.json.');
  process.exit(1);
}

const profileArg = argv.indexOf('--profile');
if (profileArg >= 0) {
  const raw = fs.readFileSync(argv[profileArg + 1], 'utf8');
  const harvested = new Set();
  harvestNames(JSON.parse(raw), harvested);
  const wanted = [...harvested].map((s) => s.trim()).filter(operatorChosen).sort();
  if (!wanted.length) {
    console.error('profile FAILED: no operator-chosen name was harvested, so this check asked nothing. '
      + 'Either the file carries no names or the vocabulary filter swallowed them.');
    process.exit(2);
  }
  console.log(`profile: harvested ${wanted.length} candidate name(s) from ${argv[profileArg + 1]}`);
  reportNames(wanted, scanNames(wanted), 'profile');
}

const namesArg = argv.indexOf('--names');
if (namesArg >= 0) {
  const wanted = fs.readFileSync(argv[namesArg + 1], 'utf8')
    .split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  reportNames(wanted, scanNames(wanted), 'names');
}

if (argv.includes('--inventory')) {
  const out = {};
  for (const det of DETECTORS) {
    out[det.id] = [...new Set((hits.get(det.id) || []).map((h) => h.text))].sort();
  }
  console.log(JSON.stringify(out, null, 1));
  process.exit(0);
}

let total = 0;
for (const det of DETECTORS) {
  const found = hits.get(det.id) || [];
  total += found.length;
  if (!found.length) continue;
  const uniq = new Map();
  for (const h of found) if (!uniq.has(h.text)) uniq.set(h.text, h);
  console.error(`\n${det.id}: ${found.length} hit(s) — ${det.what}`);
  const show = VERBOSE ? [...uniq.values()] : [...uniq.values()].slice(0, 12);
  for (const h of show) console.error(`  ${h.file}:${h.line}  ${h.text}`);
  if (!VERBOSE && uniq.size > show.length) {
    console.error(`  … ${uniq.size - show.length} more distinct value(s) — rerun with --verbose`);
  }
}

if (total) {
  console.error(`\npii check FAILED: ${total} hit(s) across ${hits.size} detector(s) in ${scanned} file(s).`);
  console.error('Each hit is either data to scrub (add a replace + deny rule in publish/scrub-rules.json)');
  console.error('or a value that belongs in the public tree (add it to publish/pii-allow.json WITH a reason).');
  process.exit(1);
}
console.log(`pii OK: ${scanned} publishable file(s), ${DETECTORS.length} shape detector(s), 0 hits.`);
