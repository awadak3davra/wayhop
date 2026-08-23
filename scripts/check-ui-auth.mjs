#!/usr/bin/env node
import { authenticateCDP, authenticateUI } from './ui-auth.mjs';
import { readFile } from 'node:fs/promises';

const appSource = await readFile(new URL('../web/dist/app.js', import.meta.url), 'utf8');
if (!/if \(authCheckPromise \|\| authGatePromise\) \{[\s\S]*?history\.replaceState\(null, "", _navGuardHash\);[\s\S]*?return;[\s\S]*?\}/.test(appSource)) {
  throw new Error('auth navigation lock is missing: hash changes can discard the sign-in gate');
}
if (!appSource.includes('$$\(".modal-backdrop:not\(.auth-gate\)"\)')) {
  throw new Error('route modal cleanup is not preserving the authentication gate');
}

const mustReject = async (name, options, pattern, secret = '') => {
  try {
    await authenticateUI(options);
    throw new Error(`${name}: accepted`);
  } catch (error) {
    if (!pattern.test(String(error.message))) throw error;
    if (secret && String(error.message).includes(secret)) throw new Error(`${name}: credential leaked`);
  }
};

let calls = 0;
await authenticateUI({
  url: 'http://router.test/', navigate: async () => { throw new Error('unexpected navigation'); },
  evaluate: async expression => {
    calls++;
    if (!expression.includes('/api/auth/status')) throw new Error('unexpected expression');
    return { ok: true, status: 200, body: { configured: true, authenticated: true } };
  },
});
if (calls !== 1) throw new Error(`authenticated session used ${calls} probe(s), want 1`);

await mustReject('setup boundary', {
  url: 'http://router.test/', navigate: async () => {},
  evaluate: async () => ({ ok: true, status: 200, body: { configured: false, authenticated: false } }),
}, /Create it explicitly/);

await mustReject('missing credentials', {
  url: 'http://router.test/', username: '', password: '', navigate: async () => {},
  evaluate: async () => ({ ok: true, status: 200, body: { configured: true, authenticated: false } }),
}, /WR_UI_USER/);

const secret = 'SENTINEL-qa-password';
let phase = 0, navigated = 0;
await authenticateUI({
  url: 'http://router.test/', username: 'qa-user', password: secret,
  navigate: async target => { if (target !== 'http://router.test/') throw new Error('wrong target'); navigated++; },
  evaluate: async expression => {
    phase++;
    if (phase === 1) return { ok: true, status: 200, body: { configured: true, authenticated: false } };
    if (phase === 2) {
      if (!expression.includes('/api/auth/login') || !expression.includes(secret)) throw new Error('login request missing inputs');
      return { ok: true, status: 200 };
    }
    return { configured: true, authenticated: true };
  },
});
if (phase !== 3 || navigated !== 1) throw new Error(`login flow = ${phase} probe(s), ${navigated} navigation(s)`);

await mustReject('failed login redaction', {
  url: 'http://router.test/', username: 'qa-user', password: secret, navigate: async () => {},
  evaluate: async expression => expression.includes('/api/auth/login')
    ? { ok: false, status: 401 }
    : { ok: true, status: 200, body: { configured: true, authenticated: false } },
}, /HTTP 401/, secret);

let cdpPhase = 0, cdpNavigation = null;
await authenticateCDP({
  url: 'http://router.test/', username: 'qa-user', password: secret,
  send: async (method, params) => {
    if (method !== 'Page.navigate') throw new Error(`unexpected CDP method ${method}`);
    cdpNavigation = params.url;
  },
  evaluate: async expression => {
    cdpPhase++;
    if (cdpPhase === 1) return { ok: true, status: 200, body: { configured: true, authenticated: false } };
    if (cdpPhase === 2) return { ok: true, status: 200 };
    if (expression.includes('typeof route')) return cdpPhase >= 5;
    return { configured: true, authenticated: true };
  },
});
if (cdpNavigation !== 'http://router.test/' || cdpPhase < 6) {
  throw new Error(`CDP login flow = navigation ${cdpNavigation}, ${cdpPhase} evaluations`);
}

try {
  await authenticateCDP({ url: 'http://router.test/', send: null, evaluate: async () => ({}) });
  throw new Error('missing CDP sender: accepted');
} catch (error) {
  if (!/missing its CDP sender/.test(String(error.message))) throw error;
}

console.log('ui auth: 9 contracts pass — route lock, modal preservation, existing session, setup refusal, credential requirement, login confirmation, redacted failure, CDP navigation, and CDP sender validation');
