// Shared authentication boundary for headless UI gates.
//
// The gates run in a fresh browser profile, so an operator's normal browser session cannot help
// them. Credentials are opt-in environment inputs and are sent only to the target panel's same-
// origin login endpoint. First-account setup is deliberately never automated: that creates persistent
// access and must remain an explicit operator action.
export async function authenticateUI({ evaluate, navigate, url, username, password }) {
  if (typeof evaluate !== 'function' || typeof navigate !== 'function' || !url) {
    throw new Error('UI authentication helper is missing its browser callbacks or target URL');
  }
  const status = await evaluate(`fetch('/api/auth/status', {
    cache: 'no-store', credentials: 'same-origin'
  }).then(async response => ({
    ok: response.ok,
    status: response.status,
    body: response.ok ? await response.json() : null
  }))`);
  if (!status?.ok) {
    throw new Error(`WayHop authentication status returned HTTP ${status?.status || 'unknown'}`);
  }
  if (status.body?.authenticated) return { alreadyAuthenticated: true };
  if (!status.body?.configured) {
    throw new Error('WayHop has no operator account. Create it explicitly in the panel before running authenticated UI QA.');
  }
  username = username ?? process.env.WR_UI_USER ?? '';
  password = password ?? process.env.WR_UI_PASSWORD ?? '';
  if (!username || !password) {
    throw new Error('WayHop requires authentication. Set WR_UI_USER and WR_UI_PASSWORD for this QA process.');
  }

  const login = await evaluate(`fetch('/api/auth/login', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: ${JSON.stringify(username)}, password: ${JSON.stringify(password)} })
  }).then(response => ({ ok: response.ok, status: response.status }))`);
  if (!login?.ok) {
    throw new Error(`WayHop login failed with HTTP ${login?.status || 'unknown'}; credentials were not logged.`);
  }
  await navigate(url);
  const confirmed = await evaluate(`fetch('/api/auth/status', {
    cache: 'no-store', credentials: 'same-origin'
  }).then(async response => response.ok ? await response.json() : null)`);
  if (!confirmed?.authenticated) {
    throw new Error('WayHop login returned success but the browser session was not authenticated.');
  }
  return { alreadyAuthenticated: false };
}

// CDP gates all used to grow their own login seam. Most never grew one at all, so after operator
// authentication became mandatory they quietly measured the two-control login screen and called the
// missing application a redesign regression. Keep the policy above independent of Chrome, and keep
// this adapter responsible only for navigating the already-open throwaway browser and waiting for the
// application bundle to execute again after a successful login.
export async function authenticateCDP({
  send, evaluate, url, username, password,
  readyExpression = 'typeof route === "function"',
}) {
  if (typeof send !== 'function') {
    throw new Error('UI authentication helper is missing its CDP sender');
  }
  return authenticateUI({
    evaluate,
    url,
    username,
    password,
    navigate: async target => {
      await send('Page.navigate', { url: target });
      for (let i = 0; i < 160; i++) {
        if (await evaluate(readyExpression).catch(() => false)) return;
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      throw new Error('WayHop did not finish loading after authenticated navigation');
    },
  });
}
