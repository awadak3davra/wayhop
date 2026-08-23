// Every HTTP route must state its authentication class at registration time. A forgotten route is
// a release failure, not an implicitly public endpoint. This gate also runs a negative fixture so a
// broken scanner cannot pass merely because it found no registrations.
import fs from 'node:fs';

const serverSource = fs.readFileSync('internal/server/server.go', 'utf8');
const authSource = fs.readFileSync('internal/server/auth.go', 'utf8');
const appSource = fs.readFileSync('web/dist/app.js', 'utf8');
const publicRoutes = new Set([
  'GET /api/auth/status',
  'POST /api/auth/setup',
  'POST /api/auth/login',
  'GET /api/health',
  '/api/',
  '/',
]);
function inspect(source) {
  const problems = [];
  const routes = [];
  const routeRE = /s\.route\(mux,\s*authRoute(Public|Protected),\s*"([^"]+)"/g;
  for (const match of source.matchAll(routeRE)) {
    routes.push({ classification: match[1].toLowerCase(), pattern: match[2] });
  }
  const direct = [...source.matchAll(/\bmux\.Handle(?:Func)?\s*\(/g)];
  if (direct.length) problems.push(`${direct.length} direct mux registration(s) bypass s.route`);
  const seen = new Set();
  for (const route of routes) {
    if (seen.has(route.pattern)) problems.push(`duplicate route ${route.pattern}`);
    seen.add(route.pattern);
    if (route.classification === 'public' && !publicRoutes.has(route.pattern)) {
      problems.push(`unexpected public route ${route.pattern}`);
    }
    if (route.classification === 'protected' && publicRoutes.has(route.pattern)) {
      problems.push(`misclassified protected route ${route.pattern}`);
    }
  }
  for (const pattern of publicRoutes) {
    if (!routes.some(r => r.classification === 'public' && r.pattern === pattern)) {
      problems.push(`missing public route ${pattern}`);
    }
  }
  if (!routes.some(r => r.classification === 'protected')) problems.push('no protected routes found');
  return { routes, problems };
}

const production = inspect(serverSource);
const helperRegistrations = [...authSource.matchAll(/\bmux\.HandleFunc\s*\(/g)].length;
if (helperRegistrations !== 2 || !/func \(s \*Server\) route\(/.test(authSource)) {
  production.problems.push('auth route helper must own both direct mux.HandleFunc registrations');
}

// Prove the scanner fires: this is the exact class of future mistake the gate exists to refuse.
const forgotten = inspect(serverSource +
  '\nfunc forgotten(mux *http.ServeMux) { mux.HandleFunc("POST /api/forgotten", http.NotFound) }\n');
if (!forgotten.problems.some(problem => problem.includes('direct mux registration'))) {
  production.problems.push('negative fixture was not rejected');
}

// A session can expire while Dashboard polling is already active. Every API helper must wait on
// the shared authentication gate; otherwise the still-running timers send protected requests every
// few seconds, flood router logs with 401s, and paint a false OFFLINE state behind the sign-in modal.
for (const method of ['get', 'post', 'put', 'del']) {
  const guarded = new RegExp(`async ${method}\\([^)]*\\)\\s*\\{\\s*await waitForAuthentication\\(\\);`);
  if (!guarded.test(appSource)) production.problems.push(`frontend api.${method} bypasses authentication gate`);
}
if (!/authCheckPromise\s*=\s*\(async \(\) =>/.test(appSource)) {
  production.problems.push('frontend authentication status check is not published as a shared promise');
}

if (production.problems.length) {
  console.error('auth route classification failed:\n- ' + production.problems.join('\n- '));
  process.exit(1);
}
console.log(`auth routes: ${production.routes.length} classified routes; negative fixture rejected`);
