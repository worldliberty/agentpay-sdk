import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../apps/web/next.config.ts', import.meta.url);
const cspModulePath = new URL('../apps/web/src/lib/csp.ts', import.meta.url);

async function loadCsp(caseSuffix) {
  return await import(`${cspModulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

function parseDirectives(policy) {
  return new Map(
    policy
      .split(';')
      .map((directive) => directive.trim())
      .filter(Boolean)
      .map((directive) => {
        const [name, ...sources] = directive.split(/\s+/u);
        return [name, sources];
      }),
  );
}

async function loadConfig(caseSuffix) {
  return await import(`${modulePath.href}?case=${caseSuffix}-${Date.now()}`);
}

test('next config serves hardened approval-console security headers', async () => {
  const configModule = await loadConfig('headers');
  const headers = await configModule.default.headers();

  assert.equal(headers.length, 3);
  assert.equal(headers[0].source, '/approvals/:path*');
  assert.equal(headers[1].source, '/daemons/:path*');
  assert.equal(headers[2].source, '/:path*');
  assert.equal(
    configModule.approvalConsoleNoStoreHeaders.some(
      (header) => header.key === 'Cache-Control' && header.value === 'private, no-store, max-age=0',
    ),
    true,
  );
  assert.equal(
    configModule.approvalConsoleNoStoreHeaders.some(
      (header) => header.key === 'Pragma' && header.value === 'no-cache',
    ),
    true,
  );
  assert.equal(
    configModule.approvalConsoleSecurityHeaders.some(
      (header) =>
        header.key === 'Strict-Transport-Security' &&
        /max-age=\d{8,}/u.test(header.value) &&
        header.value.includes('includeSubDomains'),
    ),
    true,
  );
  // The CSP is nonce-based and issued per request by src/proxy.ts, never as a
  // static header that would lack the nonce.
  assert.equal(
    configModule.approvalConsoleSecurityHeaders.some(
      (header) => header.key === 'Content-Security-Policy',
    ),
    false,
  );
  assert.equal(
    configModule.approvalConsoleSecurityHeaders.some(
      (header) => header.key === 'Referrer-Policy' && header.value === 'no-referrer',
    ),
    true,
  );
  assert.equal(
    configModule.approvalConsoleSecurityHeaders.some(
      (header) => header.key === 'X-Frame-Options' && header.value === 'DENY',
    ),
    true,
  );
});

test('production CSP is strict and nonce-based', async () => {
  const csp = await loadCsp('production');
  const nonce = csp.createCspNonce();
  const directives = parseDirectives(
    csp.buildContentSecurityPolicy({
      isDevelopment: false,
      nonce,
      relayOrigin: csp.relayOriginForCsp('https://relay.example/base/'),
    }),
  );

  assert.match(nonce, /^[A-Za-z0-9+/]{22}==$/u);
  assert.deepEqual(directives.get('default-src'), ["'self'"]);
  assert.deepEqual(directives.get('script-src'), [
    "'self'",
    `'nonce-${nonce}'`,
    "'strict-dynamic'",
  ]);
  assert.deepEqual(directives.get('style-src'), ["'self'", `'nonce-${nonce}'`]);
  assert.deepEqual(directives.get('connect-src'), ["'self'", 'https://relay.example']);
  assert.deepEqual(directives.get('form-action'), ["'self'"]);
  assert.deepEqual(directives.get('object-src'), ["'none'"]);
  assert.deepEqual(directives.get('frame-ancestors'), ["'none'"]);
  assert.deepEqual(directives.get('base-uri'), ["'self'"]);
  assert.equal(directives.has('upgrade-insecure-requests'), true);
  for (const sources of directives.values()) {
    assert.equal(sources.includes("'unsafe-inline'"), false);
    assert.equal(sources.includes("'unsafe-eval'"), false);
    assert.equal(sources.includes('*'), false);
  }
});

test('development CSP only relaxes what the Next.js dev server needs', async () => {
  const csp = await loadCsp('development');
  const directives = parseDirectives(
    csp.buildContentSecurityPolicy({
      isDevelopment: true,
      nonce: 'abc',
      relayOrigin: 'http://localhost:8787',
    }),
  );

  assert.deepEqual(directives.get('script-src'), [
    "'self'",
    "'nonce-abc'",
    "'strict-dynamic'",
    "'unsafe-eval'",
  ]);
  assert.deepEqual(directives.get('connect-src'), ["'self'", 'http://localhost:8787']);
  assert.equal(directives.has('upgrade-insecure-requests'), false);
});

test('CSP nonces are unique per call', async () => {
  const csp = await loadCsp('nonce-unique');
  const nonces = new Set(Array.from({ length: 32 }, () => csp.createCspNonce()));
  assert.equal(nonces.size, 32);
});
