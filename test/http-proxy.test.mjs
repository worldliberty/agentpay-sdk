import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import test from 'node:test';
import {
  closeGlobalFetchProxyDispatcherFromEnv,
  installGlobalFetchProxyDispatcherFromEnv,
  resolveProxyUrlForTarget,
  shouldBypassProxy,
} from '../src/lib/http-proxy.ts';

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(undefined));
  });
}

async function closeServer(server) {
  if (typeof server.closeAllConnections === 'function') {
    server.closeAllConnections();
  }
  await new Promise((resolve) => server.close(() => resolve(undefined)));
}

test('resolveProxyUrlForTarget prefers protocol-specific proxy env vars and honors NO_PROXY', () => {
  assert.equal(
    resolveProxyUrlForTarget(new URL('https://api.example.com/data'), {
      HTTPS_PROXY: 'http://secure-proxy.local:8443',
      HTTP_PROXY: 'http://plain-proxy.local:8080',
    }),
    'http://secure-proxy.local:8443',
  );

  assert.equal(
    resolveProxyUrlForTarget(new URL('http://api.example.com/data'), {
      HTTPS_PROXY: 'http://secure-proxy.local:8443',
      HTTP_PROXY: 'http://plain-proxy.local:8080',
    }),
    'http://plain-proxy.local:8080',
  );

  assert.equal(
    resolveProxyUrlForTarget(new URL('https://api.example.com/data'), {
      HTTPS_PROXY: 'http://secure-proxy.local:8443',
      NO_PROXY: '.example.com',
    }),
    null,
  );
});

test('shouldBypassProxy matches exact hosts, subdomains, and port-specific NO_PROXY rules', () => {
  assert.equal(
    shouldBypassProxy(new URL('https://api.example.com/data'), {
      NO_PROXY: 'example.com',
    }),
    true,
  );
  assert.equal(
    shouldBypassProxy(new URL('https://api.example.com:8443/data'), {
      NO_PROXY: 'example.com:8443',
    }),
    true,
  );
  assert.equal(
    shouldBypassProxy(new URL('https://api.example.com:9443/data'), {
      NO_PROXY: 'example.com:8443',
    }),
    false,
  );
});

test('installGlobalFetchProxyDispatcherFromEnv makes global fetch honor HTTP_PROXY', async () => {
  let proxyHits = 0;
  const targetServer = http.createServer((_req, res) => {
    res.setHeader('content-type', 'text/plain');
    res.end('proxy-ok');
  });
  const proxyServer = http.createServer((req, res) => {
    proxyHits += 1;
    const targetUrl = new URL(req.url);
    const upstream = http.request(
      {
        host: '127.0.0.1',
        port: Number(targetUrl.port),
        method: req.method,
        path: `${targetUrl.pathname}${targetUrl.search}`,
        headers: req.headers,
      },
      (upstreamResponse) => {
        res.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(res);
      },
    );
    req.pipe(upstream);
    upstream.on('error', (error) => {
      res.statusCode = 502;
      res.end(error instanceof Error ? error.message : String(error));
    });
  });
  proxyServer.on('connect', (req, clientSocket, head) => {
    proxyHits += 1;
    const targetUrl = new URL(`http://${req.url}`);
    const upstreamSocket = net.connect(
      {
        host: '127.0.0.1',
        port: Number(targetUrl.port),
      },
      () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length > 0) {
          upstreamSocket.write(head);
        }
        upstreamSocket.pipe(clientSocket);
        clientSocket.pipe(upstreamSocket);
      },
    );
    const destroyBoth = () => {
      upstreamSocket.destroy();
      clientSocket.destroy();
    };
    upstreamSocket.on('error', destroyBoth);
    clientSocket.on('error', destroyBoth);
  });

  await listen(targetServer);
  await listen(proxyServer);

  const targetAddress = targetServer.address();
  const proxyAddress = proxyServer.address();
  const targetUrl = `http://example.test:${targetAddress.port}/price`;
  const proxyUrl = `http://127.0.0.1:${proxyAddress.port}`;

  try {
    installGlobalFetchProxyDispatcherFromEnv({
      ...process.env,
      HTTP_PROXY: proxyUrl,
      NO_PROXY: '',
    });

    const response = await fetch(targetUrl);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), 'proxy-ok');
    assert.equal(proxyHits > 0, true, 'expected request to traverse the configured HTTP proxy');
  } finally {
    await closeGlobalFetchProxyDispatcherFromEnv();
    await closeServer(proxyServer);
    await closeServer(targetServer);
  }
});
