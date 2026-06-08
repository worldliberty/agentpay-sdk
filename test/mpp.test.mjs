import assert from 'node:assert/strict';
import test from 'node:test';

const modulePath = new URL('../src/lib/mpp.ts', import.meta.url);

test('parseMppChallengesFromHeaders parses multiple merged Payment challenges', async () => {
  const mpp = await import(`${modulePath.href}?case=${Date.now()}-multi-header`);
  const headers = new Headers({
    'WWW-Authenticate': [
      'Payment id="CdqjupugiZOwd9rkyZBjjj7TMcl2gY0nxEiSxL_hI_I", realm="mpp.quicknode.com", method="tempo", intent="session", request="eyJhbW91bnQiOiIxMCIsImN1cnJlbmN5IjoiMHgyMGMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwibWV0aG9kRGV0YWlscyI6eyJjaGFpbklkIjo0MjQzMSwiZXNjcm93Q29udHJhY3QiOiIweGUxYzRkM2RjZTE3YmMxMTExODFkZGY3MTZmNzViYWU0OWU2MWEzMzYiLCJmZWVQYXllciI6dHJ1ZX0sInJlY2lwaWVudCI6IjB4RkQyNDExNEMzOTgxQWJhNzhhRTI0NDE5OTFCMUJkQjg5MzI5YzU1NiIsInVuaXRUeXBlIjoicmVxdWVzdCJ9", description="Quicknode RPC session request", expires="2026-04-05T21:55:43.291Z"',
      'Payment id="DDb3qqfKohNsaX9w2fsMcCKbOBAZ14-bC75EdU_rZFY", realm="mpp.quicknode.com", method="tempo", intent="session", request="eyJhbW91bnQiOiIxMCIsImN1cnJlbmN5IjoiMHgyMGMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwibWV0aG9kRGV0YWlscyI6eyJjaGFpbklkIjo0MjE3LCJlc2Nyb3dDb250cmFjdCI6IjB4MzNiOTAxMDE4MTc0RERhYkU0ODQxMDQyYWI3NmJhODVENGUyNGYyNSIsImZlZVBheWVyIjp0cnVlfSwicmVjaXBpZW50IjoiMHhGRDI0MTE0QzM5ODFBYmE3OGFFMjQ0MTk5MUIxQmRCODkzMjljNTU2IiwidW5pdFR5cGUiOiJyZXF1ZXN0In0", description="Quicknode RPC session request", expires="2026-04-05T21:55:43.291Z"',
      'Payment id="4epxRUP8lbppQg4F4ZdxLuPKkLuZFxyUCEDQ0hM6dSc", realm="mpp.quicknode.com", method="tempo", intent="session", request="eyJhbW91bnQiOiIxMCIsImN1cnJlbmN5IjoiMHgyMEMwMDAwMDAwMDAwMDAwMDAwMDAwMDBiOTUzN2QxMWM2MEU4YjUwIiwibWV0aG9kRGV0YWlscyI6eyJjaGFpbklkIjo0MjE3LCJlc2Nyb3dDb250cmFjdCI6IjB4MzNiOTAxMDE4MTc0RERhYkU0ODQxMDQyYWI3NmJhODVENGUyNGYyNSIsImZlZVBheWVyIjp0cnVlfSwicmVjaXBpZW50IjoiMHhGRDI0MTE0QzM5ODFBYmE3OGFFMjQ0MTk5MUIxQmRCODkzMjljNTU2IiwidW5pdFR5cGUiOiJyZXF1ZXN0In0", description="Quicknode RPC session request", expires="2026-04-05T21:55:43.291Z"',
    ].join(', '),
  });

  const challenges = mpp.parseMppChallengesFromHeaders(headers);
  assert.equal(challenges.length, 3);
  assert.deepEqual(
    challenges.map((challenge) => challenge.request.methodDetails?.chainId),
    [42431, 4217, 4217],
  );
});

test('selectMppChallenge prefers the mainnet pathUSD challenge for Quicknode tempo-mainnet URLs', async () => {
  const mpp = await import(`${modulePath.href}?case=${Date.now()}-quicknode-mainnet`);
  const headers = new Headers({
    'WWW-Authenticate': [
      'Payment id="CdqjupugiZOwd9rkyZBjjj7TMcl2gY0nxEiSxL_hI_I", realm="mpp.quicknode.com", method="tempo", intent="session", request="eyJhbW91bnQiOiIxMCIsImN1cnJlbmN5IjoiMHgyMGMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwibWV0aG9kRGV0YWlscyI6eyJjaGFpbklkIjo0MjQzMSwiZXNjcm93Q29udHJhY3QiOiIweGUxYzRkM2RjZTE3YmMxMTExODFkZGY3MTZmNzViYWU0OWU2MWEzMzYiLCJmZWVQYXllciI6dHJ1ZX0sInJlY2lwaWVudCI6IjB4RkQyNDExNEMzOTgxQWJhNzhhRTI0NDE5OTFCMUJkQjg5MzI5YzU1NiIsInVuaXRUeXBlIjoicmVxdWVzdCJ9", description="Quicknode RPC session request", expires="2026-04-05T21:55:43.291Z"',
      'Payment id="DDb3qqfKohNsaX9w2fsMcCKbOBAZ14-bC75EdU_rZFY", realm="mpp.quicknode.com", method="tempo", intent="session", request="eyJhbW91bnQiOiIxMCIsImN1cnJlbmN5IjoiMHgyMGMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwibWV0aG9kRGV0YWlscyI6eyJjaGFpbklkIjo0MjE3LCJlc2Nyb3dDb250cmFjdCI6IjB4MzNiOTAxMDE4MTc0RERhYkU0ODQxMDQyYWI3NmJhODVENGUyNGYyNSIsImZlZVBheWVyIjp0cnVlfSwicmVjaXBpZW50IjoiMHhGRDI0MTE0QzM5ODFBYmE3OGFFMjQ0MTk5MUIxQmRCODkzMjljNTU2IiwidW5pdFR5cGUiOiJyZXF1ZXN0In0", description="Quicknode RPC session request", expires="2026-04-05T21:55:43.291Z"',
      'Payment id="4epxRUP8lbppQg4F4ZdxLuPKkLuZFxyUCEDQ0hM6dSc", realm="mpp.quicknode.com", method="tempo", intent="session", request="eyJhbW91bnQiOiIxMCIsImN1cnJlbmN5IjoiMHgyMEMwMDAwMDAwMDAwMDAwMDAwMDAwMDBiOTUzN2QxMWM2MEU4YjUwIiwibWV0aG9kRGV0YWlscyI6eyJjaGFpbklkIjo0MjE3LCJlc2Nyb3dDb250cmFjdCI6IjB4MzNiOTAxMDE4MTc0RERhYkU0ODQxMDQyYWI3NmJhODVENGUyNGYyNSIsImZlZVBheWVyIjp0cnVlfSwicmVjaXBpZW50IjoiMHhGRDI0MTE0QzM5ODFBYmE3OGFFMjQ0MTk5MUIxQmRCODkzMjljNTU2IiwidW5pdFR5cGUiOiJyZXF1ZXN0In0", description="Quicknode RPC session request", expires="2026-04-05T21:55:43.291Z"',
    ].join(', '),
  });

  const selected = mpp.selectMppChallenge(mpp.parseMppChallengesFromHeaders(headers), {
    targetUrl: 'https://mpp.quicknode.com/session/tempo-mainnet',
  });
  assert.equal(selected.request.methodDetails?.chainId, 4217);
  assert.equal(
    selected.request.currency.toLowerCase(),
    '0x20c0000000000000000000000000000000000000',
  );
});

test('selectMppChallenge prefers the testnet challenge for Quicknode tempo-testnet URLs', async () => {
  const mpp = await import(`${modulePath.href}?case=${Date.now()}-quicknode-testnet`);
  const headers = new Headers({
    'WWW-Authenticate': [
      'Payment id="CdqjupugiZOwd9rkyZBjjj7TMcl2gY0nxEiSxL_hI_I", realm="mpp.quicknode.com", method="tempo", intent="session", request="eyJhbW91bnQiOiIxMCIsImN1cnJlbmN5IjoiMHgyMGMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwibWV0aG9kRGV0YWlscyI6eyJjaGFpbklkIjo0MjQzMSwiZXNjcm93Q29udHJhY3QiOiIweGUxYzRkM2RjZTE3YmMxMTExODFkZGY3MTZmNzViYWU0OWU2MWEzMzYiLCJmZWVQYXllciI6dHJ1ZX0sInJlY2lwaWVudCI6IjB4RkQyNDExNEMzOTgxQWJhNzhhRTI0NDE5OTFCMUJkQjg5MzI5YzU1NiIsInVuaXRUeXBlIjoicmVxdWVzdCJ9", description="Quicknode RPC session request", expires="2026-04-05T21:55:43.291Z"',
      'Payment id="DDb3qqfKohNsaX9w2fsMcCKbOBAZ14-bC75EdU_rZFY", realm="mpp.quicknode.com", method="tempo", intent="session", request="eyJhbW91bnQiOiIxMCIsImN1cnJlbmN5IjoiMHgyMGMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwibWV0aG9kRGV0YWlscyI6eyJjaGFpbklkIjo0MjE3LCJlc2Nyb3dDb250cmFjdCI6IjB4MzNiOTAxMDE4MTc0RERhYkU0ODQxMDQyYWI3NmJhODVENGUyNGYyNSIsImZlZVBheWVyIjp0cnVlfSwicmVjaXBpZW50IjoiMHhGRDI0MTE0QzM5ODFBYmE3OGFFMjQ0MTk5MUIxQmRCODkzMjljNTU2IiwidW5pdFR5cGUiOiJyZXF1ZXN0In0", description="Quicknode RPC session request", expires="2026-04-05T21:55:43.291Z"',
    ].join(', '),
  });

  const selected = mpp.selectMppChallenge(mpp.parseMppChallengesFromHeaders(headers), {
    targetUrl: 'https://mpp.quicknode.com/session/tempo-testnet',
  });
  assert.equal(selected.request.methodDetails?.chainId, 42431);
});
