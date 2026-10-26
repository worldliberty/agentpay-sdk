import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type * as React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApprovalRequestRecord, RelayDaemonRecord } from '../src/lib/types';

const {
  routerRefreshMock,
  encryptApprovalUpdateMock,
  getApprovalRequestMock,
  requestSecureApprovalLinkMock,
} = vi.hoisted(() => ({
  routerRefreshMock: vi.fn(),
  encryptApprovalUpdateMock: vi.fn(),
  getApprovalRequestMock: vi.fn(),
  requestSecureApprovalLinkMock: vi.fn(),
}));

vi.mock('next/navigation', () => ({
  usePathname: () => '/approvals/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  useRouter: () => ({ refresh: routerRefreshMock }),
}));

vi.mock('@worldlibertyfinancial/agent-ui/badge', () => ({
  Badge: ({ children, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
    <div {...props}>{children}</div>
  ),
}));

vi.mock('@worldlibertyfinancial/agent-ui/button', () => ({
  Button: ({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button {...props}>{children}</button>
  ),
}));

vi.mock('@worldlibertyfinancial/agent-ui/card', () => ({
  Card: ({ children, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
    <div {...props}>{children}</div>
  ),
  CardContent: ({ children, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
    <div {...props}>{children}</div>
  ),
  CardDescription: ({ children, ...props }: React.HTMLAttributes<HTMLParagraphElement>) => (
    <p {...props}>{children}</p>
  ),
  CardHeader: ({ children, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
    <div {...props}>{children}</div>
  ),
  CardTitle: ({ children, ...props }: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h2 {...props}>{children}</h2>
  ),
}));

vi.mock('@worldlibertyfinancial/agent-ui/input', () => ({
  Input: (props: React.InputHTMLAttributes<HTMLInputElement>) => <input {...props} />,
}));

vi.mock('@worldlibertyfinancial/agent-ui/label', () => ({
  Label: ({ children, htmlFor, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) => (
    <label htmlFor={htmlFor} {...props}>
      {children}
    </label>
  ),
}));

vi.mock('@worldlibertyfinancial/agent-ui/textarea', () => ({
  Textarea: (props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) => <textarea {...props} />,
}));

vi.mock('@/lib/crypto', () => ({
  encryptApprovalUpdate: encryptApprovalUpdateMock,
}));

vi.mock('@/lib/relay-client', () => ({
  getApprovalRequest: getApprovalRequestMock,
  requestSecureApprovalLink: requestSecureApprovalLinkMock,
}));

import { ApprovalForm } from '../src/app/approvals/[approvalId]/approval-form';

class MockBroadcastChannel {
  addEventListener(): void {}
  removeEventListener(): void {}
  close(): void {}
  postMessage(): void {}
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((innerResolve, innerReject) => {
    resolve = innerResolve;
    reject = innerReject;
  });

  return { promise, reject, resolve };
}

function buildApproval(overrides: Partial<ApprovalRequestRecord> = {}): ApprovalRequestRecord {
  return {
    approvalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    daemonId: '11'.repeat(32),
    agentKeyId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    status: 'pending',
    reason: 'Manual approval required',
    actionType: 'transfer',
    chainId: 1,
    recipient: '0x3333333333333333333333333333333333333333',
    asset: 'native_eth',
    amountWei: '42',
    createdAt: '2026-03-11T00:00:00.000Z',
    updatedAt: '2026-03-11T00:00:00.000Z',
    ...overrides,
  };
}

const approvalPath = '/approvals/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

function openSecureLink(
  capability: string,
  overrides: { daemonId?: string; daemonKey?: string } = {},
): void {
  const fragment = new URLSearchParams({
    approvalCapability: capability,
    daemonId: overrides.daemonId ?? '11'.repeat(32),
    daemonKey: overrides.daemonKey ?? '22'.repeat(32),
  });
  window.history.pushState({}, '', `${approvalPath}#${fragment.toString()}`);
}

async function fillAndSubmitApproval(): Promise<void> {
  fireEvent.change(screen.getByLabelText('Vault password'), {
    target: { value: 'vault-password' },
  });
  fireEvent.click(screen.getByLabelText(/I verified this pending request/i));
  const submitForm = screen.getByRole('button', { name: 'Send encrypted update' }).closest('form');
  if (!submitForm) {
    throw new Error('approval form is missing');
  }
  fireEvent.submit(submitForm);
}

function buildDaemon(overrides: Partial<RelayDaemonRecord> = {}): RelayDaemonRecord {
  return {
    daemonId: '11'.repeat(32),
    daemonPublicKey: '22'.repeat(32),
    vaultEthereumAddress: '0x4444444444444444444444444444444444444444',
    relayBaseUrl: 'http://localhost:8787',
    updatedAt: '2026-03-11T00:00:00.000Z',
    ...overrides,
  };
}

describe('ApprovalForm duplicate submit guards', () => {
  beforeEach(() => {
    routerRefreshMock.mockReset();
    encryptApprovalUpdateMock.mockReset().mockReturnValue({
      algorithm: 'x25519-hkdf-xchacha20poly1305-v2',
      ephemeralPublicKey: '33'.repeat(32),
      nonce: '44'.repeat(24),
      ciphertext: '55',
    });
    getApprovalRequestMock.mockReset().mockResolvedValue(buildApproval({ status: 'approved' }));
    requestSecureApprovalLinkMock.mockReset();
    sessionStorage.clear();
    window.history.pushState({}, '', '/');
    vi.stubGlobal('BroadcastChannel', MockBroadcastChannel);
    Object.defineProperty(window, 'BroadcastChannel', {
      configurable: true,
      value: MockBroadcastChannel,
      writable: true,
    });
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('only submits one encrypted approval update while the first submit is still in flight', async () => {
    openSecureLink('aa'.repeat(32));
    const submission = deferred<Response>();
    const fetchMock = vi.fn(() => submission.promise);
    vi.stubGlobal('fetch', fetchMock);

    render(<ApprovalForm approval={buildApproval()} daemon={buildDaemon()} />);

    fireEvent.change(screen.getByLabelText('Vault password'), {
      target: { value: 'vault-password' },
    });
    fireEvent.click(screen.getByLabelText(/I verified this pending request/i));

    const submitForm = screen
      .getByRole('button', { name: 'Send encrypted update' })
      .closest('form');
    expect(submitForm).not.toBeNull();

    fireEvent.submit(submitForm!);
    fireEvent.submit(submitForm!);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(encryptApprovalUpdateMock).toHaveBeenCalledWith('22'.repeat(32), expect.anything());

    submission.resolve(new Response(null, { status: 200 }));

    await waitFor(() => {
      expect(getApprovalRequestMock).toHaveBeenCalledTimes(1);
    });
  });

  it('only issues one fresh secure link while the first recovery request is still in flight', async () => {
    const recovery = deferred<{
      approvalCapability: string;
      approvalId: string;
      approvalUrl: string;
      daemonId: string;
      daemonPublicKey: string;
    }>();
    requestSecureApprovalLinkMock.mockImplementation(() => recovery.promise);
    vi.stubGlobal('fetch', vi.fn());

    render(<ApprovalForm approval={buildApproval()} daemon={buildDaemon()} />);

    fireEvent.change(screen.getByLabelText('Relay admin token'), {
      target: { value: 'relay-admin-token-1234567890abcd' },
    });

    const recoveryForm = screen
      .getByRole('button', { name: 'Issue fresh secure link' })
      .closest('form');
    expect(recoveryForm).not.toBeNull();

    fireEvent.submit(recoveryForm!);
    fireEvent.submit(recoveryForm!);

    expect(requestSecureApprovalLinkMock).toHaveBeenCalledTimes(1);

    recovery.resolve({
      approvalCapability: 'bb'.repeat(32),
      approvalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      approvalUrl:
        'https://relay.example/approvals/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa#approvalCapability=bb',
      daemonId: '11'.repeat(32),
      daemonPublicKey: '22'.repeat(32),
    });

    await waitFor(() => {
      expect(
        screen.getByText(
          'Fresh secure approval link issued for this browser session. Older links are now invalid.',
        ),
      ).toBeTruthy();
    });
  });

  it('reads the secure link from the URL fragment and scrubs it from the address bar', async () => {
    openSecureLink('aa'.repeat(32));
    vi.stubGlobal('fetch', vi.fn());

    render(<ApprovalForm approval={buildApproval()} daemon={buildDaemon()} />);

    await waitFor(() => {
      expect(screen.getByText('Secure link loaded')).toBeTruthy();
    });
    expect(window.location.hash).toBe('');
    expect(window.location.pathname).toBe(approvalPath);
  });

  it('refuses to encrypt when the relay advertises a different daemon key than the link', async () => {
    openSecureLink('aa'.repeat(32), { daemonKey: '99'.repeat(32) });
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    render(<ApprovalForm approval={buildApproval()} daemon={buildDaemon()} />);
    await fillAndSubmitApproval();

    expect(screen.getByText(/relay advertises a different daemon encryption key/i)).toBeTruthy();
    expect(encryptApprovalUpdateMock).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(
      (screen.getByRole('button', { name: 'Send encrypted update' }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('treats a link that names another daemon as invalid', async () => {
    openSecureLink('aa'.repeat(32), { daemonId: '33'.repeat(32) });
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    render(<ApprovalForm approval={buildApproval()} daemon={buildDaemon()} />);
    await fillAndSubmitApproval();

    expect(screen.getByText('Invalid secure link')).toBeTruthy();
    expect(encryptApprovalUpdateMock).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('ignores legacy query-string capabilities that carry no daemon key', async () => {
    window.history.pushState({}, '', `${approvalPath}?approvalCapability=${'aa'.repeat(32)}`);
    vi.stubGlobal('fetch', vi.fn());

    render(<ApprovalForm approval={buildApproval()} daemon={buildDaemon()} />);

    await waitFor(() => {
      expect(window.location.search).toBe('');
    });
    expect(screen.getByText('View only')).toBeTruthy();
  });

  it('rejects an admin-issued secure link whose daemon key differs from the relay record', async () => {
    requestSecureApprovalLinkMock.mockResolvedValue({
      approvalCapability: 'bb'.repeat(32),
      approvalId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      approvalUrl: 'https://relay.example/approvals/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      daemonId: '11'.repeat(32),
      daemonPublicKey: '99'.repeat(32),
    });
    vi.stubGlobal('fetch', vi.fn());

    render(<ApprovalForm approval={buildApproval()} daemon={buildDaemon()} />);
    fireEvent.change(screen.getByLabelText('Relay admin token'), {
      target: { value: 'relay-admin-token-1234567890abcd' },
    });
    const recoveryForm = screen
      .getByRole('button', { name: 'Issue fresh secure link' })
      .closest('form');
    if (!recoveryForm) {
      throw new Error('recovery form is missing');
    }
    fireEvent.submit(recoveryForm);

    await waitFor(() => {
      expect(screen.getByText(/relay advertises a different daemon encryption key/i)).toBeTruthy();
    });
    expect(screen.getByText('View only')).toBeTruthy();
  });
});
