'use client';

import { Badge } from '@worldlibertyfinancial/agent-ui/badge';
import { Button } from '@worldlibertyfinancial/agent-ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@worldlibertyfinancial/agent-ui/card';
import { Input } from '@worldlibertyfinancial/agent-ui/input';
import { Label } from '@worldlibertyfinancial/agent-ui/label';
import { Textarea } from '@worldlibertyfinancial/agent-ui/textarea';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { type FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import {
  APPROVAL_CAPABILITY_QUERY_KEY,
  APPROVAL_CAPABILITY_SYNC_CHANNEL,
  CONSUMED_APPROVAL_CAPABILITY_REASON,
  clearApprovalCapability,
  createApprovalCapabilitySyncMessage,
  INVALID_APPROVAL_CAPABILITY_REASON,
  MISSING_APPROVAL_CAPABILITY_REASON,
  parseApprovalCapabilitySyncMessage,
  persistApprovalCapability,
  resolveApprovalCapability,
  resolveStoredApprovalCapability,
} from '@/lib/approval-capability';
import { clientConfig } from '@/lib/config';
import { encryptApprovalUpdate } from '@/lib/crypto';
import { getApprovalRequest, requestSecureApprovalLink } from '@/lib/relay-client';
import { createSingleFlightGate } from '@/lib/single-flight';
import type { ApprovalRequestRecord, RelayDaemonRecord } from '@/lib/types';

const MAX_OPERATOR_NOTE_CHARS = 500;
const MAX_VAULT_PASSWORD_CHARS = 4096;
const APPROVAL_REFRESH_POLL_ATTEMPTS = 4;
const APPROVAL_REFRESH_POLL_INTERVAL_MS = 1500;

export function ApprovalForm({
  approval,
  daemon,
}: {
  approval: ApprovalRequestRecord;
  daemon: RelayDaemonRecord | null;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialCapability = useMemo(
    () => resolveApprovalCapability(searchParams.getAll(APPROVAL_CAPABILITY_QUERY_KEY)),
    [searchParams],
  );
  const [liveApproval, setLiveApproval] = useState(approval);
  const [approvalCapability, setApprovalCapability] = useState<string | null>(
    initialCapability.value,
  );
  const [approvalCapabilityState, setApprovalCapabilityState] = useState(initialCapability.state);
  const [vaultPassword, setVaultPassword] = useState('');
  const [relayAdminToken, setRelayAdminToken] = useState('');
  const [note, setNote] = useState('');
  const [decision, setDecision] = useState<'approve' | 'reject'>('approve');
  const [confirmedDetails, setConfirmedDetails] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [recoveringCapability, setRecoveringCapability] = useState(false);
  const [refreshingApproval, setRefreshingApproval] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const capabilitySyncChannelRef = useRef<BroadcastChannel | null>(null);
  const submitGateRef = useRef(createSingleFlightGate());
  const recoverGateRef = useRef(createSingleFlightGate());

  const currentApproval = liveApproval;
  const daemonMismatch = Boolean(daemon && daemon.daemonId !== currentApproval.daemonId);
  const noteTooLong = note.length > MAX_OPERATOR_NOTE_CHARS;
  const capabilityReason =
    approvalCapabilityState === 'invalid'
      ? INVALID_APPROVAL_CAPABILITY_REASON
      : approvalCapabilityState === 'consumed'
        ? CONSUMED_APPROVAL_CAPABILITY_REASON
        : MISSING_APPROVAL_CAPABILITY_REASON;

  useEffect(() => {
    setLiveApproval(approval);
  }, [approval]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    if (initialCapability.state === 'loaded' && initialCapability.value) {
      persistApprovalCapability(
        approval.approvalId,
        initialCapability.value,
        window.sessionStorage,
      );
      if (!approvalCapability || approvalCapabilityState !== 'loaded') {
        setApprovalCapability(initialCapability.value);
        setApprovalCapabilityState('loaded');
      }
      return;
    }

    if (initialCapability.state === 'invalid') {
      setApprovalCapabilityState('invalid');
      setApprovalCapability(null);
      return;
    }

    if (!approvalCapability) {
      const storedCapability = resolveStoredApprovalCapability(
        approval.approvalId,
        window.sessionStorage,
      );
      if (storedCapability.state === 'loaded' && storedCapability.value) {
        setApprovalCapability(storedCapability.value);
        setApprovalCapabilityState('loaded');
        return;
      }
    }

    if (approvalCapabilityState === 'consumed') {
      return;
    }

    if (approvalCapabilityState !== 'missing') {
      setApprovalCapabilityState('missing');
    }
  }, [
    approval.approvalId,
    approvalCapability,
    approvalCapabilityState,
    initialCapability.state,
    initialCapability.value,
  ]);

  useEffect(() => {
    if (typeof window === 'undefined' || !window.location.search) {
      return;
    }

    window.history.replaceState(window.history.state, '', `${pathname}${window.location.hash}`);
  }, [pathname]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.BroadcastChannel === 'undefined') {
      capabilitySyncChannelRef.current = null;
      return;
    }

    const channel = new window.BroadcastChannel(APPROVAL_CAPABILITY_SYNC_CHANNEL);
    capabilitySyncChannelRef.current = channel;

    const handleMessage = (event: MessageEvent<unknown>) => {
      const message = parseApprovalCapabilitySyncMessage(event.data);
      if (!message || message.approvalId !== approval.approvalId) {
        return;
      }

      if (message.state === 'consumed') {
        const clearedCapability = clearApprovalCapability(
          approval.approvalId,
          window.sessionStorage,
        );
        setApprovalCapability(clearedCapability.value);
        setApprovalCapabilityState(clearedCapability.state);
        setVaultPassword('');
        setConfirmedDetails(false);
        setError(null);
        setStatus('This secure approval link was already consumed in another tab.');
        return;
      }

      const persistedCapability = persistApprovalCapability(
        approval.approvalId,
        message.capability,
        window.sessionStorage,
      );
      if (persistedCapability.state !== 'loaded' || !persistedCapability.value) {
        return;
      }

      setApprovalCapability(persistedCapability.value);
      setApprovalCapabilityState('loaded');
      setError(null);
      setStatus('A fresh secure approval link was issued in another tab for this approval.');
    };

    channel.addEventListener('message', handleMessage);

    return () => {
      if (capabilitySyncChannelRef.current === channel) {
        capabilitySyncChannelRef.current = null;
      }
      channel.removeEventListener('message', handleMessage);
      channel.close();
    };
  }, [approval.approvalId]);

  const disabledReason = useMemo(() => {
    if (!daemon) {
      return 'The relay has not advertised daemon metadata for this approval yet.';
    }

    if (daemonMismatch) {
      return 'Relay daemon metadata does not match this approval request.';
    }

    if (currentApproval.status !== 'pending') {
      return `This approval is already ${currentApproval.status}. Submit a new request instead of reusing this link.`;
    }

    if (refreshingApproval) {
      return 'Refreshing relay status…';
    }

    if (approvalCapabilityState === 'invalid') {
      return INVALID_APPROVAL_CAPABILITY_REASON;
    }

    if (approvalCapabilityState === 'consumed') {
      return CONSUMED_APPROVAL_CAPABILITY_REASON;
    }

    if (!approvalCapability) {
      return MISSING_APPROVAL_CAPABILITY_REASON;
    }

    if (!confirmedDetails) {
      return 'Confirm the request details before sending the vault password.';
    }

    if (!vaultPassword.trim()) {
      return 'Enter the vault password to create an encrypted relay update.';
    }

    if (noteTooLong) {
      return `Operator note must be ${MAX_OPERATOR_NOTE_CHARS} characters or fewer.`;
    }

    if (submitting) {
      return 'Submitting encrypted update…';
    }

    return null;
  }, [
    approvalCapabilityState,
    approvalCapability,
    confirmedDetails,
    currentApproval.status,
    daemon,
    daemonMismatch,
    noteTooLong,
    refreshingApproval,
    submitting,
    vaultPassword,
  ]);

  const disabled = disabledReason !== null;

  async function refreshApprovalState(
    pollingLabel: 'approve' | 'reject',
  ): Promise<ApprovalRequestRecord | null> {
    setRefreshingApproval(true);

    try {
      let latest: ApprovalRequestRecord | null = null;

      for (let attempt = 0; attempt < APPROVAL_REFRESH_POLL_ATTEMPTS; attempt += 1) {
        if (attempt > 0) {
          await new Promise((resolve) =>
            window.setTimeout(resolve, APPROVAL_REFRESH_POLL_INTERVAL_MS),
          );
        }

        latest = await getApprovalRequest(currentApproval.approvalId);
        setLiveApproval(latest);
        if (latest.status !== 'pending') {
          break;
        }
      }

      router.refresh();

      if (!latest) {
        return null;
      }

      if (latest.status === 'pending') {
        setStatus(
          `Encrypted ${pollingLabel} update submitted to relay. The relay still shows this approval as pending, so the daemon has not applied the update yet.`,
        );
      } else {
        setStatus(
          `Encrypted ${pollingLabel} update submitted to relay. The relay now reports this approval as ${latest.status}.`,
        );
      }

      return latest;
    } finally {
      setRefreshingApproval(false);
    }
  }

  async function submit(): Promise<void> {
    if (!daemon) {
      setError('The relay has not advertised daemon metadata yet.');
      return;
    }

    if (daemonMismatch) {
      setError('Relay daemon metadata does not match this approval request. Do not continue.');
      return;
    }

    if (currentApproval.status !== 'pending') {
      setError(`This approval is already ${currentApproval.status}.`);
      return;
    }

    if (approvalCapabilityState === 'invalid') {
      setError(INVALID_APPROVAL_CAPABILITY_REASON);
      return;
    }

    if (!approvalCapability) {
      setError(MISSING_APPROVAL_CAPABILITY_REASON);
      return;
    }

    if (!confirmedDetails) {
      setError('Confirm the request details before sending the vault password.');
      return;
    }

    if (noteTooLong) {
      setError(`Operator note must be ${MAX_OPERATOR_NOTE_CHARS} characters or fewer.`);
      return;
    }

    if (refreshingApproval || !submitGateRef.current.enter()) {
      return;
    }

    setSubmitting(true);
    setStatus(null);
    setError(null);

    try {
      const envelope = encryptApprovalUpdate(daemon.daemonPublicKey, {
        approvalId: currentApproval.approvalId,
        daemonId: currentApproval.daemonId,
        decision,
        note,
        vaultPassword,
      });

      const response = await fetch(
        `${clientConfig.relayBaseUrl}/v1/approvals/${encodeURIComponent(currentApproval.approvalId)}/updates`,
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            approvalCapability,
            daemonId: currentApproval.daemonId,
            envelope,
          }),
        },
      );

      if (!response.ok) {
        let message = `Relay update submission failed (${response.status} ${response.statusText})`;

        try {
          const payload = (await response.json()) as { error?: string };
          if (payload?.error) {
            message = payload.error;
          }
        } catch {}

        throw new Error(message);
      }

      const clearedCapability = clearApprovalCapability(
        currentApproval.approvalId,
        typeof window === 'undefined' ? null : window.sessionStorage,
      );
      capabilitySyncChannelRef.current?.postMessage(
        createApprovalCapabilitySyncMessage(currentApproval.approvalId, null, 'consumed'),
      );
      setApprovalCapability(clearedCapability.value);
      setApprovalCapabilityState(clearedCapability.state);
      setStatus(`Encrypted ${decision} update submitted to relay. Refreshing relay status…`);
      setNote('');
      setConfirmedDetails(false);
      setLiveApproval((existing) => ({ ...existing, status: 'pending' }));

      try {
        await refreshApprovalState(decision);
      } catch (refreshError) {
        router.refresh();
        setStatus(
          `Encrypted ${decision} update submitted to relay. Automatic status refresh failed: ${
            refreshError instanceof Error ? refreshError.message : String(refreshError)
          }`,
        );
      }
    } catch (submissionError) {
      setError(
        submissionError instanceof Error ? submissionError.message : String(submissionError),
      );
    } finally {
      setVaultPassword('');
      submitGateRef.current.release();
      setSubmitting(false);
    }
  }

  async function recoverCapability(): Promise<void> {
    if (!relayAdminToken.trim()) {
      setError('Enter a relay admin token to recover a secure approval link.');
      return;
    }

    if (!recoverGateRef.current.enter()) {
      return;
    }

    setRecoveringCapability(true);
    setStatus(null);
    setError(null);

    try {
      const recovered = await requestSecureApprovalLink(
        currentApproval.approvalId,
        relayAdminToken,
      );
      const persisted = persistApprovalCapability(
        currentApproval.approvalId,
        recovered.approvalCapability,
        window.sessionStorage,
      );
      if (persisted.state !== 'loaded' || !persisted.value) {
        throw new Error('relay returned an invalid secure approval capability');
      }

      capabilitySyncChannelRef.current?.postMessage(
        createApprovalCapabilitySyncMessage(currentApproval.approvalId, persisted.value, 'loaded'),
      );
      setApprovalCapability(persisted.value);
      setApprovalCapabilityState('loaded');
      setRelayAdminToken('');
      setStatus(
        'Fresh secure approval link issued for this browser session. Older links are now invalid.',
      );
    } catch (recoveryError) {
      setError(recoveryError instanceof Error ? recoveryError.message : String(recoveryError));
    } finally {
      setRelayAdminToken('');
      recoverGateRef.current.release();
      setRecoveringCapability(false);
    }
  }

  function handleRecoverCapabilitySubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    void recoverCapability();
  }

  function handleApprovalSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    void submit();
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Submit encrypted approval update</CardTitle>
        <CardDescription>
          The frontend encrypts the vault password and approval decision with the daemon’s
          advertised X25519 public key.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Badge
            variant={
              approvalCapability
                ? 'success'
                : approvalCapabilityState === 'invalid'
                  ? 'destructive'
                  : approvalCapabilityState === 'consumed'
                    ? 'warning'
                    : 'secondary'
            }
          >
            {approvalCapability
              ? 'Secure link loaded'
              : approvalCapabilityState === 'invalid'
                ? 'Invalid secure link'
                : approvalCapabilityState === 'consumed'
                  ? 'Secure link consumed'
                  : 'View only'}
          </Badge>
          {approvalCapability ? (
            <p className="text-muted-foreground">
              Secure query parameters are scrubbed from the address bar after load.
            </p>
          ) : null}
        </div>

        {!approvalCapability ? (
          <div className="rounded-xl border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
            {capabilityReason}
          </div>
        ) : null}

        {!approvalCapability ? (
          <div className="rounded-xl border border-border/70 bg-background/70 p-4">
            <form className="space-y-4" onSubmit={handleRecoverCapabilitySubmit}>
              <div className="space-y-2">
                <p className="text-sm font-medium">Issue a fresh secure approval link</p>
                <p className="text-sm text-muted-foreground">
                  If you intentionally opened the bare approval route, paste a relay admin token to
                  rotate this approval’s secure capability. Older secure links are invalidated, and
                  the relay admin token is cleared after each request attempt and is not persisted
                  by the page.
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-[1fr,auto]">
                <div className="space-y-2">
                  <Label htmlFor="relay-admin-token">Relay admin token</Label>
                  <Input
                    autoComplete="off"
                    id="relay-admin-token"
                    onChange={(event) => setRelayAdminToken(event.target.value)}
                    placeholder="Paste RELAY_ADMIN_TOKEN"
                    type="password"
                    value={relayAdminToken}
                  />
                </div>
                <div className="flex items-end">
                  <Button
                    disabled={recoveringCapability || !relayAdminToken.trim()}
                    type="submit"
                    variant="outline"
                  >
                    {recoveringCapability ? 'Issuing…' : 'Issue fresh secure link'}
                  </Button>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                Relay target: <code>{clientConfig.relayBaseUrl}</code>
              </p>
            </form>
          </div>
        ) : null}

        <form className="space-y-5" onSubmit={handleApprovalSubmit}>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="decision">Decision</Label>
              <div className="flex gap-2">
                <Button
                  onClick={() => setDecision('approve')}
                  type="button"
                  variant={decision === 'approve' ? 'default' : 'outline'}
                >
                  Approve
                </Button>
                <Button
                  onClick={() => setDecision('reject')}
                  type="button"
                  variant={decision === 'reject' ? 'destructive' : 'outline'}
                >
                  Reject
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="vault-password">Vault password</Label>
              <Input
                autoComplete="current-password"
                id="vault-password"
                maxLength={MAX_VAULT_PASSWORD_CHARS}
                onChange={(event) => setVaultPassword(event.target.value)}
                placeholder="Enter vault password"
                type="password"
                value={vaultPassword}
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="note">Operator note</Label>
            <Textarea
              id="note"
              maxLength={MAX_OPERATOR_NOTE_CHARS}
              onChange={(event) => setNote(event.target.value)}
              placeholder="Optional note for audit and feedback status"
              value={note}
            />
            <p className="text-xs text-muted-foreground">
              {note.length}/{MAX_OPERATOR_NOTE_CHARS} characters
            </p>
          </div>

          <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 text-sm">
            <p className="font-medium text-foreground">Human confirmation required</p>
            <p className="mt-1 text-muted-foreground">
              Verify the destination, amount, and daemon identity before sending the vault password.
              The password is cleared from the page after every submit attempt.
            </p>
            <label className="mt-3 flex items-start gap-3" htmlFor="confirm-details">
              <input
                checked={confirmedDetails}
                className="mt-1 h-4 w-4 rounded border border-input bg-background"
                id="confirm-details"
                onChange={(event) => setConfirmedDetails(event.target.checked)}
                type="checkbox"
              />
              <span>
                I verified this pending request for daemon <code>{currentApproval.daemonId}</code>{' '}
                and want to send an encrypted {decision} decision.
              </span>
            </label>
          </div>

          {status ? <p className="text-sm font-medium text-green-600">{status}</p> : null}
          {error ? <p className="text-sm font-medium text-red-600">{error}</p> : null}
          {disabledReason && !error ? (
            <p className="text-sm text-muted-foreground">{disabledReason}</p>
          ) : null}

          <Button disabled={disabled} type="submit">
            {submitting ? 'Submitting…' : 'Send encrypted update'}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
