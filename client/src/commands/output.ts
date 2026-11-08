/**
 * Command output. With `--json`, stdout carries exactly one JSON document (results, pending
 * approvals, and errors alike) so agents can parse it; without it, short text for people.
 */
import type { Io } from '../app/context.js';
import { copy } from '../copy/index.js';
import { AgentPayError, EXIT, guidanceFor, pendingApprovalId } from '../errors.js';
import type { ManualApprovalPendingResult } from '../generated/index.js';

export function printJson(io: Io, value: unknown): void {
  io.stdout(`${JSON.stringify(value, null, 2)}\n`);
}

export function printLines(io: Io, lines: readonly string[]): void {
  if (lines.length > 0) {
    io.stdout(`${lines.join('\n')}\n`);
  }
}

/** Prints `value` as JSON, or `text()` for people. */
export function emit(
  io: Io,
  json: boolean | undefined,
  value: unknown,
  text: () => readonly string[],
): void {
  if (json) {
    printJson(io, value);
  } else {
    printLines(io, text());
  }
}

/** A payment held for an operator: printed as a result, exit code 3. */
export function emitPending(
  io: Io,
  json: boolean | undefined,
  pending: ManualApprovalPendingResult,
  resumable: boolean,
): number {
  const p = copy.commands.pending;
  const next = resumable ? p.resume(pending.approval_request_id) : p.resend;
  emit(
    io,
    json,
    {
      status: 'manual_approval_pending',
      ...pending,
      next_action: `${p.approve(pending.approval_request_id)}. ${next}`,
    },
    () => [
      p.title,
      p.detail(pending.approval_request_id),
      p.approve(pending.approval_request_id),
      next,
    ],
  );
  return EXIT.pendingApproval;
}

/** Prints an error with its next action; returns the exit code. */
export function reportError(io: Io, json: boolean | undefined, error: unknown): number {
  const guidance = guidanceFor(error);
  const code = error instanceof AgentPayError ? error.code : 'unexpected';
  const exitCode = error instanceof AgentPayError ? error.exitCode : EXIT.failure;
  const approvalRequestId = pendingApprovalId(error);
  if (json) {
    printJson(io, {
      error: {
        code,
        message: guidance.message,
        next_action: guidance.next,
        ...(approvalRequestId ? { approval_request_id: approvalRequestId } : {}),
        ...(error instanceof AgentPayError && 'wire' in error ? { detail: error.wire } : {}),
      },
    });
  } else {
    io.stderr(`Error: ${guidance.message}\n${copy.common.next}: ${guidance.next}\n`);
  }
  return exitCode;
}
