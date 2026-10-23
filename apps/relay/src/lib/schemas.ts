import { z } from 'zod';

const PUBLIC_APPROVAL_UPDATE_MAX_CIPHERTEXT_BYTES = 16 * 1024;

/** Relay manual-approval envelope algorithm; must match the daemon and web console. */
export const RELAY_ENVELOPE_ALGORITHM = 'x25519-hkdf-xchacha20poly1305-v2';

const hexEncodedBytesSchema = (
  field: string,
  options: {
    exactBytes?: number;
    maxBytes?: number;
    minBytes?: number;
  } = {},
) =>
  z
    .string()
    .trim()
    .min(1)
    .superRefine((value, ctx) => {
      const normalized = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;

      if (!/^[0-9a-fA-F]+$/u.test(normalized)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${field} must be hex encoded`,
        });
        return;
      }

      if (normalized.length % 2 !== 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${field} must contain an even number of hex characters`,
        });
        return;
      }

      const byteLength = normalized.length / 2;

      if (options.exactBytes !== undefined && byteLength !== options.exactBytes) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${field} must be exactly ${options.exactBytes} bytes`,
        });
      }

      if (options.minBytes !== undefined && byteLength < options.minBytes) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${field} must be at least ${options.minBytes} bytes`,
        });
      }

      if (options.maxBytes !== undefined && byteLength > options.maxBytes) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${field} must be at most ${options.maxBytes} bytes`,
        });
      }
    });

export const daemonIdSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{64}$/u, 'daemonId must be 32 random bytes encoded as hex');
export const x25519PublicKeySchema = z
  .string()
  .regex(/^[0-9a-fA-F]{64}$/u, 'daemonPublicKey must be 32-byte hex');
export const addressSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/u, 'ethereumAddress must be a checksummed or lowercase EVM address');
export const isoTimestampSchema = z.string().datetime({ offset: true });
export const approvalStatusSchema = z.enum([
  'pending',
  'approved',
  'rejected',
  'completed',
  'expired',
]);
export const updateStatusSchema = z.enum(['pending', 'inflight', 'applied', 'rejected', 'failed']);

export const encryptedPayloadSchema = z.object({
  aadBase64: z.string().min(1).optional(),
  algorithm: z.literal(RELAY_ENVELOPE_ALGORITHM).default(RELAY_ENVELOPE_ALGORITHM),
  ciphertextBase64: z.string().trim().min(1),
  contentSha256Hex: z
    .string()
    .regex(/^[a-fA-F0-9]{64}$/u)
    .optional(),
  encapsulatedKeyBase64: z.string().trim().min(1),
  nonceBase64: z.string().trim().min(1),
  schemaVersion: z.number().int().min(1).default(1),
});

export const relayPolicyRecordSchema = z.object({
  action: z.string().trim().min(1),
  amountMaxWei: z.string().trim().min(1).optional(),
  amountMinWei: z.string().trim().min(1).optional(),
  maxTxCount: z.string().trim().min(1).optional(),
  maxFeePerGasWei: z.string().trim().min(1).optional(),
  maxPriorityFeePerGasWei: z.string().trim().min(1).optional(),
  maxCalldataBytes: z.string().trim().min(1).optional(),
  maxGasSpendWei: z.string().trim().min(1).optional(),
  chainId: z.number().int().positive().optional(),
  daemonId: daemonIdSchema.optional(),
  destination: addressSchema,
  metadata: z.record(z.string(), z.string()).optional(),
  policyId: z.string().uuid(),
  requiresManualApproval: z.boolean(),
  scope: z.enum(['default', 'override']),
  tokenAddress: addressSchema.optional(),
  updatedAt: isoTimestampSchema,
});

export const relayAgentKeyRecordSchema = z.object({
  agentKeyId: z.string().uuid(),
  createdAt: isoTimestampSchema.optional(),
  daemonId: daemonIdSchema.optional(),
  label: z.string().trim().min(1).optional(),
  metadata: z.record(z.string(), z.string()).optional(),
  status: z.enum(['active', 'revoked']),
  updatedAt: isoTimestampSchema,
});

export const relayApprovalRequestRecordSchema = z.object({
  agentKeyId: z.string().uuid().optional(),
  amountWei: z.string().trim().min(1).optional(),
  approvalRequestId: z.string().uuid(),
  chainId: z.number().int().positive().optional(),
  daemonId: daemonIdSchema.optional(),
  destination: addressSchema,
  metadata: z.record(z.string(), z.string()).optional(),
  network: z.string().trim().min(1).optional(),
  reason: z.string().trim().min(1).optional(),
  requestedAt: isoTimestampSchema,
  status: approvalStatusSchema,
  tokenAddress: addressSchema.optional(),
  transactionType: z.string().trim().min(1),
  updatedAt: isoTimestampSchema,
});

export const relayDaemonProfileSchema = z.object({
  daemonId: daemonIdSchema,
  daemonPublicKey: x25519PublicKeySchema,
  ethereumAddress: addressSchema,
  label: z.string().trim().min(1).optional(),
  lastSeenAt: isoTimestampSchema,
  registeredAt: isoTimestampSchema,
  relayUrl: z.string().url().optional(),
  signerBackend: z.string().trim().min(1).optional(),
  status: z.enum(['active', 'paused']).default('active'),
  updatedAt: isoTimestampSchema,
  version: z.string().trim().min(1).optional(),
});

export const daemonRegisterInputSchema = z.object({
  agentKeys: z.array(relayAgentKeyRecordSchema).default([]),
  approvalRequests: z.array(relayApprovalRequestRecordSchema).default([]),
  daemon: relayDaemonProfileSchema,
  policies: z.array(relayPolicyRecordSchema).default([]),
});

export const rekeyDaemonInputSchema = z.object({
  daemonId: daemonIdSchema,
  daemonPublicKey: x25519PublicKeySchema,
});

export const listApprovalRequestsInputSchema = z.object({
  daemonId: daemonIdSchema.optional(),
  destination: addressSchema.optional(),
  limit: z.number().int().min(1).max(500).optional(),
  status: approvalStatusSchema.optional(),
  tokenAddress: addressSchema.optional(),
});

export const submitEncryptedUpdateInputSchema = z
  .object({
    daemonId: daemonIdSchema,
    metadata: z.record(z.string(), z.string()).optional(),
    payload: encryptedPayloadSchema,
    targetApprovalRequestId: z.string().uuid().optional(),
    type: z.string().trim().min(1),
    updateId: z.string().uuid().optional(),
  })
  .superRefine((input, ctx) => {
    if (input.type === 'manual_approval_decision' && !input.targetApprovalRequestId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'targetApprovalRequestId is required for manual_approval_decision updates',
        path: ['targetApprovalRequestId'],
      });
    }
  });

export const submitPublicApprovalUpdateInputSchema = z.object({
  approvalCapability: z
    .string()
    .regex(/^[a-fA-F0-9]{64}$/u, 'approvalCapability must be a 32-byte hex token'),
  daemonId: daemonIdSchema,
  envelope: z.object({
    algorithm: z.literal(RELAY_ENVELOPE_ALGORITHM).default(RELAY_ENVELOPE_ALGORITHM),
    ciphertext: hexEncodedBytesSchema('ciphertext', {
      minBytes: 1,
      maxBytes: PUBLIC_APPROVAL_UPDATE_MAX_CIPHERTEXT_BYTES,
    }),
    ephemeralPublicKey: hexEncodedBytesSchema('ephemeralPublicKey', { exactBytes: 32 }),
    nonce: hexEncodedBytesSchema('nonce', { exactBytes: 24 }),
  }),
});

export const pollUpdatesInputSchema = z.object({
  daemonId: daemonIdSchema,
  leaseSeconds: z.number().int().min(5).max(300).optional(),
  limit: z.number().int().min(1).max(100).optional(),
});

export const submitFeedbackInputSchema = z.object({
  claimToken: z.string().uuid(),
  daemonId: daemonIdSchema,
  details: z.record(z.string(), z.string()).optional(),
  message: z.string().trim().min(1).optional(),
  status: z.enum(['applied', 'failed', 'rejected']),
  updateId: z.string().uuid(),
});
