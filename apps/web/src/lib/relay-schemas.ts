import { z } from 'zod';

const daemonIdSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{64}$/u, 'daemonId must be 32 random bytes encoded as hex');
const x25519PublicKeySchema = z
  .string()
  .regex(/^[0-9a-fA-F]{64}$/u, 'daemonPublicKey must be 32-byte hex');
const approvalIdSchema = z.string().uuid();
const agentKeyIdSchema = z.union([z.string().uuid(), z.literal('unknown')]);
const evmAddressSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/u, 'address must be a valid EVM address');
const solanaAddressSchema = z
  .string()
  .regex(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/u, 'address must be a valid Solana public key');
const addressSchema = z.union([evmAddressSchema, solanaAddressSchema]);
const approvalStatusSchema = z.enum([
  'pending',
  'approved',
  'rejected',
  'completed',
  'expired',
  'failed',
]);
const assetSchema = z
  .string()
  .regex(
    /^(native_eth|erc20:0x[a-fA-F0-9]{40}|spl:[1-9A-HJ-NP-Za-km-z]{32,44})$/u,
    'asset must be native_eth, erc20:<address>, or spl:<mint>',
  );
const isoTimestampSchema = z.string().datetime({ offset: true });

export const approvalRequestRecordSchema = z.object({
  approvalId: approvalIdSchema,
  daemonId: daemonIdSchema,
  agentKeyId: agentKeyIdSchema,
  status: approvalStatusSchema,
  reason: z.string(),
  actionType: z.string().trim().min(1),
  chainId: z.number().int().min(0),
  recipient: addressSchema,
  asset: assetSchema,
  amountWei: z.string().regex(/^\d+$/u, 'amountWei must be a decimal string'),
  createdAt: isoTimestampSchema,
  updatedAt: isoTimestampSchema,
});

export const approvalRequestListSchema = z.array(approvalRequestRecordSchema);

export const relayDaemonRecordSchema = z.object({
  daemonId: daemonIdSchema,
  daemonPublicKey: x25519PublicKeySchema,
  vaultEthereumAddress: evmAddressSchema,
  relayBaseUrl: z.string().url().nullable().optional(),
  updatedAt: isoTimestampSchema,
});

export const secureApprovalLinkRecordSchema = z.object({
  approvalCapability: z.string().regex(/^[a-fA-F0-9]{64}$/u),
  approvalId: approvalIdSchema,
  approvalUrl: z.string().url(),
  daemonId: daemonIdSchema,
});
