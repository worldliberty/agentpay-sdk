/** Error messages and the one next action each error suggests. */
import { onboarding } from './onboarding.js';

/** How to keep one of several wallets: the wizard's “keep” choice leads to the wallet picker. */
const chooseWallet = `Run \`agentpay setup\` again and choose “${onboarding.welcome.reuse}” to pick the wallet to keep; nothing is deleted.`;

/** How to name the wallet a command acts on when there are several. */
const nameWallet = 'Run the command again with `--wallet <vault-key-id|address>`.';

export const errors = {
  approvalGone: {
    message: 'That approval request is no longer waiting.',
    next: 'Open Activity to see what happened to the payment.',
  },
  notInstalled: {
    message: 'AgentPay is not installed on this machine.',
    next: 'Run `agentpay setup`.',
  },
  notSetUp: {
    message: 'No agent credentials were found for this user.',
    next: 'Run `agentpay setup`, or import credentials with `agentpay config agent-auth set --agent-key-id <uuid> --agent-auth-token-stdin`.',
  },
  tokenMissing: (agentKeyId: string, store: string) => ({
    message: `No agent auth token for agent ${agentKeyId} in ${store}.`,
    next: `Import it with \`agentpay config agent-auth set --agent-key-id ${agentKeyId} --agent-auth-token-stdin\`.`,
  }),
  socketMissing: (service: string, path: string) => ({
    message: `The ${service} is not running (no socket at ${path}).`,
    next: 'Check the services with `sudo agentpay-setup status`.',
  }),
  socketUntrusted: (service: string, reason: string) => ({
    message: `Refusing to talk to the ${service}: ${reason}.`,
    next: 'Reinstall the services with `agentpay setup`.',
  }),
  connectFailed: (service: string, reason: string) => ({
    message: `Could not connect to the ${service}: ${reason}.`,
    next: 'Check the services with `sudo agentpay-setup status`.',
  }),
  rejectedByTransport: (service: string) => ({
    message: `The ${service} closed the connection without answering. This user may not be allowed to use it, or the request was malformed.`,
    next: 'Check the services with `sudo agentpay-setup status`.',
  }),
  timeout: (service: string, seconds: number) => ({
    message: `The ${service} did not answer within ${seconds} s.`,
    next: 'Try again; if it keeps happening, check `sudo agentpay-setup status`.',
  }),
  frameTooLarge: {
    message: 'The message is larger than the 256 KiB the services accept.',
    next: 'Send a smaller request body.',
  },
  malformedResponse: (service: string) => ({
    message: `The ${service} sent a response this client cannot read.`,
    next: 'Update AgentPay so the client and services match: `agentpay setup`.',
  }),
  incompatible: (service: string, theirs: string, ours: string) => ({
    message: `The ${service} speaks API ${theirs}, but this client speaks API ${ours}.`,
    next: 'Update AgentPay so the client and services match: `agentpay setup`.',
  }),
  unexpectedResponse: (service: string, method: string, type: string) => ({
    message: `The ${service} answered ${method} with an unexpected ${type} response.`,
    next: 'Update AgentPay so the client and services match: `agentpay setup`.',
  }),
  sudoRequired: (command: string) => ({
    message: 'This needs administrator approval, and Touch ID is not set up for this user.',
    next: `Run it again with sudo: \`sudo ${command}\`.`,
  }),
  touchIdCancelled: {
    message: 'Touch ID was cancelled, so nothing was changed.',
    next: 'Run the command again and confirm with Touch ID or your Mac password.',
  },
  touchIdNoGui: (command: string) => ({
    message: 'Touch ID needs the Mac’s screen; this session cannot show the prompt (SSH?).',
    next: `Run it with sudo instead: \`sudo ${command}\`.`,
  }),
  touchIdFailed: (detail: string) => ({
    message: `Touch ID could not approve this: ${detail}.`,
    next: 'Re-enable Touch ID with `agentpay admin touch-id enable`, or use sudo.',
  }),
  touchIdKeyInvalid: {
    message:
      'The Touch ID key on this Mac no longer works (fingerprints changed or the key was removed).',
    next: 'Re-enable it with `agentpay admin touch-id disable` then `agentpay admin touch-id enable`.',
  },
  touchIdUnavailable: {
    message: 'Touch ID is not available: this Mac has no Secure Enclave or the helper is missing.',
    next: 'Use sudo for admin actions.',
  },
  helperMissing: (path: string) => ({
    message: `The Touch ID helper was not found at ${path}.`,
    next: 'Reinstall AgentPay with `agentpay setup`.',
  }),
  adminLocked: {
    message: 'Touch ID approvals are locked for 30 seconds after several failed attempts.',
    next: 'Wait 30 seconds and try again.',
  },
  leaseExpired: {
    message: 'The administrator session expired.',
    next: 'Run the command again.',
  },
  approvalNotPending: (id: string, status: string) => ({
    message: `Approval request ${id} is already ${status}.`,
    next: 'List open requests with `agentpay admin approvals`.',
  }),
  approvalUnknown: (id: string) => ({
    message: `There is no approval request ${id}.`,
    next: 'List open requests with `agentpay admin approvals`.',
  }),
  policyDenied: (detail: string) => ({
    message: `Your spending limits do not allow this: ${detail}.`,
    next: 'Review the limits with `agentpay admin limits`.',
  }),
  noSpendingPolicy: {
    message: 'This agent has no spending limits yet, so every payment is blocked.',
    next: 'Set limits with `agentpay admin limits`.',
  },
  noLimitForAsset: {
    message:
      'None of this agent’s spending limits covers this token on this network, so the payment is blocked.',
    next: 'Set a limit for it with `agentpay admin limits`.',
  },
  approvalRejected: (id: string) => ({
    message: `The request was rejected by an administrator (approval ${id}).`,
    next: 'Ask the wallet owner why, or send a smaller amount.',
  }),
  agentAuthFailed: {
    message:
      'AgentPay no longer accepts this agent’s credentials: they were revoked or rotated, or AgentPay was reinstalled without its previous state.',
    next: 'Run `agentpay setup` to get new credentials (it keeps, restores, or creates a wallet).',
  },
  signerUnavailable: (detail: string) => ({
    message: `The payments service cannot reach the signer daemon: ${detail}.`,
    next: 'Check the services with `sudo agentpay-setup status`.',
  }),
  chainRpc: (detail: string) => ({
    message: `The network did not answer as expected: ${detail}.`,
    next: 'Try again, or change the RPC URL with `agentpay config set chains.<network>.rpc_url <url>`.',
  }),
  invalidRequest: (detail: string) => ({
    message: detail,
    next: 'Fix the request and try again; nothing was signed.',
  }),
  merchant: (detail: string) => ({
    message: `The paid endpoint could not be used: ${detail}.`,
    next: 'Check the URL and try again.',
  }),
  mismatch: (detail: string) => ({
    message: `The signed transaction did not match the request, so it was not sent: ${detail}.`,
    next: 'Report this to the AgentPay maintainers.',
  }),
  persistence: (detail: string) => ({
    message: `Saving failed and nothing changed: ${detail}.`,
    next: 'Check free disk space, then try again.',
  }),
  invalidConfig: (detail: string) => ({
    message: `The configuration is invalid and was not saved: ${detail}.`,
    next: 'Fix the value and try again; see `agentpay config show`.',
  }),
  unknownPendingApproval: (id: string) => ({
    message: `No paused payment ${id} belongs to this agent.`,
    next: 'Check the id, or send the payment again.',
  }),
  generic: (kind: string, detail: string) => ({
    message: detail ? `${kind}: ${detail}` : kind,
    next: 'Try again; if it keeps happening, run `agentpay status`.',
  }),
  usage: (detail: string) => ({
    message: detail,
    next: 'See `agentpay --help`.',
  }),
  notInteractive: (command: string) => ({
    message: 'This screen needs an interactive terminal.',
    next: `Run \`${command}\` in a terminal, or add --json.`,
  }),
  unsupportedPlatform: {
    message: 'AgentPay supports macOS and Linux only.',
    next: 'Use a Mac or a Linux machine.',
  },
  rootClient: {
    message: 'Agent commands must run as your own user, not root.',
    next: 'Run the command again without sudo.',
  },
  privilegedOnly: {
    message: 'This command must run as root.',
    next: 'It is used internally by `agentpay setup`; you do not need to run it.',
  },
  alertsFailed: (detail: string) => ({
    message: `Approval alerts could not start: ${detail}.`,
    next: 'On Linux, log in to a desktop session, or run `loginctl enable-linger $USER`, then turn alerts on again in Security.',
  }),
  noUserSession: 'this login has no systemd user session',
  sudoCancelled: {
    message: 'Cancelled; nothing was changed.',
    next: 'Try again when you are ready to enter your password.',
  },
  sudoWrongPassword: {
    message: 'sudo did not accept the password.',
    next: 'Try again with your login password, and make sure your account can use sudo.',
  },
  sudoFailed: (detail: string) => ({
    message: `sudo failed: ${detail}.`,
    next: 'Make sure your account can use sudo, then try again.',
  }),
  setupFailed: {
    message: 'Installing the AgentPay services failed.',
    next: 'Fix the problem shown above, then run `agentpay setup` again.',
  },
  backupPassphraseShort: (min: number) => `Use at least ${min} characters.`,
  backupPassphraseMismatch: 'The passphrases do not match.',
  fileExists: (path: string) => ({
    message: `${path} already exists.`,
    next: 'Choose another file name.',
  }),
  walletExists: (count: number) => ({
    message:
      count > 1
        ? `${count} wallets already exist on this machine, so nothing was changed.`
        : 'A wallet already exists on this machine, so nothing was changed.',
    next:
      count > 1
        ? chooseWallet
        : `Run \`agentpay setup\` again and choose “${onboarding.welcome.reuse}”.`,
  }),
  walletChoiceNeeded: (count: number, listing: readonly string[]) => ({
    message: [`This machine has ${count} wallets, so the command must name one:`, ...listing].join(
      '\n',
    ),
    next: nameWallet,
  }),
  walletUnknown: (selector: string, listing: readonly string[]) => ({
    message: [`No wallet on this machine is ${selector}. The wallets are:`, ...listing].join('\n'),
    next: nameWallet,
  }),
  walletMissing: {
    message: 'There is no wallet on this machine yet.',
    next: 'Run `agentpay setup` to create or restore one.',
  },
  walletRequestInvalid: (detail: string) => ({
    message: `The signer daemon refused the wallet request: ${detail}.`,
    next: chooseWallet,
  }),
  limitsInvalid: (detail: string) => ({
    message: `These spending limits were not saved: ${detail}.`,
    next: 'Adjust the limits in `agentpay admin limits` and save again.',
  }),
  signedTransactionUnknown: (hash: string) => ({
    message: `The nonce of transaction ${hash} cannot be released: it was already released, signed more than 10 minutes ago, or not signed for this agent.`,
    next: 'Check on a block explorer whether the transaction reached the network before sending the payment again.',
  }),
  backupInvalid: (detail: string) => ({
    message: `This is not a usable AgentPay wallet backup: ${detail}.`,
    next: 'Check the file path and try again.',
  }),
  backupDecryption: {
    message: 'The passphrase does not open this backup, or the file was changed.',
    next: 'Check the passphrase and try again.',
  },
  backupWeak: (min: number) => ({
    message: 'The backup passphrase is too short.',
    next: `Use at least ${min} characters.`,
  }),
} as const;
