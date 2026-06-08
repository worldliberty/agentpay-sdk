#!/usr/bin/env node

import { QrCode } from './vendor/qrcodegen.mjs';

function usage() {
  console.error(
    [
      'Usage:',
      '  node scripts/prepare-funding-request.mjs --address <0x...> --chain-id <id> [options]',
      '',
      'Options:',
      '  --address <0x...>        Wallet address that should receive funds',
      '  --chain-id <id>          Numeric EVM chain id',
      '  --network-name <name>    Optional display name such as bsc or sepolia',
      '  --amount-wei <wei>       Optional suggested native top-up amount in wei',
      '  --token-symbol <symbol>  Optional symbol such as BNB or ETH',
      '  --json                   Print JSON instead of text',
    ].join('\n'),
  );
}

function parseArgs(argv) {
  const options = { json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    switch (current) {
      case '--address':
        options.address = argv[++index];
        break;
      case '--chain-id':
        options.chainId = argv[++index];
        break;
      case '--network-name':
        options.networkName = argv[++index];
        break;
      case '--amount-wei':
        options.amountWei = argv[++index];
        break;
      case '--token-symbol':
        options.tokenSymbol = argv[++index];
        break;
      case '--json':
        options.json = true;
        break;
      case '--help':
      case '-h':
        usage();
        process.exit(0);
      default:
        throw new Error(`unknown argument: ${current}`);
    }
  }
  return options;
}

function required(value, label) {
  if (!value?.trim()) {
    throw new Error(`${label} is required`);
  }
  return value.trim();
}

function normalizeAddress(value) {
  const normalized = required(value, 'address');
  if (!/^0x[a-fA-F0-9]{40}$/u.test(normalized)) {
    throw new Error('address must be a valid 20-byte EVM address');
  }
  return normalized;
}

function normalizeChainId(value) {
  const normalized = required(value, 'chain id');
  if (!/^[1-9][0-9]*$/u.test(normalized)) {
    throw new Error('chain id must be a positive integer');
  }
  return normalized;
}

function normalizeOptionalInteger(value, label) {
  if (value === undefined) {
    return null;
  }
  const normalized = required(value, label);
  if (!/^[0-9]+$/u.test(normalized)) {
    throw new Error(`${label} must be an integer string`);
  }
  return normalized;
}

function formatNativeAmount(wei) {
  if (wei === null) {
    return null;
  }
  const raw = BigInt(wei);
  const base = 10n ** 18n;
  const whole = raw / base;
  const fraction = raw % base;
  if (fraction === 0n) {
    return `${whole.toString()}.0`;
  }
  return `${whole.toString()}.${fraction.toString().padStart(18, '0').replace(/0+$/u, '')}`;
}

function renderSvgDataUri(text) {
  const qr = QrCode.encodeText(text, QrCode.Ecc.MEDIUM);
  const border = 2;
  const scale = 8;
  const size = (qr.size + border * 2) * scale;
  let path = '';

  for (let y = 0; y < qr.size; y += 1) {
    for (let x = 0; x < qr.size; x += 1) {
      if (!qr.getModule(x, y)) {
        continue;
      }
      const rectX = (x + border) * scale;
      const rectY = (y + border) * scale;
      path += `M${rectX},${rectY}h${scale}v${scale}h-${scale}z`;
    }
  }

  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="Funding QR code">` +
    `<rect width="${size}" height="${size}" fill="#fff"/>` +
    `<path d="${path}" fill="#000"/>` +
    `</svg>`;

  return {
    svg,
    svgDataUri: `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`,
  };
}

function buildPayload(options) {
  const address = normalizeAddress(options.address);
  const chainId = normalizeChainId(options.chainId);
  const amountWei = normalizeOptionalInteger(options.amountWei, 'amount wei');
  const tokenSymbol = options.tokenSymbol?.trim() || 'ETH';
  const networkName = options.networkName?.trim() || null;
  const networkLabel = networkName ? `${networkName} (${chainId})` : chainId;
  const fundingUri = `ethereum:${address}@${chainId}`;
  const { svg, svgDataUri } = renderSvgDataUri(fundingUri);
  const qrUrl = `https://quickchart.io/qr?size=240&text=${encodeURIComponent(fundingUri)}`;

  return {
    address,
    chainId,
    networkName,
    networkLabel,
    tokenSymbol,
    amountWei,
    amountDisplay: formatNativeAmount(amountWei),
    fundingUri,
    svg,
    svgDataUri,
    qrUrl,
    markdownImage: `![Funding QR](${svgDataUri})`,
    reminder: amountWei
      ? `Please fund ${address} on ${networkLabel} with at least ${formatNativeAmount(amountWei)} ${tokenSymbol}, then tell me once the transfer is confirmed.`
      : `Please fund ${address} on ${networkLabel} with native ${tokenSymbol} for gas, then tell me once the transfer is confirmed.`,
  };
}

function printText(payload) {
  const lines = [
    `Address: ${payload.address}`,
    `Network: ${payload.networkLabel}`,
    payload.amountWei
      ? `Suggested Top-up: ${payload.amountDisplay} ${payload.tokenSymbol} (${payload.amountWei} wei)`
      : `Suggested Top-up: enough native ${payload.tokenSymbol} for gas`,
    `Funding URI: ${payload.fundingUri}`,
    `Markdown Image: ${payload.markdownImage}`,
    `QR URL: ${payload.qrUrl}`,
    `Reminder: ${payload.reminder}`,
  ];
  console.log(lines.join('\n'));
}

try {
  const payload = buildPayload(parseArgs(process.argv.slice(2)));
  if (process.argv.includes('--json')) {
    console.log(JSON.stringify(payload, null, 2));
  } else {
    printText(payload);
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  usage();
  process.exit(1);
}
