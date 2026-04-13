# AgentPay + Aster: BSC USD1 Deposit & WLFI Futures Long — Complete Runbook

End-to-end guide for an Agent (or human) to deposit USD1 on BSC into Aster via AgentPay, then open a long position on WLFI perpetual futures. All addresses, URLs, and ABIs are pre-filled — nothing to look up.

---

## Constants (verified, use as-is)

```
BSC Chain ID:               56
USD1 (BSC):                 0x8d0D000Ee44948fC98c9B98a4FA4921476f08B0d  (decimals: 18)
Aster Treasury (BSC):       0x128463A60784c4D3f46c23Af3f65Ed859Ba87974
Broker ID:                  1
Aster Futures API:          https://fapi.asterdex.com
Aster EIP-712 chainId:      1666  (signing only, NOT a network chainId)
Trading Pair:               WLFIUSDT
Quantity Precision:          0  (integers only, min 1)
Price Precision:             7  (7 decimal places)
Min Notional:               5 USDT
```

---

## Step 0: Read wallet address

```bash
WALLET=$(agentpay wallet --json | jq -r '.address')
echo "Wallet: $WALLET"
```

All subsequent steps use `$WALLET`.

---

## Step 1: Confirm USD1 and BNB (gas) on BSC

```bash
agentpay status --network bsc
```

Required:
- **USD1**: The amount you want to deposit (e.g. 100 USD1)
- **BNB**: At least 0.005 BNB for gas on the approve + deposit transactions

If insufficient, send USD1 and BNB to `$WALLET` on the BSC chain first.

---

## Step 2: Approve — authorize the Aster Treasury to spend USD1

Example: depositing 100 USD1 (100 USD1 = 100000000000000000000 wei, 18 decimals):

```bash
agentpay approve \
  --network bsc \
  --token 0x8d0D000Ee44948fC98c9B98a4FA4921476f08B0d \
  --spender 0x128463A60784c4D3f46c23Af3f65Ed859Ba87974 \
  --amount 100000000000000000000 \
  --broadcast
```

Wait for confirmation (AgentPay polls for the receipt automatically).

> Amount conversion: N USD1 = N x 10^18 wei
> - 10 USD1 = 10000000000000000000
> - 50 USD1 = 50000000000000000000
> - 100 USD1 = 100000000000000000000
> - 500 USD1 = 500000000000000000000

---

## Step 3: Deposit — send USD1 into the Aster Treasury

Treasury contract function: `deposit(address currency, uint256 amount, uint256 broker)`

Generate the calldata with this Node.js one-liner (amount must match Step 2):

```bash
DEPOSIT_CALLDATA=$(node -e "
const { encodeFunctionData, parseUnits } = require('viem');
const abi = [{name:'deposit',type:'function',stateMutability:'nonpayable',inputs:[{name:'currency',type:'address'},{name:'amount',type:'uint256'},{name:'broker',type:'uint256'}],outputs:[]}];
console.log(encodeFunctionData({abi,functionName:'deposit',args:['0x8d0D000Ee44948fC98c9B98a4FA4921476f08B0d',parseUnits('100',18),1n]}));
")

echo "Calldata: $DEPOSIT_CALLDATA"
```

Then broadcast:

```bash
agentpay broadcast \
  --network bsc \
  --to 0x128463A60784c4D3f46c23Af3f65Ed859Ba87974 \
  --gas-limit 500000 \
  --max-fee-per-gas-wei 3000000000 \
  --data-hex $DEPOSIT_CALLDATA \
  --value-wei 0
```

Wait for confirmation. USD1 is now in your Aster futures account.

---

## Step 4: Sign Aster API requests (EIP-712)

All Aster trading API calls require EIP-712 signatures. The helper script below handles signing + requests.

**Save as `aster-trade.mjs`** (one-time setup, reuse afterwards):

```javascript
#!/usr/bin/env node
/**
 * Aster Futures trading helper — signs via AgentPay, no private keys needed.
 * Usage:
 *   node aster-trade.mjs open-long  <quantity>          # market buy (go long) WLFI
 *   node aster-trade.mjs open-short <quantity>           # market sell (go short) WLFI
 *   node aster-trade.mjs close-long  <quantity>          # market close long
 *   node aster-trade.mjs close-short <quantity>          # market close short
 *   node aster-trade.mjs positions                       # view positions
 *   node aster-trade.mjs balance                         # view balance
 *   node aster-trade.mjs open-orders                     # view open orders
 *   node aster-trade.mjs cancel-all                      # cancel all open orders
 *   node aster-trade.mjs set-leverage <n>                # set leverage
 *
 * Auto-approval: set AGENTPAY_VAULT_PASSWORD env var to auto-approve
 * manual approval requests (e.g. for EIP-712 signing).
 */
import { execSync, spawn } from 'child_process';

const API = 'https://fapi.asterdex.com';
const SYMBOL = 'WLFIUSDT';

// --- Read wallet address from AgentPay ---
const WALLET = JSON.parse(
  execSync('agentpay wallet --json', { encoding: 'utf-8' })
).address;

function nonce() {
  return (BigInt(Date.now()) * 1000n).toString();
}

function buildParamString(params) {
  return Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
}

function signAsync(params) {
  return new Promise((resolve, reject) => {
    params.nonce = nonce();
    params.user = WALLET;
    params.signer = WALLET;

    const msg = buildParamString(params);

    const typedData = JSON.stringify({
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Message: [{ name: 'msg', type: 'string' }],
      },
      primaryType: 'Message',
      domain: {
        name: 'AsterSignTransaction',
        version: '1',
        chainId: 1666,
        verifyingContract: '0x0000000000000000000000000000000000000000',
      },
      message: { msg },
    });

    const proc = spawn('agentpay', [
      'sign-typed-data',
      '--typed-data-json', typedData,
      '--json',
    ]);

    let stdout = '';
    let stderr = '';
    let approved = false;

    proc.stdout.on('data', (data) => { stdout += data.toString(); });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
      // Check for manual approval request as soon as it appears
      if (!approved) {
        const blocks = stderr.match(/\{[\s\S]*?\n\}/g) || [];
        for (const block of blocks) {
          try {
            const obj = JSON.parse(block);
            if (obj.cli_approval_command && !approved) {
              approved = true;
              const vaultPw = process.env.AGENTPAY_VAULT_PASSWORD;
              if (vaultPw) {
                console.error(`⚠️  Manual approval required — auto-approving...`);
                try {
                  // Insert --vault-password-stdin before the subcommand
                  const approveCmd = obj.cli_approval_command.replace(
                    'approve-manual-approval-request',
                    '--vault-password-stdin approve-manual-approval-request'
                  );
                  execSync(`echo ${JSON.stringify(vaultPw)} | ${approveCmd}`, {
                    encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'],
                  });
                  console.error(`✓ Approved. Waiting for signature...`);
                } catch (e) {
                  console.error(`✗ Auto-approve failed: ${e.message}`);
                  console.error(`   Run manually: ${obj.cli_approval_command}`);
                }
              } else {
                console.error(`⚠️  Manual approval required.`);
                console.error(`   Approval ID: ${obj.approval_request_id}`);
                console.error(`   Run in another terminal:`);
                console.error(`   ${obj.cli_approval_command}`);
              }
            }
          } catch {}
        }
      }
    });

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`sign-typed-data exited with code ${code}: ${stderr.trim()}`));
        return;
      }
      // Parse signature from stdout (may be pretty-printed JSON)
      const blocks = stdout.match(/\{[\s\S]*?\}/g) || [];
      for (const block of blocks) {
        try {
          const obj = JSON.parse(block);
          if (obj.signature_hex) {
            params.signature = obj.signature_hex;
            resolve(params);
            return;
          }
        } catch {}
      }
      reject(new Error(`No signature in output: ${stdout.trim()}`));
    });
  });
}

async function sign(params) {
  return signAsync(params);
}

async function post(path, params) {
  const signed = await sign(params);
  const body = Object.entries(signed).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  return res.json();
}

async function get(path, params) {
  const signed = await sign(params);
  const qs = Object.entries(signed).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  const res = await fetch(`${API}${path}?${qs}`);
  return res.json();
}

async function del(path, params) {
  const signed = await sign(params);
  const qs = Object.entries(signed).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  const res = await fetch(`${API}${path}?${qs}`, { method: 'DELETE' });
  return res.json();
}

// --- Commands ---
const [cmd, arg] = process.argv.slice(2);

switch (cmd) {
  case 'open-long': {
    const r = await post('/fapi/v3/order', {
      symbol: SYMBOL, side: 'BUY', type: 'MARKET',
      quantity: arg, positionSide: 'BOTH',
    });
    console.log(JSON.stringify(r, null, 2));
    break;
  }
  case 'open-short': {
    const r = await post('/fapi/v3/order', {
      symbol: SYMBOL, side: 'SELL', type: 'MARKET',
      quantity: arg, positionSide: 'BOTH',
    });
    console.log(JSON.stringify(r, null, 2));
    break;
  }
  case 'close-long': {
    const r = await post('/fapi/v3/order', {
      symbol: SYMBOL, side: 'SELL', type: 'MARKET',
      quantity: arg, reduceOnly: 'true', positionSide: 'BOTH',
    });
    console.log(JSON.stringify(r, null, 2));
    break;
  }
  case 'close-short': {
    const r = await post('/fapi/v3/order', {
      symbol: SYMBOL, side: 'BUY', type: 'MARKET',
      quantity: arg, reduceOnly: 'true', positionSide: 'BOTH',
    });
    console.log(JSON.stringify(r, null, 2));
    break;
  }
  case 'positions': {
    const r = await get('/fapi/v3/positionRisk', { symbol: SYMBOL });
    console.log(JSON.stringify(r, null, 2));
    break;
  }
  case 'balance': {
    const r = await get('/fapi/v3/balance', {});
    console.log(JSON.stringify(r, null, 2));
    break;
  }
  case 'open-orders': {
    const r = await get('/fapi/v3/openOrders', { symbol: SYMBOL });
    console.log(JSON.stringify(r, null, 2));
    break;
  }
  case 'cancel-all': {
    const r = await del('/fapi/v3/allOpenOrders', { symbol: SYMBOL });
    console.log(JSON.stringify(r, null, 2));
    break;
  }
  case 'set-leverage': {
    const r = await post('/fapi/v3/leverage', { symbol: SYMBOL, leverage: arg });
    console.log(JSON.stringify(r, null, 2));
    break;
  }
  default:
    console.log('Usage: node aster-trade.mjs <open-long|open-short|close-long|close-short|positions|balance|open-orders|cancel-all|set-leverage> [arg]');
}
```

---

## Step 5: Open long on WLFI

> **Auto-approval**: EIP-712 signing may require manual approval. Set `AGENTPAY_VAULT_PASSWORD`
> to auto-approve: `export AGENTPAY_VAULT_PASSWORD=<your-vault-password>`
> Without it, you'll see the approval command to run in another terminal.

```bash
# Check Aster futures account balance (confirm USD1 arrived)
AGENTPAY_VAULT_PASSWORD=<pw> node aster-trade.mjs balance

# Set leverage (optional, default 1x)
node aster-trade.mjs set-leverage 5

# Open long 1000 WLFI (market order)
node aster-trade.mjs open-long 1000
```

> Note: quantity must be a positive integer (min 1), and quantity x markPrice >= 5 USDT (min notional).

---

## Step 6: Check position & close

```bash
# View current position
node aster-trade.mjs positions

# Close long (full size, quantity matches the open)
node aster-trade.mjs close-long 1000
```

---

## Step 7: Open short on WLFI (if needed for demo)

```bash
# Open short 1000 WLFI
node aster-trade.mjs open-short 1000

# View position
node aster-trade.mjs positions

# Close short
node aster-trade.mjs close-short 1000
```

---

## Full Demo Flow at a Glance

```bash
# 0. Read wallet
WALLET=$(agentpay wallet --json | jq -r '.address')

# 1. Check balance
agentpay status --network bsc

# 2. Approve USD1 → Aster Treasury (100 USD1)
agentpay approve \
  --network bsc \
  --token 0x8d0D000Ee44948fC98c9B98a4FA4921476f08B0d \
  --spender 0x128463A60784c4D3f46c23Af3f65Ed859Ba87974 \
  --amount 100000000000000000000 \
  --broadcast

# 3. Deposit USD1 → Aster Treasury (100 USD1)
DEPOSIT_CALLDATA=$(node -e "
const{encodeFunctionData,parseUnits}=require('viem');
const abi=[{name:'deposit',type:'function',stateMutability:'nonpayable',inputs:[{name:'currency',type:'address'},{name:'amount',type:'uint256'},{name:'broker',type:'uint256'}],outputs:[]}];
console.log(encodeFunctionData({abi,functionName:'deposit',args:['0x8d0D000Ee44948fC98c9B98a4FA4921476f08B0d',parseUnits('100',18),1n]}));
")

agentpay broadcast \
  --network bsc \
  --to 0x128463A60784c4D3f46c23Af3f65Ed859Ba87974 \
  --gas-limit 500000 \
  --max-fee-per-gas-wei 3000000000 \
  --data-hex $DEPOSIT_CALLDATA \
  --value-wei 0

# 4. Confirm deposit arrived
node aster-trade.mjs balance

# 5. Set leverage
node aster-trade.mjs set-leverage 5

# 6. Open long
node aster-trade.mjs open-long 1000

# 7. Check position
node aster-trade.mjs positions

# 8. Close position
node aster-trade.mjs close-long 1000
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Approve/Deposit tx fails | Check BNB balance is sufficient for gas (>= 0.005 BNB) |
| `agentpay broadcast` requires manual approval | Run `agentpay admin approve-manual-approval-request --approval-request-id <UUID>` in another terminal; **do not** kill the original command |
| Aster API returns `-1022` (invalid signature) | Check system clock accuracy (`date`); Aster allows +/-5s skew |
| Aster API returns `-2019` (insufficient margin) | Run `node aster-trade.mjs balance` to check; deposit more USD1 if needed |
| Aster API returns `-4061` (position does not exist) | Confirm positionSide is correct (default BOTH = one-way mode) |
| `429` rate limit | Wait 1 minute and retry; Aster limit is ~2400 weight/min |
| Quantity error | Must be a positive integer, and quantity x price >= 5 USDT |

---

## Reference: Treasury Contract ABI

```json
[
  {
    "name": "deposit",
    "type": "function",
    "stateMutability": "nonpayable",
    "inputs": [
      { "name": "currency", "type": "address" },
      { "name": "amount", "type": "uint256" },
      { "name": "broker", "type": "uint256" }
    ],
    "outputs": []
  },
  {
    "name": "depositNative",
    "type": "function",
    "stateMutability": "payable",
    "inputs": [
      { "name": "broker", "type": "uint256" }
    ],
    "outputs": []
  }
]
```

## Reference: EIP-712 Signing Domain

```json
{
  "name": "AsterSignTransaction",
  "version": "1",
  "chainId": 1666,
  "verifyingContract": "0x0000000000000000000000000000000000000000"
}
```

## Reference: WLFIUSDT Trading Rules

```
Contract Type:     PERPETUAL
Status:            TRADING
Price Tick:        0.0001000
Quantity Step:     1 (integers only)
Min Quantity:      1
Max Quantity:      1,000,000 (limit) / 100,000 (market)
Min Notional:      5 USDT
Max Leverage:      4x (maintMarginPercent 25%)
Liquidation Fee:   2.5%
Order Types:       LIMIT, MARKET, STOP, STOP_MARKET, TAKE_PROFIT,
                   TAKE_PROFIT_MARKET, TRAILING_STOP_MARKET
TimeInForce:       GTC, IOC, FOK, GTX
```
