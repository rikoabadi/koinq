/* ===================================================
   KoinQ — Crypto Wallet SPA
   Vanilla JS, No TypeScript, No OOP, No Modules
   =================================================== */

/* ===== HTTPS Enforcement ===== */
if (location.protocol === 'http:' &&
    location.hostname !== 'localhost' &&
    location.hostname !== '127.0.0.1') {
  location.replace('https:' + location.href.substring(location.protocol.length));
}

/* ===== Brute-force Protection ===== */
var BF_STORAGE_KEY = 'koinq_bf';
var BF_MAX_ATTEMPTS = 10;          // lockout permanen setelah 10x gagal
var BF_PERM_LOCKOUT_MS = 24 * 60 * 60 * 1000; // 24 jam
var unlockCooldownTimer = null;

// Baca state dari localStorage agar persist saat refresh
function bfLoad() {
  try {
    var raw = localStorage.getItem(BF_STORAGE_KEY);
    if (raw) return JSON.parse(raw);
  } catch (e) {}
  return { attempts: 0, cooldownUntil: 0, lockedUntil: 0 };
}

function bfSave(s) {
  try { localStorage.setItem(BF_STORAGE_KEY, JSON.stringify(s)); } catch (e) {}
}

// Cooldown eksponensial: 0, 0, 10s, 30s, 90s, 3m, 9m, 15m, 15m, 15m, lalu lockout 24 jam
function getUnlockCooldownMs(attempts) {
  if (attempts <= 2) return 0;
  if (attempts >= BF_MAX_ATTEMPTS) return BF_PERM_LOCKOUT_MS;
  return Math.min(10 * Math.pow(3, attempts - 3), 15 * 60) * 1000;
}

// Tampilkan countdown dan disable tombol
function startUnlockCooldown(errEl, unlockBtn, isPermanent) {
  clearInterval(unlockCooldownTimer);
  unlockBtn.disabled = true;
  function tick() {
    var s = bfLoad();
    var until = isPermanent ? s.lockedUntil : s.cooldownUntil;
    var remaining = Math.ceil((until - Date.now()) / 1000);
    if (remaining <= 0) {
      clearInterval(unlockCooldownTimer);
      if (!isPermanent) {
        errEl.classList.add('hidden');
        unlockBtn.disabled = false;
        unlockBtn.textContent = '🔓 Unlock / Create Wallet';
      }
      return;
    }
    var mins = Math.floor(remaining / 60);
    var secs = remaining % 60;
    var timeStr = mins > 0 ? mins + 'm ' + secs + 's' : secs + 's';
    if (isPermanent) {
      errEl.textContent = '🚫 Terlalu banyak percobaan gagal. Terkunci selama ' + timeStr + '.';
    } else {
      errEl.textContent = '🔒 Too many attempts. Please wait ' + timeStr + '…';
    }
    errEl.classList.remove('hidden');
    unlockBtn.textContent = '⏳ Wait ' + timeStr + '…';
  }
  tick();
  unlockCooldownTimer = setInterval(tick, 500);
}

/* ===== Session Encryption ===== */
var sessionEncKey = null; // CryptoKey for AES-GCM (never leaves memory as raw bytes)

async function initSessionKey(password) {
  var salt = crypto.getRandomValues(new Uint8Array(16));
  var encoder = new TextEncoder();
  var km = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  sessionEncKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: 200000, hash: 'SHA-256' },
    km,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptStr(str) {
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var data = new TextEncoder().encode(str);
  var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, sessionEncKey, data);
  return { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}

async function decryptStr(enc) {
  var iv = new Uint8Array(enc.iv);
  var ct = new Uint8Array(enc.ct);
  var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, sessionEncKey, ct);
  return new TextDecoder().decode(pt);
}

/* ===== State ===== */
var state = {
  encryptedMnemonic: null, // {iv, ct} – AES-GCM encrypted, never stored as plain text
  currentIndex: 0,
  currentAddress: '',
  network: 'BSC',
  wallets: [],        // [{address, encryptedPrivateKey: {iv, ct}}, ...]
  balanceBSC: {},     // {address: '0.0'}
  balanceCELO: {},    // {address: '0.0'}
  balanceUSDT: {},    // {address_NETWORK: '0.0'}
  transactions: [],
  txLoading: false,
  balLoading: false
};

/* ===== Network Config ===== */
var networks = {
  BSC: {
    name: 'BNB Smart Chain',
    rpcUrl: 'https://bsc-dataseed.binance.org/',
    rpcFallbacks: [
      'https://bsc-dataseed1.binance.org/',
      'https://bsc-dataseed2.binance.org/',
      'https://bsc-dataseed3.binance.org/'
    ],
    chainId: 56,
    symbol: 'BNB',
    explorerApi: 'https://api.bscscan.com/api',
    explorerTx: 'https://bscscan.com/tx/',
    explorerAddr: 'https://bscscan.com/address/',
    usdtAddress: '0x55d398326f99059fF775485246999027B3197955',
    usdtDecimals: 18
  },
  CELO: {
    name: 'Celo',
    rpcUrl: 'https://forno.celo.org',
    rpcFallbacks: [
      'https://rpc.ankr.com/celo'
    ],
    chainId: 42220,
    symbol: 'CELO',
    explorerApi: 'https://api.celoscan.io/api',
    explorerTx: 'https://celoscan.io/tx/',
    explorerAddr: 'https://celoscan.io/address/',
    usdtAddress: '0x48065fbbe25f71c9282ddf5e1cd6d6a887483d5e',
    usdtDecimals: 6,
    // CIP-64: USDT butuh adapter karena 6 decimals (bukan token address langsung)
    // Adapter menormalisasi ke 18 decimals agar protokol CELO bisa hitung gas
    // Ref: https://docs.celo.org/developer/fee-currency
    feeCurrency: '0x0e2a3e05bc9a16f5292a6170456a710cb89c6f72', // USDT Adapter (bukan USDT!)
    feeCurrencySymbol: 'USDT'
  }
};

/* ===== ERC-20 Minimal ABI ===== */
var ERC20_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function name() view returns (string)',
  'function transfer(address to, uint256 amount) returns (bool)'
];

/* ===== Wallet Core Functions ===== */

// Hash a File object using SHA-256, returns lowercase hex string
async function hashFile(file) {
  var buf = await file.arrayBuffer();
  var digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest))
    .map(function(b) { return b.toString(16).padStart(2, '0'); })
    .join('');
}

// Generate 24-word mnemonic deterministically from combined secret:
// secret = "koinq:v2:" + masterPassword + ":" + fileHashHex
// Using PBKDF2 (600k iterations, SHA-256) + BIP39 entropy.
// Without the exact file, the mnemonic is computationally infeasible to reproduce.
async function generateMnemonicFromPassword(combinedSecret) {
  var encoder = new TextEncoder();
  var salt = encoder.encode('koinq-deterministic-wallet-v2');
  var keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(combinedSecret),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  var bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: 600000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  // 256-bit entropy → 24-word mnemonic via ethers BIP39
  return ethers.Mnemonic.entropyToPhrase(new Uint8Array(bits));
}

// Derive address + private key for a given HD index
function getHDWallet(mnemonic, index) {
  var path = "m/44'/60'/0'/0/" + index;
  var wallet = ethers.HDNodeWallet.fromPhrase(mnemonic, '', path);
  return { address: wallet.address, privateKey: wallet.privateKey };
}

// Fetch native balance — tries primary RPC then fallbacks
async function fetchBalance(address, network) {
  var cfg = networks[network];
  var rpcs = [cfg.rpcUrl].concat(cfg.rpcFallbacks || []);
  for (var i = 0; i < rpcs.length; i++) {
    try {
      var bal = await new ethers.JsonRpcProvider(rpcs[i]).getBalance(address);
      return ethers.formatEther(bal);
    } catch (e) { /* try next */ }
  }
  return '–';
}

// Fetch USDT balance — tries primary RPC then fallbacks
async function fetchUSDTBalance(address, network) {
  var cfg = networks[network];
  var rpcs = [cfg.rpcUrl].concat(cfg.rpcFallbacks || []);
  for (var i = 0; i < rpcs.length; i++) {
    try {
      var provider = new ethers.JsonRpcProvider(rpcs[i]);
      var bal = await new ethers.Contract(cfg.usdtAddress, ERC20_ABI, provider).balanceOf(address);
      return ethers.formatUnits(bal, cfg.usdtDecimals);
    } catch (e) { /* try next */ }
  }
  return '–';
}

// Simulate USDT transfer — returns gas estimate details without sending
async function estimateUSDTTransfer(to, amount, fromAddress, network) {
  var cfg = networks[network];
  var rpcs = [cfg.rpcUrl].concat(cfg.rpcFallbacks || []);

  // Prepare amount in token decimals
  var amountWei;
  try {
    amountWei = ethers.parseUnits(amount.toString(), cfg.usdtDecimals);
  } catch (e) {
    throw new Error('Invalid amount');
  }

  // CIP-64: CELO L2 mendukung fee abstraction — gas dibayar pakai token ERC-20
  var hasCip64 = !!(cfg.feeCurrency);

  for (var i = 0; i < rpcs.length; i++) {
    try {
      var provider = new ethers.JsonRpcProvider(rpcs[i]);
      var ctr = new ethers.Contract(cfg.usdtAddress, ERC20_ABI, provider);
      var populated = await ctr.transfer.populateTransaction(to, amountWei);

      var gasEstimate, feeData, gasPrice;

      if (hasCip64) {
        // CIP-64: gasPrice harus diambil spesifik untuk fee currency via eth_gasPrice(adapterAddress)
        // Karena USDT = 6 dec, node CELO mengembalikan gasPrice dalam 18-dec normalized via adapter
        var gpHex;
        try {
          gpHex = await provider.send('eth_gasPrice', [cfg.feeCurrency]);
        } catch (e2) {
          // Fallback jika node tidak support parameter feeCurrency di eth_gasPrice
          var fd = await provider.getFeeData();
          gpHex = '0x' + (fd.gasPrice || fd.maxFeePerGas || BigInt(0)).toString(16);
        }
        gasPrice = BigInt(gpHex);

        // eth_estimateGas dengan feeCurrency = estimasi akurat termasuk overhead adapter
        // PENTING: provider.estimateGas() ethers.js TIDAK meneruskan feeCurrency ke RPC
        // Harus pakai provider.send('eth_estimateGas') agar field feeCurrency dikirim
        try {
          var gasHex = await provider.send('eth_estimateGas', [{ to: cfg.usdtAddress, data: populated.data, from: fromAddress, feeCurrency: cfg.feeCurrency }]);
          gasEstimate = BigInt(gasHex);
        } catch (e3) {
          // fallback tanpa feeCurrency jika node tidak support
          gasEstimate = await provider.estimateGas({ to: cfg.usdtAddress, data: populated.data, from: fromAddress });
        }
        gasEstimate = gasEstimate * BigInt(120) / BigInt(100);

        // gasFeeWei = gasUsed × gasPriceWei (keduanya dalam 18-dec)
        // gasFeeCELO = gasFeeWei / 1e18
        var gasFeeWei  = gasEstimate * gasPrice;
        var gasFeeCelo = Number(ethers.formatUnits(gasFeeWei, 18));

        return {
          to:                  to,
          amountWei:           amountWei.toString(),
          network:             network,
          gasUnits:            gasEstimate.toString(),
          gasPrice:            gasPrice.toString(),
          gasPriceGwei:        Number(ethers.formatUnits(gasPrice, 9)),
          gasFeeNative:        gasFeeCelo,   // dalam CELO, 18 dec
          feeCurrency:         cfg.feeCurrency,
          feeCurrencySymbol:   cfg.feeCurrencySymbol
        };
      }

      // BSC / jaringan standar — gas dibayar native token
      gasEstimate = await provider.estimateGas({ to: cfg.usdtAddress, data: populated.data, from: fromAddress });
      feeData     = await provider.getFeeData();
      gasPrice    = feeData.gasPrice || feeData.maxFeePerGas || BigInt(0);

      return {
        to:           to,
        amountWei:    amountWei.toString(),
        network:      network,
        gasUnits:     gasEstimate.toString(),
        gasPrice:     gasPrice.toString(),
        gasPriceGwei: Number(ethers.formatUnits(gasPrice, 9)),
        gasFeeNative: Number(ethers.formatUnits(gasEstimate * gasPrice, 18))
      };
    } catch (e) {
      console.warn('[KoinQ] estimateUSDTTransfer failed for RPC', rpcs[i], e && e.message);
    }
  }
  throw new Error('Gas estimation failed');
}

// Normalize explorer-style tx objects (generic txlist / Blockscout results)
function normaliseTx(tx) {
  // isError: hanya '1' jika isError === '1' ATAU txreceipt_status === '0' (failed)
  // Jangan pakai tx.status langsung — di Blockscout status='1' artinya SUCCESS
  var isErr = '0';
  if (tx.isError === '1') isErr = '1';
  else if (tx.txreceipt_status === '0') isErr = '1';

  var out = {
    hash: tx.hash || tx.transactionHash || tx.txHash || tx.transaction_hash || tx.tx_hash || '',
    from: tx.from || tx.sender || tx.from_address || tx.owner || '',
    to: tx.to || tx.to_address || tx.recipient || '',
    value: tx.value || tx.amount || tx.contractValue || '0',
    timeStamp: parseTimestamp(tx.timeStamp || tx.timestamp || tx.time || tx.blockTimestamp || tx.blockTime),
    isError: isErr
  };

  if (tx.tokenDecimal !== undefined && tx.tokenDecimal !== null) out.tokenDecimal = Number(tx.tokenDecimal);
  if (tx.tokenSymbol) out.tokenSymbol = tx.tokenSymbol;
  if (tx.contractAddress) out.contract = tx.contractAddress;

  return out;
}

// Normalize MetaMask Accounts API / modern explorer objects (best-effort)
function normaliseExplorerTx(tx) {
  if (!tx) return { hash: '', from: '', to: '', value: '0', timeStamp: String(Math.floor(Date.now() / 1000)) };
  var out = {};
  out.hash = tx.hash || tx.txHash || tx.transactionHash || (tx.raw && tx.raw.hash) || '';
  out.from = tx.from || tx.txFrom || (tx.raw && tx.raw.from) || '';
  out.to = tx.to || tx.txTo || (tx.raw && tx.raw.to) || '';
  // MetaMask Accounts API: status is a string like 'confirmed', 'failed', 'submitted'
  // tx.isError from Etherscan-style: '1' = error
  var mmFailed = (typeof tx.status === 'string' && tx.status.toLowerCase() === 'failed');
  out.isError = (tx.isError === '1' || mmFailed) ? '1' : '0';

  // Try token transfer shapes
  if (Array.isArray(tx.valueTransfers) && tx.valueTransfers.length > 0) {
    var vt = tx.valueTransfers[0];
    out.value = vt.value || vt.amount || '0';
    out.tokenSymbol = vt.symbol || vt.tokenSymbol || null;
    out.tokenDecimal = vt.tokenDecimal !== undefined && vt.tokenDecimal !== null ? Number(vt.tokenDecimal) : null;
    out.timeStamp = parseTimestamp(vt.time || vt.timeStamp || tx.timeStamp || tx.timestamp);
    out.contract = vt.contract || vt.contractAddress || null;
    return out;
  }

  // Otherwise fall back to simpler fields
  out.value = tx.value || '0';
  out.timeStamp = parseTimestamp(tx.timeStamp || tx.timestamp || tx.receivedAt);
  return out;
}

// Parse a variety of timestamp formats into unix seconds string
function parseTimestamp(ts) {
  if (!ts) return String(Math.floor(Date.now() / 1000));
  // numeric or numeric string
  var n = Number(ts);
  if (!isNaN(n)) {
    // If timestamp looks like milliseconds (>= 1e12), convert to seconds
    if (n > 1e12) return String(Math.floor(n / 1000));
    // If it's already seconds (reasonable range), return as integer string
    if (n > 1e9) return String(Math.floor(n));
    // small numbers -> fallback to now
    return String(Math.floor(Date.now() / 1000));
  }
  // Try ISO date parse
  var parsed = Date.parse(ts);
  if (!isNaN(parsed)) return String(Math.floor(parsed / 1000));
  return String(Math.floor(Date.now() / 1000));
}

// Encode bytes sebagai RLP item (address, calldata, sig bytes)
// BUKAN untuk integer — integer 0 di-encode sebagai 0x80 (kosong), bukan 0x00
function rlpEncodeBytes(value) {
  var bytes;
  if (value === '0x' || value === '' || value === null || value === undefined) {
    bytes = new Uint8Array(0);
  } else if (typeof value === 'string') {
    var s = value.startsWith('0x') ? value.slice(2) : value;
    if (s === '') { bytes = new Uint8Array(0); }
    else {
      if (s.length % 2) s = '0' + s;
      bytes = new Uint8Array(s.match(/.{2}/g).map(function(b) { return parseInt(b, 16); }));
    }
  } else if (value instanceof Uint8Array) {
    bytes = value;
  } else {
    bytes = new Uint8Array(0);
  }
  if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
  var prefix;
  if (bytes.length <= 55) {
    prefix = new Uint8Array([0x80 + bytes.length]);
  } else {
    var lenHex = bytes.length.toString(16);
    if (lenHex.length % 2) lenHex = '0' + lenHex;
    var lenBytes = new Uint8Array(lenHex.match(/.{2}/g).map(function(b) { return parseInt(b, 16); }));
    prefix = new Uint8Array([0xb7 + lenBytes.length].concat(Array.from(lenBytes)));
  }
  var out = new Uint8Array(prefix.length + bytes.length);
  out.set(prefix); out.set(bytes, prefix.length);
  return out;
}

// Encode integer sebagai RLP (BigInt/number) — 0 → 0x80 (empty), n → minimal bytes
function rlpEncodeInt(n) {
  var bn = BigInt(n);
  if (bn === BigInt(0)) return new Uint8Array([0x80]); // RLP integer 0 = empty = 0x80
  var hex = bn.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  var bytes = new Uint8Array(hex.match(/.{2}/g).map(function(b) { return parseInt(b, 16); }));
  if (bytes.length === 1 && bytes[0] < 0x80) return bytes; // single byte < 0x80: no prefix
  var prefix = new Uint8Array([0x80 + bytes.length]);
  var out = new Uint8Array(prefix.length + bytes.length);
  out.set(prefix); out.set(bytes, prefix.length);
  return out;
}

// Encode satu item RLP — dispatch berdasarkan tipe
function rlpEncodeItem(value) {
  if (Array.isArray(value)) return rlpEncodeList(value);  // nested list
  if (typeof value === 'bigint' || typeof value === 'number') return rlpEncodeInt(value);
  return rlpEncodeBytes(value); // string hex atau Uint8Array
}

// Encode signature scalar (r atau s): 32-byte fixed, strip leading zeros untuk RLP integer
// RLP integer tidak boleh ada leading zero bytes
function rlpEncodeScalar(hexStr) {
  var s = hexStr.startsWith('0x') ? hexStr.slice(2) : hexStr;
  while (s.length < 64) s = '0' + s;   // pastikan 32 bytes dulu
  // strip leading zero bytes (RLP integer tidak boleh leading zeros)
  s = s.replace(/^(00)+/, '') || '00';
  if (s.length % 2) s = '0' + s;
  if (s === '00') return new Uint8Array([0x80]); // zero
  var bytes = new Uint8Array(s.match(/.{2}/g).map(function(b) { return parseInt(b, 16); }));
  if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
  var prefix = new Uint8Array([0x80 + bytes.length]);
  var out = new Uint8Array(prefix.length + bytes.length);
  out.set(prefix); out.set(bytes, prefix.length);
  return out;
}

// Encode daftar item sebagai RLP list
function rlpEncodeList(items) {
  var encoded = items.map(rlpEncodeItem);
  var total = encoded.reduce(function(s, e) { return s + e.length; }, 0);
  var prefix;
  if (total <= 55) {
    prefix = new Uint8Array([0xc0 + total]);
  } else {
    var lenHex = total.toString(16);
    if (lenHex.length % 2) lenHex = '0' + lenHex;
    var lenBytes = new Uint8Array(lenHex.match(/.{2}/g).map(function(b) { return parseInt(b, 16); }));
    prefix = new Uint8Array([0xf7 + lenBytes.length].concat(Array.from(lenBytes)));
  }
  var out = new Uint8Array(prefix.length + total);
  out.set(prefix);
  var offset = prefix.length;
  encoded.forEach(function(e) { out.set(e, offset); offset += e.length; });
  return out;
}

// Uint8Array → hex string dengan prefix 0x
function bytesToHex(bytes) {
  return '0x' + Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
}

// Sign digest dengan private key menggunakan ethers SigningKey
async function ecSign(digestHex, privateKeyHex) {
  var signingKey = new ethers.SigningKey(privateKeyHex);
  var sig = signingKey.sign(digestHex);
  return { r: sig.r, s: sig.s, v: sig.v, yParity: sig.yParity };
}

// Send USDT: decrypt private key, attach provider for network, and send transfer
// Untuk CELO CIP-64: encode RLP manual (type 0x7b=123) karena ethers v6 tidak support feeCurrency
// Ref: https://docs.celo.org/developer/fee-currency  (ethers.js not supported natively)
async function sendUSDT(to, amountWei, encryptedPrivateKey, network, feeCurrency) {
  var cfg = networks[network];
  if (!cfg) throw new Error('Unknown network');
  if (!sessionEncKey) throw new Error('Session key not initialized');

  var pk = (await decryptStr(encryptedPrivateKey)).trim();
  if (!pk.startsWith('0x')) pk = '0x' + pk;

  var rpcs = [cfg.rpcUrl].concat(cfg.rpcFallbacks || []);
  var lastErr = null;

  for (var rpcIdx = 0; rpcIdx < rpcs.length; rpcIdx++) {
    var provider = null;
    var wallet   = null;
    var contract = null;
    try {
      provider = new ethers.JsonRpcProvider(rpcs[rpcIdx]);
      wallet   = new ethers.Wallet(pk, provider);
      contract = new ethers.Contract(cfg.usdtAddress, ERC20_ABI, wallet);

      if (feeCurrency && network === 'CELO') {
        // === CIP-64: Transaction Type 123 (0x7b) ===
        // Format BENAR dari dokumentasi resmi CELO:
        // 0x7b || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit,
        //              to, value, data, accessList, feeCurrency,
        //              signatureYParity, signatureR, signatureS])
        // CATATAN: feeCurrency ada di AKHIR setelah accessList, bukan di tengah!

        var populated = await contract.transfer.populateTransaction(to, BigInt(amountWei));
        var nonce = await provider.getTransactionCount(wallet.address, 'pending');

        // Selalu ambil gasPrice fresh saat kirim — nilai dry-run bisa stale (harga gas berubah)
        var gpCip64;
        try {
          var gpHex = await provider.send('eth_gasPrice', [feeCurrency]);
          gpCip64 = BigInt(gpHex);
        } catch (e2) {
          var fd2 = await provider.getFeeData();
          gpCip64 = fd2.gasPrice || fd2.maxFeePerGas || BigInt(0);
        }
        var maxFee  = gpCip64;
        var maxPrio = gpCip64;

        // eth_estimateGas dengan feeCurrency = estimasi akurat termasuk overhead adapter
        var gasLimit;
        try {
          var gasLimitHex = await provider.send('eth_estimateGas', [{ to: cfg.usdtAddress, data: populated.data, from: wallet.address, feeCurrency: feeCurrency }]);
          gasLimit = BigInt(gasLimitHex);
        } catch (e3) {
          gasLimit = await provider.estimateGas({ to: cfg.usdtAddress, data: populated.data, from: wallet.address });
        }
        gasLimit = gasLimit * BigInt(120) / BigInt(100);

        var chainId = BigInt(cfg.chainId);

        // 1. Signing payload (tanpa signature)
        var signingPayload = rlpEncodeList([
          chainId, nonce, maxPrio, maxFee, gasLimit,
          cfg.usdtAddress, '0x', populated.data, [], feeCurrency
        ]);

        // 2. Prefix type 0x7b
        var typedPayload = new Uint8Array(1 + signingPayload.length);
        typedPayload[0] = 0x7b;
        typedPayload.set(signingPayload, 1);

        // 3. keccak256 digest
        var digestHex = ethers.keccak256(typedPayload);

        // 4. Sign
        var sig = await ecSign(digestHex, pk);
        var yParity = (sig.yParity !== undefined) ? sig.yParity : ((sig.v === 27 || sig.v === 0) ? 0 : 1);

        // 5. Encode tx final dengan signature
        var listItems = [
          chainId, nonce, maxPrio, maxFee, gasLimit,
          cfg.usdtAddress, '0x', populated.data, [], feeCurrency
        ];
        var baseItems = listItems.map(rlpEncodeItem);
        baseItems.push(rlpEncodeInt(yParity));
        baseItems.push(rlpEncodeScalar(sig.r));
        baseItems.push(rlpEncodeScalar(sig.s));
        var rlpTotal = baseItems.reduce(function(s, e) { return s + e.length; }, 0);
        var rlpPrefix;
        if (rlpTotal <= 55) {
          rlpPrefix = new Uint8Array([0xc0 + rlpTotal]);
        } else {
          var rlpLenHex = rlpTotal.toString(16);
          if (rlpLenHex.length % 2) rlpLenHex = '0' + rlpLenHex;
          var rlpLenBytes = new Uint8Array(rlpLenHex.match(/.{2}/g).map(function(b) { return parseInt(b, 16); }));
          rlpPrefix = new Uint8Array([0xf7 + rlpLenBytes.length].concat(Array.from(rlpLenBytes)));
        }
        var txPayload = new Uint8Array(rlpPrefix.length + rlpTotal);
        txPayload.set(rlpPrefix);
        var off = rlpPrefix.length;
        baseItems.forEach(function(e) { txPayload.set(e, off); off += e.length; });

        var finalTx = new Uint8Array(1 + txPayload.length);
        finalTx[0] = 0x7b;
        finalTx.set(txPayload, 1);

        var txHash = await provider.send('eth_sendRawTransaction', [bytesToHex(finalTx)]);
        return { hash: txHash };
      } // end CIP-64 CELO

      // BSC / CELO tanpa CIP-64 — gasPrice selalu fresh dari network agar tx tidak stuck
      var feeDataLive = await provider.getFeeData();
      var liveFee = feeDataLive.gasPrice || feeDataLive.maxFeePerGas || BigInt(0);
      var overrides = { gasPrice: liveFee };
      var txResp = await contract.transfer(to, BigInt(amountWei), overrides);
      return txResp;
    } catch (e) {
      lastErr = e;
      console.warn('[KoinQ] sendUSDT failed for RPC', rpcs[rpcIdx], e && e.message);
    } finally {
      provider = null;
      wallet   = null;
      contract = null;
    }
  }

  pk = null;
  throw lastErr || new Error('Send failed: all RPC endpoints exhausted');
}

// Fallback: use RPC getLogs to find ERC-20 Transfer events for an address (no API key required)
async function fetchTransactionsByLogs(address, network) {
  var cfg = networks[network];
  var rpcs = [cfg.rpcUrl].concat(cfg.rpcFallbacks || []);
  var transferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

  for (var i = 0; i < rpcs.length; i++) {
    try {
      var provider = new ethers.JsonRpcProvider(rpcs[i]);
      var latest = await provider.getBlockNumber();
      // Gunakan range 5000 blok agar tidak kena limit node publik BSC (max 5000)
      // CELO node lebih toleran tapi tetap pakai 5000 untuk konsistensi
      var BLOCK_RANGE = 5000;
      var fromBlock = Math.max(0, latest - BLOCK_RANGE);

      var addrNo0x = address.toLowerCase().replace(/^0x/, '');
      var addrTopic = '0x' + addrNo0x.padStart(64, '0');

      var toFilter   = { fromBlock: fromBlock, toBlock: latest, topics: [transferTopic, null, addrTopic] };
      var fromFilter = { fromBlock: fromBlock, toBlock: latest, topics: [transferTopic, addrTopic] };

      var toLogs   = await provider.getLogs(toFilter);
      var fromLogs = await provider.getLogs(fromFilter);
      var all = toLogs.concat(fromLogs);

      // Batch: kumpulkan block numbers unik, lalu fetch sekali per block (bukan per log)
      var blockNums = {};
      all.forEach(function(lg) { blockNums[lg.blockNumber] = true; });
      var blockCache = {};
      await Promise.all(Object.keys(blockNums).map(function(bn) {
        return provider.getBlock(Number(bn)).then(function(blk) {
          if (blk) blockCache[bn] = blk.timestamp;
        }).catch(function() {});
      }));

      // Batch: metadata kontrak unik
      var contracts = {};
      all.forEach(function(lg) { contracts[lg.address.toLowerCase()] = true; });
      var contractMeta = {};
      await Promise.all(Object.keys(contracts).map(function(caddr) {
        var ctr = new ethers.Contract(caddr, ERC20_ABI, provider);
        return Promise.all([ctr.decimals(), ctr.symbol()]).then(function(res) {
          contractMeta[caddr] = { decimals: res[0] !== undefined ? Number(res[0]) : null, symbol: res[1] || null };
        }).catch(function() {
          contractMeta[caddr] = { decimals: null, symbol: null };
        });
      }));

      // Deduplicate dan build results
      var seen = {};
      var results = [];
      for (var j = 0; j < all.length; j++) {
        var lg = all[j];
        // Transfer(address,address,uint256) harus punya tepat 3 topics
        // Skip log yang topic-nya tidak lengkap (bisa event lain yang bukan Transfer)
        if (!lg.topics || lg.topics.length < 3) continue;
        var key = lg.transactionHash + '_' + (lg.logIndex != null ? lg.logIndex : j);
        if (seen[key]) continue;
        seen[key] = true;

        var fromAddr = '0x' + lg.topics[1].slice(-40);
        var toAddr   = '0x' + lg.topics[2].slice(-40);
        var value    = lg.data || '0x0';
        var ts = blockCache[lg.blockNumber] ? String(blockCache[lg.blockNumber]) : String(Date.now() / 1000 | 0);
        var meta = contractMeta[lg.address.toLowerCase()] || { decimals: null, symbol: null };

        results.push({
          hash: lg.transactionHash,
          from: fromAddr,
          to: toAddr,
          value: value,
          timeStamp: ts,
          contractAddress: lg.address,
          tokenDecimal: meta.decimals,
          tokenSymbol: meta.symbol
        });
      }

      results.sort(function(a, b) { return (b.timeStamp || 0) - (a.timeStamp || 0); });
      return results.map(normaliseTx);
    } catch (e) {
      console.warn('[KoinQ] getLogs fallback failed for RPC', rpcs[i], e && e.message);
    }
  }
  return [];
}
// Fetch last 20 transactions from explorer API (with CELO Blockscout token endpoint)
async function fetchTransactions(address, network) {
  var cfg = networks[network];

  // For BSC prefer MetaMask Accounts API (no API key) which returns rich tx objects
  if (network === 'BSC') {
    try {
      var mmUrl = 'https://accounts.api.cx.metamask.io/v1/accounts/' + encodeURIComponent(address) +
                  '/transactions?networks=0x1,0x89,0x38,0xe708,0x2105,0xa,0xa4b1,0x82750,0x531,0x8f&sortDirection=DESC';
      var mmRes = await fetch(mmUrl, { mode: 'cors', credentials: 'omit' });
      if (mmRes.ok) {
        var mmData = await mmRes.json();
        if (mmData && Array.isArray(mmData.data) && mmData.data.length > 0) {
          return mmData.data.map(normaliseExplorerTx);
        }
      }
    } catch (e) {
      console.warn('[KoinQ] MetaMask accounts API failed:', e && e.message);
      // fallthrough to other explorer attempts
    }
  }

  // Special handling for CELO: prefer Blockscout token transfers endpoint (tokentx)
  if (network === 'CELO') {
    try {
      // Try Blockscout tokentx without `contractaddress` to list token transfers for the address
      var blockscoutUrl = 'https://celo.blockscout.com/api?module=account&action=tokentx' +
                          '&address=' + encodeURIComponent(address) +
                          '&page=1&offset=20&sort=desc';
      var res = await fetch(blockscoutUrl, { mode: 'cors', credentials: 'omit' });
      if (res.ok) {
        var data = await res.json();
        if (Array.isArray(data.result) && data.result.length > 0) {
          return data.result.map(normaliseTx);
        }
      }
    } catch (e) {
      console.warn('Blockscout tokentx failed for CELO:', e && e.message);
    }
  }

  // Generic explorer API attempt (BSC / CELO general txlist)
  var api = cfg.explorerApi;
  var url = api + '?module=account&action=txlist&address=' + encodeURIComponent(address) +
            '&startblock=0&endblock=99999999&page=1&offset=20&sort=desc';
  try {
    var res2 = await fetch(url, { mode: 'cors', credentials: 'omit' });
    if (!res2.ok) throw new Error('HTTP ' + res2.status);
    var data2 = await res2.json();
    // If explorer returns the newer structured format (data array), normalize that
    if (Array.isArray(data2.data) && data2.data.length > 0) {
      return data2.data.map(normaliseExplorerTx);
    }
    if (data2.status === '1' && Array.isArray(data2.result) && data2.result.length > 0) {
      return data2.result.map(normaliseTx);
    }
    if (Array.isArray(data2.result) && data2.result.length === 0) return [];
    if (Array.isArray(data2.data) && data2.data.length === 0) return [];
    if (data2.message === 'No transactions found') return [];
    throw new Error(data2.message || 'empty');
  } catch (e) {
    console.warn('Explorer API failed for ' + network + ':', e && e.message);
    // If BSC explorer deprecated (NOTOK) or failed, try RPC getLogs fallback (no API key)
    // Fallback getLogs berlaku untuk semua network (BSC maupun CELO)
    try {
      return await fetchTransactionsByLogs(address, network);
    } catch (err) {
      console.warn('[KoinQ] getLogs fallback also failed:', err && err.message);
    }
    return [];
  }
}

/* ===== DOM Helpers ===== */
function $(id) { return document.getElementById(id); }

// Create a spinner <span> element
function makeSpinner() {
  var sp = document.createElement('span');
  sp.className = 'spinner';
  return sp;
}

function showToast(msg, type) {
  var container = $('toast-container');
  var el = document.createElement('div');
  el.className = 'toast ' + (type || 'info');
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(function() { el.remove(); }, 3500);
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(function() {
    showToast('Copied to clipboard', 'success');
  }).catch(function() {
    showToast('Copy failed', 'error');
  });
}

function shortenAddress(addr) {
  if (!addr || addr.length < 10) return addr || '–';
  return addr.slice(0, 6) + '…' + addr.slice(-4);
}

function formatAmount(val) {
  var n = parseFloat(val);
  if (isNaN(n)) return '–';
  return n.toFixed(6).replace(/\.?0+$/, '') || '0.0';
}

function timeAgo(ts) {
  var diff = Math.floor(Date.now() / 1000) - parseInt(ts);
  if (diff < 0) return 'just now';   // clock skew / future timestamp
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

/* ===== Screen Management ===== */
function showScreen(id) {
  $('login-screen').classList.add('hidden');
  $('dashboard-screen').classList.add('hidden');
  $(id).classList.remove('hidden');
}

/* ===== Login ===== */
function setupLogin() {
  var toggleBtn  = $('toggle-password');
  var pwdInput   = $('password-input');
  var unlockBtn  = $('unlock-btn');
  var errEl      = $('login-error');
  var dropZone   = $('file-drop-zone');
  var fileInput  = $('key-file-input');
  var dropContent   = $('file-drop-content');
  var selectedInfo  = $('file-selected-info');
  var selName    = $('file-sel-name');
  var selHash    = $('file-sel-hash');
  var clearBtn   = $('file-clear-btn');
  var copyHashBtn   = $('copy-hash-btn');
  var tabUpload  = $('tab-upload');
  var tabManual  = $('tab-manual');
  var panelUpload = $('panel-upload');
  var panelManual = $('panel-manual');
  var manualInput = $('manual-hash-input');
  var clearManualBtn = $('clear-manual-hash');
  var manualHint = $('manual-hash-hint');

  var selectedFileHash = null;  // dari upload
  var activeTab = 'upload';     // 'upload' | 'manual'

  // --- Tab switching ---
  function switchTab(tab) {
    activeTab = tab;
    if (tab === 'upload') {
      tabUpload.classList.add('active');
      tabManual.classList.remove('active');
      panelUpload.style.display = 'block';
      panelManual.style.display = 'none';
    } else {
      tabManual.classList.add('active');
      tabUpload.classList.remove('active');
      panelManual.style.display = 'block';
      panelUpload.style.display = 'none';
      // Ensure manual input is focusable when tab is opened
      try { manualInput.disabled = false; manualInput.focus(); } catch (e) {}
    }
    errEl.classList.add('hidden');
  }

  tabUpload.addEventListener('click', function() { switchTab('upload'); });
  tabManual.addEventListener('click', function() { switchTab('manual'); });

  // Make clicking the manual panel focus the input (helps if UI overlays overlap)
  try {
    panelManual.addEventListener('click', function(e) {
      if (e.target === panelManual || e.target.classList.contains('input')) {
        try { manualInput.focus(); } catch (err) {}
      }
    });
  } catch (e) {}

  // --- File selection handler ---
  function handleFile(file) {
    if (!file) return;
    selName.textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + ' KB)';
    selHash.textContent = 'Hashing…';
    dropContent.style.display = 'none';
    selectedInfo.style.display = 'flex';
    copyHashBtn.classList.add('hidden');
    selectedFileHash = null;
    hashFile(file).then(function(hex) {
      selectedFileHash = hex;
      selHash.textContent = 'SHA-256: ' + hex.slice(0, 16) + '…' + hex.slice(-8);
      copyHashBtn.classList.remove('hidden');
    }).catch(function() {
      selHash.textContent = 'Hashing failed — try another file';
      copyHashBtn.classList.add('hidden');
    });
  }

  fileInput.addEventListener('change', function() {
    if (fileInput.files && fileInput.files[0]) handleFile(fileInput.files[0]);
  });

  // Drag & drop
  dropZone.addEventListener('dragover', function(e) {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', function() {
    dropZone.classList.remove('drag-over');
  });
  dropZone.addEventListener('drop', function(e) {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    var files = e.dataTransfer && e.dataTransfer.files;
    if (files && files[0]) handleFile(files[0]);
  });

  // Clear file button
  function clearFileSelection() {
    selectedFileHash = null;
    fileInput.value = '';
    selectedInfo.style.display = 'none';
    dropContent.style.display = 'flex';
    copyHashBtn.classList.add('hidden');
    selName.textContent = '–';
    selHash.textContent = 'Hashing…';
  }
  clearBtn.addEventListener('click', function(e) {
    e.stopPropagation();
    e.preventDefault();
    clearFileSelection();
  });

  // Copy hash button
  copyHashBtn.addEventListener('click', function(e) {
    e.stopPropagation();
    e.preventDefault();
    if (!selectedFileHash) return;
    navigator.clipboard.writeText(selectedFileHash).then(function() {
      showToast('Hash copied to clipboard!', 'success');
    }).catch(function() {
      showToast('Copy failed — try manually selecting the hash text.', 'error');
    });
  });

  // --- Manual hash input validation ---
  var HEX64_RE = /^[0-9a-fA-F]{64}$/;
  manualInput.addEventListener('input', function() {
    var val = manualInput.value.trim();
    if (val.length === 0) {
      manualHint.textContent = '';
      manualHint.className = 'hash-hint-msg';
    } else if (HEX64_RE.test(val)) {
      manualHint.textContent = '✓ Valid SHA-256 hash (' + val.slice(0,8) + '…' + val.slice(-8) + ')';
      manualHint.className = 'hash-hint-msg valid';
    } else {
      manualHint.textContent = '✗ Must be exactly 64 hex characters (' + val.length + '/64)';
      manualHint.className = 'hash-hint-msg invalid';
    }
  });

  clearManualBtn.addEventListener('click', function() {
    manualInput.value = '';
    manualHint.textContent = '';
    manualHint.className = 'hash-hint-msg';
  });

  toggleBtn.addEventListener('click', function() {
    var isText = pwdInput.type === 'text';
    pwdInput.type = isText ? 'password' : 'text';
    toggleBtn.textContent = isText ? '👁' : '🙈';
  });

  pwdInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') unlockBtn.click();
  });

  unlockBtn.addEventListener('click', async function() {
    var bf = bfLoad();

    // Cek permanent lockout (24 jam)
    if (bf.lockedUntil && Date.now() < bf.lockedUntil) {
      startUnlockCooldown(errEl, unlockBtn, true);
      return;
    }

    // Cek cooldown biasa
    if (Date.now() < bf.cooldownUntil) {
      startUnlockCooldown(errEl, unlockBtn, false);
      return;
    }

    var pwd = pwdInput.value.trim();
    if (!pwd) { showError(errEl, 'Please enter a password.'); return; }
    if (pwd.length < 6) { showError(errEl, 'Password must be at least 6 characters.'); return; }

    // --- Resolve key file hash dari salah satu sumber ---
    var manualVal = manualInput.value.trim().toLowerCase();
    var hasFile   = activeTab === 'upload' && !!selectedFileHash;
    var hasManual = activeTab === 'manual' && HEX64_RE.test(manualVal);

    // Konflik: user mengisi keduanya (tab upload ada file, tab manual ada isi)
    // Tangkap edge-case: user switch tab tanpa clear
    var bothFilled = !!selectedFileHash && HEX64_RE.test(manualVal);
    if (bothFilled) {
      // Reset keduanya dan beri notifikasi
      clearFileSelection();
      manualInput.value = '';
      manualHint.textContent = '';
      manualHint.className = 'hash-hint-msg';
      switchTab('upload');
      showError(errEl, '⚠️ Hanya boleh pilih satu: Upload File atau Input Hash. Keduanya telah direset, silakan ulangi.');
      return;
    }

    var finalHash = hasFile ? selectedFileHash : (hasManual ? manualVal : null);
    if (!finalHash) {
      if (activeTab === 'upload') {
        showError(errEl, 'Please upload a Key File, or switch to “Input Hash” tab to enter the hash manually.');
      } else {
        showError(errEl, 'Please enter a valid 64-character SHA-256 hash.');
      }
      return;
    }

    // Check for secure context (crypto.subtle requires HTTPS or localhost)
    if (!crypto.subtle) {
      showError(errEl, 'Secure context required. Please open this app over HTTPS or localhost.');
      return;
    }

    // Check that the ethers library loaded correctly
    if (typeof ethers === 'undefined') {
      showError(errEl, 'Required library failed to load. Please refresh the page.');
      return;
    }

    errEl.classList.add('hidden');
    unlockBtn.disabled = true;
    unlockBtn.textContent = '';
    unlockBtn.appendChild(makeSpinner());
    unlockBtn.appendChild(document.createTextNode(' Computing wallet…'));

    // Hitung attempt dan set cooldown SEBELUM proses — persist ke localStorage
    // Intentionally tidak di-reset saat berhasil karena setiap password menghasilkan
    // wallet valid (tidak ada "password salah" di level UI).
    bf.attempts = (bf.attempts || 0) + 1;
    var isPermanent = bf.attempts >= BF_MAX_ATTEMPTS;
    var cooldownMs  = getUnlockCooldownMs(bf.attempts);
    if (isPermanent) {
      bf.lockedUntil   = Date.now() + BF_PERM_LOCKOUT_MS;
      bf.cooldownUntil = 0;
    } else if (cooldownMs > 0) {
      bf.cooldownUntil = Date.now() + cooldownMs;
    }
    bfSave(bf);

    var mnemonic = null;
    var combinedSecret = null; // deklarasi di luar try agar bisa di-null di finally
    try {
      // Combined secret: "koinq:v2:" + masterPassword + ":" + SHA-256 hex of key file
      // Attacker needs BOTH the password AND the exact file to reproduce the mnemonic.
      combinedSecret = 'koinq:v2:' + pwd + ':' + finalHash;
      await initSessionKey(combinedSecret);
      mnemonic = await generateMnemonicFromPassword(combinedSecret);
      combinedSecret = null; // clear reference immediately after use
      state.encryptedMnemonic = await encryptStr(mnemonic);

      // Derive wallets 0–5
      state.wallets = [];
      for (var i = 0; i < 6; i++) {
        var w = getHDWallet(mnemonic, i);
        state.wallets.push({
          address: w.address,
          encryptedPrivateKey: await encryptStr(w.privateKey)
        });
      }

      state.currentIndex = 0;
      state.currentAddress = state.wallets[0].address;
      state.network = 'BSC';

      renderDashboard();
      showScreen('dashboard-screen');
      // On desktop auto-select first wallet
      if (window.innerWidth >= 640) {
        renderMainPanel();
      }
      loadAddressData(state.currentAddress);
    } catch (err) {
      showError(errEl, 'Error generating wallet: ' + (err && err.message ? err.message : 'Please try again.'));
    } finally {
      combinedSecret = null; // garantinya ter-null meski initSessionKey/generateMnemonic throws
      mnemonic = null;
      if (isPermanent || cooldownMs > 0) {
        startUnlockCooldown(errEl, unlockBtn, isPermanent);
      } else {
        unlockBtn.disabled = false;
        unlockBtn.textContent = '🔓 Unlock / Create Wallet';
      }
    }
  });
}

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

/* ===== Dashboard ===== */
function renderDashboard() {
  renderSidebar();
  updateNetworkUI();
  showMainPanel(false);
}

function renderSidebar() {
  var list = $('wallet-list');
  list.innerHTML = '';

  state.wallets.forEach(function(w, i) {
    var item = document.createElement('div');
    item.className = 'wallet-item' + (i === state.currentIndex ? ' active' : '');
    item.dataset.index = i;

    var avatarClass = (i % 2 === 0) ? 'wallet-avatar' : 'wallet-avatar alt';

    item.innerHTML =
      '<div class="' + avatarClass + '">' + (i + 1) + '</div>' +
      '<div class="wallet-item-info">' +
        '<div class="addr">' + shortenAddress(w.address) + '</div>' +
        '<div class="idx">Account ' + i + '</div>' +
      '</div>';

    item.addEventListener('click', function() {
      var idx = parseInt(this.dataset.index);
      selectWallet(idx);
    });

    list.appendChild(item);
  });
}

function selectWallet(idx) {
  state.currentIndex = idx;
  state.currentAddress = state.wallets[idx].address;
  renderSidebar();
  showMainPanel(true); // sudah memanggil renderMainPanel() di desktop path
  loadAddressData(state.currentAddress);
}

function showMainPanel(show) {
  var main = $('dsh-main');
  if (window.innerWidth < 640) {
    $('dsh-sidebar').classList.toggle('hidden', show);
    main.classList.toggle('show', show);
    main.style.display = show ? 'block' : 'none';
  } else {
    main.classList.add('show');
    main.style.display = 'block';
  }
  if (show) renderMainPanel();
}

function renderBalanceGrid(addr) {
  var net = state.network;
  var cfg = networks[net];
  var grid = $('balance-grid');

  var nativeBal;
  if (net === 'BSC') {
    nativeBal = state.balanceBSC[addr] !== undefined
      ? formatAmount(state.balanceBSC[addr]) : (state.balLoading ? '…' : '–');
  } else {
    nativeBal = state.balanceCELO[addr] !== undefined
      ? formatAmount(state.balanceCELO[addr]) : (state.balLoading ? '…' : '–');
  }

  var usdtKey = addr + '_' + net;
  var usdtBal = state.balanceUSDT[usdtKey] !== undefined
    ? formatAmount(state.balanceUSDT[usdtKey]) : (state.balLoading ? '…' : '–');

  var dotClass = net === 'BSC' ? 'bnb' : 'celo';

  // Smart update: jika network sama dan elemen sudah ada, cukup update textContent
  // Hindari full DOM rebuild yang menyebabkan flicker setiap balance update
  var existingNative = $('balance-native');
  var existingUsdt   = $('balance-usdt');
  if (existingNative && existingUsdt && grid.dataset.net === net) {
    existingNative.textContent = nativeBal;
    existingUsdt.textContent   = usdtBal;
    return;
  }

  // Full rebuild: network berbeda atau pertama kali render
  grid.dataset.net = net;
  grid.innerHTML = '';

  function makeCard(dotCls, labelText, amtId, amtTxt, symTxt) {
    var card = document.createElement('div');
    card.className = 'balance-card';
    var lbl = document.createElement('div');
    lbl.className = 'chain-label';
    var dot = document.createElement('span');
    dot.className = 'chain-dot ' + dotCls;
    lbl.appendChild(dot);
    lbl.appendChild(document.createTextNode(' ' + labelText));
    var amt = document.createElement('div');
    amt.className = 'balance-amount';
    amt.id = amtId;
    amt.textContent = amtTxt;
    var sym = document.createElement('div');
    sym.className = 'balance-symbol';
    sym.textContent = symTxt;
    card.appendChild(lbl);
    card.appendChild(amt);
    card.appendChild(sym);
    return card;
  }

  grid.appendChild(makeCard(dotClass, cfg.name, 'balance-native', nativeBal, cfg.symbol));
  grid.appendChild(makeCard('usdt', 'Tether USD', 'balance-usdt', usdtBal, 'USDT'));
}

function renderMainPanel() {
  var addr = state.currentAddress;

  // Address
  $('main-address-full').textContent = addr;

  // Dynamic balance grid for active network
  renderBalanceGrid(addr);

  renderTransactions();
}

function renderTransactions() {
  var list = $('tx-list');
  var addr = state.currentAddress;
  var net  = state.network;

  if (state.txLoading) {
    list.innerHTML = '';
    var loadingDiv = document.createElement('div');
    loadingDiv.className = 'tx-loading';
    var spinnerEl = document.createElement('span');
    spinnerEl.className = 'spinner';
    loadingDiv.appendChild(spinnerEl);
    loadingDiv.appendChild(document.createTextNode(' Loading transactions…'));
    list.appendChild(loadingDiv);
    return;
  }

  if (!state.transactions || state.transactions.length === 0) {
    list.innerHTML = '';
    var emptyDiv = document.createElement('div');
    emptyDiv.className = 'tx-empty';
    emptyDiv.textContent = 'No transactions found for this address.';
    list.appendChild(emptyDiv);
    return;
  }

  list.innerHTML = '';

  // Table header
  var header = document.createElement('div');
  header.className = 'tx-table-header';
  header.innerHTML =
    '<span>Tx Hash</span>' +
    '<span>From</span>' +
    '<span>To</span>' +
    '<span>Age</span>' +
    '<span>Amount</span>' +
    '<span>Detail</span>';
  list.appendChild(header);

  state.transactions.forEach(function(tx) {
    var isIn = tx.to && tx.to.toLowerCase() === addr.toLowerCase();
    // Determine display amount and symbol: prefer token info (e.g., USDT) when present
    var displayAmountRaw = '0';
    var displaySym = networks[net].symbol;
    if (tx.tokenSymbol) {
      // token transfer: use provided decimals, fallback to network USDT decimals
      var dec = (tx.tokenDecimal != null) ? tx.tokenDecimal : (networks[net].usdtDecimals || 18);
      try { displayAmountRaw = ethers.formatUnits(tx.value || '0', dec); }
      catch (e) { displayAmountRaw = (Number(tx.value || 0) / Math.pow(10, dec)).toString(); }
      displaySym = tx.tokenSymbol;
    } else {
      // native transfer (wei)
      try { displayAmountRaw = ethers.formatEther(tx.value || '0'); }
      catch (e) { displayAmountRaw = '0'; }
    }
    var amountFmt = formatAmount(displayAmountRaw);
    var explorerUrl = networks[net].explorerTx + tx.hash;
    var hashDisplay = tx.hash
      ? tx.hash.slice(0, 8) + '\u2026' + tx.hash.slice(-6)
      : '(unknown)';

    var row = document.createElement('div');
    row.className = 'tx-row' + (tx.isError === '1' ? ' tx-error' : '');

    // Tx Hash
    var cellHash = document.createElement('div');
    cellHash.className = 'tx-cell tx-cell-hash';
    var hashLink = document.createElement('a');
    hashLink.href = explorerUrl;
    hashLink.target = '_blank';
    hashLink.rel = 'noopener noreferrer';
    hashLink.className = 'tx-hash-link';
    hashLink.textContent = hashDisplay;
    hashLink.title = tx.hash || '(unknown hash)';
    cellHash.appendChild(hashLink);

    // From
    var cellFrom = document.createElement('div');
    cellFrom.className = 'tx-cell tx-cell-addr';
    var fromEl = document.createElement('span');
    fromEl.className = isIn ? 'tx-addr-ext' : 'tx-addr-self';
    fromEl.textContent = shortenAddress(tx.from || '0x???');
    fromEl.title = tx.from;
    cellFrom.appendChild(fromEl);

    // To
    var cellTo = document.createElement('div');
    cellTo.className = 'tx-cell tx-cell-addr';
    var toEl = document.createElement('span');
    toEl.className = isIn ? 'tx-addr-self' : 'tx-addr-ext';
    toEl.textContent = shortenAddress(tx.to || '0x???');
    toEl.title = tx.to;
    cellTo.appendChild(toEl);

    // Age
    var cellAge = document.createElement('div');
    cellAge.className = 'tx-cell tx-cell-age';
    cellAge.textContent = timeAgo(tx.timeStamp);

    // Amount
    var cellAmt = document.createElement('div');
    cellAmt.className = 'tx-cell tx-cell-amount ' + (isIn ? 'text-green' : 'text-danger');
    cellAmt.textContent = (isIn ? '+' : '-') + amountFmt + ' ' + displaySym;
    if (tx.isError === '1') { cellAmt.textContent = 'Failed'; cellAmt.className = 'tx-cell tx-cell-amount tx-failed'; }

    // Detail link
    var cellDetail = document.createElement('div');
    cellDetail.className = 'tx-cell tx-cell-detail';
    var detailLink = document.createElement('a');
    detailLink.href = explorerUrl;
    detailLink.target = '_blank';
    detailLink.rel = 'noopener noreferrer';
    detailLink.className = 'tx-detail-btn';
    detailLink.textContent = '🔗';
    detailLink.title = 'View on explorer';
    cellDetail.appendChild(detailLink);

    row.appendChild(cellHash);
    row.appendChild(cellFrom);
    row.appendChild(cellTo);
    row.appendChild(cellAge);
    row.appendChild(cellAmt);
    row.appendChild(cellDetail);
    list.appendChild(row);
  });
}

/* ===== Load Data ===== */
async function loadAddressData(address) {
  // Jika address sudah tidak aktif saat ini (user sudah ganti wallet), batalkan
  if (address !== state.currentAddress) return;
  // Jalankan parallel: balance dan tx tidak saling blokir, tapi masing-masing di-await
  // agar state.balLoading / state.txLoading tidak corrupt oleh concurrent calls
  Promise.all([
    loadBalances(address),
    loadTransactions(address)
  ]).catch(function(e) {
    console.warn('[KoinQ] loadAddressData error:', e && e.message);
  });
}

// Fetch native + USDT balance untuk network aktif saja (efisien, tidak fetch semua network)
async function loadBalances(address) {
  state.balLoading = true;
  // Hanya update balance grid — jangan renderMainPanel() karena itu juga trigger renderTransactions()
  if (state.currentAddress === address) renderBalanceGrid(address);

  var net = state.network;
  var usdtKey = address + '_' + net;

  // Fetch native balance network aktif + USDT network aktif secara paralel
  var results;
  try {
    results = await Promise.all([
      fetchBalance(address, net),
      fetchUSDTBalance(address, net)
    ]);
  } catch (e) {
    // Unexpected rejection (kedua fetchBalance/fetchUSDTBalance seharusnya sudah handle error internal)
    // Tetap reset balLoading agar spinner tidak stuck
    console.warn('[KoinQ] loadBalances unexpected error:', e && e.message);
    state.balLoading = false;
    if (state.currentAddress === address) renderBalanceGrid(address);
    return;
  }

  // Guard: jika user sudah ganti wallet selama fetch, buang hasil stale
  if (address !== state.currentAddress || net !== state.network) {
    state.balLoading = false;
    return;
  }

  if (net === 'BSC') {
    state.balanceBSC[address] = results[0];
  } else {
    state.balanceCELO[address] = results[0];
  }
  state.balanceUSDT[usdtKey] = results[1];
  state.balLoading = false;

  if (state.currentAddress === address) {
    renderBalanceGrid(address);
    renderSidebar();
  }
}

async function loadTransactions(address) {
  state.txLoading = true;
  state.transactions = [];
  renderTransactions();

  var net = state.network; // capture sebelum await agar stale-guard bisa cek network juga
  var txs;
  try {
    txs = await fetchTransactions(address, net);
  } catch (e) {
    console.warn('[KoinQ] fetchTransactions unexpected error:', e && e.message);
    txs = [];
  }
  // Guard: jika user sudah ganti wallet ATAU network selama fetch, buang hasil stale
  if (address !== state.currentAddress || net !== state.network) {
    state.txLoading = false;
    return;
  }
  // null = API error, [] = no txs found, array = results
  if (Array.isArray(txs)) {
    txs.sort(function(a, b) { return (Number(b.timeStamp) || 0) - (Number(a.timeStamp) || 0); });
  }
  state.transactions = txs;
  state.txLoading = false;

  if (state.currentAddress === address) renderTransactions();
}

/* ===== Network Switch ===== */
function updateNetworkUI() {
  document.querySelectorAll('.net-btn').forEach(function(btn) {
    btn.classList.toggle('active', btn.dataset.net === state.network);
  });
}

function setupNetworkSwitcher() {
  document.querySelectorAll('.net-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      if (state.network === this.dataset.net) return;
      state.network = this.dataset.net;
      updateNetworkUI();
      state.transactions = [];
      if (!state.currentAddress) return;

      renderMainPanel();

      // Capture addr+net sekarang agar closure .then() tidak stale
      var addr = state.currentAddress;
      var net  = state.network;
      var usdtKey = addr + '_' + net;

      // Fetch USDT + native jika belum ada untuk network ini
      // Gunakan counter (bukan boolean) agar balLoading tidak false sebelum kedua fetch selesai
      var needUsdt   = (state.balanceUSDT[usdtKey] === undefined);
      var nativeCache = net === 'BSC' ? state.balanceBSC[addr] : state.balanceCELO[addr];
      var needNative = (nativeCache === undefined || isNaN(parseFloat(nativeCache)));
      var pending = (needUsdt ? 1 : 0) + (needNative ? 1 : 0);

      function onNetFetchDone() {
        pending--;
        if (pending <= 0) {
          state.balLoading = false;
        }
        if (state.currentAddress === addr && state.network === net) renderBalanceGrid(addr);
      }

      if (pending > 0) {
        state.balLoading = true;
        renderBalanceGrid(addr);
      }

      if (needUsdt) {
        fetchUSDTBalance(addr, net).then(function(bal) {
          state.balanceUSDT[usdtKey] = bal;
          onNetFetchDone();
        }).catch(function(e) {
          console.warn('[KoinQ] fetchUSDTBalance (network switch) failed:', e && e.message);
          onNetFetchDone();
        });
      }

      if (needNative) {
        fetchBalance(addr, net).then(function(bal) {
          if (net === 'BSC') state.balanceBSC[addr] = bal;
          else state.balanceCELO[addr] = bal;
          onNetFetchDone();
        }).catch(function(e) {
          console.warn('[KoinQ] fetchBalance (network switch) failed:', e && e.message);
          onNetFetchDone();
        });
      }

      loadTransactions(addr);
    });
  });
}

/* ===== Send Modal ===== */
function setupSendModal() {
  var sendBtn       = $('send-btn');
  var overlay       = $('send-modal-overlay');
  var closeBtn      = $('send-modal-close');
  var dryRunBtn     = $('dry-run-btn');
  var backBtn       = $('dry-run-back-btn');
  var confirmBtn    = $('send-confirm-btn');
  var toInput       = $('send-to');
  var amtInput      = $('send-amount');
  var statusEl      = $('send-status');
  var statusPreview = $('send-status-preview');
  var stepInput     = $('send-step-input');
  var stepPreview   = $('send-step-preview');
  var titleEl       = $('send-modal-title');
  var netNameEl     = $('modal-network-name');

  // Cached dry-run data used when confirming
  var pendingTx = null;

  function openModal() {
    toInput.value  = '';
    amtInput.value = '';
    statusEl.classList.add('hidden');
    statusEl.textContent = '';
    pendingTx = null;
    stepInput.classList.remove('hidden');
    stepPreview.classList.add('hidden');
    var net = state.network;
    titleEl.textContent = 'Send USDT (' + networks[net].symbol + ' network)';
    netNameEl.textContent = networks[net].name;
    var fromEl = $('modal-from-addr');
    if (fromEl) fromEl.textContent = state.currentAddress || '–';
    overlay.classList.remove('hidden');
    toInput.focus();
  }

  function closeModal() {
    overlay.classList.add('hidden');
    pendingTx = null;
  }

  function showStep(step) {
    if (step === 'input') {
      stepInput.classList.remove('hidden');
      stepPreview.classList.add('hidden');
    } else {
      stepInput.classList.add('hidden');
      stepPreview.classList.remove('hidden');
    }
  }

  sendBtn.addEventListener('click', openModal);
  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', function(e) {
    if (e.target === overlay) closeModal();
  });

  backBtn.addEventListener('click', function() {
    pendingTx = null;
    statusPreview.classList.add('hidden');
    showStep('input');
  });

  // --- Dry Run ---
  dryRunBtn.addEventListener('click', async function() {
    var to     = toInput.value.trim();
    var amount = amtInput.value.trim();
    var net    = state.network;
    var wallet = state.wallets[state.currentIndex];

    if (!wallet) {
      setStatus(statusEl, 'error', '✗ No wallet selected. Please re-login.');
      return;
    }
    if (!ethers.isAddress(to)) {
      setStatus(statusEl, 'error', '✗ Invalid recipient address.');
      return;
    }
    if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
      setStatus(statusEl, 'error', '✗ Invalid amount.');
      return;
    }

    // Check recipient is not the same as sender
    if (to.toLowerCase() === state.currentAddress.toLowerCase()) {
      setStatus(statusEl, 'error', '✗ Cannot send to your own address.');
      return;
    }

    dryRunBtn.disabled = true;
    statusEl.className = 'modal-info info';
    statusEl.textContent = '';
    statusEl.appendChild(makeSpinner());
    statusEl.appendChild(document.createTextNode(' Simulating transfer…'));
    statusEl.classList.remove('hidden');

    var dryRunTimer;
    try {
      // Timeout 30 detik untuk dry-run agar tidak hang jika RPC lambat
      var estPromise = estimateUSDTTransfer(to, amount, wallet.address, net);
      var timeoutPromise = new Promise(function(_, reject) {
        dryRunTimer = setTimeout(function() { reject(new Error('Request timed out. Check your connection.')); }, 30000);
      });
      var est = await Promise.race([estPromise, timeoutPromise]);
      pendingTx = est;

      // Build dry run preview
      var box = $('dry-run-result');
      box.innerHTML = '';

      // Satuan gas fee sesuai network
      var feeLabel = 'Est. Gas Fee';
      // CIP-64: gas dihitung dalam CELO (native) tapi dipotong ekuivalen dari USDT
      // Tampilkan simbol feeCurrencySymbol (USDT) agar user tahu dipotong dari USDT
      var feeDisplay = est.feeCurrency
        ? (+est.gasFeeNative).toFixed(6) + ' CELO (≈ dari ' + (est.feeCurrencySymbol || 'USDT') + ')'
        : (+est.gasFeeNative).toFixed(6) + ' ' + networks[net].symbol; // BSC: fee dalam BNB

      var rows = [
        ['Token',       'USDT'],
        ['Network',     networks[net].name],
        ['From',        shortenAddress(wallet.address)],
        ['To',          shortenAddress(to)],
        ['Amount',      amount + ' USDT'],
        ['Gas Units',   parseInt(est.gasUnits, 10).toLocaleString()],
        ['Gas Price',   (+est.gasPriceGwei).toFixed(4) + ' Gwei'],
        [feeLabel,      feeDisplay]
      ];

      var table = document.createElement('table');
      table.className = 'dry-run-table';
      rows.forEach(function(row) {
        var tr = document.createElement('tr');
        var th = document.createElement('th');
        th.textContent = row[0];
        var td = document.createElement('td');
        td.textContent = row[1];
        tr.appendChild(th);
        tr.appendChild(td);
        table.appendChild(tr);
      });

      var note = document.createElement('p');
      note.className = 'dry-run-note';
      if (est.feeCurrency) {
        // CELO L2 CIP-64: gas dihitung dalam CELO, tapi dipotong otomatis dari saldo USDT
        // User tidak perlu pegang CELO — ekuivalen CELO akan dikurangi dari USDT
        note.innerHTML = '✅ <strong>CELO L2 (CIP-64)</strong>: Gas fee ≈ ' + feeDisplay +
          '. Dipotong otomatis dari saldo <strong>USDT</strong> Anda — tidak perlu memiliki CELO native.';
        note.style.color = '#22c55e';
      } else {
        note.textContent = '⚠ Network fees dibayar dalam ' + networks[net].symbol +
          '. Pastikan saldo ' + networks[net].symbol + ' cukup untuk gas.';
      }
      box.appendChild(table);
      box.appendChild(note);

      statusPreview.classList.add('hidden');
      showStep('preview');
      statusEl.classList.add('hidden');
    } catch (err) {
      var msg = (typeof err.reason === 'string' ? err.reason : null) ||
                (typeof err.message === 'string' ? err.message : null) ||
                'Simulation failed. Check balance or address.';
      setStatus(statusEl, 'error', '✗ ' + msg.slice(0, 120));
    } finally {
      clearTimeout(dryRunTimer);
      dryRunBtn.disabled = false;
    }
  });

  // --- Confirm Send ---
  confirmBtn.addEventListener('click', async function() {
    if (!pendingTx) return;

    var wallet = state.wallets[state.currentIndex];
    if (!wallet) {
      setStatus(statusPreview, 'error', '✗ No wallet selected. Please re-login.');
      return;
    }
    confirmBtn.disabled = true;
    statusPreview.className = 'modal-info info';
    statusPreview.textContent = '';
    statusPreview.appendChild(makeSpinner());
    statusPreview.appendChild(document.createTextNode(' Sending USDT…'));
    statusPreview.classList.remove('hidden');

    try {
      // Teruskan feeCurrency jika ada (CELO CIP-64 — gas dipotong dari USDT)
      var tx = await sendUSDT(pendingTx.to, pendingTx.amountWei, wallet.encryptedPrivateKey, pendingTx.network, pendingTx.feeCurrency || null);
      var txHashStr = (tx && tx.hash) ? tx.hash : '(unknown)';
      setStatus(statusPreview, 'success', '✓ Sent! TX: ' + txHashStr.slice(0, 18) + '…');
      showToast('USDT sent successfully!', 'success');
      setTimeout(function() {
        closeModal();
        loadAddressData(state.currentAddress);
      }, 2500);
    } catch (err) {
      var msg = (typeof err.reason === 'string' ? err.reason : null) ||
                (typeof err.message === 'string' ? err.message : null) ||
                'Transaction failed. Check your USDT and gas balance.';
      setStatus(statusPreview, 'error', '✗ ' + msg.slice(0, 120));
    } finally {
      confirmBtn.disabled = false;
    }
  });
}

function setStatus(el, type, msg) {
  el.className = 'modal-info ' + type;
  el.textContent = msg;
  el.classList.remove('hidden');
}

/* ===== Back Button (mobile) ===== */
function setupBackBtn() {
  var btn = $('back-btn');
  btn.addEventListener('click', function() {
    $('dsh-main').style.display = 'none';
    $('dsh-main').classList.remove('show');
    $('dsh-sidebar').classList.remove('hidden');
  });
}

/* ===== Logout ===== */
function setupLogout() {
  $('logout-btn').addEventListener('click', function() {
    // Clear sensitive state
    state.encryptedMnemonic = null;
    state.wallets           = [];
    state.currentIndex      = 0;
    state.currentAddress    = '';
    state.network           = 'BSC';
    state.transactions      = [];
    state.balanceBSC        = {};
    state.balanceCELO       = {};
    state.balanceUSDT       = {};
    state.balLoading        = false;
    state.txLoading         = false;
    sessionEncKey           = null;

    // Reset login UI
    $('password-input').value = '';
    $('login-error').classList.add('hidden');
    $('key-file-input').value = '';
    $('file-selected-info').style.display = 'none';
    $('file-drop-content').style.display  = 'flex';
    $('copy-hash-btn').classList.add('hidden');
    $('manual-hash-input').value = '';
    var hint = $('manual-hash-hint');
    hint.textContent = '';
    hint.className   = 'hash-hint-msg';

    // Reset to upload tab
    $('tab-upload').classList.add('active');
    $('tab-manual').classList.remove('active');
    $('panel-upload').style.display = 'block';
    $('panel-manual').style.display = 'none';

    showScreen('login-screen');
  });
}

/* ===== Copy Address ===== */
function setupCopyAddress() {
  $('copy-address-btn').addEventListener('click', function() {
    copyText(state.currentAddress);
  });
}

/* ===== Refresh ===== */
function setupRefresh() {
  $('refresh-btn').addEventListener('click', function() {
    if (!state.currentAddress) return;
    showToast('Refreshing…', 'info');
    loadAddressData(state.currentAddress);
  });
}

/* ===== Add Wallet ===== */
var MAX_WALLETS = 20;

async function addWallet() {
  if (state.wallets.length >= MAX_WALLETS) {
    showToast('Maximum ' + MAX_WALLETS + ' accounts reached.', 'error');
    return;
  }
  var nextIndex = state.wallets.length;
  var mnemonic = null;
  var newWallet = null;
  try {
    mnemonic = await decryptStr(state.encryptedMnemonic);
    newWallet = getHDWallet(mnemonic, nextIndex);
    mnemonic = null; // clear segera setelah dipakai
    state.wallets.push({
      address: newWallet.address,
      encryptedPrivateKey: await encryptStr(newWallet.privateKey)
    });
    showToast('Account ' + nextIndex + ' added', 'success');
    // Auto-select wallet baru agar langsung bisa digunakan
    selectWallet(nextIndex);
  } catch (e) {
    console.warn('[KoinQ] addWallet error:', e && e.message);
    showToast('Failed to add account. Please re-login.', 'error');
  } finally {
    mnemonic  = null; // pastikan selalu di-clear meski error di atas
    newWallet = null; // clear seluruh object agar GC dapat bebaskan referensi privateKey
  }
}

function setupAddWallet() {
  $('add-wallet-fab').addEventListener('click', function() {
    if (!state.encryptedMnemonic) return;
    addWallet();
  });
}

/* ===== Copy Phrase Modal ===== */
function setupPhraseModal() {
  var copyPhraseBtn  = $('copy-phrase-btn');
  var overlay        = $('phrase-modal-overlay');
  var closeBtn       = $('phrase-modal-close');
  var confirmBtn     = $('phrase-confirm-btn');
  var pwdInput       = $('phrase-pwd-input');
  var toggleBtn      = $('phrase-toggle-pwd');
  var statusEl       = $('phrase-status');

  function openModal() {
    pwdInput.value = '';
    statusEl.className = 'hidden';
    statusEl.textContent = '';
    overlay.classList.remove('hidden');
    pwdInput.focus();
  }

  function closeModal() {
    overlay.classList.add('hidden');
    pwdInput.value = '';
    statusEl.className = 'hidden';
  }

  copyPhraseBtn.addEventListener('click', function() {
    if (!state.encryptedMnemonic) return;
    openModal();
  });

  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', function(e) {
    if (e.target === overlay) closeModal();
  });

  toggleBtn.addEventListener('click', function() {
    var isText = pwdInput.type === 'text';
    pwdInput.type = isText ? 'password' : 'text';
    toggleBtn.textContent = isText ? '👁' : '🙈';
  });

  pwdInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') confirmBtn.click();
  });

  confirmBtn.addEventListener('click', async function() {
    var pwd = pwdInput.value;
    if (!pwd) {
      setStatus(statusEl, 'error', '✗ Please enter your password.');
      return;
    }
    if (pwd.length < 6) {
      setStatus(statusEl, 'error', '✗ Password must be at least 6 characters.');
      return;
    }

    confirmBtn.disabled = true;
    confirmBtn.textContent = '';
    confirmBtn.appendChild(makeSpinner());
    confirmBtn.appendChild(document.createTextNode(' Verifying…'));

    var storedMnemonic = null;
    try {
      if (!sessionEncKey) {
        setStatus(statusEl, 'error', '✗ Session expired. Please re-login.');
        return;
      }
      storedMnemonic = await decryptStr(state.encryptedMnemonic);

      await navigator.clipboard.writeText(storedMnemonic);
      setStatus(statusEl, 'success', '✓ Recovery phrase copied to clipboard!');
      showToast('Recovery phrase copied to clipboard', 'success');
      setTimeout(closeModal, 2000);
    } catch (err) {
      if (err && err.name === 'NotAllowedError') {
        setStatus(statusEl, 'error', '✗ Clipboard access denied. Please allow clipboard permissions.');
      } else {
        setStatus(statusEl, 'error', '✗ Error accessing recovery phrase. Please re-login.');
      }
    } finally {
      storedMnemonic = null; // clear dari memory segera
      confirmBtn.disabled = false;
      confirmBtn.textContent = '📋 Copy Phrase to Clipboard';
    }
  });
}

/* ===== Init ===== */
function init() {
  setupLogin();
  setupNetworkSwitcher();
  setupSendModal();
  setupBackBtn();
  setupLogout();
  setupCopyAddress();
  setupRefresh();
  setupAddWallet();
  setupPhraseModal();
  showScreen('login-screen');
}

document.addEventListener('DOMContentLoaded', init);

