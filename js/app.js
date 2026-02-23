/* ===================================================
   KoinQ — Crypto Wallet SPA
   Vanilla JS, No TypeScript, No OOP, No Modules
   =================================================== */

/* ===== HTTPS Enforcement ===== */
if (location.protocol !== 'https:' &&
    location.hostname !== 'localhost' &&
    location.hostname !== '127.0.0.1') {
  location.replace('https:' + location.href.substring(location.protocol.length));
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
  transactions: [],
  txLoading: false,
  balLoading: false
};

/* ===== Network Config ===== */
var networks = {
  BSC: {
    name: 'BNB Smart Chain',
    rpcUrl: 'https://bsc-dataseed.binance.org/',
    chainId: 56,
    symbol: 'BNB',
    explorerApi: 'https://api.bscscan.com/api',
    explorerTx: 'https://bscscan.com/tx/'
  },
  CELO: {
    name: 'Celo',
    rpcUrl: 'https://forno.celo.org',
    chainId: 42220,
    symbol: 'CELO',
    explorerApi: 'https://api.celoscan.io/api',
    explorerTx: 'https://celoscan.io/tx/'
  }
};

/* ===== Wallet Core Functions ===== */

// Generate 24-word mnemonic deterministically from a password using PBKDF2 + BIP39 entropy
async function generateMnemonicFromPassword(password) {
  var encoder = new TextEncoder();
  var salt = encoder.encode('koinq-deterministic-wallet-v1');
  var keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  var bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: 200000, hash: 'SHA-256' },
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

// Fetch native balance for a single network
async function fetchBalance(address, network) {
  try {
    var provider = new ethers.JsonRpcProvider(networks[network].rpcUrl);
    var bal = await provider.getBalance(address);
    return ethers.formatEther(bal);
  } catch (e) {
    return '–';
  }
}

// Fetch last 10 transactions from explorer API
async function fetchTransactions(address, network) {
  try {
    var api = networks[network].explorerApi;
    var url = api + '?module=account&action=txlist&address=' + encodeURIComponent(address) +
              '&startblock=0&endblock=99999999&page=1&offset=10&sort=desc';
    var res = await fetch(url, { mode: 'cors', credentials: 'omit' });
    var data = await res.json();
    if (data.status === '1' && Array.isArray(data.result)) return data.result;
    return [];
  } catch (e) {
    return [];
  }
}

// Send native token
async function sendToken(to, amount, encryptedPrivateKey, network) {
  var privateKey = await decryptStr(encryptedPrivateKey);
  var provider = new ethers.JsonRpcProvider(networks[network].rpcUrl);
  var wallet = new ethers.Wallet(privateKey, provider);
  var feeData = await provider.getFeeData();
  var tx = await wallet.sendTransaction({
    to: to,
    value: ethers.parseEther(amount),
    gasPrice: feeData.gasPrice
  });
  return tx;
}

/* ===== DOM Helpers ===== */
function $(id) { return document.getElementById(id); }

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
  return addr.slice(0, 6) + '…' + addr.slice(-4);
}

function formatAmount(val) {
  var n = parseFloat(val);
  if (isNaN(n)) return '–';
  return n.toFixed(6).replace(/\.?0+$/, '') || '0.0';
}

function timeAgo(ts) {
  var diff = Math.floor(Date.now() / 1000) - parseInt(ts);
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
  var toggleBtn = $('toggle-password');
  var pwdInput  = $('password-input');
  var unlockBtn = $('unlock-btn');
  var errEl     = $('login-error');

  toggleBtn.addEventListener('click', function() {
    var isText = pwdInput.type === 'text';
    pwdInput.type = isText ? 'password' : 'text';
    toggleBtn.textContent = isText ? '👁' : '🙈';
  });

  pwdInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') unlockBtn.click();
  });

  unlockBtn.addEventListener('click', async function() {
    var pwd = pwdInput.value.trim();
    if (!pwd) { showError(errEl, 'Please enter a password.'); return; }
    if (pwd.length < 6) { showError(errEl, 'Password must be at least 6 characters.'); return; }

    errEl.classList.add('hidden');
    unlockBtn.disabled = true;
    unlockBtn.textContent = '';
    var sp = document.createElement('span');
    sp.className = 'spinner';
    unlockBtn.appendChild(sp);
    unlockBtn.appendChild(document.createTextNode(' Generating wallet…'));

    try {
      await initSessionKey(pwd);
      var mnemonic = await generateMnemonicFromPassword(pwd);
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
      mnemonic = null;

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
      showError(errEl, 'Error generating wallet. Please try again.');
    }

    unlockBtn.disabled = false;
    unlockBtn.textContent = '🔓 Unlock / Create Wallet';
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
    var bnbBal  = state.balanceBSC[w.address]  ? formatAmount(state.balanceBSC[w.address])  : '…';
    var celoBal = state.balanceCELO[w.address] ? formatAmount(state.balanceCELO[w.address]) : '…';

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
  showMainPanel(true);
  renderMainPanel();
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
    if (show) renderMainPanel();
  }
}

function renderMainPanel() {
  var addr = state.currentAddress;
  var idx  = state.currentIndex;
  var net  = state.network;

  // Address
  $('main-address-full').textContent = addr;

  // Balances
  var bnbEl  = $('balance-bnb');
  var celoEl = $('balance-celo');
  bnbEl.textContent  = state.balanceBSC[addr]  ? formatAmount(state.balanceBSC[addr])  : (state.balLoading ? '…' : '–');
  celoEl.textContent = state.balanceCELO[addr] ? formatAmount(state.balanceCELO[addr]) : (state.balLoading ? '…' : '–');

  // Network badge on send btn
  $('send-btn').textContent = '↑ Send ' + networks[net].symbol;

  renderTransactions();
}

function renderTransactions() {
  var list = $('tx-list');
  var addr = state.currentAddress;
  var net  = state.network;

  if (state.txLoading) {
    list.textContent = '';
    var loadingDiv = document.createElement('div');
    loadingDiv.className = 'tx-loading';
    var spinnerEl = document.createElement('span');
    spinnerEl.className = 'spinner';
    loadingDiv.appendChild(spinnerEl);
    list.appendChild(loadingDiv);
    return;
  }

  if (!state.transactions || state.transactions.length === 0) {
    list.textContent = '';
    var emptyDiv = document.createElement('div');
    emptyDiv.className = 'tx-empty';
    emptyDiv.textContent = 'No transactions found';
    list.appendChild(emptyDiv);
    return;
  }

  list.textContent = '';
  state.transactions.forEach(function(tx) {
    var isIn = tx.to && tx.to.toLowerCase() === addr.toLowerCase();
    var direction = isIn ? 'in' : 'out';
    var dirIcon   = isIn ? '↓' : '↑';
    var dirLabel  = isIn ? 'Received' : 'Sent';
    var amountEth = ethers.formatEther(tx.value || '0');
    var amountFmt = formatAmount(amountEth);
    var sym       = networks[net].symbol;
    var explorerUrl = networks[net].explorerTx + encodeURIComponent(tx.hash);

    var item = document.createElement('div');
    item.className = 'tx-item';

    var iconEl = document.createElement('div');
    iconEl.className = 'tx-icon ' + direction;
    iconEl.textContent = dirIcon;

    var infoEl = document.createElement('div');
    infoEl.className = 'tx-info';

    var typeEl = document.createElement('div');
    typeEl.className = 'tx-type';
    typeEl.textContent = dirLabel;

    var hashEl = document.createElement('a');
    hashEl.className = 'tx-hash';
    hashEl.href = explorerUrl;
    hashEl.target = '_blank';
    hashEl.rel = 'noopener noreferrer';
    hashEl.textContent = tx.hash.slice(0, 20) + '…';

    infoEl.appendChild(typeEl);
    infoEl.appendChild(hashEl);

    var rightEl = document.createElement('div');
    rightEl.className = 'tx-right';

    var amountEl = document.createElement('div');
    amountEl.className = 'tx-amount ' + (isIn ? 'text-green' : 'text-danger');
    amountEl.textContent = (isIn ? '+' : '-') + amountFmt + ' ' + sym;

    var timeEl = document.createElement('div');
    timeEl.className = 'tx-time';
    timeEl.textContent = timeAgo(tx.timeStamp);

    rightEl.appendChild(amountEl);
    rightEl.appendChild(timeEl);

    item.appendChild(iconEl);
    item.appendChild(infoEl);
    item.appendChild(rightEl);

    list.appendChild(item);
  });
}

/* ===== Load Data ===== */
async function loadAddressData(address) {
  loadBalances(address);
  loadTransactions(address);
}

async function loadBalances(address) {
  state.balLoading = true;
  renderMainPanel();

  var [bnb, celo] = await Promise.all([
    fetchBalance(address, 'BSC'),
    fetchBalance(address, 'CELO')
  ]);

  state.balanceBSC[address]  = bnb;
  state.balanceCELO[address] = celo;
  state.balLoading = false;

  if (state.currentAddress === address) {
    $('balance-bnb').textContent  = formatAmount(bnb);
    $('balance-celo').textContent = formatAmount(celo);
    renderSidebar();
  }
}

async function loadTransactions(address) {
  state.txLoading = true;
  state.transactions = [];
  renderTransactions();

  var txs = await fetchTransactions(address, state.network);
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
      state.network = this.dataset.net;
      updateNetworkUI();
      state.transactions = [];
      if (state.currentAddress) {
        renderMainPanel();
        loadTransactions(state.currentAddress);
      }
    });
  });
}

/* ===== Send Modal ===== */
function setupSendModal() {
  var sendBtn    = $('send-btn');
  var overlay    = $('send-modal-overlay');
  var closeBtn   = $('send-modal-close');
  var confirmBtn = $('send-confirm-btn');
  var toInput    = $('send-to');
  var amtInput   = $('send-amount');
  var statusEl   = $('send-status');
  var symEl      = $('send-symbol');

  function openModal() {
    toInput.value  = '';
    amtInput.value = '';
    statusEl.classList.add('hidden');
    statusEl.textContent = '';
    symEl.textContent = networks[state.network].symbol;
    var fromEl = document.getElementById('modal-from-addr');
    if (fromEl) fromEl.textContent = state.currentAddress || '–';
    overlay.classList.remove('hidden');
    toInput.focus();
  }

  function closeModal() {
    overlay.classList.add('hidden');
  }

  sendBtn.addEventListener('click', openModal);
  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', function(e) {
    if (e.target === overlay) closeModal();
  });

  confirmBtn.addEventListener('click', async function() {
    var to     = toInput.value.trim();
    var amount = amtInput.value.trim();
    var net    = state.network;
    var wallet = state.wallets[state.currentIndex];

    // Validate
    if (!ethers.isAddress(to)) {
      setStatus(statusEl, 'error', '✗ Invalid recipient address.');
      return;
    }
    if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
      setStatus(statusEl, 'error', '✗ Invalid amount.');
      return;
    }

    confirmBtn.disabled = true;
    statusEl.className = 'modal-info info';
    statusEl.textContent = '';
    var sp = document.createElement('span');
    sp.className = 'spinner';
    statusEl.appendChild(sp);
    statusEl.appendChild(document.createTextNode(' Sending transaction…'));
    statusEl.classList.remove('hidden');

    try {
      var tx = await sendToken(to, amount, wallet.encryptedPrivateKey, net);
      setStatus(statusEl, 'success', '✓ Sent! TX: ' + tx.hash.slice(0, 16) + '…');
      showToast('Transaction sent successfully!', 'success');
      setTimeout(function() {
        closeModal();
        loadAddressData(state.currentAddress);
      }, 2500);
    } catch (err) {
      var msg = err.reason || 'Transaction failed. Please check your balance and try again.';
      setStatus(statusEl, 'error', '✗ ' + msg.slice(0, 80));
    }

    confirmBtn.disabled = false;
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
    state.encryptedMnemonic = null;
    state.wallets  = [];
    state.currentAddress = '';
    state.transactions = [];
    state.balanceBSC  = {};
    state.balanceCELO = {};
    sessionEncKey = null;
    $('password-input').value = '';
    $('login-error').classList.add('hidden');
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
async function addWallet() {
  var nextIndex = state.wallets.length;
  var mnemonic = await decryptStr(state.encryptedMnemonic);
  var newWallet = getHDWallet(mnemonic, nextIndex);
  mnemonic = null;
  state.wallets.push({
    address: newWallet.address,
    encryptedPrivateKey: await encryptStr(newWallet.privateKey)
  });
  renderSidebar();
  showToast('Account ' + nextIndex + ' added', 'success');
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

    confirmBtn.disabled = true;
    confirmBtn.textContent = '';
    var sp = document.createElement('span');
    sp.className = 'spinner';
    confirmBtn.appendChild(sp);
    confirmBtn.appendChild(document.createTextNode(' Verifying…'));

    try {
      var derivedMnemonic = await generateMnemonicFromPassword(pwd);
      var storedMnemonic = await decryptStr(state.encryptedMnemonic);
      if (derivedMnemonic === storedMnemonic) {
        navigator.clipboard.writeText(storedMnemonic).then(function() {
          storedMnemonic = null;
          setStatus(statusEl, 'success', '✓ Recovery phrase copied to clipboard!');
          showToast('Recovery phrase copied to clipboard', 'success');
          setTimeout(closeModal, 2000);
        }).catch(function() {
          storedMnemonic = null;
          setStatus(statusEl, 'error', '✗ Clipboard access denied. Please allow clipboard permissions.');
        });
      } else {
        storedMnemonic = null;
        derivedMnemonic = null;
        setStatus(statusEl, 'error', '✗ Incorrect password. Please try again.');
        pwdInput.value = '';
        pwdInput.focus();
      }
    } catch (err) {
      setStatus(statusEl, 'error', '✗ Error verifying password.');
    }

    confirmBtn.disabled = false;
    confirmBtn.textContent = '📋 Copy Phrase to Clipboard';
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
