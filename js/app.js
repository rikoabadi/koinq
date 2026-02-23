/* ===================================================
   KoinQ — Crypto Wallet SPA
   Vanilla JS, No TypeScript, No OOP, No Modules
   =================================================== */

/* ===== State ===== */
var state = {
  mnemonic: '',
  currentIndex: 0,
  currentAddress: '',
  network: 'BSC',
  wallets: [],        // [{address, privateKey}, ...]
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
    { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
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
    var url = api + '?module=account&action=txlist&address=' + address +
              '&startblock=0&endblock=99999999&page=1&offset=10&sort=desc';
    var res = await fetch(url);
    var data = await res.json();
    if (data.status === '1' && Array.isArray(data.result)) return data.result;
    return [];
  } catch (e) {
    return [];
  }
}

// Send native token
async function sendToken(to, amount, privateKey, network) {
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
    unlockBtn.innerHTML = '<span class="spinner"></span> Generating wallet…';

    try {
      var mnemonic = await generateMnemonicFromPassword(pwd);
      state.mnemonic = mnemonic;

      // Derive wallets 0–5
      state.wallets = [];
      for (var i = 0; i < 6; i++) {
        state.wallets.push(getHDWallet(mnemonic, i));
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
      showError(errEl, 'Error generating wallet: ' + err.message);
    }

    unlockBtn.disabled = false;
    unlockBtn.innerHTML = '🔓 Unlock / Create Wallet';
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
    list.innerHTML = '<div class="tx-loading"><span class="spinner"></span></div>';
    return;
  }

  if (!state.transactions || state.transactions.length === 0) {
    list.innerHTML = '<div class="tx-empty">No transactions found</div>';
    return;
  }

  list.innerHTML = '';
  state.transactions.forEach(function(tx) {
    var isIn = tx.to && tx.to.toLowerCase() === addr.toLowerCase();
    var direction = isIn ? 'in' : 'out';
    var dirIcon   = isIn ? '↓' : '↑';
    var dirLabel  = isIn ? 'Received' : 'Sent';
    var amountEth = ethers.formatEther(tx.value || '0');
    var amountFmt = formatAmount(amountEth);
    var sym       = networks[net].symbol;
    var explorerUrl = networks[net].explorerTx + tx.hash;

    var item = document.createElement('div');
    item.className = 'tx-item';
    item.innerHTML =
      '<div class="tx-icon ' + direction + '">' + dirIcon + '</div>' +
      '<div class="tx-info">' +
        '<div class="tx-type">' + dirLabel + '</div>' +
        '<a class="tx-hash" href="' + explorerUrl + '" target="_blank" rel="noopener">' + tx.hash.slice(0, 20) + '…</a>' +
      '</div>' +
      '<div class="tx-right">' +
        '<div class="tx-amount ' + (isIn ? 'text-green' : 'text-danger') + '">' +
          (isIn ? '+' : '-') + amountFmt + ' ' + sym +
        '</div>' +
        '<div class="tx-time">' + timeAgo(tx.timeStamp) + '</div>' +
      '</div>';

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
    setStatus(statusEl, 'info', '<span class="spinner"></span> Sending transaction…');

    try {
      var tx = await sendToken(to, amount, wallet.privateKey, net);
      setStatus(statusEl, 'success', '✓ Sent! TX: ' + tx.hash.slice(0, 16) + '…');
      showToast('Transaction sent successfully!', 'success');
      setTimeout(function() {
        closeModal();
        loadAddressData(state.currentAddress);
      }, 2500);
    } catch (err) {
      var msg = err.reason || err.message || 'Transaction failed. Please check your balance and try again.';
      setStatus(statusEl, 'error', '✗ ' + msg.slice(0, 80));
    }

    confirmBtn.disabled = false;
  });
}

function setStatus(el, type, html) {
  el.className = 'modal-info ' + type;
  el.innerHTML = html;
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
    state.mnemonic = '';
    state.wallets  = [];
    state.currentAddress = '';
    state.transactions = [];
    state.balanceBSC  = {};
    state.balanceCELO = {};
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

/* ===== Init ===== */
function init() {
  setupLogin();
  setupNetworkSwitcher();
  setupSendModal();
  setupBackBtn();
  setupLogout();
  setupCopyAddress();
  setupRefresh();
  showScreen('login-screen');
}

document.addEventListener('DOMContentLoaded', init);
