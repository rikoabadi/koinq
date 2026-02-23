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
    chainId: 56,
    symbol: 'BNB',
    explorerApi: 'https://api.bscscan.com/api',
    explorerTx: 'https://bscscan.com/tx/',
    usdtAddress: '0x55d398326f99059fF775485246999027B3197955',
    usdtDecimals: 18
  },
  CELO: {
    name: 'Celo',
    rpcUrl: 'https://forno.celo.org',
    chainId: 42220,
    symbol: 'CELO',
    explorerApi: 'https://api.celoscan.io/api',
    explorerTx: 'https://celoscan.io/tx/',
    usdtAddress: '0x617f3112bf5397D0467D315cC709EF968D9ba546',
    usdtDecimals: 6
  }
};

/* ===== ERC-20 Minimal ABI ===== */
var ERC20_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function transfer(address to, uint256 amount) returns (bool)'
];

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

// Fetch USDT balance on the given network
async function fetchUSDTBalance(address, network) {
  try {
    var cfg = networks[network];
    var provider = new ethers.JsonRpcProvider(cfg.rpcUrl);
    var contract = new ethers.Contract(cfg.usdtAddress, ERC20_ABI, provider);
    var bal = await contract.balanceOf(address);
    return ethers.formatUnits(bal, cfg.usdtDecimals);
  } catch (e) {
    return '–';
  }
}

// Simulate USDT transfer — returns gas estimate details without sending
async function estimateUSDTTransfer(to, amount, fromAddress, network) {
  var cfg = networks[network];
  var provider = new ethers.JsonRpcProvider(cfg.rpcUrl);
  var contract = new ethers.Contract(cfg.usdtAddress, ERC20_ABI, provider);
  var amountWei = ethers.parseUnits(amount, cfg.usdtDecimals);

  var [feeData, gasUnits] = await Promise.all([
    provider.getFeeData(),
    contract.transfer.estimateGas(to, amountWei, { from: fromAddress })
  ]);

  var gasPrice = feeData.gasPrice;
  var gasFeeWei = gasUnits * gasPrice;

  return {
    to: to,
    amount: amount,
    amountWei: amountWei,
    gasUnits: gasUnits.toString(),
    gasPriceGwei: ethers.formatUnits(gasPrice, 'gwei'),
    gasFeeNative: ethers.formatEther(gasFeeWei),
    gasPrice: gasPrice,
    network: network
  };
}

// Send USDT via ERC-20 transfer
async function sendUSDT(to, amountWei, privateKey, network, gasPrice) {
  var cfg = networks[network];
  var provider = new ethers.JsonRpcProvider(cfg.rpcUrl);
  var wallet = new ethers.Wallet(privateKey, provider);
  var contract = new ethers.Contract(cfg.usdtAddress, ERC20_ABI, wallet);
  var tx = await contract.transfer(to, amountWei, { gasPrice: gasPrice });
  return tx;
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

  // Build cards safely
  grid.innerHTML = '';

  var card1 = document.createElement('div');
  card1.className = 'balance-card';
  var label1 = document.createElement('div');
  label1.className = 'chain-label';
  var dot1 = document.createElement('span');
  dot1.className = 'chain-dot ' + dotClass;
  label1.appendChild(dot1);
  label1.appendChild(document.createTextNode(' ' + cfg.name));
  var amt1 = document.createElement('div');
  amt1.className = 'balance-amount';
  amt1.id = 'balance-native';
  amt1.textContent = nativeBal;
  var sym1 = document.createElement('div');
  sym1.className = 'balance-symbol';
  sym1.textContent = cfg.symbol;
  card1.appendChild(label1);
  card1.appendChild(amt1);
  card1.appendChild(sym1);

  var card2 = document.createElement('div');
  card2.className = 'balance-card';
  var label2 = document.createElement('div');
  label2.className = 'chain-label';
  var dot2 = document.createElement('span');
  dot2.className = 'chain-dot usdt';
  label2.appendChild(dot2);
  label2.appendChild(document.createTextNode(' Tether USD'));
  var amt2 = document.createElement('div');
  amt2.className = 'balance-amount';
  amt2.id = 'balance-usdt';
  amt2.textContent = usdtBal;
  var sym2 = document.createElement('div');
  sym2.className = 'balance-symbol';
  sym2.textContent = 'USDT';
  card2.appendChild(label2);
  card2.appendChild(amt2);
  card2.appendChild(sym2);

  grid.appendChild(card1);
  grid.appendChild(card2);
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
        '<a class="tx-hash" href="' + explorerUrl + '" target="_blank" rel="noopener noreferrer">' + tx.hash.slice(0, 20) + '…</a>' +
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
  if (state.currentAddress === address) renderMainPanel();

  var net = state.network;
  var usdtKey = address + '_' + net;

  var results = await Promise.all([
    fetchBalance(address, 'BSC'),
    fetchBalance(address, 'CELO'),
    fetchUSDTBalance(address, net)
  ]);

  state.balanceBSC[address]   = results[0];
  state.balanceCELO[address]  = results[1];
  state.balanceUSDT[usdtKey]  = results[2];
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
      if (state.network === this.dataset.net) return;
      state.network = this.dataset.net;
      updateNetworkUI();
      state.transactions = [];
      if (state.currentAddress) {
        renderMainPanel();
        // Reload USDT balance for new network and transactions
        var addr = state.currentAddress;
        var net = state.network;
        var usdtKey = addr + '_' + net;
        if (state.balanceUSDT[usdtKey] === undefined) {
          state.balLoading = true;
          renderBalanceGrid(addr);
          fetchUSDTBalance(addr, net).then(function(bal) {
            state.balanceUSDT[usdtKey] = bal;
            state.balLoading = false;
            if (state.currentAddress === addr) renderBalanceGrid(addr);
          });
        }
        loadTransactions(addr);
      }
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
    setStatus(statusEl, 'info', '<span class="spinner"></span> Simulating transfer…');

    try {
      var est = await estimateUSDTTransfer(to, amount, wallet.address, net);
      pendingTx = est;

      // Build dry run preview
      var box = $('dry-run-result');
      box.innerHTML = '';

      var rows = [
        ['Token',          'USDT'],
        ['Network',        networks[net].name],
        ['From',           shortenAddress(wallet.address)],
        ['To',             shortenAddress(to)],
        ['Amount',         amount + ' USDT'],
        ['Gas Units',      parseInt(est.gasUnits, 10).toLocaleString()],
        ['Gas Price',      (+est.gasPriceGwei).toFixed(4) + ' Gwei'],
        ['Est. Network Fee', (+est.gasFeeNative).toFixed(8) + ' ' + networks[net].symbol]
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
      note.textContent = '⚠ Network fees are paid in ' + networks[net].symbol + '. Make sure your wallet has enough ' + networks[net].symbol + ' for gas.';
      box.appendChild(table);
      box.appendChild(note);

      statusPreview.classList.add('hidden');
      showStep('preview');
      statusEl.classList.add('hidden');
    } catch (err) {
      var msg = err.reason || err.message || 'Simulation failed. Check balance or address.';
      setStatus(statusEl, 'error', '✗ ' + msg.slice(0, 120));
    }

    dryRunBtn.disabled = false;
  });

  // --- Confirm Send ---
  confirmBtn.addEventListener('click', async function() {
    if (!pendingTx) return;

    var wallet = state.wallets[state.currentIndex];
    confirmBtn.disabled = true;
    setStatus(statusPreview, 'info', '<span class="spinner"></span> Sending USDT…');

    try {
      var tx = await sendUSDT(pendingTx.to, pendingTx.amountWei, wallet.privateKey, pendingTx.network, pendingTx.gasPrice);
      setStatus(statusPreview, 'success', '✓ Sent! TX: ' + tx.hash.slice(0, 18) + '…');
      showToast('USDT sent successfully!', 'success');
      setTimeout(function() {
        closeModal();
        loadAddressData(state.currentAddress);
      }, 2500);
    } catch (err) {
      var msg = err.reason || err.message || 'Transaction failed. Check your USDT and gas balance.';
      setStatus(statusPreview, 'error', '✗ ' + msg.slice(0, 120));
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
    state.balanceUSDT = {};
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
function addWallet() {
  var nextIndex = state.wallets.length;
  var newWallet = getHDWallet(state.mnemonic, nextIndex);
  state.wallets.push(newWallet);
  renderSidebar();
  showToast('Account ' + nextIndex + ' added', 'success');
}

function setupAddWallet() {
  $('add-wallet-fab').addEventListener('click', function() {
    if (!state.mnemonic) return;
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
    if (!state.mnemonic) return;
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
    confirmBtn.innerHTML = '<span class="spinner"></span> Verifying…';

    try {
      var derivedMnemonic = await generateMnemonicFromPassword(pwd);
      if (derivedMnemonic === state.mnemonic) {
        navigator.clipboard.writeText(state.mnemonic).then(function() {
          setStatus(statusEl, 'success', '✓ Recovery phrase copied to clipboard!');
          showToast('Recovery phrase copied to clipboard', 'success');
          setTimeout(closeModal, 2000);
        }).catch(function() {
          setStatus(statusEl, 'error', '✗ Clipboard access denied. Please allow clipboard permissions.');
        });
      } else {
        setStatus(statusEl, 'error', '✗ Incorrect password. Please try again.');
        pwdInput.value = '';
        pwdInput.focus();
      }
    } catch (err) {
      setStatus(statusEl, 'error', '✗ Error verifying password.');
    }

    confirmBtn.disabled = false;
    confirmBtn.innerHTML = '📋 Copy Phrase to Clipboard';
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

