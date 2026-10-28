import { CryptoVault } from './crypto-vault.js';
import { NfcKeyReader } from './nfc-key-reader.js';

// ===================================================================
// UI APPLICATION CONTROLLER
// ===================================================================

const $ = (id) => document.getElementById(id);

// Elements
const hwSupportBadge = $('hw-support-badge');
const hwSupportLabel = $('hw-support-label');
const compatNotice = $('compat-notice');
const inputPlaintext = $('input-plaintext');
const inputKey = $('input-key');
const btnGenerateKey = $('btn-generate-key');
const btnCopyKey = $('btn-copy-key');
const btnRunEncrypt = $('btn-run-encrypt');
const btnWriteNfc = $('btn-write-nfc');
const outputPayload = $('output-payload');
const badgePayloadStatus = $('badge-payload-status');
const btnCopyPayload = $('btn-copy-payload');

const scanner = $('scanner');
const btnStartScan = $('btn-start-scan');
const btnStopScan = $('btn-stop-scan');
const scannerStatusText = $('scanner-status-text');
const scannerSubText = $('scanner-sub-text');
const scannerStatusIcon = $('scanner-status-icon');

const btnSimValid = $('btn-sim-valid');
const btnSimInvalid = $('btn-sim-invalid');
const decryptedBox = $('decrypted-box');
const decryptedPlaceholder = $('decrypted-placeholder');
const decryptedContent = $('decrypted-content');
const btnClearDecrypted = $('btn-clear-decrypted');

const btnToggleSource = $('btn-toggle-source');
const sourceDrawer = $('source-drawer');
const codeSnippetDisplay = $('code-snippet-display');
const btnCopyCode = $('btn-copy-code');
const toastContainer = $('toast-container');

// Scanner visual states (見た目は css/style.css の [data-state] で定義)
const SCANNER_STATES = {
  idle:      { icon: 'fa-nfc-directional', label: 'スキャナー待機中 (IDLE)' },
  scanning:  { icon: 'fa-wave-square',     label: 'スキャン待機中 (SCANNING)' },
  writing:   { icon: 'fa-pen-to-square',   label: '書き込み待機中 (WRITING)', look: 'scanning' },
  reading:   { icon: 'fa-spinner fa-spin', label: '読み取り処理中...' },
  success:   { icon: 'fa-unlock-keyhole',  label: 'AUTHENTICATED (解錠完了)' },
  denied:    { icon: 'fa-ban',             label: 'ACCESS DENIED (解錠失敗)', look: 'error' },
  nfcError:  { icon: 'fa-triangle-exclamation', label: 'NFC ERROR (通信エラー)', look: 'error' }
};

const TOAST_ICONS = {
  info: 'fa-circle-info',
  success: 'fa-circle-check',
  error: 'fa-triangle-exclamation'
};

const DEMO_PLAINTEXT = "【最高機密文書】\nプロジェクト・イージス内部通信コード: 994-Alpha-Delta\nこのテキストは物理NFC指輪がない限り数学的に閲覧できません。";
const BOGUS_KEY = "INVALID_ROGUE_KEY_99999999999999";

// App State
let currentPayload = null; // Encrypted payload {salt, iv, ciphertext}
let currentKey = null; // Key used to produce currentPayload
let currentPlaintext = null;
let nfcReader = null;

// Toast Notification helper
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast--${type}`;

  // メッセージはタグ由来の値（UID等）を含み得るため、textContentで挿入する
  const iconEl = document.createElement('i');
  iconEl.className = `fa-solid ${TOAST_ICONS[type] || TOAST_ICONS.info}`;
  const textEl = document.createElement('span');
  textEl.textContent = message;
  toast.append(iconEl, textEl);
  toastContainer.appendChild(toast);

  requestAnimationFrame(() => toast.classList.add('is-visible'));

  setTimeout(() => {
    toast.classList.remove('is-visible');
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Clipboard helper (Clipboard API -> execCommand fallback)
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (err) {
    const temp = document.createElement('textarea');
    temp.value = text;
    document.body.appendChild(temp);
    temp.select();
    document.execCommand('copy');
    document.body.removeChild(temp);
  }
}

// Initialize UI
function initApp() {
  // Check Hardware Support
  if (NfcKeyReader.isSupported()) {
    hwSupportBadge.dataset.state = 'supported';
    hwSupportLabel.textContent = 'Web NFC 対応';
  } else {
    hwSupportBadge.dataset.state = 'unsupported';
    hwSupportLabel.textContent = 'Web NFC 非対応 (シミュレーター可)';
    compatNotice.hidden = false;
  }

  // Setup NFC Reader Instance
  nfcReader = new NfcKeyReader({
    onKeyRead: async (keyString, meta) => {
      showToast(`物理タグ検知 (UID: ${meta.serialNumber})`, 'info');
      await attemptDecryption(keyString);
    },
    onError: (err) => {
      showToast(err.message, 'error');
      updateScannerVisuals('nfcError', err.message);
    },
    onStatus: (status, message) => {
      if (status in SCANNER_STATES) {
        updateScannerVisuals(status, message);
      }
    }
  });

  // Generate default demo key and plaintext, then encrypt
  inputPlaintext.value = DEMO_PLAINTEXT;
  generateNewKey({ silent: true });
  performEncryption({ silent: true });
  populateCodeDisplay();
}

function generateNewKey({ silent = false } = {}) {
  inputKey.value = CryptoVault.generateRandomKey(32);
  markPayloadStale();
  if (!silent) showToast("32文字の暗号化鍵を生成しました（暗号化を再実行してください）", "info");
}

// 本文・鍵が暗号化後に変更されたら、ペイロードが古いことを表示する
function markPayloadStale() {
  if (!currentPayload) return;
  const unchanged = inputKey.value.trim() === currentKey && inputPlaintext.value.trim() === currentPlaintext;
  setPayloadBadge(unchanged ? 'done' : 'stale');
}

function setPayloadBadge(state) {
  badgePayloadStatus.dataset.state = state;
  badgePayloadStatus.textContent = state === 'stale' ? "入力変更あり (再暗号化が必要)" : "暗号化完了 (AES-256)";
}

async function performEncryption({ silent = false } = {}) {
  const text = inputPlaintext.value.trim();
  const key = inputKey.value.trim();

  if (!text) {
    showToast("暗号化する本文を入力してください", "error");
    return;
  }
  if (!key) {
    showToast("鍵文字列を入力してください", "error");
    return;
  }

  try {
    currentPayload = await CryptoVault.encrypt(text, key);
    currentKey = key;
    currentPlaintext = text;
    outputPayload.textContent = JSON.stringify(currentPayload, null, 2);
    setPayloadBadge('done');
    if (!silent) showToast("データをAES-GCMで暗号化しました", "success");

    // Clear previous decrypted view to test freshly
    clearDecryptedView();
  } catch (err) {
    showToast(`暗号化エラー: ${err.message}`, "error");
  }
}

async function attemptDecryption(keyString) {
  if (!currentPayload) {
    showToast("暗号化ペイロードが存在しません。先に暗号化を実行してください。", "error");
    return;
  }

  try {
    const decryptedText = await CryptoVault.decrypt(currentPayload, keyString);

    updateScannerVisuals('success', '認証成功: コンテンツが解読されました');
    decryptedPlaceholder.hidden = true;
    decryptedContent.hidden = false;
    decryptedContent.textContent = decryptedText;
    decryptedBox.dataset.state = 'unlocked';
    btnClearDecrypted.hidden = false;

    showToast("復号に成功しました！", "success");
  } catch (err) {
    // 認証失敗時は、直前に解錠していた内容も再ロックする
    clearDecryptedView();
    updateScannerVisuals('denied', err.message);
    showToast(err.message, "error");
  }
}

function clearDecryptedView() {
  decryptedPlaceholder.hidden = false;
  decryptedContent.hidden = true;
  decryptedContent.textContent = '';
  decryptedBox.dataset.state = 'locked';
  btnClearDecrypted.hidden = true;
}

function updateScannerVisuals(state, message) {
  const config = SCANNER_STATES[state] || SCANNER_STATES.idle;
  scanner.dataset.state = config.look || state;
  scannerStatusIcon.className = `fa-solid ${config.icon}`;
  scannerStatusText.textContent = config.label;
  scannerSubText.textContent = message;

  // scan()/write() の待機中は isScanning がまだ false のため、停止ボタンを明示的に出す
  const waiting = state === 'scanning' || state === 'writing';
  if (state !== 'reading') {
    syncScanButtons(waiting);
  }
}

// 成功/失敗表示後もリーダーはスキャンを継続しているため、実際の状態でボタンを切り替える
function syncScanButtons(forceWaiting = false) {
  const scanning = forceWaiting || Boolean(nfcReader && nfcReader.isScanning);
  btnStartScan.hidden = scanning;
  btnStopScan.hidden = !scanning;
}

function populateCodeDisplay() {
  codeSnippetDisplay.textContent = `import { CryptoVault } from './js/crypto-vault.js';
import { NfcKeyReader } from './js/nfc-key-reader.js';

// 1. 暗号化して保管（HTML内に平文は残さない）
const key = CryptoVault.generateRandomKey(32);
const payload = await CryptoVault.encrypt("秘密の文書", key);

// 2. NFC指輪に鍵を書き込み、かざされたら復号（Android Chrome）
const nfc = new NfcKeyReader({
  onKeyRead: async (scannedKey, meta) => {
    try {
      const secret = await CryptoVault.decrypt(payload, scannedKey);
      console.log("解読成功:", secret);
    } catch (err) {
      console.error("解読失敗: 不正な指輪です");
    }
  }
});

await nfc.writeKey(key);
await nfc.startScan();`;
}

// ===================================================================
// EVENT LISTENERS
// ===================================================================
btnGenerateKey.addEventListener('click', () => generateNewKey());

btnCopyKey.addEventListener('click', async () => {
  await copyText(inputKey.value);
  showToast("鍵文字列をクリップボードにコピーしました", "info");
});

btnRunEncrypt.addEventListener('click', () => performEncryption());
inputKey.addEventListener('input', markPayloadStale);
inputPlaintext.addEventListener('input', markPayloadStale);

btnWriteNfc.addEventListener('click', async () => {
  const key = inputKey.value.trim();
  if (!key) {
    showToast("書き込む鍵文字列がありません", "error");
    return;
  }
  if (currentPayload && key !== currentKey) {
    showToast("鍵が暗号化時と異なります。先に暗号化を再実行してください", "error");
    return;
  }
  try {
    await nfcReader.writeKey(key);
    showToast("指輪に鍵の書き込みが成功しました！", "success");
  } catch (err) {
    // 停止ボタンによる中断は通知不要
    if (err.name !== 'AbortError') {
      showToast(err.message, "error");
    }
  }
});

btnCopyPayload.addEventListener('click', async () => {
  if (!currentPayload) return;
  await copyText(JSON.stringify(currentPayload, null, 2));
  showToast("ペイロードJSONをコピーしました", "info");
});

btnStartScan.addEventListener('click', () => {
  // エラーは onError コールバックで表示済み
  nfcReader.startScan().catch(() => {});
});

btnStopScan.addEventListener('click', () => {
  nfcReader.stopScan();
  showToast("スキャンをキャンセルしました", "info");
});

// Simulation Triggers (Fallback for PC/iOS)
btnSimValid.addEventListener('click', () => {
  // 指輪には暗号化に使った鍵が書き込まれている想定
  if (!currentKey) {
    showToast("暗号化済みの鍵がありません。先に暗号化を実行してください", "error");
    return;
  }
  nfcReader.simulateRead(currentKey);
});

btnSimInvalid.addEventListener('click', () => {
  nfcReader.simulateRead(BOGUS_KEY);
});

btnClearDecrypted.addEventListener('click', () => {
  clearDecryptedView();
  updateScannerVisuals('idle', '再ロックしました。');
  showToast("コンテンツを再ロックしました", "info");
});

btnToggleSource.addEventListener('click', () => {
  const expanded = btnToggleSource.getAttribute('aria-expanded') === 'true';
  btnToggleSource.setAttribute('aria-expanded', String(!expanded));
  sourceDrawer.hidden = expanded;
});

btnCopyCode.addEventListener('click', async () => {
  await copyText(codeSnippetDisplay.textContent);
  showToast("ライブラリ利用コードをコピーしました", "info");
});

// Boot (type="module" は defer 扱いのため、この時点で DOM は構築済み)
initApp();
