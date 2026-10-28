import { CryptoVault } from './crypto-vault.js';
import { NfcKeyReader } from './nfc-key-reader.js';

// ===================================================================
// UI APPLICATION CONTROLLER
// ===================================================================

const $ = (id) => document.getElementById(id);

// Elements
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

const btnSimValid = $('btn-sim-valid');
const btnSimInvalid = $('btn-sim-invalid');
const decryptedContent = $('decrypted-content');
const btnClearDecrypted = $('btn-clear-decrypted');

const codeSnippetDisplay = $('code-snippet-display');
const btnCopyCode = $('btn-copy-code');
const toastContainer = $('toast-container');

// Scanner states (色は css/style.css の .status[data-state] で定義)
const SCANNER_STATES = {
  idle:     { label: '待機中' },
  scanning: { label: 'スキャン中' },
  writing:  { label: '書き込み待機中', look: 'scanning' },
  reading:  { label: '読み取り中...' },
  success:  { label: '解錠成功' },
  denied:   { label: '解錠失敗', look: 'error' },
  nfcError: { label: 'NFCエラー', look: 'error' }
};

const DEMO_PLAINTEXT = "【最高機密文書】\nプロジェクト・イージス内部通信コード: 994-Alpha-Delta\nこのテキストは物理NFC指輪がない限り数学的に閲覧できません。";
const BOGUS_KEY = "INVALID_ROGUE_KEY_99999999999999";
const LOCKED_TEXT = "（ロック中）";

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
  toast.textContent = message;
  toastContainer.appendChild(toast);

  requestAnimationFrame(() => toast.classList.add('is-visible'));

  setTimeout(() => {
    toast.classList.remove('is-visible');
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Clipboard helper（Clipboard API は HTTPS / localhost で利用可能）
async function copyText(text, successMessage) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(successMessage, "info");
  } catch (err) {
    showToast("クリップボードにコピーできませんでした", "error");
  }
}

// Initialize UI
function initApp() {
  // Check Hardware Support
  if (NfcKeyReader.isSupported()) {
    hwSupportLabel.dataset.state = 'supported';
    hwSupportLabel.textContent = 'Web NFC対応ブラウザです。';
  } else {
    hwSupportLabel.dataset.state = 'unsupported';
    hwSupportLabel.textContent = 'Web NFC非対応のため、シミュレートで試せます。';
    compatNotice.hidden = false;
    btnStartScan.disabled = true;
    btnWriteNfc.disabled = true;
  }

  // Setup NFC Reader Instance
  nfcReader = new NfcKeyReader({
    onKeyRead: async (keyString, meta) => {
      await attemptDecryption(keyString, meta);
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
  if (!silent) showToast("32文字の鍵を生成しました（暗号化を再実行してください）", "info");
}

// 本文・鍵が暗号化後に変更されたら、ペイロードが古いことを表示する
function markPayloadStale() {
  if (!currentPayload) return;
  const unchanged = inputKey.value.trim() === currentKey && inputPlaintext.value.trim() === currentPlaintext;
  setPayloadBadge(unchanged ? 'done' : 'stale');
}

function setPayloadBadge(state) {
  badgePayloadStatus.dataset.state = state;
  badgePayloadStatus.textContent = state === 'stale' ? "要再暗号化" : "暗号化済み";
}

async function performEncryption({ silent = false } = {}) {
  const text = inputPlaintext.value.trim();
  const key = inputKey.value.trim();

  if (!text) {
    showToast("暗号化する本文を入力してください", "error");
    return;
  }
  if (!key) {
    showToast("鍵を入力してください", "error");
    return;
  }

  try {
    currentPayload = await CryptoVault.encrypt(text, key);
    currentKey = key;
    currentPlaintext = text;
    outputPayload.textContent = JSON.stringify(currentPayload, null, 2);
    setPayloadBadge('done');
    if (!silent) showToast("AES-GCMで暗号化しました", "success");

    // Clear previous decrypted view to test freshly
    clearDecryptedView();
  } catch (err) {
    showToast(`暗号化エラー: ${err.message}`, "error");
  }
}

async function attemptDecryption(keyString, meta) {
  if (!currentPayload) {
    showToast("暗号化ペイロードがありません。先に暗号化を実行してください。", "error");
    return;
  }

  try {
    const decryptedText = await CryptoVault.decrypt(currentPayload, keyString);

    updateScannerVisuals('success', `鍵が一致し、内容を復号しました（UID: ${meta.serialNumber}）。`);
    decryptedContent.textContent = decryptedText;
    decryptedContent.dataset.state = 'unlocked';
    btnClearDecrypted.hidden = false;
  } catch (err) {
    // 認証失敗時は、直前に解錠していた内容も再ロックする
    clearDecryptedView();
    updateScannerVisuals('denied', `${err.message}（UID: ${meta.serialNumber}）`);
  }
}

function clearDecryptedView() {
  decryptedContent.textContent = LOCKED_TEXT;
  decryptedContent.dataset.state = 'locked';
  btnClearDecrypted.hidden = true;
}

function updateScannerVisuals(state, message) {
  const config = SCANNER_STATES[state] || SCANNER_STATES.idle;
  scanner.dataset.state = config.look || state;
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

btnCopyKey.addEventListener('click', () => {
  copyText(inputKey.value, "鍵をコピーしました");
});

btnRunEncrypt.addEventListener('click', () => performEncryption());
inputKey.addEventListener('input', markPayloadStale);
inputPlaintext.addEventListener('input', markPayloadStale);

btnWriteNfc.addEventListener('click', async () => {
  const key = inputKey.value.trim();
  if (!key) {
    showToast("書き込む鍵がありません", "error");
    return;
  }
  if (currentPayload && key !== currentKey) {
    showToast("鍵が暗号化時と異なります。先に暗号化を再実行してください", "error");
    return;
  }
  try {
    await nfcReader.writeKey(key);
    showToast("タグに鍵を書き込みました", "success");
  } catch (err) {
    // 停止ボタンによる中断は通知不要
    if (err.name !== 'AbortError') {
      showToast(err.message, "error");
    }
  }
});

btnCopyPayload.addEventListener('click', () => {
  if (!currentPayload) return;
  copyText(JSON.stringify(currentPayload, null, 2), "ペイロードJSONをコピーしました");
});

btnStartScan.addEventListener('click', () => {
  // エラーは onError コールバックで表示済み
  nfcReader.startScan().catch(() => {});
});

btnStopScan.addEventListener('click', () => {
  nfcReader.stopScan();
});

// Simulation Triggers (Fallback for PC/iOS)
btnSimValid.addEventListener('click', () => {
  // タグには暗号化に使った鍵が書き込まれている想定
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
});

btnCopyCode.addEventListener('click', () => {
  copyText(codeSnippetDisplay.textContent, "利用例のコードをコピーしました");
});

// Boot (type="module" は defer 扱いのため、この時点で DOM は構築済み)
initApp();
