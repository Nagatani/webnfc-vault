import { CryptoVault } from './crypto-vault.js';
import { NfcKeyReader } from './nfc-key-reader.js';

    // ===================================================================
    // UI APPLICATION CONTROLLER
    // ===================================================================

    // Elements
    const hwSupportBadge = document.getElementById('hw-support-badge');
    const compatNotice = document.getElementById('compat-notice');
    const inputPlaintext = document.getElementById('input-plaintext');
    const inputKey = document.getElementById('input-key');
    const btnGenerateKey = document.getElementById('btn-generate-key');
    const btnCopyKey = document.getElementById('btn-copy-key');
    const btnRunEncrypt = document.getElementById('btn-run-encrypt');
    const btnWriteNfc = document.getElementById('btn-write-nfc');
    const outputPayload = document.getElementById('output-payload');
    const badgePayloadStatus = document.getElementById('badge-payload-status');
    const btnCopyPayload = document.getElementById('btn-copy-payload');

    const btnStartScan = document.getElementById('btn-start-scan');
    const btnStopScan = document.getElementById('btn-stop-scan');
    const scannerStatusText = document.getElementById('scanner-status-text');
    const scannerSubText = document.getElementById('scanner-sub-text');
    const scannerStatusIcon = document.getElementById('scanner-status-icon');
    const scannerIconBg = document.getElementById('scanner-icon-bg');
    const radarPulse = document.getElementById('radar-pulse');

    const btnSimValid = document.getElementById('btn-sim-valid');
    const btnSimInvalid = document.getElementById('btn-sim-invalid');
    const decryptedBox = document.getElementById('decrypted-box');
    const decryptedPlaceholder = document.getElementById('decrypted-placeholder');
    const decryptedContent = document.getElementById('decrypted-content');
    const btnClearDecrypted = document.getElementById('btn-clear-decrypted');

    const btnToggleSource = document.getElementById('btn-toggle-source');
    const sourceDrawer = document.getElementById('source-drawer');
    const accordionArrow = document.getElementById('accordion-arrow');
    const codeSnippetDisplay = document.getElementById('code-snippet-display');
    const btnCopyCode = document.getElementById('btn-copy-code');
    const toastContainer = document.getElementById('toast-container');

    // App State
    let currentPayload = null; // Store encrypted payload JSON
    let currentKey = null; // Key used to produce currentPayload
    let currentPlaintext = null;
    let nfcReader = null;

    // Toast Notification helper
    function showToast(message, type = 'info') {
      const toast = document.createElement('div');
      const borderClass = type === 'error' ? 'border-rose-500 bg-rose-950/90 text-rose-200' :
                          type === 'success' ? 'border-emerald-500 bg-emerald-950/90 text-emerald-200' :
                          'border-sky-500 bg-slate-900/90 text-sky-200';
      const icon = type === 'error' ? 'fa-triangle-exclamation text-rose-400' :
                   type === 'success' ? 'fa-circle-check text-emerald-400' :
                   'fa-circle-info text-sky-400';

      toast.className = `p-3 rounded-xl border ${borderClass} backdrop-blur shadow-2xl text-xs flex items-center gap-2.5 transition-all duration-300 pointer-events-auto transform translate-y-2 opacity-0`;
      // メッセージはタグ由来の値（UID等）を含み得るため、textContentで挿入する
      const iconEl = document.createElement('i');
      iconEl.className = `fa-solid ${icon} shrink-0 text-sm`;
      const textEl = document.createElement('span');
      textEl.className = 'flex-1 font-mono';
      textEl.textContent = message;
      toast.append(iconEl, textEl);
      toastContainer.appendChild(toast);

      requestAnimationFrame(() => {
        toast.classList.remove('translate-y-2', 'opacity-0');
      });

      setTimeout(() => {
        toast.classList.add('opacity-0', 'translate-y-2');
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
        hwSupportBadge.className = 'px-3 py-1 rounded-full text-xs font-mono flex items-center gap-2 border bg-emerald-950/60 text-emerald-400 border-emerald-500/50 shadow-[0_0_12px_rgba(16,185,129,0.2)]';
        hwSupportBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>Web NFC 対応';
      } else {
        hwSupportBadge.className = 'px-3 py-1 rounded-full text-xs font-mono flex items-center gap-2 border bg-amber-950/60 text-amber-300 border-amber-500/50';
        hwSupportBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-400"></span>Web NFC 非対応 (シミュレーター可)';
        compatNotice.classList.remove('hidden');
      }

      // Generate default demo key and plaintext
      inputPlaintext.value = "【最高機密文書】\nプロジェクト・イージス内部通信コード: 994-Alpha-Delta\nこのテキストは物理NFC指輪がない限り数学的に閲覧できません。";
      generateNewKey({ silent: true });

      // Setup NFC Reader Instance
      nfcReader = new NfcKeyReader({
        onKeyRead: async (keyString, meta) => {
          showToast(`物理タグ検知 (UID: ${meta.serialNumber})`, 'info');
          await attemptDecryption(keyString);
        },
        onError: (err) => {
          showToast(err.message, 'error');
          updateScannerVisuals('error', err.message);
        },
        onStatus: (status, message) => {
          if (status === 'scanning') {
            updateScannerVisuals('scanning', message);
          } else if (status === 'reading') {
            updateScannerVisuals('reading', message);
          } else if (status === 'idle') {
            updateScannerVisuals('idle', message);
          } else if (status === 'writing') {
            updateScannerVisuals('scanning', message);
          }
        }
      });

      // Default encrypt initial payload
      performEncryption({ silent: true });
      populateCodeDisplay();
    }

    function generateNewKey({ silent = false } = {}) {
      const newKey = CryptoVault.generateRandomKey(32);
      inputKey.value = newKey;
      markPayloadStale();
      if (!silent) showToast("32文字の暗号化鍵を生成しました（暗号化を再実行してください）", "info");
    }

    // 本文・鍵が暗号化後に変更されたら、ペイロードが古いことを表示する
    function markPayloadStale() {
      if (!currentPayload) return;
      if (inputKey.value.trim() === currentKey && inputPlaintext.value.trim() === currentPlaintext) {
        setPayloadBadge('done');
      } else {
        setPayloadBadge('stale');
      }
    }

    function setPayloadBadge(state) {
      if (state === 'stale') {
        badgePayloadStatus.textContent = "入力変更あり (再暗号化が必要)";
        badgePayloadStatus.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800";
      } else {
        badgePayloadStatus.textContent = "暗号化完了 (AES-256)";
        badgePayloadStatus.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800";
      }
    }

    async function performEncryption({ silent = false } = {}) {
      try {
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
        
        // Success Display
        updateScannerVisuals('success', '認証成功: コンテンツが解読されました');
        decryptedPlaceholder.classList.add('hidden');
        decryptedContent.classList.remove('hidden');
        decryptedContent.textContent = decryptedText;
        decryptedBox.className = 'min-h-[90px] rounded-xl border border-emerald-500/50 bg-emerald-950/20 p-4 transition-all duration-300 shadow-[0_0_20px_rgba(16,185,129,0.15)]';
        btnClearDecrypted.classList.remove('hidden');

        showToast("復号に成功しました！", "success");
      } catch (err) {
        updateScannerVisuals('error', err.message);
        showToast(err.message, "error");
      }
    }

    function clearDecryptedView() {
      decryptedPlaceholder.classList.remove('hidden');
      decryptedContent.classList.add('hidden');
      decryptedContent.textContent = '';
      decryptedBox.className = 'min-h-[90px] rounded-xl border border-cyber-border bg-slate-950 p-3.5 flex flex-col justify-center transition-all duration-300';
      btnClearDecrypted.classList.add('hidden');
    }

    function updateScannerVisuals(state, message) {
      scannerSubText.textContent = message;

      if (state === 'scanning') {
        radarPulse.className = 'absolute inset-0 rounded-full border-2 border-sky-400 animate-ping opacity-60';
        scannerIconBg.className = 'w-14 h-14 rounded-full bg-sky-950/80 border-2 border-sky-400 flex items-center justify-center text-sky-400 text-xl shadow-[0_0_25px_rgba(56,189,248,0.5)]';
        scannerStatusIcon.className = 'fa-solid fa-wave-square animate-pulse';
        scannerStatusText.textContent = 'スキャン待機中 (SCANNING)';
        scannerStatusText.className = 'text-xs font-bold font-mono uppercase tracking-wider text-sky-400';
        btnStartScan.classList.add('hidden');
        btnStopScan.classList.remove('hidden');
      } else if (state === 'reading') {
        radarPulse.className = 'absolute inset-0 rounded-full border-2 border-amber-400 animate-pulse';
        scannerIconBg.className = 'w-14 h-14 rounded-full bg-amber-950/80 border-2 border-amber-400 flex items-center justify-center text-amber-400 text-xl';
        scannerStatusIcon.className = 'fa-solid fa-spinner fa-spin';
        scannerStatusText.textContent = '読み取り処理中...';
        scannerStatusText.className = 'text-xs font-bold font-mono uppercase tracking-wider text-amber-400';
      } else if (state === 'success') {
        radarPulse.className = 'absolute inset-0 rounded-full border border-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.4)]';
        scannerIconBg.className = 'w-14 h-14 rounded-full bg-emerald-950 border-2 border-emerald-400 flex items-center justify-center text-emerald-400 text-xl shadow-[0_0_25px_rgba(16,185,129,0.5)]';
        scannerStatusIcon.className = 'fa-solid fa-unlock-keyhole';
        scannerStatusText.textContent = 'AUTHENTICATED (解錠完了)';
        scannerStatusText.className = 'text-xs font-bold font-mono uppercase tracking-wider text-emerald-400';
        syncScanButtons();
      } else if (state === 'error') {
        radarPulse.className = 'absolute inset-0 rounded-full border border-rose-500';
        scannerIconBg.className = 'w-14 h-14 rounded-full bg-rose-950 border-2 border-rose-500 flex items-center justify-center text-rose-400 text-xl shadow-[0_0_20px_rgba(244,63,94,0.4)]';
        scannerStatusIcon.className = 'fa-solid fa-ban';
        scannerStatusText.textContent = 'ACCESS DENIED (解錠失敗)';
        scannerStatusText.className = 'text-xs font-bold font-mono uppercase tracking-wider text-rose-400';
        syncScanButtons();
      } else {
        // Idle
        radarPulse.className = 'absolute inset-0 rounded-full border border-slate-700';
        scannerIconBg.className = 'w-14 h-14 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center text-slate-400 text-xl';
        scannerStatusIcon.className = 'fa-solid fa-nfc-directional';
        scannerStatusText.textContent = 'スキャナー待機中 (IDLE)';
        scannerStatusText.className = 'text-xs font-bold font-mono uppercase tracking-wider text-slate-300';
        btnStartScan.classList.remove('hidden');
        btnStopScan.classList.add('hidden');
      }
    }

    // 成功/失敗表示後もリーダーはスキャンを継続しているため、実際の状態でボタンを切り替える
    function syncScanButtons() {
      const scanning = nfcReader && nfcReader.isScanning;
      btnStartScan.classList.toggle('hidden', scanning);
      btnStopScan.classList.toggle('hidden', !scanning);
    }

    function populateCodeDisplay() {
      codeSnippetDisplay.textContent = `// 1. 暗号化して保管（HTML内に平文は残さない）
const key = CryptoVault.generateRandomKey(32);
const payload = await CryptoVault.encrypt("秘密の文書", key);

// 2. NFC指輪に鍵を書き込む（Android Chrome）
const nfc = new NfcKeyReader({
  onKeyRead: async (scannedKey, meta) => {
    try {
      const secret = await CryptoVault.decrypt(payload, scannedKey);
      console.log("解読成功:", secret);
    } catch(err) {
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
        showToast(err.message, "error");
      }
    });

    btnCopyPayload.addEventListener('click', async () => {
      if (!currentPayload) return;
      await copyText(JSON.stringify(currentPayload, null, 2));
      showToast("ペイロードJSONをコピーしました", "info");
    });

    btnStartScan.addEventListener('click', async () => {
      try {
        await nfcReader.startScan();
      } catch (err) {
        // Error handled in callback
      }
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
      const bogusKey = "INVALID_ROGUE_KEY_99999999999999";
      nfcReader.simulateRead(bogusKey);
    });

    btnClearDecrypted.addEventListener('click', () => {
      clearDecryptedView();
      updateScannerVisuals('idle', '再ロックしました。');
      showToast("コンテンツを再ロックしました", "info");
    });

    btnToggleSource.addEventListener('click', () => {
      sourceDrawer.classList.toggle('hidden');
      accordionArrow.classList.toggle('rotate-180');
    });

    btnCopyCode.addEventListener('click', async () => {
      await copyText(codeSnippetDisplay.textContent);
      showToast("ライブラリ利用コードをコピーしました", "info");
    });

    // Boot
    window.addEventListener('DOMContentLoaded', initApp);
