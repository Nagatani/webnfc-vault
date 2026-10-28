# webnfc-vault

NFCタグ（指輪型タグなど）を「物理鍵」として使い、ブラウザだけでデータを暗号化・復号するデモです。
ビルド不要の Vanilla JS（ES Modules）で、Web Crypto API と Web NFC (`NDEFReader`) を利用しています。

## ファイル構成

| パス | 内容 |
|---|---|
| `index.html` / `js/app.js` | フル機能デモ（鍵生成・暗号化・タグ書き込み・スキャン・シミュレーター） |
| `demo.html` | 2つのライブラリだけを使った最小構成のデモ |
| `js/crypto-vault.js` | `CryptoVault`: PBKDF2 (SHA-256, 100,000回) + AES-GCM-256 による暗号化・復号 |
| `js/nfc-key-reader.js` | `NfcKeyReader`: Web NFC のスキャン・書き込みをコールバック形式でラップ |

## 動かし方

ES Modules を使うため、`file://` ではなく HTTP サーバー経由で開いてください。

```sh
python3 -m http.server 8000
# http://localhost:8000/ または http://localhost:8000/demo.html
```

- 実際のタグの読み書きには **Android 版 Chrome** と **HTTPS**（または localhost）が必要です。
- PC や iOS では、シミュレートボタンで復号フローを試せます。

## 使い方

```js
import { CryptoVault } from './js/crypto-vault.js';
import { NfcKeyReader } from './js/nfc-key-reader.js';

const key = CryptoVault.generateRandomKey(32);
const payload = await CryptoVault.encrypt('秘密の文書', key); // { salt, iv, ciphertext }

const nfc = new NfcKeyReader({
  onKeyRead: async (scannedKey, meta) => {
    const secret = await CryptoVault.decrypt(payload, scannedKey); // 鍵が違えば例外
  },
  onError: (err) => console.error(err),
  onStatus: (status, message) => console.log(status, message),
});

await nfc.writeKey(key);  // タグにテキストレコードとして書き込み
await nfc.startScan();    // タグ検知で onKeyRead が呼ばれる
nfc.stopScan();           // スキャン／書き込み待機を中止
```
