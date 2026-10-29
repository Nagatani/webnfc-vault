# webnfc-vault

NFCタグ（指輪型タグなど）を「物理鍵」として使い、ブラウザだけでデータを暗号化・復号するデモです。
ビルド不要の Vanilla JS（ES Modules）で、Web Crypto API と Web NFC (`NDEFReader`) を利用しています。

https://nagatani.github.io/webnfc-vault/

## ファイル構成

| パス | 内容 |
|---|---|
| `index.html` / `js/app.js` / `css/style.css` | フル機能デモ（鍵生成・暗号化・タグ書き込み・スキャン・シミュレーター） |
| `demo.html` | 貼り付けたJSONペイロードを、NFCタグから読み取った鍵で復号するデモ（ペイロード作成用のドロワー付き） |
| `js/crypto-vault.js` | `CryptoVault`: PBKDF2 (SHA-256, 100,000回) + AES-GCM-256 による暗号化・復号 |
| `js/nfc-key-reader.js` | `NfcKeyReader`: Web NFC のスキャン・書き込みをコールバック形式でラップ |
| `tests/` | Node.js 組み込みテストランナー用のテスト |

CSSフレームワークや外部のフォント・アイコンは使わず、すべてのファイルがリポジトリ内で完結しています。配色はOSのライト／ダーク設定に追従します。

## 動かし方

ES Modules を使うため、`file://` ではなく HTTP サーバー経由で開いてください。

```sh
python3 -m http.server 8000
# http://localhost:8000/ または http://localhost:8000/demo.html
```

- 実際のタグの読み書きには **Android 版 Chrome** と **HTTPS**（または localhost）が必要です。
- PC や iOS では、シミュレートボタンで復号フローを試せます。

## テスト

Node.js 20 以上で、追加パッケージなしに実行できます（`NDEFReader` はモックで代用）。

```sh
node --test tests/*.test.mjs
```

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
