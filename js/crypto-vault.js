    /**
     * ===================================================================
     * LIBRARY 1: CryptoVault
     * Web Crypto API (AES-GCM 256 + PBKDF2) を用いたセキュア暗号化ライブラリ
     * ===================================================================
     */
    export class CryptoVault {
      /**
       * 暗号学的に安全なランダム鍵文字列（英数字）を生成
       * @param {number} length 鍵の文字数 (デフォルト: 32)
       * @returns {string} ランダム文字列
       */
      static generateRandomKey(length = 32) {
        const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_#";
        const randomValues = new Uint8Array(length);
        window.crypto.getRandomValues(randomValues);
        return Array.from(randomValues, byte => charset[byte % charset.length]).join('');
      }

      /**
       * 平文テキストをキー文字列で暗号化（AES-GCM 256）
       * @param {string} plainText 暗号化対象文字列
       * @param {string} keyString パスワード・鍵文字列
       * @returns {Promise<{salt: string, iv: string, ciphertext: string}>} Base64エンコードされたJSONオブジェクト
       */
      static async encrypt(plainText, keyString) {
        if (!plainText || !keyString) {
          throw new Error("暗号化する本文と鍵文字列の両方を入力してください。");
        }

        const enc = new TextEncoder();
        
        // 16バイトのランダムソルトと12バイトのIVを生成
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // PBKDF2用のベースキーをインポート
        const keyMaterial = await window.crypto.subtle.importKey(
          "raw",
          enc.encode(keyString),
          { name: "PBKDF2" },
          false,
          ["deriveKey"]
        );

        // PBKDF2 (100,000回イテレーション, SHA-256) で 256-bit AES-GCM 鍵を導出
        const aesKey = await window.crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
          },
          keyMaterial,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt"]
        );

        // AES-GCM 暗号化を実行（認証タグ128bitを含む）
        const encryptedBuffer = await window.crypto.subtle.encrypt(
          { name: "AES-GCM", iv: iv },
          aesKey,
          enc.encode(plainText)
        );

        // Uint8Array -> Base64 変換ヘルパー
        const toBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));

        return {
          salt: toBase64(salt),
          iv: toBase64(iv),
          ciphertext: toBase64(encryptedBuffer)
        };
      }

      /**
       * 暗号化ペイロードをキー文字列で復号
       * @param {{salt: string, iv: string, ciphertext: string}} payload 暗号化データ
       * @param {string} keyString 復号用鍵文字列
       * @returns {Promise<string>} 復号された平文文字列
       */
      static async decrypt(payload, keyString) {
        if (!payload || !payload.salt || !payload.iv || !payload.ciphertext) {
          throw new Error("無効な暗号化ペイロード形式です。");
        }
        if (!keyString) {
          throw new Error("復号用鍵が空です。");
        }

        const enc = new TextEncoder();
        const fromBase64 = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

        const salt = fromBase64(payload.salt);
        const iv = fromBase64(payload.iv);
        const encryptedData = fromBase64(payload.ciphertext);

        // PBKDF2用のベースキーをインポート
        const keyMaterial = await window.crypto.subtle.importKey(
          "raw",
          enc.encode(keyString),
          { name: "PBKDF2" },
          false,
          ["deriveKey"]
        );

        // 同一パラメータで鍵を再導出
        const aesKey = await window.crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
          },
          keyMaterial,
          { name: "AES-GCM", length: 256 },
          false,
          ["decrypt"]
        );

        try {
          // AES-GCM 復号（鍵が不一致の場合はここで例外スロー）
          const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            encryptedData
          );

          return new TextDecoder().decode(decryptedBuffer);
        } catch (err) {
          throw new Error("復号失敗: 物理鍵の照合に失敗しました（鍵が正しくないか、データが破損しています）。");
        }
      }
    }

