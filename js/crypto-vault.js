/**
 * ===================================================================
 * LIBRARY 1: CryptoVault
 * Web Crypto API (AES-GCM 256 + PBKDF2) を用いたセキュア暗号化ライブラリ
 * ===================================================================
 */

const KEY_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_#";
const PBKDF2_ITERATIONS = 100000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
// getRandomValues() は1回あたり 65,536 バイトまで
const MAX_RANDOM_BYTES = 65536;

// Uint8Array -> Base64（大きなデータでも引数展開でスタックを溢れさせないよう分割して変換）
function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

// Base64 -> Uint8Array
function fromBase64(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// PBKDF2 (SHA-256) で鍵文字列から 256-bit AES-GCM 鍵を導出
async function deriveAesKey(keyString, salt, usage) {
  const keyMaterial = await globalThis.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(keyString),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return globalThis.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    [usage]
  );
}

export class CryptoVault {
  /**
   * 暗号学的に安全なランダム鍵文字列（英数字と -_#）を生成
   * @param {number} length 鍵の文字数 (デフォルト: 32)
   * @returns {string} ランダム文字列
   */
  static generateRandomKey(length = 32) {
    // 剰余による偏りを避けるため、charset長の倍数を超えるバイトは棄却する
    const limit = 256 - (256 % KEY_CHARSET.length);
    let result = "";
    while (result.length < length) {
      const randomValues = new Uint8Array(Math.min(length, MAX_RANDOM_BYTES));
      globalThis.crypto.getRandomValues(randomValues);
      for (const byte of randomValues) {
        if (byte < limit && result.length < length) {
          result += KEY_CHARSET[byte % KEY_CHARSET.length];
        }
      }
    }
    return result;
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

    // 16バイトのランダムソルトと12バイトのIVを生成
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const aesKey = await deriveAesKey(keyString, salt, "encrypt");

    // AES-GCM 暗号化を実行（認証タグ128bitを含む）
    const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      new TextEncoder().encode(plainText)
    );

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

    let salt, iv, encryptedData;
    try {
      salt = fromBase64(payload.salt);
      iv = fromBase64(payload.iv);
      encryptedData = fromBase64(payload.ciphertext);
    } catch (err) {
      throw new Error("無効な暗号化ペイロード形式です（Base64の解析に失敗しました）。");
    }

    // 同一パラメータで鍵を再導出
    const aesKey = await deriveAesKey(keyString, salt, "decrypt");

    try {
      // AES-GCM 復号（鍵が不一致の場合はここで例外スロー）
      const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
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
