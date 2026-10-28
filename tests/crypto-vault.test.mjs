import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CryptoVault } from '../js/crypto-vault.js';

test('generateRandomKey: 指定長・許可文字のみ', () => {
  for (const length of [1, 32, 100]) {
    const key = CryptoVault.generateRandomKey(length);
    assert.equal(key.length, length);
    assert.match(key, /^[A-Za-z0-9\-_#]+$/);
  }
});

test('generateRandomKey: getRandomValues の上限を超える長さでも生成できる', () => {
  assert.equal(CryptoVault.generateRandomKey(100000).length, 100000);
});

test('generateRandomKey: 文字の出現頻度に大きな偏りがない', () => {
  const key = CryptoVault.generateRandomKey(65 * 2000);
  const counts = new Map();
  for (const c of key) counts.set(c, (counts.get(c) || 0) + 1);
  assert.equal(counts.size, 65);
  for (const n of counts.values()) {
    // 期待値 2000、標準偏差 ≈ 44.4 に対して十分に広い許容幅
    assert.ok(n > 1700 && n < 2300, `count ${n}`);
  }
});

test('encrypt/decrypt: 往復で元の文字列に戻る', async () => {
  const key = CryptoVault.generateRandomKey(32);
  const plain = '秘密の文書 🔐\n2行目';
  const payload = await CryptoVault.encrypt(plain, key);
  assert.deepEqual(Object.keys(payload).sort(), ['ciphertext', 'iv', 'salt']);
  assert.equal(await CryptoVault.decrypt(payload, key), plain);
});

test('encrypt: 同じ入力でも salt / iv / ciphertext は毎回異なる', async () => {
  const a = await CryptoVault.encrypt('same', 'key');
  const b = await CryptoVault.encrypt('same', 'key');
  assert.notEqual(a.salt, b.salt);
  assert.notEqual(a.iv, b.iv);
  assert.notEqual(a.ciphertext, b.ciphertext);
});

test('encrypt/decrypt: 大きなデータでもスタックが溢れない', async () => {
  const plain = 'x'.repeat(1_000_000);
  const payload = await CryptoVault.encrypt(plain, 'key');
  assert.equal(await CryptoVault.decrypt(payload, 'key'), plain);
});

test('decrypt: 誤った鍵では失敗する', async () => {
  const payload = await CryptoVault.encrypt('secret', 'right-key');
  await assert.rejects(CryptoVault.decrypt(payload, 'wrong-key'), /復号失敗/);
});

test('decrypt: 改ざんされた暗号文では失敗する', async () => {
  const payload = await CryptoVault.encrypt('secret', 'key');
  const bytes = Buffer.from(payload.ciphertext, 'base64');
  bytes[0] ^= 0xff;
  await assert.rejects(
    CryptoVault.decrypt({ ...payload, ciphertext: bytes.toString('base64') }, 'key'),
    /復号失敗/
  );
});

test('decrypt: 不正なペイロード・空の鍵を拒否する', async () => {
  const payload = await CryptoVault.encrypt('secret', 'key');
  await assert.rejects(CryptoVault.decrypt(null, 'key'), /無効な暗号化ペイロード/);
  await assert.rejects(CryptoVault.decrypt({ ...payload, iv: '!!!' }, 'key'), /Base64/);
  await assert.rejects(CryptoVault.decrypt(payload, ''), /鍵が空/);
});

test('encrypt: 本文または鍵が空なら拒否する', async () => {
  await assert.rejects(CryptoVault.encrypt('', 'key'), /両方を入力/);
  await assert.rejects(CryptoVault.encrypt('text', ''), /両方を入力/);
});
