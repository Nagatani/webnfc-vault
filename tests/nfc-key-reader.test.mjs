import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { NfcKeyReader } from '../js/nfc-key-reader.js';

// Web NFC の NDEFReader を最小限に模したモック
class FakeNDEFReader {
  static instances = [];
  constructor() {
    this.onreading = null;
    this.onreadingerror = null;
    FakeNDEFReader.instances.push(this);
  }
  async scan({ signal } = {}) {
    this.scanSignal = signal;
  }
  write(message, { signal } = {}) {
    this.written = message;
    return new Promise((resolve, reject) => {
      this.resolveWrite = resolve;
      signal?.addEventListener('abort', () => {
        reject(new DOMException('aborted', 'AbortError'));
      });
    });
  }
  emitText(text, serialNumber = '04:AA:BB') {
    this.onreading({
      serialNumber,
      message: { records: [{ recordType: 'text', encoding: 'utf-8', data: new TextEncoder().encode(text) }] }
    });
  }
}

function createReader() {
  const events = { keys: [], errors: [], statuses: [] };
  const reader = new NfcKeyReader({
    onKeyRead: (key, meta) => events.keys.push({ key, meta }),
    onError: (err) => events.errors.push(err),
    onStatus: (status) => events.statuses.push(status)
  });
  return { reader, events };
}

afterEach(() => {
  delete globalThis.NDEFReader;
  FakeNDEFReader.instances = [];
});

test('isSupported: NDEFReader の有無で判定する', () => {
  assert.equal(NfcKeyReader.isSupported(), false);
  globalThis.NDEFReader = FakeNDEFReader;
  assert.equal(NfcKeyReader.isSupported(), true);
});

test('startScan: 非対応環境では onError を呼んで例外を投げる', async () => {
  const { reader, events } = createReader();
  await assert.rejects(reader.startScan(), /Web NFC非対応/);
  assert.equal(events.errors.length, 1);
});

test('startScan: テキストレコードから鍵を読み取る', async () => {
  globalThis.NDEFReader = FakeNDEFReader;
  const { reader, events } = createReader();
  await reader.startScan();
  assert.equal(reader.isScanning, true);

  FakeNDEFReader.instances.at(-1).emitText('my-secret-key');
  assert.equal(events.keys.length, 1);
  assert.equal(events.keys[0].key, 'my-secret-key');
  assert.equal(events.keys[0].meta.serialNumber, '04:AA:BB');
});

test('startScan: テキストレコードがなければ onError', async () => {
  globalThis.NDEFReader = FakeNDEFReader;
  const { reader, events } = createReader();
  await reader.startScan();
  FakeNDEFReader.instances.at(-1).onreading({ serialNumber: 'X', message: { records: [{ recordType: 'url' }] } });
  assert.equal(events.keys.length, 0);
  assert.match(events.errors[0].message, /テキスト形式の鍵が見つかりません/);
});

test('stopScan: スキャンを中断して状態をリセットする', async () => {
  globalThis.NDEFReader = FakeNDEFReader;
  const { reader } = createReader();
  await reader.startScan();
  const signal = FakeNDEFReader.instances.at(-1).scanSignal;
  reader.stopScan();
  assert.equal(signal.aborted, true);
  assert.equal(reader.isScanning, false);
});

test('writeKey: テキストレコードとして書き込む', async () => {
  globalThis.NDEFReader = FakeNDEFReader;
  const { reader, events } = createReader();
  const done = reader.writeKey('abc');
  const writer = FakeNDEFReader.instances.at(-1);
  assert.deepEqual(writer.written, { records: [{ recordType: 'text', data: 'abc' }] });
  writer.resolveWrite();
  assert.equal(await done, true);
  assert.deepEqual(events.statuses, ['writing', 'idle']);
});

test('writeKey: stopScan で書き込み待機を中断できる', async () => {
  globalThis.NDEFReader = FakeNDEFReader;
  const { reader } = createReader();
  const done = reader.writeKey('abc');
  reader.stopScan();
  await assert.rejects(done, { name: 'AbortError' });
});

test('simulateRead: 疑似メタデータ付きで onKeyRead を呼ぶ', async () => {
  const { reader, events } = createReader();
  reader.simulateRead('mock');
  await new Promise(r => setTimeout(r, 250));
  assert.equal(events.keys[0].key, 'mock');
  assert.equal(events.keys[0].meta.simulated, true);
});
