    /**
     * ===================================================================
     * LIBRARY 2: NfcKeyReader
     * Web NFC (NDEFReader) をカプセル化したイベント駆動型リーダー＆ライター
     * ===================================================================
     */
    export class NfcKeyReader {
      /**
       * @param {Object} callbacks
       * @param {Function} callbacks.onKeyRead - (keyString: string, meta: Object) => void
       * @param {Function} callbacks.onError - (err: Error) => void
       * @param {Function} callbacks.onStatus - (status: string, message: string) => void
       */
      constructor({ onKeyRead, onError, onStatus } = {}) {
        this.onKeyRead = onKeyRead || (() => {});
        this.onError = onError || (() => {});
        this.onStatus = onStatus || (() => {});
        this.reader = null;
        this.abortController = null;
        this.isScanning = false;
      }

      /**
       * ブラウザがWeb NFC (NDEFReader) に対応しているか判定
       * @returns {boolean}
       */
      static isSupported() {
        return ('NDEFReader' in window);
      }

      /**
       * NFCタグのスキャン（待機）を開始
       */
      async startScan() {
        if (!NfcKeyReader.isSupported()) {
          const err = new Error("Web NFC非対応環境です。Android Chromeでアクセスするか、シミュレーターをご利用ください。");
          this.onError(err);
          throw err;
        }

        try {
          this.stopScan(); // 既存のスキャンがあれば破棄
          this.abortController = new AbortController();
          this.reader = new NDEFReader();

          this.onStatus("scanning", "NFCスキャン待機中... 指標をスマートフォンの背面にかざしてください。");
          await this.reader.scan({ signal: this.abortController.signal });
          this.isScanning = true;

          // タグ検知イベント
          this.reader.onreading = (event) => {
            this.onStatus("reading", "タグを検知しました。鍵データを読み取り中...");
            let extractedKey = "";

            // NDEFレコードからテキストレコードを抽出
            if (event.message && event.message.records) {
              for (const record of event.message.records) {
                if (record.recordType === "text") {
                  const decoder = new TextDecoder(record.encoding || 'utf-8');
                  extractedKey = decoder.decode(record.data);
                  break;
                }
              }
            }

            // メタデータ（シリアル番号UIDなど）
            const meta = {
              serialNumber: event.serialNumber || "UNKNOWN_UID",
              recordsCount: event.message ? event.message.records.length : 0,
              timestamp: new Date().toISOString()
            };

            if (extractedKey) {
              this.onKeyRead(extractedKey, meta);
            } else {
              this.onError(new Error(`タグは検知されましたが（UID: ${meta.serialNumber}）、テキスト形式の鍵が見つかりません。`));
            }
          };

          // 読み取りエラーハンドリング
          this.reader.onreadingerror = () => {
            this.onError(new Error("タグを検出しましたが通信に失敗しました。指輪をしっかり当てたまま静止させてください。"));
          };

        } catch (err) {
          this.isScanning = false;
          this.onStatus("idle", "スキャン停止");
          this.onError(err);
          throw err;
        }
      }

      /**
       * NFCタグにテキスト形式で鍵を書き込む
       * @param {string} keyString 書き込む鍵文字列
       */
      async writeKey(keyString) {
        if (!NfcKeyReader.isSupported()) {
          throw new Error("Web NFC非対応環境のため、ブラウザからのタグ書き込みは行えません。");
        }
        if (!keyString) {
          throw new Error("書き込む鍵文字列が指定されていません。");
        }

        try {
          const writer = new NDEFReader();
          this.onStatus("writing", "書き込み待機中... 指輪をスマホ背面にタッチしてください。");
          
          await writer.write({
            records: [
              {
                recordType: "text",
                data: keyString
              }
            ]
          });

          this.onStatus("idle", "タグへの書き込みが完了しました。");
          return true;
        } catch (err) {
          this.onStatus("idle", "書き込み中断");
          throw err;
        }
      }

      /**
       * スキャンの停止
       */
      stopScan() {
        if (this.abortController) {
          this.abortController.abort();
          this.abortController = null;
        }
        this.reader = null;
        this.isScanning = false;
        this.onStatus("idle", "スキャン停止中");
      }

      /**
       * PCやiOSブラウザ向けのフォールバック（シミュレーション読み取り）
       * @param {string} mockKey 
       */
      simulateRead(mockKey) {
        this.onStatus("reading", "[シミュレート] タグを検知しました。");
        const meta = {
          serialNumber: "04:SIMULATED:RING:TAG:80",
          recordsCount: 1,
          simulated: true,
          timestamp: new Date().toISOString()
        };
        setTimeout(() => {
          this.onKeyRead(mockKey, meta);
        }, 200);
      }
    }

