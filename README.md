# x402 Token Preflight Check — 有料API「棚」

ERC-20トークンの「プリフライトチェック」を1回 **$0.04 USDC（Base）** で販売する
x402 対応API。決定的処理のみ・ステートレス・LLM不使用。
ファシリテーターは **PayAI**（`https://facilitator.payai.network`）で、
売り手側はアカウント登録・APIキーなしで開始できる（受取ウォレットごとの
無料決済クレジット枠内）。受取はエージェント専用ウォレット（受取専用、
このサービスは一切署名しない）。

## エンドポイント

| メソッド | パス | 料金 | 内容 |
|---|---|---|---|
| GET | `/` | 無料 | サービス説明JSON（名前・使い方・価格・対応チェーン） |
| GET | `/check?chain=base&token=0x…` | $0.04 USDC (Base) | トークンのプリフライトチェック結果JSON |

- `chain`: `base` / `ethereum`（チェック対象チェーン。支払いは常に Base USDC）
- `token`: ERC-20コントラクトアドレス
- 不正なパラメータは課金前に **400** で弾く（バリデーションを決済ミドルウェアより前に配置）

## `/check` が返すもの

- トークン情報: name / symbol / decimals / totalSupply（生値＋整形値）
- プロキシ検出: EIP-1967 と ZeppelinOS（旧OpenZeppelin）スロットを確認し、
  プロキシの場合は実装コントラクトのバイトコードも走査
- owner（Ownable。ゼロアドレス/リバート時は null）
- バイトコードのセレクタ走査による危険シグナル検出:
  mint/issue、pause、blacklist、freeze、fee control（setFee/setTax系・
  excludeFromFee系）、転送制限（maxTx/maxWallet系）、upgrade、burn
  - セレクタは署名文字列から同梱のKeccak-256実装で導出（定数の写し間違いを防止。
    テストで既知ベクトルと照合済み）
- `flags`（ソート済み）と簡易 `verdict`:
  `elevated_admin_control` / `admin_controls_present` /
  `limited_admin_surface` / `minimal_admin_surface`
- 出力は読み取ったチェーン状態の純粋関数（タイムスタンプ・乱数なし）

データ取得はAPIキー不要の公開RPC（複数エンドポイントを順に試行、
バッチ読み取り＋失敗時の個別再試行つき）。環境変数 `BASE_RPC_URL` /
`ETH_RPC_URL` で上書き可能。

## 構成

```
src/
  app.js          Honoアプリ（x402決済ミドルウェア＋ルート定義）
  check.js        チェックロジック（RPC読み取り・デコード・走査・verdict）
  keccak.js       Keccak-256（セレクタ導出専用、自己テストベクトルつき）
  node-server.js  Node用エントリ（PORT環境変数、既定4021）
  worker.js       Cloudflare Workers / Deno Deploy用エントリ
test/
  verify-check.mjs  実RPCでの検証（keccakベクトル、Base USDC、ETH USDT、ETH USDC）
  verify-402.mjs    HTTP検証（無料エンドポイント、400、402の支払い要求内容）
  VERIFICATION.md   検証結果の記録
DEPLOY.md           デプロイ手順メモ
```

## ローカル実行

```bash
npm install
npm start            # http://localhost:4021
curl http://localhost:4021/
curl "http://localhost:4021/check?chain=base&token=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"   # -> 402
npm run verify:check # 実RPC検証
npm run verify:402   # 402応答の検証
```

## 設定（`src/app.js` の定数）

- `PAY_TO`: `0x384F27a30557b4d19bD54dAb196D170F429C6D90`（エージェント専用Baseウォレット）
- `PRICE`: `$0.04`
- `NETWORK`: `eip155:8453`（Base）、scheme は `exact`
- `FACILITATOR_URL`: `https://facilitator.payai.network`

## 注意

- セレクタ走査はバイトコード上のヒューリスティクス。検出された関数は
  「ほぼ確実に存在」、未検出は「不在の証明ではない」（出力の `caveats` にも明記）。
- PayAIの無料クレジットは受取ウォレット単位だが、共有ホスト/IPでは
  共有プールを消費し得る（PayAI公式ドキュメントの注意書き）。枯渇した場合は
  APIキー取得（x402で支払って取得する方式）が必要になる — DEPLOY.md参照。
