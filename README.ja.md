# credtype

[English](README.md) | [中文](README.zh.md) | [日本語](README.ja.md)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Rust ≥1.75](https://img.shields.io/badge/rust-%E2%89%A51.75-orange)](Cargo.toml) [![Version](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md) [![Tests](https://img.shields.io/badge/tests-91%20passed-brightgreen)](tests/) [![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

**シークレット向けの file(1)：漏洩したトークン 1 個を、接頭辞・形式・埋め込みチェックサムだけで識別し構造的に検証する — 完全オフライン。**

![Demo](docs/assets/demo.svg)

```bash
git clone https://github.com/JaydenCJ/credtype.git && cargo install --path credtype
```

## なぜ credtype なのか？

ログ、`.env`、貼り付けられた断片、バグ報告の中でトークンを見つけたとき、素早く 2 つの答えが欲しくなる。*これは何か？* そして *本物か、それとも切り詰められたゴミか？* gitleaks や trufflehog のようなリポジトリスキャナは逆の仕事のために作られている —— ツリー全体を走査してシークレットらしきものを探す —— し、手渡した単一の文字列を分類することも、そのチェックサムが通るかを教えることもしない。credtype はもう一方のツールだ。トークン 1 個に狙いを定めれば、それが属するファミリ（GitHub PAT、AWS キー、JWT、Stripe キー、カード番号、秘密鍵……）を言い当て、形式が自己完結型のチェックサムを埋め込んでいれば再計算して `valid` か `invalid` かを告げる。まさにシークレット向けの `file(1)` だ —— 入力 1 つ、正直な答え 1 つ —— 依存ゼロ、ネットワークなし、テレメトリなし。だからこそ、ウェブサイトに貼り付けたくない資格情報にも安全に使える。

|  | credtype | gitleaks | trufflehog |
|---|---|---|---|
| 目的 | トークン 1 個を分類・検証 | リポジトリ/ツリーを走査 | リポジトリ/ツリーを走査 |
| 埋め込みチェックサムの再計算 | あり（GitHub CRC-32、Luhn、OpenSSH magic） | なし | なし（オフライン時） |
| 構造的デコード | AWS アカウント id、JWT クレーム、UUID 版 | 正規表現一致のみ | 正規表現一致のみ |
| オンラインで生きたキーを検証 | 一切しない（設計上オフライン） | なし | あり（ネットワーク通信） |
| ランタイム依存 | なし（標準ライブラリのみ） | 多数（Go モジュール） | 多数（Go モジュール） |
| 出力でシークレットをマスク | あり、既定で有効 | 該当なし | 該当なし |
| 判定ごとのスクリプト可能な終了コード | あり（0/1/2/3） | 検出件数 | 検出件数 |

## 特長

- **「何か？」だけでなく「本物か？」に答える** —— 自己完結型チェックサムを持つ形式（GitHub の Base62 CRC-32、カードの Luhn、OpenSSH の `openssh-key-v1` magic）では credtype が再計算して `valid`/`invalid` を報告し、切り詰められた・捏造されたトークンを捕まえる。
- **チェックサムが無ければ構造的にデコード** —— アクセスキーから AWS アカウント id を、JWT から `alg`/`iss`/`exp` クレームを、UUID から版/バリアントを復元するので、「チェックサムなし」でも実証を伴う。
- **正直さが設計に組み込まれている** —— 実際にチェックサムを検証したときだけ検出器は `valid`/`invalid` と言い、そうでなければ `absent` と言う。credtype は行っていない検証をほのめかさない。
- **本物のシークレットにも安全に使える** —— テキストと JSON の出力でトークンは既定でマスクされ（`--no-redact` で原文表示）、データは一切端末の外に出ない：ネットワークなし、テレメトリなし、標準ライブラリのみ。
- **スクリプト可能** —— 判定ごとに明確な終了コード（`0` 有効/なし、`1` チェックサム失敗、`2` 未識別、`3` 使い方エラー）、機械向けの `--json`、一語だけ出す `--quiet`、パイプ用の `--stdin`。
- **小さなバイナリでの広いカバレッジ** —— GitHub、AWS、JWT、カード番号、UUID、PEM/OpenSSH 鍵、そしてベンダーキーの表（Stripe、Slack、Google、SendGrid、npm、PyPI、GitLab、OpenAI、Anthropic、Shopify、Square、Twilio、DigitalOcean）。

## クイックスタート

インストール（Rust 1.75+ が必要）：

```bash
git clone https://github.com/JaydenCJ/credtype.git && cargo install --path credtype
```

トークンを識別し、そのチェックサムを検証する——この全部 `A` の偽造トークンは検証に失敗する：

```bash
credtype ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

出力（トークンは既定でマスクされる）：

```text
GitHub personal access token (classic)  [checksum FAILED]
  id:         github-pat
  category:   vendor
  confidence: medium
  structure:  valid
  checksum:   INVALID
  token:      ghp_AAAA****************************AAAA (40 chars)
  details:
    checksum: crc32/base62
  note: embedded CRC-32 checksum does NOT verify — truncated, mistyped or fabricated
```

クラウドキーは一致するだけでなくデコードされる。JSON 出力は 1 行で、シークレットを含まない：

```bash
credtype --json AKIAIOSFODNN7EXAMPLE
```

```text
{"input_length":20,"is_fallback":false,"best":{"id":"aws-access-key-id","name":"AWS access key ID","category":"cloud","confidence":"medium","structural_ok":true,"checksum":"absent","length":20,"redacted":"AKIAIOSF********MPLE","details":{"key_type":"long-term IAM user access key","account_id":"581039954779","checksum":"none (structure + account-id decode only)"},"notes":["AWS keys carry no self-contained checksum; validity confirmed structurally"]},"alternates":[]}
```

## トークンファミリ

`credtype list` が全一覧を表示する。チェックサム検証つきのファミリには印が付く。それ以外は構造（接頭辞・アルファベット・長さ）で識別し、チェックサムは正直に `absent` と報告する。

| ファミリ | id | チェックサム | credtype が抽出する情報 |
|---|---|---|---|
| GitHub トークン（クラシック） | `github-pat`、`gho`、`ghu`、`ghs`、`ghr` | CRC-32（検証済み） | 接頭辞の種類、チェックサム判定 |
| AWS アクセスキー ID | `aws-access-key-id` | なし（構造的） | キー種別、12 桁アカウント id |
| JSON Web Token | `jwt` | `alg=none` を警告 | alg、typ、iss、sub、exp |
| カード番号 | `payment-card` | Luhn（検証済み） | 発行者（IIN）、桁数 |
| UUID / GUID | `uuid` | なし（構造的） | 版、バリアント、nil/max |
| 秘密鍵 | `pem-*`、`openssh-private` | OpenSSH magic（検証済み） | アーマーの種類 |
| ベンダー API キー | `stripe-*`、`slack-token`、`npm-token`… | なし（構造的） | 接頭辞、アルファベット、長さ |

## 終了コード

credtype は `pre-commit` フックやトリアージスクリプトに組み込みやすいよう設計されている。

| コード | 意味 |
|---|---|
| `0` | 識別済みで、チェックサムが有効または存在しない |
| `1` | 識別済みだが、埋め込みチェックサムが失敗した |
| `2` | 未識別（汎用エントロピーへのフォールバック） |
| `3` | 使い方エラー |

## アーキテクチャ

```mermaid
flowchart LR
    T[one token] --> R[registry]
    R --> D[detectors: github / aws / jwt / card / uuid / pem / vendors]
    D --> C[checksum: CRC-32 / Luhn / magic]
    D --> S[structural decode: account id / claims / version]
    C --> K[ranked classification]
    S --> K
    R --> F[entropy fallback]
    K --> O[report: text / JSON, redacted]
    F --> O
```

## ロードマップ

- [x] v0.1.0：単一トークン分類器。GitHub CRC-32、AWS アカウント id デコード、JWT デコード + `alg=none`、Luhn カード、UUID、PEM/OpenSSH、ベンダーキー表、マスク、JSON、スクリプト可能な終了コード、91 個のテストと `scripts/smoke.sh` を搭載
- [ ] チェックサムを持つ形式の追加（Google `AIza` 系、Azure、GCP サービスアカウントキー id）
- [ ] `--batch` モード：トークンのファイルを分類し、ファミリ別に件数を集計
- [ ] ライブラリ API の安定化と crates.io への公開
- [ ] 任意で明示的な `--probe`：プロバイダに対してキーを検証（オプトイン、既定はオフ）

全一覧は [open issues](https://github.com/JaydenCJ/credtype/issues) を参照。

## コントリビュート

貢献を歓迎する —— [CONTRIBUTING.md](CONTRIBUTING.md) を参照し、[good first issue](https://github.com/JaydenCJ/credtype/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) から始めるか、[discussion](https://github.com/JaydenCJ/credtype/discussions) を開いてほしい。本リポジトリは CI を一切同梱しない。上記の主張はすべて `cargo test` と `scripts/smoke.sh` のローカル実行で検証される。

## ライセンス

[MIT](LICENSE)
