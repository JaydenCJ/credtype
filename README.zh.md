# credtype

[English](README.md) | [中文](README.zh.md) | [日本語](README.ja.md)

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Rust ≥1.75](https://img.shields.io/badge/rust-%E2%89%A51.75-orange)](Cargo.toml) [![Version](https://img.shields.io/badge/version-0.1.0-blue)](CHANGELOG.md) [![Tests](https://img.shields.io/badge/tests-91%20passed-brightgreen)](tests/) [![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](CONTRIBUTING.md)

**面向密钥的 file(1)：仅凭前缀、格式与内嵌校验和，识别并结构化验证单个泄露的令牌 —— 完全离线。**

![Demo](docs/assets/demo.svg)

```bash
git clone https://github.com/JaydenCJ/credtype.git && cargo install --path credtype
```

## 为什么选择 credtype？

你在日志、`.env`、粘贴的片段或缺陷报告里发现一个令牌，需要快速得到两个答案：*这是什么？* 以及 *它是真的，还是被截断的垃圾？* 像 gitleaks、trufflehog 这类仓库扫描器做的是相反的事 —— 在整棵目录树里搜寻任何看起来像密钥的东西 —— 它们既不会对你交给它的单个字符串做分类，也不会告诉你其校验和是否通过。credtype 是另一类工具：只对准一个令牌，它就会说出所属家族（GitHub PAT、AWS 密钥、JWT、Stripe 密钥、银行卡号、私钥……），并在格式内嵌自包含校验和时重新计算，告诉你 `valid` 还是 `invalid`。它就是面向密钥的 `file(1)` —— 一个输入、一个诚实的答案 —— 零依赖、无网络、无遥测，因此可以安全地用在你绝不会粘贴到网站上的凭据上。

|  | credtype | gitleaks | trufflehog |
|---|---|---|---|
| 用途 | 分类并验证单个令牌 | 扫描仓库/目录树找密钥 | 扫描仓库/目录树找密钥 |
| 重算内嵌校验和 | 是（GitHub CRC-32、Luhn、OpenSSH magic） | 否 | 否（离线模式） |
| 结构化解码 | AWS 账号 id、JWT 声明、UUID 版本 | 仅正则匹配 | 仅正则匹配 |
| 联网验证活令牌 | 从不（设计上离线） | 否 | 是（会发起网络请求） |
| 运行时依赖 | 无（仅标准库） | 多（Go 模块） | 多（Go 模块） |
| 输出中脱敏密钥 | 是，默认开启 | 不适用 | 不适用 |
| 按判定给出可脚本化退出码 | 是（0/1/2/3） | 命中计数 | 命中计数 |

## 功能

- **回答"它是真的吗？"，而不只是"它是什么？"** —— 对携带自包含校验和的格式（GitHub 的 Base62 CRC-32、银行卡 Luhn、OpenSSH 的 `openssh-key-v1` magic），credtype 会重算并报告 `valid`/`invalid`，从而抓出被截断或伪造的令牌。
- **无校验和时也做结构化解码** —— 它能从访问密钥中还原 AWS 账号 id，从 JWT 中取出 `alg`/`iss`/`exp` 声明，从 UUID 中读出版本/变体，因此"无校验和"依然附带真实证据。
- **诚实是内建的** —— 只有真正验证过校验和，检测器才会说 `valid`/`invalid`；否则它说 `absent`。credtype 绝不暗示它没做过的验证。
- **可安全地用在真实密钥上** —— 文本与 JSON 输出中令牌默认脱敏（用 `--no-redact` 显示原文），且任何数据都不会离开本机：无网络、无遥测、仅标准库。
- **可脚本化** —— 每种判定对应清晰的退出码（`0` 有效/无校验和、`1` 校验和失败、`2` 无法识别、`3` 用法错误），`--json` 供机器读取，`--quiet` 只输出一个词，`--stdin` 供管道使用。
- **小巧二进制里的广泛覆盖** —— GitHub、AWS、JWT、银行卡、UUID、PEM/OpenSSH 密钥，以及一张厂商密钥表（Stripe、Slack、Google、SendGrid、npm、PyPI、GitLab、OpenAI、Anthropic、Shopify、Square、Twilio、DigitalOcean）。

## 快速上手

安装（需要 Rust 1.75+）：

```bash
git clone https://github.com/JaydenCJ/credtype.git && cargo install --path credtype
```

识别一个令牌并验证它的校验和——这个全 `A` 的伪造令牌无法通过：

```bash
credtype ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

输出（令牌默认脱敏）：

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

云密钥会被解码，而不仅仅是匹配；JSON 输出是一行、且不含密钥：

```bash
credtype --json AKIAIOSFODNN7EXAMPLE
```

```text
{"input_length":20,"is_fallback":false,"best":{"id":"aws-access-key-id","name":"AWS access key ID","category":"cloud","confidence":"medium","structural_ok":true,"checksum":"absent","length":20,"redacted":"AKIAIOSF********MPLE","details":{"key_type":"long-term IAM user access key","account_id":"581039954779","checksum":"none (structure + account-id decode only)"},"notes":["AWS keys carry no self-contained checksum; validity confirmed structurally"]},"alternates":[]}
```

## 令牌家族

`credtype list` 会打印完整清单。带校验和验证的家族会被标注；其余的按结构（前缀、字母表、长度）识别，并诚实地报告为校验和 `absent`。

| 家族 | id | 校验和 | credtype 提取的信息 |
|---|---|---|---|
| GitHub 令牌（经典） | `github-pat`、`gho`、`ghu`、`ghs`、`ghr` | CRC-32（已校验） | 前缀类型、校验和判定 |
| AWS 访问密钥 ID | `aws-access-key-id` | 无（结构化） | 密钥类型、12 位账号 id |
| JSON Web Token | `jwt` | 标记 `alg=none` | alg、typ、iss、sub、exp |
| 银行卡号 | `payment-card` | Luhn（已校验） | 发卡方（IIN）、位数 |
| UUID / GUID | `uuid` | 无（结构化） | 版本、变体、nil/max |
| 私钥 | `pem-*`、`openssh-private` | OpenSSH magic（已校验） | 外层封装类型 |
| 厂商 API 密钥 | `stripe-*`、`slack-token`、`npm-token`…… | 无（结构化） | 前缀、字母表、长度 |

## 退出码

credtype 的设计便于嵌入 `pre-commit` 钩子或分诊脚本。

| 退出码 | 含义 |
|---|---|
| `0` | 已识别，且校验和有效或不存在 |
| `1` | 已识别，但内嵌校验和验证失败 |
| `2` | 无法识别（回退到通用熵描述） |
| `3` | 用法错误 |

## 架构

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

## 路线图

- [x] v0.1.0：单令牌分类器，含 GitHub CRC-32、AWS 账号 id 解码、JWT 解码 + `alg=none`、Luhn 银行卡、UUID、PEM/OpenSSH、厂商密钥表、脱敏、JSON、可脚本化退出码，91 个测试与 `scripts/smoke.sh`
- [ ] 更多携带校验和的格式（Google `AIza` 变体、Azure、GCP 服务账号密钥 id）
- [ ] `--batch` 模式：分类一个令牌文件，并按家族汇总计数
- [ ] 稳定库 API 并发布到 crates.io
- [ ] 可选、显式的 `--probe`，向提供方测试某个密钥（需主动开启，默认关闭）

完整清单见 [open issues](https://github.com/JaydenCJ/credtype/issues)。

## 参与贡献

欢迎贡献 —— 见 [CONTRIBUTING.md](CONTRIBUTING.md)，可以从 [good first issue](https://github.com/JaydenCJ/credtype/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) 开始，或发起一个 [discussion](https://github.com/JaydenCJ/credtype/discussions)。本仓库不附带任何 CI；上述每条声明都由本地运行 `cargo test` 与 `scripts/smoke.sh` 验证。

## 许可证

[MIT](LICENSE)
