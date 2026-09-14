# API セキュリティパターン 再現ガイド（第14章 → デモ対応）

> 🌐 [한국어](PATTERNS.md) · [English](PATTERNS.en.md) · [日本語](PATTERNS.ja.md)

本書『Advanced API Security』**第14章「Patterns and Practices」** の10個の実務的な
API セキュリティ・ソリューションパターンを、このデモプロジェクト
(`api-security-lab`) のエンドポイントで再現する方法をまとめたものです。
各パターンは前の章で実装した仕組みの**組み合わせ**で構成されます。

> 実行前にまずアプリを起動してください。デフォルトでは 19080 の平文 HTTP のみが
> 開きます（mTLS は無効）。パターン1（mTLS）だけがポート 8443 + 証明書を必要とし、
> `MTLS_ENABLED=true` で有効化します。
>
> ```bash
> # ほとんどのパターン(2〜10): そのまま起動 (19080)。ポート競合時は APP_PORT で変更
> mvn spring-boot:run
> #   APP_PORT=29080 mvn spring-boot:run
>
> # パターン1(mTLS)まで試す場合: 証明書生成後に mTLS を有効化
> ./certs/generate-certs.sh
> MTLS_ENABLED=true mvn spring-boot:run
> ```
>
> 以下のコマンドは実際にアプリを起動して検証済みです。本書のシナリオ説明は要約で
> あり、デモは概念を示すための簡略化実装です（本番用途ではありません）。

## パターン → デモ対応 早見表

| # | パターン | 中核メカニズム | デモ実装 |
|---|---|---|---|
| 1 | Direct Auth + Trusted Subsystem | Web アプリが mTLS でバックエンド API を呼ぶ | `ch4` (mTLS, 8443) |
| 2 | SSO + Delegated Access Control | SAML トークン → OAuth アクセストークン交換 | `ch11` (assertion → jwt-bearer grant) |
| 3 | SSO + Integrated Windows Auth | IdP を IWA で保護（自動認証） | `ch11` + 説明 |
| 4 | Identity Proxy + Delegated | 内部 IdP が外部 IdP と信頼をブローカリング | `ch11` (外部 IdP フェデレーション) |
| 5 | Delegated Access Control + JWT | ID token(JWT) → アクセストークン交換 | `ch12` + `ch11` jwt-bearer |
| 6 | Nonrepudiation + JWS | ユーザー秘密鍵で JWS 署名 + JWE 暗号化 | `ch13` (JWS→JWE) |
| 7 | Chained Access Delegation | API→API 呼び出し時のトークン交換 | `ch9b` (chain grant) |
| 8 | Trusted Master Access Delegation | master が発行する自己記述型 JWT + introspection | `ch9`/`ch9b` |
| 9 | Resource STS + Delegated | インターセプター/STS による SAML トークン交換 | `ch5` (broker) + `ch11` |
| 10 | Delegated Access Control + Hidden Credentials | 資格情報を送らない（MAC トークン） | `ch8` (DPoP, MAC の代替) |

---

## パターン1 — Direct Authentication with the Trusted Subsystem

**本書のシナリオ**: ファイアウォール内の Web アプリがユーザーを認証した後、信頼された
サブシステムとしてバックエンド API を呼び出す。API は **mTLS** で保護する。

**デモ** (`ch4`): クライアント証明書を提示した場合のみアクセスできる mTLS エンド
ポイント。

```bash
./certs/generate-certs.sh                 # 初回のみ（鍵/トラストストア生成）
MTLS_ENABLED=true mvn spring-boot:run      # mTLS コネクタ 8443 を有効化（既定は無効）
# 8443 も競合する場合: MTLS_ENABLED=true MTLS_PORT=18443 mvn spring-boot:run

# 信頼されたクライアント証明書でアクセス → 200 + 証明書 Subject DN
curl -k --cert certs/client-cert.pem --key certs/client-key.pem \
     https://localhost:8443/api/ch4/whoami

# 証明書なしでアクセス → 拒否
curl -k https://localhost:8443/api/ch4/whoami
```

**要点**: ユーザーはバックエンド API ではなく Web アプリ（＝ trusted subsystem）で
認証され、Web アプリ↔API 間は相互 TLS で信頼を確立する。

---

## パターン2 — Single Sign-On with the Delegated Access Control

**本書のシナリオ**: SAML 2.0 IdP でログイン後、受け取った SAML トークンを **SAML
grant type** で OAuth アクセストークンに交換してバックエンド API にアクセスする
（refresh token なし。アクセストークンの寿命は SAML トークンの寿命内）。

**デモ** (`ch11`): SAML/XML ツールの代わりに、同じ信頼モデルを **JWT bearer grant
(RFC 7523)** で実現。外部 IdP が署名した assertion → 自前の認可サーバーが独自の
アクセストークンを発行。

```bash
# 1. 外部 IdP（"Foo Inc."）が署名した assertion を取得（SAML assertion に相当）
ASSERTION=$(curl -s "http://localhost:19080/api/ch11/external-idp/assertion?user=alice@foo-inc.example" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['assertion'])")

# 2. jwt-bearer grant で自前の認可サーバーのアクセストークンに交換
TOKEN=$(curl -s -u demo-jwtbearer-client:jwtbearer-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion="$ASSERTION" -d scope=ch11.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 3. 交換したトークンでバックエンド API にアクセス
curl -H "Authorization: Bearer $TOKEN" http://localhost:19080/api/ch11/resource
```

**要点**: ユーザーの資格情報は Web アプリに直接渡されない — IdP が署名した
assertion のみを信頼する（本書の SAML grant type と同じ out-of-band 信頼確立）。

---

## パターン3 — Single Sign-On with Integrated Windows Authentication

**本書のシナリオ**: パターン2と同じだが、ユーザーが Windows ドメインに既にログイン
していれば IdP を **IWA** で保護し、資格情報入力なしで自動認証する。IdP の認証方式が
IWA に変わるだけで、残りのフロー（SAML → アクセストークン交換）は同一。

**デモ**: IWA（Kerberos/SPNEGO）は Windows ドメイン環境が必要なため、本デモの範囲外。
**フロー自体はパターン2と同一**なので、パターン2のコマンドをそのまま使い、「assertion
を発行する IdP の認証方式だけが IWA に置き換わる」と理解してください。

---

## パターン4 — Identity Proxy with the Delegated Access Control

**本書のシナリオ**: 自社従業員だけでなく信頼するパートナー企業の従業員もアクセス
する。内部アプリは**自ドメインの IdP のみを信頼**し、内部 IdP が外部 IdP との信頼を
ブローカリング（必要ならプロトコル変換）する。

**デモ** (`ch11`): "Foo Inc." は当方が制御しない**独立した外部 IdP**で、独自の RSA
鍵で assertion に署名する。自前の認可サーバーはその外部 IdP を信頼するよう明示的に
設定 (`ExternalIdpConfig`) されており、外部ユーザーの assertion を受けて独自の
トークンを発行する — これが identity proxy のブローカリングである。

```bash
# パートナー企業ユーザーの identity で assertion を発行 → 認可サーバーが信頼してトークン発行
ASSERTION=$(curl -s "http://localhost:19080/api/ch11/external-idp/assertion?user=bob@partner.example" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['assertion'])")
TOKEN=$(curl -s -u demo-jwtbearer-client:jwtbearer-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion="$ASSERTION" -d scope=ch11.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -H "Authorization: Bearer $TOKEN" http://localhost:19080/api/ch11/resource
```

> ⚠️ このフローのセキュリティ上の落とし穴（外部 IdP assertion の任意発行 + audience
> 未検証による identity なりすまし）は
> [`VULNERABILITY-SCENARIOS.ja.md`](VULNERABILITY-SCENARIOS.ja.md) のシナリオ6で扱います。

---

## パターン5 — Delegated Access Control with the JSON Web Token

**本書のシナリオ**: OpenID Connect IdP でログインして得た **ID token(JWT)** を、
OIDC サーバーと認可サーバーが異なる場合に **JWT bearer grant** でアクセストークンに
交換する。

**デモ** (`ch12` + `ch11`): OIDC ID token の発行/検証は `ch12` が、JWT をアクセス
トークンに交換する jwt-bearer grant は `ch11` が担う。

```bash
# 1. OIDC ID token を発行（認証済みユーザー identity の assertion）
IDT=$(curl -s -X POST http://localhost:19080/api/ch12/id-token/issue -H 'Content-Type: application/json' \
  -d '{"subject":"alice@foo.com","clientId":"demo-client","nonce":"n-123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['id_token'])")

# 2. ID token を検証（signature + iss + aud + nonce）
curl -s -X POST http://localhost:19080/api/ch12/id-token/validate -H 'Content-Type: application/json' \
  -d "{\"idToken\":\"$IDT\",\"expectedClientId\":\"demo-client\",\"expectedNonce\":\"n-123\"}"
```

> **デモ上の正確なニュアンス**: `ch12` の ID token は**自前の認可サーバーの鍵**で
> 署名されます。一方 `ch11` の jwt-bearer grant は**外部 IdP の鍵**で署名された
> assertion を検証するよう構成されています。したがって「ID token をそのまま
> jwt-bearer で交換」が成立するのは両サーバーが同一ドメイン/鍵の場合のみです
> （本書の Note も同様に指摘：OIDC サーバーと認可サーバーが同一ならそもそも交換は
> 不要）。異なるドメインのシナリオはパターン2/4 の外部 IdP assertion フローで
> 再現してください。

---

## パターン6 — Nonrepudiation with the JSON Web Signature

**本書のシナリオ**: 金融 API など否認防止が必須の場合。機関がユーザーごとに鍵ペアを
発行し、公開証明書のみ保管する。すべての API 呼び出しを**ユーザー秘密鍵で JWS 署名**
した後、**機関の公開鍵で JWE 暗号化**する（署名が先、暗号化が後 — 法的受容性のため）。

**デモ** (`ch13`): JWS 署名・検証と JWE 暗号化・復号をそれぞれ再現。

```bash
# 1. ユーザー秘密鍵でペイロードを署名（JWS, RS256）— 否認防止の中核
JWS=$(curl -s -X POST http://localhost:19080/api/ch13/jws/rsa/sign -H 'Content-Type: application/json' \
  -d '{"subject":"customer-42","issuer":"mobile-app"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['jws'])")

# 2. 署名を検証（受信側：信頼された発行者の署名かを確認 → 偽造不可能な証明）
curl -s -X POST http://localhost:19080/api/ch13/jws/rsa/verify -H 'Content-Type: application/json' \
  -d "{\"jwt\":\"$JWS\"}"

# 3. 機密性も必要なら JWE で暗号化（RSA-OAEP-256 + A128GCM, compact = 5 パート）
#    本書のルール：「署名が先 → 暗号化が後」に従う。
JWE=$(curl -s -X POST http://localhost:19080/api/ch13/jwe/encrypt -H 'Content-Type: application/json' \
  -d '{"subject":"customer-42"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['jwe'])")
curl -s -X POST http://localhost:19080/api/ch13/jwe/decrypt -H 'Content-Type: application/json' \
  -d "{\"jwt\":\"$JWE\"}"
```

**要点**: 署名は「誰がやったか」を偽造不可能に証明（否認防止）、暗号化は「第三者に
読ませない」（機密性）。目的が異なり、併用時は署名が先。

---

## パターン7 — Chained Access Delegation

**本書のシナリオ**: モバイルアプリが Water API を呼び、Water API がさらにユーザーに
代わって MyHealth API を呼ぶ。audience 制約のため受け取ったトークンをそのまま渡せ
ないので、**Chain Grant Type** で新しいトークンに交換する。

**デモ** (`ch9b`): 元のアクセストークンをより狭い（または同一の）scope の新しい
トークンに交換する。refresh token は発行されない。

```bash
# 1. クライアントが最初の API 用トークンを取得
TOKEN=$(curl -s -u demo-service-client:service-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=client_credentials -d scope='ch7.read ch7.write' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 2. 最初の API が 2 番目の API 呼び出し用にトークンを chain 交換（狭い scope + 別 audience）
curl -s -X POST http://localhost:19080/api/ch9b/chain/token -H 'Content-Type: application/json' \
  -d "{\"oauthToken\":\"$TOKEN\",\"scope\":\"ch7.read\",\"audience\":\"myhealth-api\"}"

# 3. 元にない scope への昇格を試みる → 拒否
curl -s -X POST http://localhost:19080/api/ch9b/chain/token -H 'Content-Type: application/json' \
  -d "{\"oauthToken\":\"$TOKEN\",\"scope\":\"admin.super\"}"   # -> invalid_scope
```

**要点**: 交換されたトークンは元の scope の**部分集合**のみを持ち、refresh token が
ないため再交換には元のトークンを再提示する必要がある。

---

## パターン8 — Trusted Master Access Delegation

**本書のシナリオ**: 部署ごとに独自の認可サーバー + 中央（master）認可サーバーがある。
master が発行する**自己記述型 JWT（iss を含む）** でどの部署の API にもアクセスできる。
部署の認可サーバーは JWT ヘッダーから発行者を確認し、master の **introspection**
エンドポイントでトークンの状態・scope を照会してから（必要なら XACML PDP で）認可する。

**デモ** (`ch9`/`ch9b`): 標準の introspection で「どのサーバーが発行し、まだ有効か」を
確認する部分を再現。

```bash
# master(= 自前の認可サーバー)が JWT アクセストークンを発行
TOKEN=$(curl -s -u demo-service-client:service-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=client_credentials -d scope=ch7.read \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 部署の認可サーバーが master の introspection でトークンを検証（active/scope/client_id/aud）
curl -s -u demo-service-client:service-secret -X POST http://localhost:19080/oauth2/introspect \
  -d "token=$TOKEN"
```

**要点**: 部署の認可サーバーは introspection 応答の `active`/`scope`/`aud` でアクセス
可否を判断できる（本書ではこの応答から XACML リクエストを作り PDP に問い合わせる）。
トークンが JWT なので `iss` クレームで発行者を即座に識別できる。

---

## パターン9 — Resource STS with the Delegated Access Control

**本書のシナリオ**: クライアント・API を変更せずにセキュリティを追加する。両側に
インターセプター（PEP）を置き、クライアント地域の STS が発行した SAML トークンを
API 地域の STS が交換（WS-Trust）し、最終的に **SAML grant type** でアクセストークンに
交換する。

**デモ** (`ch5` broker + `ch11`): WS-Trust/SOAP STS は範囲外だが、中核の**トークン交換**
は `ch5` のブローカード委任で、**assertion → アクセストークン**の段階は `ch11` で再現。

```bash
# (a) ch5 ブローカード委任: 元のトークンを別 audience/狭い scope に交換（STS トークン交換に相当）
LTOKEN=$(curl -s -u lucidchart-client:lucidchart-secret -X POST http://localhost:19080/oauth2/token \
  -d grant_type=client_credentials -d scope='ch5.read ch5.write' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -s -H "Authorization: Bearer $LTOKEN" -X POST http://localhost:19080/api/ch5/broker/exchange \
  -H 'Content-Type: application/json' -d '{"audience":"api-region-sts","scope":["ch5.read"]}'

# (b) ch11: 最終的に（外部 IdP が署名した）assertion をアクセストークンに交換 → API アクセス
#     上のパターン2と同じフロー
```

**要点**: 複数の信頼ドメインをまたぐ際、「トークンをその地域が理解する別のトークンに
繰り返し交換する」のが中核のアイデアである。

---

## パターン10 — Delegated Access Control with Hidden Credentials

**本書のシナリオ**: 資格情報を通信路に乗せてはいけない場合。HTTP Digest または
**OAuth 2.0 MAC トークン**を使う。MAC トークンは API ごとの発行・個別失効が可能で
より優れる。

**デモ** (`ch8`): 廃止された MAC Token Profile の代わりに、現代の標準 **DPoP
(RFC 9449)** で「トークンの秘密を通信路に乗せない所有証明 (PoP)」を再現。

```bash
# 1. デモ鍵ペアを生成（privateJwk はサーバーが文字列として受け取るため json.dumps で包んで渡す）
KEYS=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/keypair)
PRIVATE_JWK=$(echo "$KEYS" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['privateJwk']))")

# 2. トークン要求用の DPoP proof に署名
PROOF=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/proof -H 'Content-Type: application/json' \
  -d "{\"privateJwk\": $PRIVATE_JWK, \"htm\":\"POST\", \"htu\":\"http://localhost:19080/api/ch8/dpop/token\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['proof'])")

# 3. DPoP バインドされたアクセストークンを取得
TOKEN=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/token -H "DPoP: $PROOF" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 4. リソース要求用の新しい proof(ath バインド)に署名し、トークン + proof を同時に提示
PROOF2=$(curl -s -X POST http://localhost:19080/api/ch8/dpop/proof -H 'Content-Type: application/json' \
  -d "{\"privateJwk\": $PRIVATE_JWK, \"htm\":\"GET\", \"htu\":\"http://localhost:19080/api/ch8/protected/resource\", \"accessToken\":\"$TOKEN\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['proof'])")
curl -H "Authorization: Bearer $TOKEN" -H "DPoP: $PROOF2" http://localhost:19080/api/ch8/protected/resource
```

**要点**: bearer トークンと異なり、トークンを盗んでも**秘密鍵がなければ**有効な proof
を作れないため使用できない（＝「hidden credentials」の現代的な実現）。

---

## 参考

- 各章の詳細要約: [`BOOK-SUMMARY.md`](BOOK-SUMMARY.md)（韓国語）
- デモコードで練習できる脆弱性シナリオ: [`VULNERABILITY-SCENARIOS.ja.md`](VULNERABILITY-SCENARIOS.ja.md)
- 章ごとのエンドポイント/実行方法: [`README.md`](README.md)
