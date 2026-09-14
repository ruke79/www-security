# www-security

> 🌐 [日本語](README.md) · [한국어](README.ko.md) · [English](README.en.md)

Web セキュリティおよびペネトレーションテスト(Web Pentest)のトレーニングを目的と
したプロジェクト集のリポジトリです。

> ⚠️ **意図的に脆弱に作られた教育用プロジェクトです。** 一部のエンドポイント
> (`/api/lab/**`)は認証なしでアクセスでき、SQL インジェクション・XSS・SSRF・
> コマンドインジェクション・SSTI などの実際の攻撃が動作するように作られています。
> **必ずローカルまたは統制されたトレーニング環境でのみ実行し、公開インターネットや
> 共有サーバーには絶対にデプロイしないでください。**

## プロジェクト一覧

### [api-security-lab](api-security-lab/)

書籍 *"Advanced API Security: Securing APIs with OAuth 2.0, OpenID Connect, JWS,
and JWE"* をベースにした Spring Boot 3.4.1 / Spring Security 6.4 / Spring
Authorization Server のデモプロジェクトです。各章を独立してテスト可能な REST
エンドポイントのグループとして実装しています。

扱うトピック:

- HTTP Basic / Digest 認証
- 相互 TLS 認証(mTLS)
- OAuth 2.0 認可コード(PKCE) / クライアントクレデンシャルフロー
- 送信者制約トークン (DPoP, RFC 9449)
- OAuth 2.0 プロファイル (トークンの introspection/revocation、JWT Bearer グラント)
- User-Managed Access(UMA) 2.0
- 外部 IdP 連携によるフェデレーション

詳細な実行方法と章ごとのエンドポイントマッピングは、[プロジェクトの
README](api-security-lab/README.md) を参照してください。

ペネトレーションテスト実習用にまとめた脆弱性シナリオ(再現手順、根本原因、対策)は
[VULNERABILITY-SCENARIOS.md](api-security-lab/VULNERABILITY-SCENARIOS.md) を
参照してください。

このデモのベースとなった書籍『Advanced API Security』の章ごとの詳細な要約(韓国語)は
[BOOK-SUMMARY.md](api-security-lab/BOOK-SUMMARY.md) を参照してください。

書籍第 14 章の 10 個の API セキュリティパターンをデモエンドポイントで再現する実行
ガイドは [PATTERNS.md](api-security-lab/PATTERNS.md) を参照してください。

各メカニズム・脆弱性が実務でどのように活用されるか(「状況 → 適用 → よくある
ミス」、IDOR・mTLS の掘り下げを含む)をまとめた実務活用ガイドは
[USE-CASES.md](api-security-lab/USE-CASES.md) を参照してください。

## ライセンス

このリポジトリの**ソースコード**は [MIT ライセンス](LICENSE)で配布されます。

ただし、`BOOK-SUMMARY.md` をはじめとする要約文書は、原書 *"Advanced API Security:
Securing APIs with OAuth 2.0, OpenID Connect, JWS, and JWE"* (Prabath
Siriwardena, Apress)の内容を学習用に要約・整理したものであり、**原書の著作権は
原著者/出版社に帰属します。** MIT ライセンスはこのプロジェクトが作成したコードに
のみ適用され、要約文書における原著作物の著作権には影響しません。
