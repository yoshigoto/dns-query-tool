# DNSクエリー送信ツール

Webブラウザからの操作によりDNSクエリーを送信し、受信したDNSメッセージの応答内容を解析して表示するWebアプリケーションです。`dig` や `drill` のような確認を、DNSの委任や各種オプションを意識しながらWebブラウザで行うことができます。

## 公開サイト

https://www.on-link.jp/dnsquerytool/

## 主な機能

- DNSサーバー (権威サーバー、フルサービスリゾルバー) を指定したクエリーの送信
- UDP、TCP、DNS over HTTPS (DoH)、DNS over TLS (DoT) によるDNS通信
- IPv4またはIPv6を優先したDNSサーバー名の解決
- 非再帰検索と再帰検索 (RD) の切り替え
- QNAME minimisation (RFC 7816 / RFC 9156) を利用した反復検索
- EDNS0、DNSSEC OK (DO) 、Checking Disabled (CD) 、NSIDの要求
- UDPメッセージサイズの指定
- MQTYPE-Query (RFC 10029) の指定と応答表示
- A、AAAA、MX、NS、SOA、TXT、CNAME、DNSKEY、DS、HTTPS、SVCBなどのレコード表示
- DNS応答の `ANSWER`、`AUTHORITY`、`ADDITIONAL` セクションの解析
- TCフラグなどの各種フラグ、応答コード (rcode)、DNSSEC関連情報、Extended DNS Errorの表示
- 応答に含まれるドメイン名やIPアドレスから、次のクエリーを実行
- クエリー条件をURLのクエリーパラメーターとして保持

## 使い方

1. 「対象ドメイン名」に問い合わせたいドメイン名を入力します。
2. 必要に応じて「クエリー先DNSサーバー」、「クエリータイプ」、「RD」などを変更します。
3. 「DNSメッセージを送信」をクリックします。
4. 表示された `ANSWER`、`AUTHORITY`、`ADDITIONAL` の内容を確認します。

デフォルトでは `a.root-servers.net` を問い合わせ先とする非再帰検索です。委任を辿る場合は、応答として表示されたNSやIPアドレスをクリックして次の問い合わせを行います。

フルサービスリゾルバーに名前解決を任せる場合は、問い合わせ先にフルサービスリゾルバーを指定し、「RD」にチェックを入れてください。

### IXFR のシリアル番号

クエリータイプで `IXFR` を選ぶと「IXFR シリアル番号」欄が表示されます。取得済みゾーンの SOA SERIAL を `0`～`4294967295` の整数で指定してください（必須）。dig の指定は `ixfr=N` です。このツールでは `type=IXFR&ixfrserial=N` として URL に保持し、問い合わせの AUTHORITY セクションに指定した SERIAL の SOA レコードを追加します。

AXFR は [RFC 5936](https://datatracker.ietf.org/doc/html/rfc5936#section-2.2) により TCP を使用します。TCP送受信を有効にせず AXFR を問い合わせた場合、応答の基本情報に RFC 非準拠の案内を表示します。IXFR は UDP でも問い合わせできますが、応答が収まらない場合は TCP で再確認してください。現在は単一 DNS 応答の解析・表示のみで、複数メッセージにわたる IXFR/AXFR の転送全体の受信やゾーンの更新には対応していません。QNAME minimisation の途中では通常の A/NS 問い合わせを行い、最終的な IXFR 問い合わせにのみ SOA を追加します。

## ローカルで実行する

### 必要な環境

- Node.js 18以上
- DNSサーバー (権威サーバー、フルサービスリゾルバー) に対して通信方式に応じたポートへ接続できるネットワーク (UDP/TCP 53、DoT 853、DoH 443)

### 起動

```sh
npm install
node dns-query-tool.js
```

起動後、次のURLを開きます。

http://127.0.0.1:3000/dnsquerytool/

サーバーは `127.0.0.1:3000` のみで待ち受けます。nginx からは `proxy_pass http://127.0.0.1:3000;` で転送してください。外部ホストから Node.js へ直接接続することはできません。公開環境などでアプリケーションのパスを変更する場合は、`APPLICATION_PATH` 環境変数を指定できます。

環境変数を指定する場合:

```sh
APPLICATION_PATH=/dnsquerytool \
node dns-query-tool.js
```

## クエリーオプション

画面で指定できる主なオプションは次のとおりです。

| 項目 | URLパラメーター | 説明 |
| --- | --- | --- |
| クエリー先DNSサーバー | `server` | DNSサーバー (権威サーバー、フルサービスリゾルバー) のホスト名またはIPアドレス (省略時は `a.root-servers.net`) |
| 対象ドメイン名 (name) | `name` | 問い合わせ対象のドメイン名 |
| クエリータイプ (type) | `type` | `index.html` の選択肢にあるタイプのみ受付。TSIG、TKEYなど選択肢にないタイプはAPIでも拒否 |
| IXFR シリアル番号 | `ixfrserial` | `type=IXFR` のとき必須。取得済みゾーンの SOA SERIAL (`0`～`4294967295`)。他のクエリータイプでは使用しない |
| 再帰検索の要求 (RD) | `rd=1` | RDフラグを付ける |
| チェックの無効化 (CD) | `cd=1` | CDフラグを付ける |
| QNAME minimisation | `qmini=1` | QNAME minimisationを有効にする |
| - | `qposi` | QNAME minimisationで問い合わせるラベル位置 |
| QNAMEタイプ | `qtype` | `A` または `NS` |
| EDNS0の付与 | `edns0=1` | EDNS0を付与する |
| DNSSEC情報の要求 (DO) | `dnssec=1` | DOフラグを付ける |
| UDPメッセージサイズ | `udpsize` | EDNS0のUDPメッセージサイズ (`512`～`65535`) |
| NSIDの要求 | `nsid=1` | NSID情報を要求する |
| MQTYPE-Query | `mqtype` | 例: `A,AAAA,MX` |
| TCP送受信 | `tcp=1` | TCPで問い合わせる |
| DoT送受信 | `dot=1` | TLSでポート853へ問い合わせる。接続先の証明書を検証する |
| IPv6送受信 | `ipv6=1` | DNSサーバー名の解決やクエリー送信の際にIPv6を優先する |

APIのエンドポイントは、アプリケーションパスからの相対パスで `api/query` です。ブラウザ画面はこのエンドポイントへリクエストし、解析済みのHTMLを受け取って結果欄に表示します。

例:

```text
http://127.0.0.1:3000/dnsquerytool/api/query?server=8.8.8.8&name=example.com&type=A&rd=1
```

## ファイル構成

| ファイル | 役割 |
| --- | --- |
| `index.html` | 入力フォーム、説明、結果表示領域 |
| `dns-query-tool-client.js` | フォーム送信、履歴操作、結果表示、リンクからの再クエリー |
| `dns-query-tool.js` | HTTPサーバー、DNSメッセージ生成、UDP/TCP通信、応答解析、HTML生成 |
| `test-mqtype.js` | MQTYPEオプションの構築と応答解析の簡易テスト |
| `package.json` | Node.js依存関係の定義 |

## MQTYPEテスト

依存関係をインストールした後、次のコマンドでMQTYPEの簡易テストを実行できます。

```sh
node test-mqtype.js
```

このテストはMQTYPEのバイト列の構築と、`A,AAAA,MX` のような応答データの解析を確認します。実際のDNSサーバーがRFC 10029に対応しているかどうかは検証しません。

## IXFRテスト

Node.js 18.0 以降で、次のコマンドにより IXFR の入力検証、送信する SOA、再問い合わせリンク、フォーム復元を確認できます。

```sh
node test-ixfr.js
```

DNS通信はテスト内で置き換え、外部のDNSサーバーには接続しません。差し替えた関数とHTTPサーバーは、テストが失敗した場合も `finally` で復元・終了します。

## 注意事項

- このツールはDNSの動作確認・学習を目的としています。
- DNSSECの検証処理は行いません。DO/CDなどのフラグを付けて問い合わせるためのツールです。
- `localhost`、ループバックアドレス、プライベートアドレスなどのDNSサーバーは問い合わせ先に指定できません。
- DNSサーバーへの問い合わせは、実行環境から対象サーバーへ直接行われます。DoTは853番ポートを使用し、接続先がDoT非対応の場合やTLS証明書を検証できない場合は、DoTを無効にして再試行してください。ネットワークやファイアウォールの設定によっては応答を受信できません。
- DNSクエリーの結果は問い合わせ先サーバーやネットワークの状態によって変わります。
- 公開サーバーとして運用する場合は、アクセス制御、レート制限、ログ、HTTPS、Node.jsの更新などを別途検討してください。
- `127.0.0.1` への bind は外部ホストからの直接接続を防ぎますが、同一ホスト上の他プロセスからの接続は防ぎません。同一ホスト上のプロセスも制限する必要がある場合は、OS のアクセス制御や nginx と Node.js 間の認証も追加してください。

## 依存関係

- [dns-packet](https://www.npmjs.com/package/dns-packet) `^5.6.1`