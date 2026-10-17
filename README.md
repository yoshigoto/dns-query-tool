# DNSクエリー送信ツール

Webブラウザからの操作によりDNSクエリーを送信し、受信したDNSメッセージの応答内容を解析して表示するWebアプリケーションです。`dig` や `drill` のような確認を、DNSの委任や各種オプションを意識しながらWebブラウザで行うことができます。

## 公開サイト

https://www.on-link.jp/dns-query-tool/

## 主な機能

- DNSサーバー (権威サーバー、フルサービスリゾルバー) を指定したクエリーの送信
- UDP、TCP、DNS over HTTPS (DoH)、DNS over TLS (DoT) によるDNS通信
- IPv4またはIPv6を優先したDNSサーバー名の解決
- 非再帰検索と再帰検索 (RD) の切り替え
- QNAME minimisation (RFC 7816 / RFC 9156) を模した反復検索 (検索自体は手動 - 後述の「使い方」参照)
- EDNS0、DNSSEC OK (DO) 、Checking Disabled (CD) 、NSIDの要求
- UDPメッセージサイズの指定
- MQTYPE-Query (RFC 10029) の指定と応答表示
- A、AAAA、MX、NS、SOA、TXT、CNAME、DNSKEY、DS、HTTPS、SVCBなどのレコード表示
- DNS応答の `ANSWER`、`AUTHORITY`、`ADDITIONAL` セクションの解析
- TCフラグなどの各種フラグ、応答コード (rcode)、DNSSEC関連情報、Extended DNS Errorの表示
- 応答に含まれるドメイン名やIPアドレスから、次のクエリーを実行
- クエリー条件をURLのクエリーパラメーターとして保持

応答の `OPT PSEUDOSECTION` の `Version` には、受信した OPT レコードの EDNS バージョンを表示します。送信クエリーは EDNS0（バージョン0）ですが、応答にバージョン1などが含まれる場合も、その値を表示します。

## 使い方

1. 「対象ドメイン名」に問い合わせたいドメイン名を入力します。
2. 必要に応じて「クエリー先DNSサーバー」、「クエリータイプ」、「RD」などを変更します。
3. 「DNSメッセージを送信」をクリックします。
4. 表示された `ANSWER`、`AUTHORITY`、`ADDITIONAL` の内容を確認します。

デフォルトでは `a.root-servers.net` を問い合わせ先とする非再帰検索です。委任を辿る場合は、応答として表示されたNSやIPアドレスをクリックして次の問い合わせを行います。

SOA レコードの `mname` は、そのゾーンのプライマリサーバーのドメイン名です。`ANSWER`、`AUTHORITY`、`ADDITIONAL` の各セクションで `mname` のドメイン名をクリックすると、その名前の A レコードをルートサーバーから新たに探索できます。RD、DoH、DoT、MQTYPE は無効になり、QNAME minimisation が有効な場合はラベル位置を初期化します。委任を辿る操作は引き続き手動です。

フルサービスリゾルバーに名前解決を任せる場合は、問い合わせ先にフルサービスリゾルバーを指定し、「RD」にチェックを入れてください。

### dig コマンド形式で入力する

通常のフォームとは別に、`dig.html`（ローカルでは `http://127.0.0.1:3000/dig.html` または `http://127.0.0.1:3000/dns-query-tool/dig.html`）で dig コマンド、または引数だけを入力できます。通常画面からも移動できます。
入力欄は1行で、Enterキーまたは「DNSメッセージを送信」ボタンで送信できます。

```text
dig in a @a.root-servers.net www.on-link.jp -6 +rd +cd +dnssec
dig @8.8.8.8 example.com -t AAAA +tcp +nsid +bufsize=1232
delv @a.root-servers.net www.on-link.jp +qmin +nord
```

最初の例は IN / A、サーバー `a.root-servers.net`、対象名 `www.on-link.jp`、IPv6優先・RD・CD・DO On（EDNS0もOn）に変換します。コマンドそのものをOSで実行することはありません。既存の `api/query` でDNS送信・応答解析を行います。

| dig / delv 引数 | 本ツールの設定 |
| --- | --- |
| `@server`、`name`、`type`、`class` | サーバー、対象名、タイプ、クラス（順不同・大文字小文字不問のタイプ/クラス） |
| `-q name`、`-t type`、`-c class` | 対象名、タイプ、クラス（`-tAAAA` のような連結形式も可） |
| `-x address` | `PTR-x` によるIPv4/IPv6逆引き |
| `-4` / `-6` | IPv4 / IPv6優先（digの通信ファミリー固定とは異なります） |
| `+[no]rd` / `+[no]recurse` | RD |
| `+[no]cd` / `+[no]cdflag` | CD |
| `+[no]dnssec`、`+[no]nsid` | DO、NSID（有効化時はEDNS0もOn） |
| `+edns[=0]` / `+noedns`、`+bufsize=N` | EDNS0、UDPサイズ512～65535（サイズ指定時はEDNS0もOn） |
| `+[no]tcp` / `+[no]vc` | TCP |
| `+[no]tls`、`+[no]https[=/path]` | DoT、DoH (POST)。本ツールでは証明書を検証します |
| `ixfr=N` | IXFRとSOA SERIAL。AXFR/IXFRは既定でTCP（`+notcp` で解除可能） |
| `+[no]qmin` | delv形式の指定を既存のQNAME minimisationへ対応付け。委任を辿る操作は手動 |

省略時は IN、A（対象名も省略した場合は `. NS`）、RD・EDNS0 On、UDPサイズ1232です。サーバーは本ツール既定の `a.root-servers.net` とし、OSのリゾルバー設定や `.digrc` は使用しません。それ以外の本ツール独自機能（MQTYPE、QNAMEタイプ切り替えなど）は自動では追加しません。通常フォームの既定値は変わりません。

受信結果の上に入力コマンドを元の空白・引用符を含めて表示し、無視した引数とその値を赤字・波線で強調します。理由の一覧と、実際に反映されたAPIパラメーターも確認できます。「通常の入力フォームへ」から反映された設定を通常画面で開けます。結果のリンクをクリックした場合も通常画面に移動します。

対応しない引数（`+short`、`+trace`、`+time`、`+retry`、`-p`、`-b`、`-f`、TSIG、EDNS Cookie / ECSなど）は無視します。未対応のクエリータイプ・クラスや範囲外のオプション値も赤字で示し、既定値または直前の有効な指定を使います。値が欠けた `-t` 等や閉じていない引用符、シリアル番号のないIXFRはエラーとして送信を止めます。オプション名の省略形、複数問い合わせ、シェルの変数展開・パイプ・リダイレクト、delvのDNSSEC検証は再現しません。繰り返し指定した設定は原則として後の有効な指定を優先します。

URL・ブラウザー履歴には `dig.html?server=...&name=...&type=...` のように、対応するDNS設定だけを保存します。元の入力コマンドや、無視したオプションとその値（例: `-y` のTSIGキー）は保存・送信しません。再読み込みや履歴からは保存した設定を使ってコマンドを再構成して再送信するため、元の空白・引用符・未対応引数の表示は復元されません。入力直後の画面では引き続き元のコマンドと無視した引数を表示します。

旧形式の `?command=...` URLは自動実行せず、URLから削除して再入力を案内します。ただし、既に記録された過去の履歴・アクセスログ等を削除できるものではありません。鍵を貼り付けたことがある場合は履歴・ログ等を確認し、必要に応じて鍵を更新してください。対応するDNS設定自体はURL・リクエストに含まれるため、対象名・サーバー名・DoHパス等にも機密情報を含めないでください。

### IXFR のシリアル番号

クエリータイプで `IXFR` を選ぶと「IXFR シリアル番号」欄が表示されます。取得済みゾーンの SOA SERIAL を `0`～`4294967295` の整数で指定してください（必須）。対応する dig の指定方法は `ixfr=N` です。このツールでは `type=IXFR&ixfrserial=N` として URL に保持し、問い合わせの AUTHORITY セクションに指定した SERIAL の SOA レコードを追加します。

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

http://127.0.0.1:3000/

`http://127.0.0.1:3000/dns-query-tool/` でもアクセスできます。`/dns-query-tool/` は公開サイトと同じ既定のアプリケーションパスで、nginx などのリバースプロキシ配下で使う場合に利用します。

サーバーは `127.0.0.1:3000` のみで待ち受けます。nginx からは `proxy_pass http://127.0.0.1:3000;` で転送してください。外部ホストから Node.js へ直接接続することはできません。アプリケーションのパスを変更する場合は、`APPLICATION_PATH` 環境変数を指定できます。

別のパスに変更する場合:

```sh
APPLICATION_PATH=/custom-path \
node dns-query-tool.js
```

## クエリーオプション

画面で指定できる主なオプションは次のとおりです。

| 項目 | URLパラメーター | 説明 |
| --- | --- | --- |
| 対象ドメイン名 (name) | `name` | 問い合わせ対象のドメイン名 |
| クエリー先DNSサーバー | `server` | DNSサーバー (権威サーバー、フルサービスリゾルバー) のホスト名またはIPアドレス (省略時は `a.root-servers.net`) |
| クエリータイプ (type) | `type` | `index.html` の選択肢にあるタイプのみ受付。DLV、SPFは「歴史的・特殊なタイプ」、OPT、TSIG、TKEYなど選択肢にないタイプはAPIでも拒否。EDNSはクエリータイプではなくEDNS0設定で有効化 |
| クエリークラス (class) | `class` | `index.html` の選択肢 (`IN`、`CS`、`CH`、`HS`、`ANY`) から指定。通常は `IN` を指定する。 |
| IXFR シリアル番号 | `ixfrserial` | `type=IXFR` のとき必須。取得済みゾーンの SOA SERIAL (`0`～`4294967295`)。他のクエリータイプでは使用しない |
| QNAME minimisation | `qmini=1` | QNAME minimisationを有効にする |
| - | `qposi` | QNAME minimisationで問い合わせるラベル位置 |
| QNAMEタイプ | `qtype` | `A` または `NS` |
| EDNS0の付与 | `edns0=1` | EDNS0を付与する |
| DNSSEC情報の要求 (DO) | `dnssec=1` | DOフラグを付ける |
| UDPメッセージサイズ | `udpsize` | EDNS0のUDPメッセージサイズ (`512`～`65535`) |
| NSIDの要求 | `nsid=1` | NSID情報を要求する |
| MQTYPE-Query | `mqtype` | 例: `A,AAAA,MX` |
| IPv6送受信 | `ipv6=1` | DNSサーバー名の解決やクエリー送信の際にIPv6を優先する |
| TCP送受信 | `tcp=1` | TCPで問い合わせる |
| TLS送受信 | `dot=1` | TLSでポート853へ問い合わせる。接続先の証明書を検証する |
| HTTPS送受信 | `https=1` | HTTPSでポート443へ問い合わせる。接続先の証明書を検証する |
| 再帰検索の要求 (RD) | `rd=1` | RDフラグを付ける |
| チェックの無効化 (CD) | `cd=1` | CDフラグを付ける |

APIのエンドポイントは、アプリケーションパスからの相対パスで `api/query` です。ブラウザ画面はこのエンドポイントへリクエストし、解析済みのHTMLを受け取って結果欄に表示します。

例:

```text
http://127.0.0.1:3000/dns-query-tool/api/query?server=8.8.8.8&name=example.com&type=A&rd=1
```

## ファイル構成

| ファイル | 役割 |
| --- | --- |
| `index.html` | 入力フォーム、説明、結果表示領域 |
| `dns-query-tool-client.js` | フォーム送信、履歴操作、結果表示、リンクからの再クエリー |
| `dig.html` | dig形式の入力画面、無視した引数・反映設定・応答の表示 |
| `dig-command.js` | ブラウザー/Node.js共通のdig引数パーサー |
| `dig-client.js` | dig画面の送信、引数の色分け、URL・履歴操作 |
| `dns-query-options.js` | APIとdigパーサーが共有する許可タイプ・クラス |
| `dns-query-tool.css` | 通常画面とdig画面の共通スタイル |
| `dns-query-tool.js` | HTTPサーバー、DNSメッセージ生成、UDP/TCP通信、応答解析、HTML生成 |
| `test-mqtype.js` | MQTYPEオプションの構築と応答解析の簡易テスト |
| `test-ixfr.js` | IXFRオプションの構築と応答解析の簡易テスト |
| `test-dns-query-tool.js` | DNSクエリーツール全体の簡易テスト |
| `test-dig-command.js` | dig引数の解析、静的ファイル配信、DNS送信設定のテスト |
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
- `localhost`、ループバックアドレス、プライベートアドレスなどのDNSサーバーは問い合わせ先に指定できません。問い合わせ先はグローバルに到達可能なユニキャストアドレスに限られ、`0.0.0.0`、`::`、IPv4射影アドレス (`::ffff:127.0.0.1` 等)、リンクローカル (クラウドのメタデータ `169.254.169.254` 等)、CGNAT (`100.64.0.0/10`)、文書用・ベンチマーク用・マルチキャストなどの特殊用途アドレスも拒否します。DNSサーバー名を指定した場合も、名前解決の結果が同じ条件で検査されます。
- 悪意あるDNSサーバーによる資源占有を防ぐため、TCP/DoH の応答は 1 メッセージあたり 65535 バイト (AXFR/IXFR は合計 4 MiB)、通信全体で 15 秒を上限として打ち切ります。DNSサーバーを名前で指定した場合の名前解決も、全体で 10 秒・問い合わせ 50 回を上限とします。
- HTTP 応答には Content-Security-Policy、X-Content-Type-Options、X-Frame-Options などのセキュリティヘッダーを付与し、GET/HEAD 以外のメソッドは拒否します。
- DNSサーバーへの問い合わせは、実行環境から対象サーバーへ直接行われます。DoTは853番ポートを使用し、接続先がDoT非対応の場合やTLS証明書を検証できない場合は、DoTを無効にして再試行してください。ネットワークやファイアウォールの設定によっては応答を受信できません。
- DNSクエリーの結果は問い合わせ先サーバーやネットワークの状態によって変わります。
- 公開サーバーとして運用する場合は、アクセス制御、レート制限、ログ、HTTPS、Node.jsの更新などを別途検討してください。特に、匿名の利用者が任意の公開DNSサーバーへ問い合わせ (AXFR を含む) を行えるため、nginx の `limit_req` / `limit_conn` などでクライアントごとの要求数・同時接続数を制限することを推奨します。
- `127.0.0.1` への bind は外部ホストからの直接接続を防ぎますが、同一ホスト上の他プロセスからの接続は防ぎません。同一ホスト上のプロセスも制限する必要がある場合は、OS のアクセス制御や nginx と Node.js 間の認証も追加してください。

## 依存関係

- [dns-packet](https://www.npmjs.com/package/dns-packet) `^5.6.1`