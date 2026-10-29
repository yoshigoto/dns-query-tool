# DNSクエリー送信ツール

ブラウザーからDNSクエリーを送信し、応答を解析・表示するWebアプリケーションです。DNSサーバーや通信方式、各種フラグを指定して、権威サーバーやフルサービスリゾルバーの応答を確認できます。

## 公開サイト

https://www.on-link.jp/dns-query-tool/

## 主な機能

- DNSサーバー（権威サーバーまたはフルサービスリゾルバー）を指定したクエリー
- UDP、TCP、DNS over HTTPS（DoH）、DNS over TLS（DoT）による通信
- DNSサーバー名の解決とクエリー送信におけるIPv4／IPv6の優先設定
- 再帰検索（RD）、Checking Disabled（CD）、EDNS0、DNSSEC OK（DO）、NSIDの指定
- UDPメッセージサイズの指定
- QNAME minimisationを使った段階的な問い合わせ（委任を辿る操作は手動）
- MQTYPE-Query（RFC 10029）の送信と応答表示
- 各種リソースレコード、応答セクション、フラグ、応答コード（RCODE）、Extended DNS Errorの表示
- 応答中のドメイン名やIPアドレスから次のクエリーを実行
- クエリー設定をURLおよびブラウザー履歴に保存

応答内容の解析・表示を行いますが、DNSSEC署名の検証やSVCB／HTTPSレコードに基づく接続先の選択は行いません。解析できないレコードデータは `malformed` と表示する場合があります。

## 使い方

1. 対象ドメイン名を入力します。
2. 必要に応じてDNSサーバー、クエリータイプ、RDなどを設定します。
3. 「DNSメッセージを送信」をクリックします。
4. `ANSWER`、`AUTHORITY`、`ADDITIONAL` セクションの応答を確認します。

通常フォームの既定値は、DNSサーバーが `a.root-servers.net`、タイプがA、クラスがIN、RDとEDNS0がオフ、UDPメッセージサイズが1232バイトです。委任を辿るには、応答に表示されたNS名やIPアドレスのリンクをクリックして次の問い合わせを行います。委任先への問い合わせは自動ではありません。

SOAレコードの `mname` はプライマリーサーバー名です。これをクリックすると、`a.root-servers.net` からその名前のAレコードを探索できます。このリンクではRD、DoH、DoT、MQTYPEを無効にします。QNAME minimisationが有効な場合は、ラベル位置を初期状態に戻します。

名前解決をフルサービスリゾルバーに任せる場合は、そのサーバーを指定してRDを有効にしてください。

### dig コマンド形式で入力する

通常フォームのほかに、`dig.html` で `dig`／`delv` 形式のコマンドまたは引数を入力できます。通常画面のリンクから移動できます。入力後、Enterキーまたは「DNSメッセージを送信」ボタンで実行します。

```text
dig in a @a.root-servers.net www.on-link.jp -6 +rd +cd +dnssec
dig @8.8.8.8 example.com -t AAAA +tcp +nsid +bufsize=1232
delv @a.root-servers.net www.on-link.jp +qmin +nord
```

最初の例は、INクラスのAレコードを `a.root-servers.net` に問い合わせる設定に変換します。IPv6優先、RD、CD、DOを有効にし、DOに伴ってEDNS0も有効になります。入力したコマンドをOS上で実行することはなく、解析した設定でDNSクエリーを送信します。

| dig / delv 引数 | 本ツールの設定 |
| --- | --- |
| `@server`、`name`、`type`、`class` | サーバー、対象名、タイプ、クラス（順不同・大文字小文字不問のタイプ/クラス） |
| `-q name`、`-t type`、`-c class` | 対象名、タイプ、クラス（`-tAAAA` のような連結形式も可） |
| `-x address` | `PTR-x` によるIPv4/IPv6逆引き |
| `-4` / `-6` | IPv4 / IPv6優先（digの通信ファミリー固定とは異なります） |
| `+[no]rd` / `+[no]recurse` | RD |
| `+[no]cd` / `+[no]cdflag` | CD |
| `+[no]dnssec`、`+[no]nsid` | DO、NSID（有効化するとEDNS0も有効） |
| `+edns[=0]` / `+noedns`、`+bufsize=N` | EDNS0、UDPサイズ512～65535（サイズ指定時はEDNS0も有効） |
| `+[no]tcp` / `+[no]vc` | TCP |
| `+[no]tls`、`+[no]https[=/path]` | DoT、DoH（POST）。TLS証明書を検証します |
| `ixfr=N` | IXFRとSOA SERIAL。AXFR／IXFRは既定でTCP（`+notcp` で解除可能） |
| `+[no]qmin` | QNAME minimisationの切り替え。委任先への問い合わせは手動です |

省略時はIN、RD・EDNS0 On、UDPサイズ1232です。対象名を指定した場合のタイプはA、対象名も省略した場合はルートのNS（`. NS`）です。DNSサーバーは `a.root-servers.net` になります。OSのリゾルバー設定や `.digrc` は参照しません。MQTYPEなど、本ツール独自の設定はコマンドから自動で追加されません。ここに記載した既定値はdig形式画面に限り、通常フォームには適用されません。

送信直後は、入力コマンドを空白や引用符も含めて表示します。無視した引数は理由とともに強調表示され、反映された設定も確認できます。「通常の入力フォームへ」や応答内のリンクから、通常画面に移動できます。

未対応の引数（例: `+short`、`+trace`、`+time`、`-p`、TSIG、EDNS Cookie／ECS）は無視され、その理由を表示します。未対応のタイプ・クラスや範囲外の値も無視し、既定値または直前の有効な指定を使用します。一方、値のない `-t` などの不完全な指定、閉じていない引用符、シリアル番号のないIXFRはエラーになります。オプションの省略形、複数の問い合わせ、シェル展開・パイプ・リダイレクト、`delv` によるDNSSEC検証には対応しません。同じ設定を複数回指定した場合は、原則として最後の有効な値を使用します。

URLとブラウザー履歴には、有効なDNS設定だけを保存します。入力したコマンドや無視した引数（例: `-y` のTSIGキー）は保存・送信しません。再読み込みや履歴復元時は保存済みの設定からコマンドを再構成するため、元の空白・引用符・無視した引数は復元されません。

旧形式の `?command=...` URLは実行せず、URLから削除して再入力を案内します。ただし、既存のブラウザー履歴やアクセスログは削除されません。鍵を入力したことがある場合は、履歴やログを確認し、必要に応じて鍵を更新してください。DNS設定はURLやリクエストに含まれるため、対象名・サーバー名・DoHパスにも機密情報を含めないでください。

### IXFR のシリアル番号

クエリータイプで `IXFR` を選ぶと「IXFR シリアル番号」欄が表示されます。取得済みゾーンのSOA SERIALを `0`～`4294967295` の整数で指定してください。`dig` 形式では `ixfr=N` を使います。問い合わせには、指定したSERIALを持つSOAレコードをAUTHORITYセクションに追加します。

AXFRは[RFC 5936](https://datatracker.ietf.org/doc/html/rfc5936#section-2.2)によりTCPを使用します。TCPを有効にせずAXFRを問い合わせた場合は、応答に注意を表示します。IXFRはUDPでも問い合わせできますが、応答が切り詰められた場合はTCPで再確認してください。TCPによるAXFR／IXFRでは、複数のDNSメッセージを受信して表示します。転送データを使ってローカルのゾーンを更新する機能はありません。QNAME minimisationの途中では通常のA／NS問い合わせを行い、最終的なIXFR問い合わせにのみSOAレコードを追加します。

## ローカルで実行する

### 必要な環境

- Node.js 18以上
- DNSサーバー (権威サーバー、フルサービスリゾルバー) に対して通信方式に応じたポートへ接続できるネットワーク (UDP/TCP 53、DoT 853、DoH 443)

### 起動

```sh
npm install
node dns-query-tool.js
```

テストは次のコマンドで実行できます。

```sh
npm test
```

起動後、次のURLを開きます。

http://127.0.0.1:3000/

`http://127.0.0.1:3000/dns-query-tool/` でもアクセスできます。このパスは公開サイトと同じ既定値で、nginxなどのリバースプロキシ配下で利用できます。

サーバーは `127.0.0.1:3000` で待ち受けます。nginxからは `proxy_pass http://127.0.0.1:3000;` で転送してください。外部ホストからNode.jsへ直接接続することはできません。アプリケーションパスは `APPLICATION_PATH` 環境変数で変更できます。

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
| クエリータイプ（type） | `type` | 対応タイプを指定します。EDNSはクエリータイプではなくEDNS0設定で有効にします |
| クエリークラス（class） | `class` | `IN`、`CS`、`CH`、`HS`、`ANY`。通常は `IN` を指定します |
| IXFRシリアル番号 | `ixfrserial` | `type=IXFR` の場合に必須。取得済みゾーンのSOA SERIAL（`0`～`4294967295`） |
| QNAME minimisation | `qmini=1` | QNAME minimisationを有効にします |
| 問い合わせるラベル位置 | `qposi` | QNAME minimisationで使用するラベル位置です |
| QNAMEタイプ | `qtype` | `A` または `NS` |
| EDNS0 | `edns0=1` | EDNS0を付加します |
| DNSSEC情報の要求（DO） | `dnssec=1` | DOフラグを付けます |
| UDPメッセージサイズ | `udpsize` | EDNS0のUDPメッセージサイズ（`512`～`65535`） |
| NSIDの要求 | `nsid=1` | NSIDを要求します |
| MQTYPE-Query | `mqtype` | 例: `A,AAAA,MX` |
| IPv6優先 | `ipv6=1` | DNSサーバー名の解決とクエリー送信でIPv6を優先します |
| TCP | `tcp=1` | TCPで問い合わせます |
| DoT | `dot=1` | ポート853でTLS接続します。証明書を検証します |
| DoH | `https=1` | ポート443でHTTPS接続します。証明書を検証します |
| 再帰検索の要求（RD） | `rd=1` | RDフラグを付けます |
| チェックの無効化（CD） | `cd=1` | CDフラグを付けます |

APIのエンドポイントは、アプリケーションパス配下の `api/query` です。ブラウザー画面はこのエンドポイントから解析済みのHTMLを受け取り、結果を表示します。

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
| `test-mqtype.js` | MQTYPEの単体テスト |
| `test-ixfr.js` | IXFRの入力検証、送信内容、画面復元のテスト |
| `test-dns-query-tool.js` | DNS通信、応答解析、HTTP APIなどのテスト |
| `test-dig-command.js` | dig引数の解析とdig画面のテスト |
| `package.json` | Node.js依存関係の定義 |

## 注意事項

- 本ツールはDNSの動作確認・学習を目的としており、DNSSEC署名の検証は行いません。DO／CDは問い合わせに付加するフラグです。
- 問い合わせ先には、グローバルに到達可能なユニキャストアドレスのみ指定できます。ループバック、プライベート、リンクローカル、CGNAT、文書用などの特殊用途アドレスは拒否します。ホスト名を指定した場合も、名前解決後のIPアドレスを同じ基準で検査します。
- TCP／DoHのDNSメッセージは最大65535バイト、AXFR／IXFRのTCP応答は合計4 MiBまでです。通信時間は最大15秒、DNSサーバー名の解決は最大10秒・50問い合わせに制限されます。
- DNSサーバーへの通信はアプリケーションの実行環境から直接行います。使用ポートはUDP／TCPが53、DoTが853、DoHが443です。ネットワークやファイアウォールによっては通信できない場合があります。
- HTTP応答にはセキュリティヘッダーを付与し、GET／HEAD以外のメソッドを拒否します。
- 公開運用ではアクセス制御やレート制限を検討してください。匿名利用者が公開DNSサーバーへ任意の問い合わせ（AXFRを含む）を行えるため、nginxの `limit_req`／`limit_conn` などで要求数や同時接続数を制限することを推奨します。
- Node.jsは `127.0.0.1` のみで待ち受けるため、外部ホストから直接接続できません。ただし、同一ホスト上の別プロセスからの接続は防げません。必要に応じてOSのアクセス制御やリバースプロキシとの間の認証を設定してください。

## 依存関係

- [dns-packet](https://www.npmjs.com/package/dns-packet) `^5.6.1`