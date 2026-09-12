const assert = require('node:assert/strict');
const http = require('node:http');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const dnsPacket = require('dns-packet');
const {
    analyzeDnsPacketError,
    buildDnsFlags,
    getDnsTypeCode,
    isInvalidDnsServer,
    isInvalidQueryType,
    isInvalidUdpSize,
    makeHtmlFromDns,
    queryAuthoritativeServer,
    reverseIPv4,
    reverseIPv6,
    resolveDnsServerAddress,
    server,
    validateDomainName,
    validateMQType
} = require('./dns-query-tool');

test('DNSサーバーとUDPサイズの入力検証', () => {
    assert.equal(isInvalidDnsServer('localhost'), true);
    assert.equal(isInvalidDnsServer('127.0.0.1'), true);
    assert.equal(isInvalidDnsServer('192.168.1.1'), true);
    assert.equal(isInvalidDnsServer('::1'), true);
    assert.equal(isInvalidDnsServer('8.8.8.8'), false);
    assert.equal(isInvalidUdpSize('511'), true);
    assert.equal(isInvalidUdpSize('512'), false);
    assert.equal(isInvalidUdpSize('65535'), false);
    assert.equal(isInvalidUdpSize('65536'), true);
});

test('クエリータイプ、フラグ、逆引き名を正しく処理する', () => {
    assert.equal(isInvalidQueryType('A'), false);
    assert.equal(isInvalidQueryType('AXFR'), true);
    assert.equal(buildDnsFlags(true, true), dnsPacket.RECURSION_DESIRED | dnsPacket.CHECKING_DISABLED);
    assert.equal(reverseIPv4('192.0.2.4'), '4.2.0.192');
    assert.equal(reverseIPv4('192.0.2.256'), '');
    assert.equal(reverseIPv6('2001:db8::1'), '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2');
});

test('RFCに基づくドメイン名の入力検証 (validateDomainName)', () => {
    // 正常系
    assert.equal(validateDomainName('example.com'), null);
    assert.equal(validateDomainName('example.com.'), null);
    assert.equal(validateDomainName('.'), null);
    assert.equal(validateDomainName('sub.example.com'), null);
    assert.equal(validateDomainName('_dmarc.example.com'), null);
    assert.equal(validateDomainName('a-b-c.example.jp'), null);
    assert.equal(validateDomainName('example\\.com'), null);
    assert.equal(validateDomainName('example\\032com'), null);

    // empty name
    assert.match(validateDomainName(''), /ドメイン名が空です/);
    assert.match(validateDomainName('   '), /ドメイン名が空です/);

    // empty label (連続ピリオド、ルート以外の先頭ピリオド、複数末尾ピリオド等)
    assert.match(validateDomainName('..'), /空のラベル/);
    assert.match(validateDomainName('foo..bar'), /空のラベル/);
    assert.match(validateDomainName('.example.com'), /空のラベル/);
    assert.match(validateDomainName('example.com..'), /空のラベル/);
    assert.match(validateDomainName('a..'), /空のラベル/);

    // label too long (63オクテット超)
    const label63 = 'a'.repeat(63);
    const label64 = 'a'.repeat(64);
    assert.equal(validateDomainName(`${label63}.com`), null);
    assert.match(validateDomainName(`${label64}.com`), /ラベルが長すぎます/);

    // name too long (ワイヤ形式で255オクテット超)
    // 63文字ラベル * 3 (各64バイト) + 57文字ラベル (58バイト) + ルート (1バイト) = 251バイト (OK)
    const longValidDomain = `${label63}.${label63}.${label63}.${'a'.repeat(57)}`;
    assert.equal(validateDomainName(longValidDomain), null);
    // 63文字ラベル * 3 + 62文字ラベル = 64*3 + 63 + 1 = 256バイト (超過)
    const longInvalidDomain = `${label63}.${label63}.${label63}.${'a'.repeat(62)}`;
    assert.match(validateDomainName(longInvalidDomain), /ドメイン名が長すぎます/);

    // bad escape sequence
    assert.match(validateDomainName('example\\'), /不正なエスケープシーケンス/);
    assert.match(validateDomainName('example\\999'), /不正なエスケープシーケンス/);
    assert.match(validateDomainName('example\\1'), /不正なエスケープシーケンス/);
    assert.match(validateDomainName('example\\12'), /不正なエスケープシーケンス/);

    // illegal character
    assert.match(validateDomainName('example com'), /不正な文字/);
    assert.match(validateDomainName('example\tcom'), /不正な文字/);
});

test('MQTYPEの検証と型コード変換', () => {
    assert.equal(getDnsTypeCode('AAAA'), 28);
    assert.equal(getDnsTypeCode('65'), 65);
    assert.equal(validateMQType('A, AAAA, MX', 'A', 'IN'), '');
    assert.equal(validateMQType('EMPTY', 'A', 'IN'), '');
    assert.match(validateMQType('A,,AAAA', 'A', 'IN'), /リストが空/);
    assert.match(validateMQType('A', 'VERSION', 'CH'), /IN クラス/);
    assert.match(validateMQType('0', 'A', 'IN'), /無効な QTYPE/);
    assert.match(validateMQType('65536', 'A', 'IN'), /無効な QTYPE/);
});

test('QUESTION SECTIONがなくても要求値を表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [],
        answers: [],
        authorities: [],
        additionals: []
    }, 12, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, '1232', false, '', false, 255, 'A');

    assert.match(html, /応答に QUESTION SECTION が存在しません/);
    assert.match(html, /example\.com/);
    assert.match(html, /クエリータイプ: <code>A<\/code>/);
});

test('OPTのExtended RCODEを通常のRCODEと合成して表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: [{
            type: 'OPT',
            name: '.',
            extendedRcode: 1,
            version: 0,
            udpPayloadSize: 1232,
            flags: 0,
            options: []
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, '1232', false, '', false, 255, 'A');

    assert.match(html, /応答ステータス \(rcode\): <code>BADVERS<\/code>/);
    assert.match(html, /Extended RCODE: 1 \(BADVERS \/ BADSIG\)/);
});

test('Extended RCODEの略称をヘッダーRCODEと合成して判定する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'FORMERR',
        questions: [{ name: 'rcode-badkey.anomaly.test.ldns.jp', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: [{
            type: 'OPT',
            name: '.',
            extendedRcode: 1,
            version: 0,
            udpPayloadSize: 1232,
            flags: 0,
            options: []
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'rcode-badkey.anomaly.test.ldns.jp', 'A', 100,
    false, false, false, false, '1232', false, '', false, 255, 'A');

    assert.match(html, /応答ステータス \(rcode\): <code>BADKEY<\/code>/);
    assert.match(html, /Extended RCODE: 1 \(BADKEY\)/);
});

test('MQTYPE応答を表示し、形式不正を警告する', () => {
    const createResponse = (data) => ({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: [{
            type: 'OPT',
            name: '.',
            udpPayloadSize: 1232,
            flags: 0,
            options: [{ code: 21, data }]
        }]
    });
    const render = (response) => makeHtmlFromDns(response, 20, 'http://localhost:3000', '/api/query',
        '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100, false, false, false, false,
        '1232', false, 'AAAA,MX', false, 255, 'A');

    assert.match(render(createResponse(Buffer.from([0, 28, 0, 15]))), /MQTYPE-Response.*AAAA,MX/);
    assert.match(render(createResponse(Buffer.from([0, 28, 0]))), /RFC 10029 の形式に適合していません/);
});

test('EDNS optionをraw表示し、NSIDをhexで表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: [{
            type: 'OPT',
            name: '.',
            udpPayloadSize: 1232,
            flags: 0,
            options: [
                { code: 3, data: Buffer.from([0xff, 0x00, 0x41]) },
                { code: 10, data: Buffer.from([0x01, 0x02]) },
                { code: 65001, data: Buffer.alloc(0) }
            ]
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, '1232', false, '', false, 255, 'A');

    assert.match(html, /\[NSID\]<\/strong> <code>ff0041<\/code>/);
    assert.match(html, /OPTION_10 \(10\): 0102/);
    assert.match(html, /OPTION_65001 \(65001\): \(empty\)/);
    assert.doesNotMatch(html, /�/);
});

test('応答内のMQTYPE-Queryと予約TYPEを検出する', () => {
    const render = (data) => makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: [{
            type: 'OPT',
            name: '.',
            udpPayloadSize: 1232,
            flags: 0,
            options: [{ code: 20, data: Buffer.alloc(0) }, { code: 21, data }]
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, '1232', false, 'AAAA', false, 255, 'A');

    assert.match(render(Buffer.from([0, 0])), /MQTYPE-Query が含まれているため/);
    assert.match(render(Buffer.from([0, 128])), /RFC 10029 の形式に適合していません/);
});

test('DNS応答内のHTMLとEDE追加テキストをエスケープする', () => {
    const render = (infoCode) => makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'TXT' }],
        answers: [{ name: '<img src=x>', type: 'TXT', data: '<script>alert(1)</script>', ttl: 60 }],
        authorities: [],
        additionals: [{
            type: 'OPT',
            name: '.',
            udpPayloadSize: 1232,
            flags: 0,
            options: [
                { code: 3, data: Buffer.from('<svg>') },
                { code: 15, data: Buffer.concat([Buffer.from([0, infoCode]), Buffer.from('<b>note</b>')]) }
            ]
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'TXT', 100,
    false, false, true, false, '1232', true, '', false, 255, 'A');

    const knownEdeHtml = render(15);
    assert.doesNotMatch(knownEdeHtml, /<script>|<img|<svg>|<b>note/);
    assert.match(knownEdeHtml, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(knownEdeHtml, /iana\.org.*Blocked/);
    assert.match(render(255), /255 \(Unknown Error\)/);
});

const request = (port, pathname) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: pathname }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => { body += chunk; });
        response.on('end', () => resolve({ statusCode: response.statusCode, body }));
    }).on('error', reject);
});

test('HTTP入力境界はDNS通信前にエラーを返す', async (testContext) => {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    testContext.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
    const port = server.address().port;

    const [staticFile, missingName, invalidType, invalidUdpSize, invalidServer, invalidDomainEmptyLabel, invalidDomainLabelTooLong] = await Promise.all([
        request(port, '/dnsquerytool/'),
        request(port, '/dnsquerytool/api/query'),
        request(port, '/dnsquerytool/api/query?name=example.com&type=%3Cscript%3E'),
        request(port, '/dnsquerytool/api/query?name=example.com&udpsize=511'),
        request(port, '/dnsquerytool/api/query?name=example.com&server=127.0.0.1'),
        request(port, '/dnsquerytool/api/query?name=foo..bar'),
        request(port, `/dnsquerytool/api/query?name=${'a'.repeat(64)}.com`)
    ]);

    assert.equal(staticFile.statusCode, 200);
    assert.match(staticFile.body, /DNSクエリー送信ツール/);
    assert.equal(missingName.statusCode, 400);
    assert.match(invalidType.body, /不正なクエリータイプ/);
    assert.doesNotMatch(invalidType.body, /<script>/);
    assert.match(invalidUdpSize.body, /UDPメッセージサイズを入力し直してください/);
    assert.match(invalidServer.body, /DNSサーバーを選択し直してください/);
    assert.match(invalidDomainEmptyLabel.body, /不正なドメイン名です \('foo\.\.bar' は無効なドメイン名です: 空のラベルが含まれています \(連続したピリオド等\)\)/);
    assert.match(invalidDomainLabelTooLong.body, /は無効なドメイン名です: ラベルが長すぎます \(最大63バイト\)/);
});

test('UDPのTCフラグを受けるとTCP応答へ切り替える', async () => {
    const udpResponse = dnsPacket.encode({
        type: 'response',
        flags: dnsPacket.TRUNCATED_RESPONSE,
        questions: [{ name: 'example.com', type: 'A', class: 'IN' }]
    });
    const createSocket = () => {
        const socket = new EventEmitter();
        socket.close = () => {};
        socket.send = (...args) => {
            args.at(-1)();
            queueMicrotask(() => socket.emit('message', udpResponse));
        };
        return socket;
    };
    const tcpResponse = { id: 1, answers: [] };
    let tcpQuery;
    const queryOverTcp = async (address, query) => {
        assert.equal(address, '8.8.8.8');
        tcpQuery = query;
        return tcpResponse;
    };

    assert.equal(await queryAuthoritativeServer('8.8.8.8', 'example.com', 'A', createSocket, queryOverTcp), tcpResponse);
    assert.deepEqual(tcpQuery.questions, [{ name: 'example.com', type: 'A', class: 'IN' }]);
});

test('TCP問い合わせ時はTC推奨メッセージを出さない', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: dnsPacket.TRUNCATED_RESPONSE,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, true, false, false, '1232', false, '', false, 255, 'A');

    assert.doesNotMatch(html, /TCフラグが立っているので TCPでの再確認を推奨します/);
});

test('DNSサーバー解決はIPv4失敗時にIPv6を試し、委任先を再帰解決する', async () => {
    const calls = [];
    const resolveWithIpv6Fallback = async (address, name, type) => {
        calls.push({ address, name, type });
        if (type === 'A') throw new Error('IPv4 unavailable');
        return { answers: [{ type: 'AAAA', name: 'ns.example', data: '2001:4860:4860::8888' }], authorities: [], additionals: [] };
    };
    assert.equal(await resolveDnsServerAddress('ns.example', false, 0, resolveWithIpv6Fallback), '2001:4860:4860::8888');
    assert.equal(calls[0].type, 'A');
    assert.equal(calls.at(-1).type, 'AAAA');

    let targetQueryCount = 0;
    const resolveDelegation = async (address, name, type) => {
        if (name === 'target.example') {
            targetQueryCount += 1;
            if (targetQueryCount === 1) {
                return { answers: [], authorities: [{ type: 'NS', name: 'example', data: 'ns.delegate.' }], additionals: [] };
            }
            return { answers: [{ type, name: 'target.example', data: '8.8.4.4' }], authorities: [], additionals: [] };
        }
        assert.equal(name, 'ns.delegate');
        return { answers: [{ type, name: 'ns.delegate', data: '9.9.9.9' }], authorities: [], additionals: [] };
    };
    assert.equal(await resolveDnsServerAddress('target.example', false, 0, resolveDelegation), '8.8.4.4');
    assert.equal(targetQueryCount, 2);
    await assert.rejects(resolveDnsServerAddress('example.com', false, 5, resolveDelegation), /入れ子の委任が上限を超えました/);
});

test('analyzeDnsPacketError が QDCOUNT 不一致などのアノマリーメッセージの異常理由を正しく検出・表示する', () => {
    // qdcount-mismatch メッセージ (QDCOUNT=2 なのに QUESTION は 1 つだけ)
    const rawHex = '04d284000002000000000000107164636f756e742d6d69736d6174636807616e6f6d616c790474657374046c646e73026a700000010001';
    const buf = Buffer.from(rawHex, 'hex');
    const resultHtml = analyzeDnsPacketError(buf, new Error('Cannot decode name (buffer overflow)'));

    assert.match(resultHtml, /【DNSメッセージ異常の分析結果】/);
    assert.match(resultHtml, /QDCOUNT: <code>2<\/code>/);
    assert.match(resultHtml, /QUESTION SECTION の 2 個目のレコードを読み込もうとしましたが、メッセージ末尾に達しました/);
    assert.match(resultHtml, /ヘッダー宣言 QDCOUNT: 2 に対し、実際に解読できた Question は 1 個です/);

    // 12バイト未満メッセージ (UDP / TCPヘッダー付き)
    const shortUdpBuf = Buffer.from([0x01, 0x02, 0x03]);
    assert.match(analyzeDnsPacketError(shortUdpBuf, new Error('short')), /最小長 \(12 バイト\) 未満です/);

    const shortTcpBuf = Buffer.from([0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]); // TCP 2バイト長ヘッダー(5) + 5バイトのDNSデータ
    assert.match(analyzeDnsPacketError(shortTcpBuf, new Error('short tcp')), /最小長 \(12 バイト\) 未満です/);
});

test('ヘッダー宣言数を超えるリソースレコードを検出する', () => {
    const cases = [
        {
            section: 'answers',
            countOffset: 6,
            records: [
                { name: 'example.com', type: 'A', class: 'IN', ttl: 60, data: '192.0.2.1' },
                { name: 'example.com', type: 'A', class: 'IN', ttl: 60, data: '192.0.2.2' }
            ]
        },
        {
            section: 'authorities',
            countOffset: 8,
            records: [
                { name: 'example.com', type: 'NS', class: 'IN', ttl: 60, data: 'ns1.example.com' },
                { name: 'example.com', type: 'NS', class: 'IN', ttl: 60, data: 'ns2.example.com' }
            ]
        },
        {
            section: 'additionals',
            countOffset: 10,
            records: [
                { name: 'ns1.example.com', type: 'A', class: 'IN', ttl: 60, data: '192.0.2.1' },
                { name: 'ns2.example.com', type: 'A', class: 'IN', ttl: 60, data: '192.0.2.2' }
            ]
        }
    ];

    for (const { section, countOffset, records } of cases) {
        const packet = dnsPacket.encode({
            type: 'response',
            id: 100,
            questions: [{ name: 'example.com', type: 'A', class: 'IN' }],
            [section]: records
        });
        packet.writeUInt16BE(1, countOffset);

        const resultHtml = analyzeDnsPacketError(packet);

        assert.match(resultHtml, /ANCOUNT \+ NSCOUNT \+ ARCOUNT: 1 個/);
        assert.match(resultHtml, /実際のリソースレコードは 2 個/);
        assert.match(resultHtml, /1 個の余剰レコード/);
    }
});