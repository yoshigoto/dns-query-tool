const assert = require('node:assert/strict');
const http = require('node:http');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const dnsPacket = require('dns-packet');
const dnsTypes = require('dns-packet/types');
const dnsClasses = require('dns-packet/classes');
const {
    analyzeDnsPacketError,
    buildDnsFlags,
    createResolutionBudget,
    getDnsTypeCode,
    isInvalidDnsServer,
    isInvalidQueryClass,
    isInvalidQueryType,
    isInvalidUdpSize,
    makeHtmlFromDns,
    queryAuthoritativeServer,
    queryAuthoritativeServerOverTls,
    reverseIPv4,
    reverseIPv6,
    resolveDnsServerAddress,
    server,
    SUPPORTED_QUERY_TYPES,
    validateDomainName,
    validateMQType
} = require('./dns-query-tool');

const renderWireResponse = (fields) => {
    const raw = dnsPacket.encode({
        type: 'response', id: 100, flags: 0,
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [], authorities: [], additionals: [],
        ...fields
    });
    return makeHtmlFromDns(dnsPacket.decode(raw), raw.length, 'http://localhost:3000', '/api/query',
        '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
        false, false, false, false, false, '', false, false, '1232', false, '', false, 255, 'A', raw);
};

test('既知のDNSワイヤデータを解析・表示し、問い合わせのワイヤ形式を検証する', () => {
    const responseWire = Buffer.from(
        '1a2b81800001000100000000076578616d706c6503636f6d0000010001c00c000100010000003c0004c0000201',
        'hex'
    );
    const responseFrame = Buffer.concat([Buffer.from([0x00, responseWire.length]), responseWire]);
    const response = dnsPacket.decode(responseWire);

    assert.equal(response.id, 0x1a2b);
    assert.equal(response.type, 'response');
    assert.equal(response.flags, 0x0180);
    assert.deepEqual(response.questions, [{ name: 'example.com', type: 'A', class: 'IN' }]);
    assert.deepEqual(response.answers, [{
        name: 'example.com', type: 'A', class: 'IN', ttl: 60, flush: false, data: '192.0.2.1'
    }]);
    assert.deepEqual(dnsPacket.streamDecode(responseFrame), response);

    const html = makeHtmlFromDns(
        response, responseWire.length, 'http://localhost:3000', '/api/query',
        '8.8.8.8', '8.8.8.8', 'example.com', 'A', 0x1a2b,
        false, false, false, false, false, '', false, false, '1232', false, '', false, 255, 'A', responseWire
    );
    assert.match(html, /192\.0\.2\.1/);

    const query = {
        type: 'query',
        id: 0x1a2b,
        flags: 0x0100,
        questions: [{ name: 'example.com', type: 'A', class: 'IN' }]
    };
    const queryWire = Buffer.from(
        '1a2b01000001000000000000076578616d706c6503636f6d0000010001',
        'hex'
    );

    assert.deepEqual(dnsPacket.encode(query), queryWire);
    assert.deepEqual(
        dnsPacket.streamEncode(query),
        Buffer.concat([Buffer.from([0x00, queryWire.length]), queryWire])
    );
});

test('DNS TYPE・CLASS の固定ワイヤ値を名前とコードの間で変換する', () => {
    const cases = [
        { typeCode: 1, classCode: 1, typeName: 'A', className: 'IN', wire: '1a2b01000001000000000000076578616d706c6503636f6d0000010001' },
        { typeCode: 64, classCode: 3, typeName: 'SVCB', className: 'CH', wire: '1a2b01000001000000000000076578616d706c6503636f6d0000400003' },
        { typeCode: 65, classCode: 4, typeName: 'HTTPS', className: 'HS', wire: '1a2b01000001000000000000076578616d706c6503636f6d0000410004' },
        { typeCode: 65280, classCode: 255, typeName: 'UNKNOWN_65280', className: 'ANY', wire: '1a2b01000001000000000000076578616d706c6503636f6d00ff0000ff' }
    ];

    for (const { typeCode, classCode, typeName, className, wire } of cases) {
        const packet = Buffer.from(wire, 'hex');
        const decoded = dnsPacket.decode(packet);
        assert.equal(decoded.questions[0].type, dnsTypes.toString(typeCode));
        assert.equal(decoded.questions[0].class, dnsClasses.toString(classCode));
        assert.equal(getDnsTypeCode(typeName), typeCode);
        assert.deepEqual(dnsPacket.encode({
            type: 'query',
            id: 0x1a2b,
            flags: 0x0100,
            questions: [{ name: 'example.com', type: dnsTypes.toString(typeCode), class: dnsClasses.toString(classCode) }]
        }), packet);
    }

    assert.equal(getDnsTypeCode('SVCB'), 64);
    assert.equal(getDnsTypeCode('HTTPS'), 65);
    for (const queryClass of ['IN', 'CS', 'CH', 'HS', 'ANY']) {
        assert.equal(isInvalidQueryClass(queryClass), false, queryClass);
    }
    assert.equal(isInvalidQueryClass('UNKNOWN_3'), true);
});

test('RFC 5155 の NSEC3/NSEC3PARAM 表示は hex salt と unpadded base32hex を使う', () => {
    const vectors = [
        ['f', 'CO'], ['fo', 'CPNG'], ['foo', 'CPNMU'],
        ['foob', 'CPNMUOG'], ['fooba', 'CPNMUOJ1'], ['foobar', 'CPNMUOJ1E8']
    ];
    for (const section of ['answers', 'authorities', 'additionals']) {
        for (const [text, encoded] of vectors) {
            for (const salt of [Buffer.alloc(0), Buffer.from('aabb', 'hex')]) {
                const html = renderWireResponse({
                    [section]: [
                        {
                            name: 'example.com', type: 'NSEC3', ttl: 300,
                            data: {
                                algorithm: 253, flags: 0, iterations: 2, salt,
                                nextDomain: Buffer.from(text), rrtypes: ['A', 'UNKNOWN_65']
                            }
                        },
                        {
                            name: 'example.com', type: 'NSEC3PARAM', ttl: 300,
                            data: Buffer.concat([Buffer.from([1, 0, 0, 2, salt.length]), salt])
                        }
                    ]
                });
                const saltText = salt.length === 0 ? '-' : 'aabb';
                assert.ok(html.includes(`salt: ${saltText}, nextDomain: ${encoded}, rrtypes: A HTTPS`));
                assert.ok(html.includes(`iterations: 2, salt: ${saltText}</code>`));
                assert.doesNotMatch(html, /malformed/);
            }
        }
    }
});

test('RFC 4034 Appendix B.1 の RSA/MD5 Key Tag は modulus の末尾3バイトの上位16ビット', () => {
    for (const exponent of [Buffer.from([1, 3]), Buffer.from([0, 0, 1, 3])]) {
        for (const modulus of [Buffer.from([0x12, 0x34, 0x56]), Buffer.from([0x7f, 0x12, 0x34, 0x56])]) {
            const html = renderWireResponse({
                answers: [{
                    name: 'example.com', type: 'DNSKEY', ttl: 300,
                    data: { flags: 256, algorithm: 1, key: Buffer.concat([exponent, modulus]) }
                }]
            });
            assert.match(html, /keyTag: 4660, flags: 256, protocol: 3, algorithm: 1/);
            assert.doesNotMatch(html, /malformed/);
        }
    }
});

test('RFC 6891 の Extended RCODE は上位8ビットであり破損状態を意味しない', () => {
    for (const [extendedRcode, flags, expected] of [[1, 0, 'BADVERS'], [1, 6, 'BADTRUNC'], [22, 2, 'RCODE_354']]) {
        const html = renderWireResponse({
            flags,
            additionals: [{ type: 'OPT', name: '.', extendedRcode, udpPayloadSize: 1232, options: [] }]
        });
        assert.ok(html.includes(`<dt>応答ステータス (rcode)</dt><dd><code>${expected}</code>`));
        assert.doesNotMatch(html, /OPT疑似セクションとして破損|BADSIG|WARNING SECTION/);
        if (extendedRcode === 22) assert.doesNotMatch(html, /BADTRUNC/);
    }
});

test('RFC 9824 の CO ビットと NXNAME を表示する', () => {
    const html = renderWireResponse({
        authorities: [{
            name: 'example.com', type: 'NSEC', ttl: 300,
            data: { nextDomain: 'next.example.com', rrtypes: ['NSEC', 'RRSIG', 'UNKNOWN_128'] }
        }],
        additionals: [{ type: 'OPT', name: '.', flags: 0x4000, udpPayloadSize: 1232, options: [] }]
    });
    assert.match(html, /rrtypes: RRSIG NSEC NXNAME/);
    assert.match(html, /title="Compact Answers OK">CO<\/span>/);
    assert.doesNotMatch(html, /title="DNSSEC OK">DO<\/span>/);
});

test('RFC 9460/9848 の SVCB/HTTPS パラメーターを全セクションで表示する', () => {
    const param = (key, data) => {
        const header = Buffer.alloc(4);
        header.writeUInt16BE(key, 0);
        header.writeUInt16BE(data.length, 2);
        return Buffer.concat([header, data]);
    };
    const rdata = Buffer.concat([
        Buffer.from([0, 1, 0]),
        param(0, Buffer.from([0, 1, 0, 5])),
        param(1, Buffer.from([2, 104, 50, 2, 104, 51])),
        param(2, Buffer.alloc(0)),
        param(3, Buffer.from([0x20, 0xfb])),
        param(4, Buffer.from([192, 0, 2, 1, 192, 0, 2, 2])),
        param(5, Buffer.from('0006ffff00020102', 'hex')),
        param(6, Buffer.from('20010db800000000000000000000000120010db8000000000000000000530001', 'hex')),
        param(7, Buffer.from('/dns-query{?dns}')),
        param(65400, Buffer.from([0xaa, 0xbb]))
    ]);
    for (const section of ['answers', 'authorities', 'additionals']) {
        for (const type of ['UNKNOWN_64', 'UNKNOWN_65']) {
            const html = renderWireResponse({ [section]: [{ name: 'example.com', type, ttl: 300, data: rdata }] });
            assert.ok(html.includes('priority: 1, targetName: ., params: [ mandatory=alpn,ech, alpn=h2,h3, no-default-alpn, port=8443, ipv4hint=192.0.2.1,192.0.2.2, ech=AAb//wACAQI=, ipv6hint=2001:db8::1,2001:db8::53:1, dohpath=/dns-query{?dns}, other(65400)=aabb ]'));
            assert.doesNotMatch(html, /malformed/);
        }
    }
});

test('RFC 9460 に違反する SVCB のキー順序、空値、mandatory を検出する', () => {
    const invalidParams = [
        '0003000201bb00010003026832',
        '0003000201bb0003000201bb',
        'ffff0000',
        '00010000',
        '0001000100',
        '00040000',
        '00060000',
        '0002000100',
        '00020000',
        '00000000',
        '0000000101',
        '000000020000',
        '0000000400030003',
        '0000000400050003',
        '000000020003',
        '00000002ffff'
    ];
    for (const params of invalidParams) {
        const html = renderWireResponse({
            answers: [{
                name: 'example.com', type: 'UNKNOWN_64', ttl: 300,
                data: Buffer.concat([Buffer.from([0, 1, 0]), Buffer.from(params, 'hex')])
            }]
        });
        assert.match(html, /malformed SVCB\/HTTPS/, params);
    }
});

test('RFC 9460 の ALPN と TargetName は任意のオクテットを失わずに表示する', () => {
    const html = renderWireResponse({
        answers: [{
            name: 'example.com', type: 'UNKNOWN_65', ttl: 300,
            data: Buffer.from([
                0, 1, 3, 97, 46, 255, 0,
                0, 1, 0, 5, 4, 104, 44, 92, 255
            ])
        }]
    });
    assert.ok(html.includes('targetName: a\\046\\255.'));
    assert.ok(html.includes('alpn=h\\092,\\092\\092\\255'));
    assert.doesNotMatch(html, /malformed|\ufffd/);
});

test('RFC 1035 の名前長上限を超えた SVCB TargetName は不正とする', () => {
    for (const lastLabelLength of [61, 63]) {
        const labels = [63, 63, 63, lastLabelLength].map(length =>
            Buffer.concat([Buffer.from([length]), Buffer.alloc(length, 97)]));
        const html = renderWireResponse({
            answers: [{
                name: 'example.com', type: 'UNKNOWN_64', ttl: 300,
                data: Buffer.concat([Buffer.from([0, 1]), ...labels, Buffer.from([0])])
            }]
        });
        if (lastLabelLength === 63) assert.match(html, /malformed SVCB\/HTTPS TargetName/);
        else assert.doesNotMatch(html, /malformed/);
    }
});

test('RFC 7871/7873/8914 の不正な EDNS データは raw 表示し警告する', () => {
    const cases = [
        [8, '00012100c0000200', 'ECS'],
        [8, '00011821c00002', 'ECS'],
        [8, '00011900c0000201', 'ECS'],
        [8, '00011800c0000200', 'ECS'],
        [8, '00011800c000', 'ECS'],
        [10, '00'.repeat(7), 'Cookie'],
        [10, '00'.repeat(9), 'Cookie'],
        [10, '00'.repeat(15), 'Cookie'],
        [10, '00'.repeat(41), 'Cookie'],
        [15, '00', 'EDE']
    ];
    for (const [code, hex, name] of cases) {
        const html = renderWireResponse({
            additionals: [{ type: 'OPT', name: '.', options: [{ code, data: Buffer.from(hex, 'hex') }] }]
        });
        assert.ok(html.includes(`(${code}): ${hex}</code>`));
        assert.ok(html.includes(`malformed ${name} OPTION-DATA`), `${name}: ${hex}`);
        assert.match(html, /WARNING SECTION/);
        assert.ok(!html.includes(`<strong>${name}</strong>`));
    }
});

test('RFC 7871/7873 の有効な境界値と IPv6 ECS を表示する', () => {
    for (const length of [8, 16, 40]) {
        const html = renderWireResponse({
            additionals: [{
                type: 'OPT', name: '.', options: [
                    { code: 10, data: Buffer.alloc(length, 0xab) },
                    { code: 8, data: Buffer.from('00020000', 'hex') },
                    { code: 8, data: Buffer.from('0002394020010db800000080', 'hex') }
                ]
            }]
        });
        assert.match(html, /<strong>Cookie<\/strong>/);
        assert.match(html, /sourcePrefix: 0, scopePrefix: 0, address: ::/);
        assert.match(html, /sourcePrefix: 57, scopePrefix: 64, address: 2001:db8:0:80::/);
        assert.doesNotMatch(html, /WARNING SECTION|malformed/);
    }
});

test('RFC 8914/7830 の EDE と任意の Padding データを表示する', () => {
    const html = renderWireResponse({
        flags: 2,
        additionals: [{
            type: 'OPT', name: '.', options: [
                { code: 15, data: Buffer.from([0, 22]) },
                { code: 15, data: Buffer.concat([Buffer.from([0, 35]), Buffer.from('<blocked>')]) },
                { code: 15, data: Buffer.from([0xfd, 0xe8]) },
                { code: 12, data: Buffer.from([0xff, 0x01]) }
            ]
        }]
    });
    assert.match(html, /22 \(<a[^>]+>No Reachable Authority<\/a>\)/);
    assert.match(html, /35 \(<a[^>]+>Blocked by Upstream DNS Server<\/a>\): \(&lt;blocked&gt;\)/);
    assert.match(html, /65000 \(Unknown Error\)/);
    assert.match(html, /Padding<\/strong><code>length: 2 bytes/);
    assert.doesNotMatch(html, /WARNING SECTION|BADTRUNC|<blocked>/);
});

test('OPT の生データ検査は UDP/DoH と TCP/DoT のフレーミングを区別する', () => {
    for (const malformed of [false, true]) {
        const raw = dnsPacket.encode({
            type: 'response', id: 100,
            questions: [{ name: 'example.com', type: 'A' }],
            additionals: [{ type: 'OPT', name: '.', options: [{ code: 65001, data: Buffer.from([0xaa]) }] }]
        });
        if (malformed) raw.writeUInt16BE(2, raw.length - 3);
        for (const [sendTcp, sendDot, sendHttps] of [[false, false, false], [true, false, false], [false, true, false], [true, false, true]]) {
            const tcpFramed = (sendTcp || sendDot) && !sendHttps;
            const prefix = Buffer.alloc(2);
            prefix.writeUInt16BE(raw.length);
            const received = tcpFramed ? Buffer.concat([prefix, raw]) : raw;
            const html = makeHtmlFromDns(dnsPacket.decode(raw), received.length, 'http://localhost:3000', '/api/query',
                '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
                false, false, sendTcp, false, sendHttps, '', true, false, '1232', false, '', false, 255, 'A', received, 'IN', sendDot);
            if (malformed) assert.match(html, /OPTION-LENGTH.*RDATA の残りの長さ.*超過/);
            else assert.doesNotMatch(html, /WARNING SECTION|破損/);
        }
    }
});

test('RFC 10029 の MQTYPE-Response では OPT と予約値を不正とし既知タイプ名を表示する', () => {
    for (const [code, invalid] of [[41, true], [65535, true], [64, false], [65, false]]) {
        const data = Buffer.alloc(2);
        data.writeUInt16BE(code);
        const html = renderWireResponse({
            additionals: [{ type: 'OPT', name: '.', options: [{ code: 21, data }] }]
        });
        if (invalid) assert.match(html, /RFC 10029 の形式に適合していません/);
        else {
            assert.match(html, /MQTYPE-Response<\/strong><code>(SVCB|HTTPS)<\/code>/);
            assert.doesNotMatch(html, /RFC 10029 の形式に適合していません/);
        }
    }
});

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
    assert.equal(isInvalidQueryType('AXFR'), false);
    assert.equal(isInvalidQueryType('IXFR'), false);
    assert.equal(isInvalidQueryType('NSEC3PARAM'), false);
    assert.equal(isInvalidQueryType('TA'), false);
    assert.equal(isInvalidQueryType('SVCB'), false);
    assert.equal(isInvalidQueryType('HTTPS'), false);
    assert.equal(isInvalidQueryType('TSIG'), true);
    assert.equal(isInvalidQueryType('TKEY'), true);
    assert.equal(isInvalidQueryType('OPT'), true);
    assert.equal(isInvalidQueryType('UNKNOWN_65280'), true);
    assert.equal(isInvalidQueryType('VERSION'), true);
    assert.equal(isInvalidQueryType('NOT_A_TYPE'), true);
    assert.equal(isInvalidQueryClass('IN'), false);
    assert.equal(isInvalidQueryClass('CH'), false);
    assert.equal(isInvalidQueryClass('BAD'), true);
    assert.equal(buildDnsFlags(true, true), dnsPacket.RECURSION_DESIRED | dnsPacket.CHECKING_DISABLED);
    assert.equal(reverseIPv4('192.0.2.4'), '4.2.0.192');
    assert.equal(reverseIPv4('192.0.2.256'), '');
    assert.equal(reverseIPv6('2001:db8::1'), '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2');
});

test('クエリータイプの選択肢とAPI許可タイプが一致する', () => {
    const indexHtml = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
    const typeSelect = /<select id="type" name="type">([\s\S]*?)<\/select>/.exec(indexHtml);
    const resourceRecordDecoderTypes = [
        'TXT', 'SPF', 'NSEC3PARAM', 'CDS', 'CDNSKEY', 'CAA', 'DNSKEY', 'DS', 'NSEC', 'NSEC3',
        'RRSIG', 'SOA', 'SRV', 'TLSA', 'SSHFP', 'NAPTR', 'SVCB', 'HTTPS'
    ];

    assert.ok(typeSelect, 'クエリータイプの select がありません');
    const optionValues = [...typeSelect[1].matchAll(/<option value="([^"]+)"/g)].map(([, value]) => value);

    assert.deepEqual(optionValues, SUPPORTED_QUERY_TYPES);
    for (const type of resourceRecordDecoderTypes) {
        assert.ok(SUPPORTED_QUERY_TYPES.includes(type), `${type} がAPI許可タイプにありません`);
    }
    const historicalTypes = /<optgroup label="歴史的・特殊なタイプ">([\s\S]*?)<\/optgroup>/.exec(typeSelect[1]);
    assert.ok(historicalTypes, '歴史的・特殊なタイプのグループがありません');
    assert.deepEqual(
        [...historicalTypes[1].matchAll(/<option value="([^"]+)"/g)].map(([, value]) => value),
        ['DLV', 'SPF']
    );
    assert.equal(optionValues.includes('TSIG'), false);
    assert.equal(optionValues.includes('TKEY'), false);
    assert.equal(optionValues.includes('OPT'), false);
    assert.equal(optionValues[optionValues.indexOf('PTR') + 1], 'PTR-x');
});

test('クエリークラスはメニューで選択する', () => {
    const indexHtml = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
    const classSelect = /<select id="class" name="class">([\s\S]*?)<\/select>/.exec(indexHtml);

    assert.ok(classSelect, 'クエリークラスの select がありません');
    const classOptions = [...classSelect[1].matchAll(/<option value="([^"]+)"/g)].map(([, value]) => value);

    assert.deepEqual(classOptions, ['IN', 'CS', 'CH', 'HS', 'ANY']);
    assert.match(classSelect[1], /<option value="IN" selected>/);
    assert.doesNotMatch(indexHtml, /<input[^>]+name="class"/);
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
    assert.match(validateMQType('A', 'TXT', 'CH'), /IN クラス/);
    assert.match(validateMQType('0', 'A', 'IN'), /無効な QTYPE/);
    assert.match(validateMQType('65536', 'A', 'IN'), /無効な QTYPE/);
});

test('QUESTION SECTIONが無いときは警告を表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [],
        answers: [],
        authorities: [],
        additionals: []
    }, 12, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /応答に QUESTION SECTION が存在しませんでした。/);
});

test('QUESTION SECTIONの名前比較は末尾ピリオドを無視する', () => {
    const render = (questionName) => makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: questionName, type: 'A' }],
        answers: [],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com.', 'A', 100,
    false, false, false, false, false, '', false, false, '1232', false, '', false, 255, 'A');

    assert.doesNotMatch(render('example.com'), /QUESTION SECTION のドメイン名が.*一致しませんでした/);
    assert.doesNotMatch(render('EXAMPLE.COM.'), /QUESTION SECTION のドメイン名が.*一致しませんでした/);
    assert.match(render('other.example.com'), /QUESTION SECTION のドメイン名が.*一致しませんでした/);
});

test('QNAME minimisationのNS名比較は末尾ピリオドを無視する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'NS' }],
        answers: [{ name: 'example.com', type: 'NS', data: 'ns1.example.com', ttl: 300 }],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com.', 'NS', 100,
    false, false, false, false, false, '', false, false, '1232', false, '', true, 0, 'NS');

    assert.match(html, /class="rr-annotation">先頭からのラベル削除数: <code>0<\/code>個 \(QNAME minimisation\)/);
    assert.match(html, /server=a\.root-servers\.net&amp;name=ns1\.example\.com&amp;type=A/);
});

test('Authority NS と Additional A/AAAA の RFC 9499 関係を DATA 列に表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'www.child.example.com', type: 'A' }],
        answers: [],
        authorities: [
            { name: 'child.example.com', type: 'NS', data: 'ns1.child.example.com', ttl: 300 },
            { name: 'child.example.com', type: 'NS', data: 'ns1.sibling.example.com', ttl: 300 },
            { name: 'child.example.com', type: 'NS', data: 'ns1.example.net', ttl: 300 }
        ],
        additionals: [
            { name: 'ns1.child.example.com', type: 'A', data: '192.0.2.1', ttl: 300 },
            { name: 'ns1.sibling.example.com', type: 'AAAA', data: '2001:db8::1', ttl: 300 },
            { name: 'ns1.example.net', type: 'A', data: '192.0.2.2', ttl: 300 },
            { name: 'ns2.sibling.example.com', type: 'A', data: '192.0.2.4', ttl: 300 },
            { name: 'other.example.net', type: 'A', data: '192.0.2.3', ttl: 300 }
        ]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'www.child.example.com', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /class="rr-annotation">RFC 9499: in-domain/);
    assert.match(html, /class="rr-annotation">RFC 9499: sibling domain/);
    assert.match(html, /class="rr-annotation">RFC 9499: unrelated/);
    assert.equal((html.match(/class="rr-annotation">RFC 9499: unrelated/g) || []).length, 3);
});

test('OPTのEDNSバージョンをワイヤ形式からデコードして表示する', () => {
    for (const ednsVersion of [0, 1, 255]) {
        const wire = dnsPacket.encode({
            type: 'response',
            id: 100,
            questions: [{ name: 'opt-badvers.anomaly.test.ldns.jp', type: 'A' }],
            answers: [],
            authorities: [],
            additionals: [{
                type: 'OPT',
                name: '.',
                ednsVersion,
                udpPayloadSize: 4096,
                flags: 0,
                options: []
            }]
        });
        const response = dnsPacket.decode(wire);
        assert.equal(response.additionals[0].ednsVersion, ednsVersion);

        const html = makeHtmlFromDns(response, 20, 'http://localhost:3000', '/api/query',
            'ns2.ldns.jp', '160.16.111.88', 'opt-badvers.anomaly.test.ldns.jp', 'A', 100,
            true, false, false, false, false, '', true, false, '1232', false, '', false, 255, 'A');

        assert.match(html, new RegExp(`Extended RCODE: 0, Version: ${ednsVersion}, flags: , UDP payload size: 4096`));
        assert.match(html, /<dt>応答ステータス \(rcode\)<\/dt><dd><code>NOERROR<\/code><\/dd>/);
    }
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
            ednsVersion: 0,
            udpPayloadSize: 1232,
            flags: 0,
            options: []
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /OPT PSEUDOSECTION <span class="section-count">1 項目<\/span>/);
    assert.match(html, /<dt>応答ステータス \(rcode\)<\/dt><dd><code>BADVERS<\/code><\/dd>/);
    assert.match(html, /Extended RCODE: 1 \(BADVERS\)/);
    assert.doesNotMatch(html, /BADSIG/);
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
            ednsVersion: 0,
            udpPayloadSize: 1232,
            flags: 0,
            options: []
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'rcode-badkey.anomaly.test.ldns.jp', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /<dt>応答ステータス \(rcode\)<\/dt><dd><code>BADKEY<\/code><\/dd>/);
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
        '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100, false, false, false, false, false, '',
        '1232', false, 'AAAA,MX', false, 255, 'A');

    assert.match(render(createResponse(Buffer.from([0, 28, 0, 15]))), /MQTYPE-Response.*AAAA,MX/);
    assert.match(render(createResponse(Buffer.from([0, 28, 0]))), /RFC 10029 の形式に適合していません/);
});

test('EDNS optionをraw表示し、NSIDをhexと文字列で表示する', () => {
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
                { code: 3, data: Buffer.from('nsid-01') },
                { code: 10, data: Buffer.from([0x01, 0x02]) },
                { code: 65001, data: Buffer.alloc(0) }
            ]
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /OPT PSEUDOSECTION <span class="section-count">4 項目<\/span>/);
    assert.match(html, /<strong>NSID<\/strong><code>text: nsid-01, hex: 6e7369642d3031<\/code>/);
    assert.match(html, /OPTION_10 \(10\): 0102/);
    assert.match(html, /OPTION_65001 \(65001\): \(empty\)/);
});
test('EDNS0 の DO フラグおよび CO フラグ (Compact Answers OK) を正しく解析・表示する', () => {
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
            flags: dnsPacket.DNSSEC_OK | 0x4000,
            options: []
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    true, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /flags: <span class="dns-flag" title="DNSSEC OK">DO<\/span> <span class="dns-flag" title="Compact Answers OK">CO<\/span>/);
});
test('OPT疑似セクションが一般的に破損している場合を表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'SERVFAIL',
        questions: [{ name: 'rdata-opt-truncated.anomaly.test.ldns.jp', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: [{
            type: 'OPT',
            name: '.',
            udpPayloadSize: 512,
            flags: dnsPacket.DNSSEC_OK,
            options: [{
                code: 'invalid',
                data: Buffer.from([])
            }]
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'rdata-opt-truncated.anomaly.test.ldns.jp', 'A', 100,
    true, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /OPT 疑似セクションとしては破損しています: <code>OPTION コードが不正です<\/code>/);
});

test('WARNING SECTIONを最後に出して、構造は解釈できるが異常な応答を示す', () => {
    const raw = dnsPacket.encode({
        type: 'response',
        id: 100,
        flags: 2,
        questions: [{ name: 'rdata-opt-truncated.anomaly.test.ldns.jp', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: [{
            type: 'OPT',
            name: '.',
            udpPayloadSize: 512,
            flags: dnsPacket.DNSSEC_OK,
            options: [{ code: 65001, data: Buffer.from([0xaa]) }]
        }]
    });
    raw.writeUInt16BE(2, raw.length - 3);
    const html = makeHtmlFromDns(dnsPacket.decode(raw), raw.length, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'rdata-opt-truncated.anomaly.test.ldns.jp', 'A', 100,
    true, false, false, false, false, '', true, false, '1232', false, '', false, 255, 'A', raw);

    assert.match(html, /WARNING SECTION/);
    assert.match(html, /OPTION-LENGTH.*RDATA の残りの長さ.*超過/);
    assert.ok(html.lastIndexOf('WARNING SECTION') > html.lastIndexOf('OPT PSEUDOSECTION'));
});

test('ヘッダーで宣言された RR を全部読んだ後に余剰バイトが残る場合を警告する', () => {
    const validPacket = dnsPacket.encode({
        id: 100,
        flags: 0,
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: []
    });
    const raw = Buffer.concat([validPacket, Buffer.from([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])]);
    const html = analyzeDnsPacketError(raw);

    assert.match(html, /未消費データ|残っています|extra bytes/i);
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
    false, false, false, false, false, '', '1232', false, 'AAAA', false, 255, 'A');

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
    false, false, true, false, false, '', '1232', true, '', false, 255, 'A');

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

    const [staticFile, missingName, invalidType, invalidTsigType, invalidTkeyType, invalidOptType, invalidUdpSize, invalidServer, invalidDomainEmptyLabel, invalidDomainLabelTooLong] = await Promise.all([
        request(port, '/dns-query-tool/'),
        request(port, '/dns-query-tool/api/query'),
        request(port, '/dns-query-tool/api/query?name=example.com&type=%3Cscript%3E'),
        request(port, '/dns-query-tool/api/query?name=example.com&type=TSIG'),
        request(port, '/dns-query-tool/api/query?name=example.com&type=TKEY'),
        request(port, '/dns-query-tool/api/query?name=example.com&type=OPT'),
        request(port, '/dns-query-tool/api/query?name=example.com&udpsize=511'),
        request(port, '/dns-query-tool/api/query?name=example.com&server=127.0.0.1'),
        request(port, '/dns-query-tool/api/query?name=foo..bar'),
        request(port, `/dns-query-tool/api/query?name=${'a'.repeat(64)}.com`)
    ]);

    assert.equal(staticFile.statusCode, 200);
    assert.match(staticFile.body, /DNSクエリー送信ツール/);
    assert.equal(missingName.statusCode, 400);
    assert.match(invalidType.body, /不正なクエリータイプ/);
    assert.doesNotMatch(invalidType.body, /<script>/);
    assert.match(invalidTsigType.body, /不正なクエリータイプ/);
    assert.match(invalidTkeyType.body, /不正なクエリータイプ/);
    assert.match(invalidOptType.body, /不正なクエリータイプ/);
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
            const query = dnsPacket.decode(args[0]);
            const response = dnsPacket.encode({
                ...dnsPacket.decode(udpResponse),
                id: query.id,
                questions: query.questions
            });
            queueMicrotask(() => socket.emit('message', response));
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

test('DoTはTLSの853番ポートでDNSストリームフレームを送受信する', async () => {
    const query = {
        type: 'query',
        id: 1234,
        questions: [{ name: 'example.com', type: 'A', class: 'IN' }]
    };
    const responseFrame = dnsPacket.streamEncode({
        type: 'response',
        id: query.id,
        questions: query.questions,
        answers: []
    });
    const client = new EventEmitter();
    client.destroy = () => {};
    let writtenBuffer;

    const resultPromise = queryAuthoritativeServerOverTls('192.0.2.53', 'resolver.example', query, (options) => {
        assert.deepEqual(options, {
            host: '192.0.2.53',
            port: 853,
            servername: 'resolver.example'
        });
        client.write = (buffer) => { writtenBuffer = buffer; };
        queueMicrotask(() => {
            client.emit('secureConnect');
            client.emit('data', responseFrame.subarray(0, 1));
            client.emit('data', responseFrame.subarray(1));
        });
        return client;
    });

    const result = await resultPromise;
    assert.deepEqual(writtenBuffer, dnsPacket.streamEncode(query));
    assert.equal(result.response.id, query.id);
    assert.deepEqual(result.rawBuffer, responseFrame);
});

test('DoTは接続先がIPアドレスの場合にTLS servernameを指定しない', async () => {
    const client = new EventEmitter();
    client.destroy = () => {};
    const responseFrame = dnsPacket.streamEncode({
        type: 'response',
        id: 1234,
        questions: [{ name: 'example.com', type: 'A', class: 'IN' }],
        answers: []
    });
    const resultPromise = queryAuthoritativeServerOverTls('192.0.2.53', '192.0.2.53', {
        type: 'query',
        id: 1234,
        questions: [{ name: 'example.com', type: 'A', class: 'IN' }]
    }, (options) => {
        assert.deepEqual(options, { host: '192.0.2.53', port: 853 });
        client.write = () => {};
        queueMicrotask(() => {
            client.emit('secureConnect');
            client.emit('data', responseFrame);
        });
        return client;
    });

    const result = await resultPromise;
    assert.equal(result.response.id, 1234);
});

test('DoT応答から生成する再検索リンクにDoT設定を引き継ぐ', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'SERVFAIL',
        questions: [{ name: 'example.com', type: 'A', class: 'IN' }],
        answers: [],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', 'resolver.example', '192.0.2.53', 'example.com', 'A', 100,
    true, false, false, false, false, '', false, false, '1232', false, '', false, 255, 'A', null, 'IN', true);

    assert.match(html, /dot=1/);
    assert.match(html, /<div class="basic-info-item"><dt>応答サイズ<\/dt><dd><code>20<\/code> byte<\/dd><\/div><div class="basic-info-item"><dt>プロトコル<\/dt><dd><code>DoT<\/code><\/dd><\/div>/);
});

test('クエリークラスをDNSメッセージと再検索リンクに反映する', async () => {
    const udpResponse = dnsPacket.encode({
        type: 'response',
        flags: dnsPacket.TRUNCATED_RESPONSE,
        questions: [{ name: 'version.bind', type: 'TXT', class: 'CH' }]
    });
    const createSocket = () => {
        const socket = new EventEmitter();
        socket.close = () => {};
        socket.send = (...args) => {
            args.at(-1)();
            const query = dnsPacket.decode(args[0]);
            const response = dnsPacket.encode({
                ...dnsPacket.decode(udpResponse),
                id: query.id,
                questions: query.questions
            });
            queueMicrotask(() => socket.emit('message', response));
        };
        return socket;
    };
    const tcpResponse = { id: 1, answers: [] };
    let tcpQuery;
    const queryOverTcp = async (address, query) => {
        tcpQuery = query;
        return tcpResponse;
    };

    assert.equal(await queryAuthoritativeServer('8.8.8.8', 'version.bind', 'TXT', createSocket, queryOverTcp, false, 'CH'), tcpResponse);
    assert.deepEqual(tcpQuery.questions, [{ name: 'version.bind', type: 'TXT', class: 'CH' }]);

    const html = makeHtmlFromDns({
        id: 100,
        flags: dnsPacket.TRUNCATED_RESPONSE,
        rcode: 'NOERROR',
        questions: [{ name: 'version.bind', type: 'TXT', class: 'CH' }],
        answers: [],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'version.bind', 'TXT', 100,
    false, false, false, false, false, '', false, false, '1232', false, '', false, 255, 'A', null, 'CH');

    assert.match(html, /class=CH/);
    assert.match(html, /data-label="TYPE"><span class="rr-type rr-type-question">TXT<\/span><\/th><td data-label="NAME"><code class="rr-value">version\.bind<\/code><\/td><td data-label="CLASS"><code class="rr-value">CH<\/code>/);
});

test('各リソースレコードセクションで CLASS を表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'A', class: 'CH' }],
        answers: [{ name: 'example.com', type: 'TXT', class: 'CH', data: 'answer text', ttl: 60 }],
        authorities: [{ name: 'example.com', type: 'NS', class: 'HS', data: 'ns.example.com', ttl: 300 }],
        additionals: [{ name: 'ns.example.com', type: 'A', class: 'IN', data: '192.0.2.53', ttl: 300 }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, false, '', false, false, '1232', false, '', false, 255, 'A');

    assert.match(html, /data-label="TYPE"><span class="rr-type rr-type-answer">TXT<\/span><\/th><td data-label="NAME"><code class="rr-value">example\.com<\/code><\/td><td data-label="CLASS"><code class="rr-value">CH<\/code>/);
    assert.match(html, /data-label="TYPE"><span class="rr-type">NS<\/span><\/th><td data-label="NAME"><code class="rr-value">example\.com<\/code><\/td><td data-label="CLASS"><code class="rr-value">HS<\/code>/);
    assert.match(html, /data-label="TYPE"><span class="rr-type">A<\/span><\/th><td data-label="NAME"><code class="rr-value">ns\.example\.com<\/code><\/td><td data-label="CLASS"><code class="rr-value">IN<\/code>/);
});

test('A と AAAA を共通の RR 列で表示し、DATA の問い合わせリンクを維持する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [
            { name: 'example.com', type: 'A', data: '192.0.2.10', ttl: 300 },
            { name: 'example.com', type: 'AAAA', data: '2001:db8::10', ttl: 300 }
        ],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /ANSWER SECTION <span class="section-count">2 件<\/span>/);
    assert.equal((html.match(/<tr><th scope="row" data-label="TYPE"><span class="rr-type rr-type-answer">/g) || []).length, 2);
    assert.match(html, /data-label="DATA"><code class="rr-value"><a data-dns-query-link[^>]*>192\.0\.2\.10<\/a><\/code>/);
    assert.match(html, /data-label="DATA"><code class="rr-value"><a data-dns-query-link[^>]*>2001:db8::10<\/a><\/code>/);
    assert.equal((html.match(/data-label="TTL"><span class="rr-ttl">300秒<\/span>/g) || []).length, 2);
});

test('UDP問い合わせは不一致IDと不正な送信元の応答を無視する', async () => {
    const createSocket = () => {
        const socket = new EventEmitter();
        socket.close = () => {};
        socket.send = (...args) => {
            args.at(-1)();
            const query = dnsPacket.decode(args[0]);
            const response = {
                type: 'response',
                id: query.id,
                questions: query.questions,
                answers: []
            };
            queueMicrotask(() => {
                socket.emit('message', dnsPacket.encode({ ...response, id: (query.id + 1) % 65536 }), { address: '8.8.8.8' });
                socket.emit('message', dnsPacket.encode(response), { address: '192.0.2.1' });
                socket.emit('message', dnsPacket.encode(response), { address: '8.8.8.8' });
            });
        };
        return socket;
    };

    const response = await queryAuthoritativeServer('8.8.8.8', 'example.com', 'A', createSocket);
    assert.ok(Number.isInteger(response.id));
    assert.equal(response.questions[0].name, 'example.com');
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
    false, false, true, false, false, '', false, '1232', false, '', false, 255, 'A');

    assert.doesNotMatch(html, /TCフラグが立っているので TCPでの再確認を推奨します/);
});

test('UDP応答のTCフラグはTCP再確認アクションを表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: dnsPacket.TRUNCATED_RESPONSE,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /class="basic-info-notice notice-info"[^>]*>TCフラグが立っているので TCPでの再確認を推奨します/);
    assert.match(html, /<a class="notice-action" data-dns-query-link href="[^"]*tcp=1[^"]*">TCPで再確認<\/a>/);
});

test('TCP送受信が無効なAXFR問い合わせはRFC違反の案内を表示する', () => {
    const render = (queryType, sendTcp) => makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: queryType }],
        answers: [],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', queryType, 100,
    false, false, sendTcp, false, false, '', false, false, '1232', false, '', false, 255, 'A');

    const udpAxfrHtml = render('AXFR', false);
    assert.match(udpAxfrHtml, /class="basic-info-notice notice-warning"[^>]*>AXFR クエリーでは TCP での送受信が求められます。/);
    assert.match(udpAxfrHtml, /TCPでの再確認を推奨します。/);
    assert.match(udpAxfrHtml, /<a class="notice-action" data-dns-query-link href="[^"]*type=AXFR[^"]*tcp=1[^"]*https=0[^"]*dot=0[^"]*">TCPで再確認<\/a>/);
    assert.doesNotMatch(render('AXFR', true), /AXFR クエリーでは TCP での送受信が求められます/);
    assert.doesNotMatch(render('A', false), /AXFR クエリーでは TCP での送受信が求められます/);
});

test('DNSSECとQNAME minimisationの案内リンクをアクションボタンで表示する', () => {
    const dnssecHtml = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'SERVFAIL',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    true, false, false, false, false, '/dns-query', false, false, '1232', false, '', false, 255, 'A');

    assert.match(dnssecHtml, /DNSSEC検証に失敗した可能性があります。<a class="notice-action" data-dns-query-link href="[^"]*cd=1[^"]*">CDフラグで再確認<\/a>/);

    const qnameHtml = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NXDOMAIN',
        questions: [{ name: 'www.example.com', type: 'A' }],
        answers: [],
        authorities: [{
            name: 'example.com',
            type: 'SOA',
            ttl: 300,
            data: { mname: 'ns.example.com', rname: 'hostmaster.example.com', serial: 1, refresh: 3600, retry: 600, expire: 86400, minimum: 300 }
        }],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'www.example.com', 'A', 100,
    true, false, false, false, false, '/dns-query', false, false, '1232', false, '', true, 1, 'A');

    assert.match(qnameHtml, /QNAME minimisation が有効になっています。<a class="notice-action" data-dns-query-link href="[^"]*qposi=0[^"]*">ラベルを増やして確認<\/a>/);
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

test('analyzeDnsPacketError が TXT 文字列長オクテットの RDATA 長超過を検出する', () => {
    const qname = 'rdata-txt-len-mismatch.anomaly.test.ldns.jp';
    const packet = dnsPacket.encode({
        type: 'response',
        id: 0x1234,
        questions: [{ name: qname, type: 'TXT', class: 'IN' }],
        answers: [{
            name: qname,
            type: 'TXT',
            class: 'IN',
            ttl: 60,
            data: Buffer.from([1, 2, 3, 4, 5])
        }]
    });
    // dnsPacket.encode が生成した RDATA ([0x05, 1, 2, 3, 4, 5], rdlength = 6) の先頭バイト (txtLen) を 10 に書き換える
    packet[packet.length - 6] = 10;

    const resultHtml = analyzeDnsPacketError(packet, new Error('Buffer overflow'));

    assert.match(resultHtml, /【DNSメッセージ異常の分析結果】/);
    assert.match(resultHtml, /ANSWER SECTION \(rdata-txt-len-mismatch\.anomaly\.test\.ldns\.jp\) の TXT レコードにおいて/);
    assert.match(resultHtml, /TXT 文字列長オクテット \(10 バイト\) が RDATA 長 \(6 バイト\) を超過しています/);
});

test('analyzeDnsPacketError が 2 つ目以降の TXT 文字列長オクテットの残りの RDATA 長超過を検出する', () => {
    const qname = 'rdata-txt-len-mismatch.anomaly.test.ldns.jp';
    const packet = dnsPacket.encode({
        type: 'response',
        id: 0x1234,
        questions: [{ name: qname, type: 'TXT', class: 'IN' }],
        answers: [{
            name: qname,
            type: 'TXT',
            class: 'IN',
            ttl: 60,
            data: [Buffer.from([1, 2]), Buffer.from([3, 4, 5])]
        }]
    });
    // dnsPacket.encode が生成した RDATA は [0x02, 1, 2, 0x03, 3, 4, 5] (rdlength = 7)
    // 2つ目の文字列長オクテット 0x03 (末尾から4バイト目) を 10 に書き換える
    packet[packet.length - 4] = 10;

    const resultHtml = analyzeDnsPacketError(packet, new Error('Buffer overflow'));

    assert.match(resultHtml, /【DNSメッセージ異常の分析結果】/);
    assert.match(resultHtml, /ANSWER SECTION \(rdata-txt-len-mismatch\.anomaly\.test\.ldns\.jp\) の TXT レコードにおいて/);
    assert.match(resultHtml, /TXT 文字列長オクテット \(10 バイト\) が残りの RDATA 長 \(4 バイト\) を超過しています/);
});

test('SVCB TargetName の RDATA 長超過を検出し、表示処理を停止させない', () => {
    const qname = 'rdata-svcb-overflow.anomaly.test.ldns.jp';
    const packet = dnsPacket.encode({
        type: 'response',
        id: 0x1234,
        questions: [{ name: qname, type: 'SVCB', class: 'IN' }],
        answers: [{
            name: qname,
            type: 'UNKNOWN_64',
            class: 'IN',
            ttl: 60,
            data: Buffer.from([0, 1, 20, 0x74, 0x61, 0x72, 0x67, 0x65])
        }]
    });

    const resultHtml = analyzeDnsPacketError(packet, new Error('Buffer overflow'));
    assert.match(resultHtml, /SVCB レコードの TargetName のラベル長 \(20 バイト\) が残りの RDATA 長 \(5 バイト\) を超過しています/);

    const response = dnsPacket.decode(packet);
    const html = makeHtmlFromDns(response, packet.length, 'http://localhost:3000', '/api/query',
        'ns2.ldns.jp', '160.16.111.88', qname, 'SVCB', 0x1234,
        false, false, false, false, false, '', '1232', false, '', false, 255, 'A');
    assert.match(html, /malformed SVCB\/HTTPS TargetName/);
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

test('Opcode, QR(0), Reserved(Z) フラグを解析・表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        type: 'query',
        opcode: 'NOTIFY',
        flags: 0x0040,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /<div class="basic-info-item"><dt>Opcode<\/dt><dd><code>NOTIFY<\/code> <span class="basic-info-inline-warning">QUERY 以外の Opcode です<\/span><\/dd><\/div>/);
    assert.equal((html.match(/class="basic-info-item basic-info-item-wide"/g) || []).length, 2);
    assert.equal((html.match(/class="basic-info-item"/g) || []).length, 6);
    assert.match(html, /QUERY 以外の Opcode です/);
    assert.match(html, /class="basic-info-notice notice-warning"[^>]*>応答 \(response\) メッセージなのに QRフラグが立っていませんでした。/);
    assert.match(html, /<span class="dns-flag dns-flag-warning" title="Reserved">Z<\/span>/);
});

test('EDNS Option の ECS, Cookie, Padding をデコード表示する', () => {
    const ecsIPv4Data = Buffer.from([0x00, 0x01, 24, 0, 192, 0, 2]);
    const cookieData = Buffer.from('12345678876543210000000000000000', 'hex');
    const paddingData = Buffer.alloc(10);

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
                { code: 8, data: ecsIPv4Data },
                { code: 10, data: cookieData },
                { code: 12, data: paddingData }
            ]
        }]
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /<strong>ECS<\/strong><code>family: 1 \(IPv4\), sourcePrefix: 24, scopePrefix: 0, address: 192\.0\.2\.0<\/code>/);
    assert.match(html, /<strong>Cookie<\/strong><code>Client Cookie: 1234567887654321, Server Cookie: 0000000000000000<\/code>/);
    assert.match(html, /<strong>Padding<\/strong><code>length: 10 bytes<\/code>/);
});

test('RFC 2308 ネガティブキャッシュ (Negative Caching) の TTL 算出と表示を検証する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NXDOMAIN',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: [],
        authorities: [{
            name: 'example.com',
            type: 'SOA',
            ttl: 300,
            data: {
                mname: 'ns1.example.com',
                rname: 'admin.example.com',
                serial: 1,
                refresh: 3600,
                retry: 1800,
                expire: 604800,
                minimum: 60
            }
        }],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /ネガティブキャッシュ有効期間 \(TTL\) は <code>60秒<\/code>/);
});

test('全セクションの SOA mname リンクはルートから A レコードを新たに探索する', () => {
    const sections = ['answers', 'authorities', 'additionals'];
    for (const options of [
        { qmini: false, tcp: false, https: false, dot: false, name: 'ns.example.com.' },
        { qmini: true, tcp: true, https: false, dot: false, name: 'ns.example.com' },
        { qmini: true, tcp: false, https: true, dot: false, name: 'ns.example.com' },
        { qmini: false, tcp: false, https: false, dot: true, name: '.' }
    ]) {
        const soa = {
            name: 'example.com', type: 'SOA', class: 'IN', ttl: 300,
            data: {
                mname: options.name, rname: 'admin.example.com', serial: 42,
                refresh: 3600, retry: 600, expire: 86400, minimum: 60
            }
        };
        const html = makeHtmlFromDns({
            id: 100, type: 'response', flags: 0, rcode: 'NOERROR',
            questions: [{ name: 'example.com', type: 'IXFR' }],
            ...Object.fromEntries(sections.map(section => [section, [soa]]))
        }, 20, 'http://localhost:3000', '/api/query', 'dns.google', '8.8.8.8', 'example.com', 'IXFR', 100,
        true, true, options.tcp, true, options.https, '/dns-query', true, true, '1232', true, 'AAAA,MX',
        options.qmini, 1, 'NS', null, 'IN', options.dot, 42);

        const links = [...html.matchAll(/mname: <a data-dns-query-link href="([^"]+)">([^<]+)<\/a>([^<]+)/g)];
        assert.equal(links.length, sections.length);
        for (const [, href, label, rest] of links) {
            const url = new URL(href.replaceAll('&amp;', '&'), 'http://localhost:3000/dns-query-tool/');
            assert.equal(url.pathname, '/dns-query-tool/api/query');
            assert.equal(label, options.name);
            assert.equal(rest, ', rname: admin.example.com, serial: 42, refresh: 3600, retry: 600, expire: 86400, minimum: 60');
            assert.deepEqual(Object.fromEntries(url.searchParams), {
                server: 'a.root-servers.net', name: options.name, type: 'A', class: 'IN',
                rd: '0', cd: '1', tcp: options.tcp ? '1' : '0', ipv6: '1',
                https: '0', dot: '0', httpspath: '', edns0: '1', dnssec: '1',
                udpsize: '1232', nsid: '1', mqtype: '',
                qmini: options.qmini ? '1' : '0', qposi: '255', qtype: 'NS'
            });
        }
    }
});

test('SOA のリンク名とその他のフィールドを HTML エスケープする', () => {
    const mname = 'ns.<example>&".com';
    const html = makeHtmlFromDns({
        id: 100, type: 'response', flags: 0, rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'SOA' }],
        answers: [{
            name: 'example.com', type: 'SOA', ttl: 300,
            data: {
                mname, rname: '<admin>&".example.com', serial: 42,
                refresh: 3600, retry: 600, expire: 86400, minimum: 60
            }
        }],
        authorities: [], additionals: []
    }, 20, 'http://localhost:3000', '/', '8.8.8.8', '8.8.8.8', 'example.com', 'SOA', 100,
    false, false, false, false, false, '', false, false, '1232', false, '', false, 255, 'A');

    assert.match(html, />ns\.&lt;example&gt;&amp;&quot;\.com<\/a>, rname: &lt;admin&gt;&amp;&quot;\.example\.com, serial: 42/);
    const link = /mname: <a data-dns-query-link href="([^"]+)"/.exec(html);
    assert.ok(link);
    const url = new URL(link[1].replaceAll('&amp;', '&'), 'http://localhost:3000/');
    assert.equal(url.searchParams.get('name'), mname);
    assert.doesNotMatch(html, /<example>|<admin>/);
});

test('TLSA, SSHFP, NAPTR リソースレコードのデコード表示を検証する', () => {
    const packet = dnsPacket.encode({
        type: 'response',
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'TLSA' }],
        answers: [
            {
                name: '_443._tcp.example.com',
                type: 'TLSA',
                ttl: 300,
                data: { usage: 3, selector: 1, matchingType: 1, certificate: Buffer.from('abcd', 'hex') }
            },
            {
                name: 'example.com',
                type: 'SSHFP',
                ttl: 300,
                data: { algorithm: 4, hash: 2, fingerprint: '1234abcd'.repeat(8) }
            },
            {
                name: 'example.com',
                type: 'NAPTR',
                ttl: 300,
                data: { order: 100, preference: 10, flags: 'S', services: 'SIP+D2U', regexp: '', replacement: '_sip._udp.example.com' }
            }
        ],
        authorities: [],
        additionals: []
    });
    const response = dnsPacket.decode(packet);
    const html = makeHtmlFromDns(response, packet.length, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'TLSA', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /<span class="rr-type rr-type-answer">TLSA<\/span>.*?usage: DANE-EE, selector: SPKI, matchingType: SHA-256, certificate: abcd/s);
    assert.ok(html.includes(`algorithm: Ed25519, fpType: SHA-256, fingerprint: ${'1234abcd'.repeat(8)}</code>`));
    assert.doesNotMatch(html, /malformed/);
    assert.match(html, /<span class="rr-type rr-type-answer">NAPTR<\/span>.*?order: 100, preference: 10, flags: S, services: SIP\+D2U/s);
});

test('SSHFP の実デコード結果を全セクションで表示する', () => {
    for (const section of ['answers', 'authorities', 'additionals']) {
        for (const [hash, hashName, length] of [[1, 'SHA-1', 20], [2, 'SHA-256', 32]]) {
            const fingerprint = 'ab'.repeat(length);
            const packet = dnsPacket.encode({
                type: 'response',
                id: 100,
                questions: [{ name: 'example.com', type: 'SSHFP' }],
                answers: [],
                authorities: [],
                additionals: [],
                [section]: [{
                    name: 'example.com', type: 'SSHFP', ttl: 300,
                    data: { algorithm: 255, hash, fingerprint }
                }]
            });
            const response = dnsPacket.decode(packet);
            assert.deepEqual(response[section][0].data, {
                algorithm: 255, hash, fingerprint: fingerprint.toUpperCase()
            });
            const html = makeHtmlFromDns(response, packet.length, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'SSHFP', 100,
                false, false, false, false, false, '', false, false, '1232', false, '', false, 255, 'A');

            assert.ok(html.includes(`algorithm: 255, fpType: ${hashName}, fingerprint: ${fingerprint}</code>`), `${section}, hash=${hash}`);
            assert.doesNotMatch(html, /malformed SSHFP RDATA/);
        }
    }
});

test('TLSA と SSHFP は dns-packet にない代替フィールドや型を受け付けない', () => {
    const invalidRecords = [
        { type: 'TLSA', data: { usage: 3, selector: 1, matchingType: 1, data: Buffer.from('abcd', 'hex') } },
        { type: 'TLSA', data: { usage: 3, selector: 1, matchingType: 1, certificate: 'abcd' } },
        { type: 'SSHFP', data: { algorithm: 4, fpType: 2, fingerprint: 'ab'.repeat(32) } },
        { type: 'SSHFP', data: { algorithm: 4, type: 2, fingerprint: 'ab'.repeat(32) } },
        { type: 'SSHFP', data: { algorithm: 4, hash: 2, fingerprint: Buffer.alloc(32) } },
        { type: 'SSHFP', data: { algorithm: 4, hash: 2, data: Buffer.alloc(32) } }
    ];
    for (const record of invalidRecords) {
        const html = makeHtmlFromDns({
            type: 'response', id: 100, flags: 0, rcode: 'NOERROR',
            questions: [{ name: 'example.com', type: record.type }],
            answers: [{ ...record, name: 'example.com', ttl: 300 }],
            authorities: [], additionals: []
        }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', record.type, 100,
        false, false, false, false, false, '', false, false, '1232', false, '', false, 255, 'A');

        assert.match(html, new RegExp(`malformed ${record.type} RDATA`));
    }
});

test('SPF, NSEC3PARAM, CDS, CDNSKEY の生 RDATA をデコード表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'SPF' }],
        answers: [
            { name: 'example.com', type: 'SPF', ttl: 300, data: Buffer.from([3, 97, 98, 99, 2, 100, 101]) },
            { name: 'example.com', type: 'NSEC3PARAM', ttl: 300, data: Buffer.from([1, 0, 0, 2, 2, 0xaa, 0xbb]) },
            { name: 'example.com', type: 'CDS', ttl: 300, data: Buffer.from([0x12, 0x34, 8, 2, 0xde, 0xad]) },
            { name: 'example.com', type: 'CDNSKEY', ttl: 300, data: Buffer.from([0x01, 0x00, 3, 13, 1, 2, 3]) }
        ],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'SPF', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /<span class="rr-type rr-type-answer">SPF<\/span>.*?strings: abcde/s);
    assert.match(html, /<span class="rr-type rr-type-answer">NSEC3PARAM<\/span>.*?algorithm: 1, flags: 0, iterations: 2, salt: aabb/s);
    assert.match(html, /<span class="rr-type rr-type-answer">CDS<\/span>.*?keyTag: 4660, algorithm: 8, digestType: 2, digest: dead/s);
    assert.match(html, /<span class="rr-type rr-type-answer">CDNSKEY<\/span>.*?flags: 256, protocol: 3, algorithm: 13, key: AQID/s);
});

test('DNSKEY の Key Tag を flags より前に表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'DNSKEY' }],
        answers: [
            { name: 'example.com', type: 'DNSKEY', ttl: 300, data: { flags: 256, algorithm: 13, key: Buffer.from([1, 2, 3]) } },
            { name: 'example.com', type: 'DNSKEY', ttl: 300, data: { flags: 256, algorithm: 1, key: Buffer.from([1, 3, 1, 2, 3, 4, 5, 6]) } }
        ],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'DNSKEY', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /keyTag: 2063, flags: 256, protocol: 3, algorithm: 13, key: AQID/);
    assert.match(html, /keyTag: 1029, flags: 256, protocol: 3, algorithm: 1, key: AQMBAgMEBQY=/);
});

test('SVCB の不正な SvcParam 長を malformed として表示する', () => {
    const invalidRdata = [
        { data: Buffer.from([0, 1, 0, 0, 1, 0, 2, 3, 97]), message: 'ALPN SvcParam' },
        { data: Buffer.from([0, 1, 0, 0, 3, 0, 1, 0]), message: 'port SvcParam' },
        { data: Buffer.from([0, 1, 0, 0, 4, 0, 1, 192]), message: 'ipv4hint SvcParam' },
        { data: Buffer.from([0, 1, 0, 0, 6, 0, 1, 0]), message: 'ipv6hint SvcParam' }
    ];

    for (const { data, message } of invalidRdata) {
        const html = makeHtmlFromDns({
            id: 100,
            flags: 0,
            rcode: 'NOERROR',
            questions: [{ name: 'example.com', type: 'SVCB' }],
            answers: [{ name: 'example.com', type: 'SVCB', ttl: 300, data }],
            authorities: [],
            additionals: []
        }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'SVCB', 100,
        false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

        assert.match(html, new RegExp(`malformed SVCB/HTTPS ${message}`));
    }
});

test('TXT の wire-format Buffer を character-string として表示する', () => {
    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'TXT' }],
        answers: [{ name: 'example.com', type: 'TXT', ttl: 300, data: Buffer.from([3, 97, 98, 99, 2, 100, 101]) }],
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'TXT', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    assert.match(html, /<span class="rr-type rr-type-answer">TXT<\/span>.*?<td data-label="DATA"><code class="rr-value">abcde<\/code>/s);
});

test('既存のオブジェクト型 RDATA の必須フィールド欠損を malformed として表示する', () => {
    const invalidRecords = [
        { type: 'CAA', data: {} },
        { type: 'DNSKEY', data: { flags: 256, algorithm: 13 } },
        { type: 'DS', data: { keyTag: 1, algorithm: 8, digestType: 2 } },
        { type: 'NSEC', data: { nextDomain: 'example.com' } },
        { type: 'NSEC3', data: { algorithm: 1, flags: 0, iterations: 1, salt: Buffer.alloc(0), nextDomain: Buffer.alloc(1) } },
        { type: 'RRSIG', data: { expiration: 'invalid', inception: 1, signature: Buffer.alloc(1) } },
        { type: 'SOA', data: {} },
        { type: 'SRV', data: {} },
        { type: 'TLSA', data: { usage: 3, selector: 1, matchingType: 1 } },
        { type: 'SSHFP', data: { algorithm: 4, hash: 2 } },
        { type: 'NAPTR', data: {} }
    ];

    const html = makeHtmlFromDns({
        id: 100,
        flags: 0,
        rcode: 'NOERROR',
        questions: [{ name: 'example.com', type: 'A' }],
        answers: invalidRecords.map(record => ({ ...record, name: 'example.com', ttl: 300 })),
        authorities: [],
        additionals: []
    }, 20, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8', 'example.com', 'A', 100,
    false, false, false, false, false, '', '1232', false, '', false, 255, 'A');

    for (const { type } of invalidRecords) {
        assert.match(html, new RegExp(`malformed ${type} RDATA`));
    }
});

test('RRSIG の typeCovered に含まれる UNKNOWN RR type を既知タイプ名で表示する', () => {
    const expectedTypes = {
        UNKNOWN_63: 'ZONEMD',
        UNKNOWN_64: 'SVCB',
        UNKNOWN_65: 'HTTPS'
    };

    for (const [typeCovered, expectedType] of Object.entries(expectedTypes)) {
        const packet = dnsPacket.encode({
            type: 'response',
            id: 100,
            flags: dnsPacket.AUTHORITATIVE_ANSWER,
            questions: [{ name: 'example.com', type: 'RRSIG' }],
            answers: [{
                name: 'example.com',
                type: 'RRSIG',
                ttl: 300,
                data: {
                    typeCovered,
                    algorithm: 13,
                    labels: 2,
                    originalTTL: 300,
                    expiration: 2000000000,
                    inception: 1900000000,
                    keyTag: 1,
                    signersName: 'example.com',
                    signature: Buffer.from([1, 2, 3])
                }
            }],
            authorities: [],
            additionals: []
        });
        const response = dnsPacket.decode(packet);
        const html = makeHtmlFromDns(
            response, packet.length, 'http://localhost:3000', '/api/query', '8.8.8.8', '8.8.8.8',
            'example.com', 'RRSIG', 100, false, false, false, false, false, '', false, '1232',
            false, '', false, 255, 'A', packet
        );

        assert.match(html, new RegExp(`typeCovered: ${expectedType},`));
    }
});

test('rdata-opt-truncated の生パケットで OPTION-LENGTH 超過による WARNING SECTION の表示を検証する', () => {
    const rawMsg = Buffer.from('04d2840000010000000000011372646174612d6f70742d7472756e636174656407616e6f6d616c790474657374046c646e73026a7000000100010000291000000000000008000a001031323334', 'hex');
    const decoded = dnsPacket.decode(rawMsg);
    const html = makeHtmlFromDns(
        decoded, rawMsg.length, 'http://localhost:3000', '/api/query', 'ns2.ldns.jp', '160.16.111.88',
        'rdata-opt-truncated.anomaly.test.ldns.jp', 'A', 1234,
        false, false, false, false, false, '', true, false, '1232', false,
        '', false, '255', 'A', rawMsg
    );

    assert.match(html, /WARNING SECTION/);
    assert.match(html, /OPT 疑似セクションとしては破損しています/);
    assert.match(html, /OPTION-LENGTH \(16 バイト\) が RDATA の残りの長さ \(4 バイト\) を超過しています/);
});

test('DNSサーバー解決時に権威サーバー問い合わせでタイムアウトが発生した場合、そのエラーが伝播する', async () => {
    const mockQueryServer = async (serverAddress, name, type) => {
        if (serverAddress === '198.41.0.4') {
            return {
                answers: [],
                authorities: [{ type: 'NS', name: 'drop.anomaly.test.ldns.jp', data: 'ns.drop.anomaly.test.ldns.jp' }],
                additionals: [
                    { type: 'A', name: 'ns.drop.anomaly.test.ldns.jp', data: '203.0.114.53' },
                    { type: 'AAAA', name: 'ns.drop.anomaly.test.ldns.jp', data: '2001:4860:ffff::53' }
                ]
            };
        }
        throw new Error(`${serverAddress} から UDP 応答がありませんでした。`);
    };

    await assert.rejects(
        async () => resolveDnsServerAddress('drop.anomaly.test.ldns.jp', false, 0, mockQueryServer),
        /UDP 応答がありませんでした/
    );
});

test('DNSサーバー解決時にTCP指定の場合も権威サーバー問い合わせのタイムアウトエラーが伝播する', async () => {
    const mockQueryServer = async (serverAddress, name, type, createSocket, queryOverTcp, sendTcp) => {
        if (serverAddress === '198.41.0.4') {
            return {
                answers: [],
                authorities: [{ type: 'NS', name: 'drop.anomaly.test.ldns.jp', data: 'ns.drop.anomaly.test.ldns.jp' }],
                additionals: [
                    { type: 'A', name: 'ns.drop.anomaly.test.ldns.jp', data: '203.0.114.53' },
                    { type: 'AAAA', name: 'ns.drop.anomaly.test.ldns.jp', data: '2001:4860:ffff::53' }
                ]
            };
        }
        throw new Error(`${serverAddress} から TCP 応答がありませんでした。`);
    };

    await assert.rejects(
        async () => resolveDnsServerAddress('drop.anomaly.test.ldns.jp', false, 0, mockQueryServer, true),
        /TCP 応答がありませんでした/
    );
});

test('DNSサーバー解決時にTCP指定で接続切断が発生した場合、切断エラーが伝播する', async () => {
    const mockQueryServer = async (serverAddress, name, type, createSocket, queryOverTcp, sendTcp) => {
        if (serverAddress === '198.41.0.4') {
            return {
                answers: [],
                authorities: [{ type: 'NS', name: 'drop.anomaly.test.ldns.jp', data: 'ns.drop.anomaly.test.ldns.jp' }],
                additionals: [
                    { type: 'A', name: 'ns.drop.anomaly.test.ldns.jp', data: '203.0.114.53' },
                    { type: 'AAAA', name: 'ns.drop.anomaly.test.ldns.jp', data: '2001:4860:ffff::53' }
                ]
            };
        }
        throw new Error(`${serverAddress} から TCP 接続が切断されました。`);
    };

    await assert.rejects(
        async () => resolveDnsServerAddress('drop.anomaly.test.ldns.jp', false, 0, mockQueryServer, true),
        /TCP 接続が切断されました/
    );
});
test('SSRF対策: 非公開・特殊用途アドレスへの問い合わせを拒否する', () => {
    const blocked = [
        '0.0.0.0', '0.1.2.3', '::', '::ffff:127.0.0.1', '::ffff:7f00:1', '::127.0.0.1', '64:ff9b::7f00:1',
        '169.254.169.254', '169.254.169.253', '100.64.0.1', '100.100.100.200', '198.18.0.1', '192.0.0.1',
        '192.0.2.1', '224.0.0.251', '255.255.255.255', '172.31.255.255', '10.0.0.1',
        'fc00::1', 'fd00:ec2::254', 'fe80::1', 'fe80::1%eth0', 'fec0::1', 'ff02::1', '2001:db8::1', '2002:7f00:1::1',
        'LOCALHOST', 'localhost.', 'foo.localhost', ''
    ];
    for (const address of blocked) {
        assert.equal(isInvalidDnsServer(address), true, address);
    }
    const allowed = ['8.8.8.8', '1.1.1.1', '198.41.0.4', '2001:4860:4860::8888', '2001:500:2f::f', 'a.root-servers.net', 'dns.google'];
    for (const address of allowed) {
        assert.equal(isInvalidDnsServer(address), false, address);
    }
});

const listenServerForTest = async (testContext) => {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    testContext.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
    return server.address().port;
};

// 公開アドレス宛ての53番ポートへの TCP 接続を、ローカルの模擬DNSサーバーへ転送する
const redirectTcpPort53 = (testContext, localPort) => {
    const net = require('node:net');
    const originalConnect = net.Socket.prototype.connect;
    net.Socket.prototype.connect = function (...args) {
        if (args[0] === 53 && typeof args[1] === 'string') {
            return originalConnect.call(this, localPort, '127.0.0.1', ...args.slice(2));
        }
        return originalConnect.apply(this, args);
    };
    testContext.after(() => { net.Socket.prototype.connect = originalConnect; });
};

const startMockTcpDnsServer = async (testContext, onConnection) => {
    const net = require('node:net');
    const sockets = new Set();
    // クライアントが送信側を閉じた (half-close) 後も、悪意あるサーバーとしてデータを送り続けられるようにする
    const mockServer = net.createServer({ allowHalfOpen: true }, (socket) => {
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
        socket.on('error', () => {});
        onConnection(socket);
    });
    await new Promise((resolve) => mockServer.listen(0, '127.0.0.1', resolve));
    testContext.after(() => new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        mockServer.close(() => resolve());
    }));
    return mockServer.address().port;
};

test('HTTP応答にセキュリティヘッダーを付与し、不正なHostヘッダーやGET以外のメソッドで停止しない', async (testContext) => {
    const port = await listenServerForTest(testContext);
    const net = require('node:net');

    const staticFile = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port, path: '/dns-query-tool/' }, (response) => {
            response.resume();
            response.on('end', () => resolve(response));
        }).on('error', reject);
    });
    assert.match(staticFile.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.match(staticFile.headers['content-security-policy'], /script-src 'self'/);
    assert.equal(staticFile.headers['x-content-type-options'], 'nosniff');
    assert.equal(staticFile.headers['x-frame-options'], 'DENY');

    const rawResponse = await new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1', () => {
            socket.write('GET /dns-query-tool/api/query?name=example.com&server=127.0.0.1 HTTP/1.1\r\nHost: [\r\nConnection: close\r\n\r\n');
        });
        let body = '';
        socket.setEncoding('utf8');
        socket.on('data', (chunk) => { body += chunk; });
        socket.on('end', () => resolve(body));
        socket.on('error', reject);
    });
    assert.match(rawResponse, /DNSサーバーを選択し直してください/);

    const postResponse = await new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, path: '/dns-query-tool/api/query', method: 'POST' }, (response) => {
            response.resume();
            response.on('end', () => resolve(response));
        });
        req.on('error', reject);
        req.end();
    });
    assert.equal(postResponse.statusCode, 405);
    assert.equal(server.listening, true);
});

test('TCP応答が1バイトだけで切断されてもプロセスを停止させない', async (testContext) => {
    const mockPort = await startMockTcpDnsServer(testContext, (socket) => {
        socket.once('data', () => socket.end(Buffer.from([0x00])));
    });
    redirectTcpPort53(testContext, mockPort);
    const port = await listenServerForTest(testContext);

    const response = await request(port, '/dns-query-tool/api/query?name=example.com&server=8.8.8.8&tcp=1');
    assert.equal(response.statusCode, 200);
    assert.match(response.body, /応答を受信する前に TCP 接続が切断されました/);
});

test('TCP応答の分割されたプレフィックス・本文と複数フレーム後の不完全データを処理する', async (testContext) => {
    const mockPort = await startMockTcpDnsServer(testContext, (socket) => {
        let buffer = Buffer.alloc(0);
        socket.on('data', (data) => {
            buffer = Buffer.concat([buffer, data]);
            if (buffer.length < 2 || buffer.length < buffer.readUInt16BE(0) + 2) return;

            const query = dnsPacket.streamDecode(buffer);
            const responseFrame = (name, address) => dnsPacket.streamEncode({
                type: 'response',
                id: query.id,
                flags: 0,
                questions: query.questions,
                answers: [{ type: 'A', name, class: 'IN', ttl: 60, data: address }]
            });

            if (query.questions[0].type === 'AXFR') {
                const frames = [
                    responseFrame('first.example.com', '203.0.114.1'),
                    responseFrame('second.example.com', '203.0.114.2'),
                    responseFrame('incomplete.example.com', '203.0.114.3')
                ];
                socket.end(Buffer.concat([...frames.slice(0, 2), frames[2].subarray(0, 5)]));
                return;
            }

            const frame = responseFrame(query.questions[0].name, '203.0.114.10');
            if (query.questions[0].name.startsWith('prefix-split.')) {
                socket.write(frame.subarray(0, 1));
                setTimeout(() => {
                    socket.write(frame.subarray(1, 2 + Math.floor((frame.length - 2) / 2)));
                    setTimeout(() => socket.end(frame.subarray(2 + Math.floor((frame.length - 2) / 2))), 10);
                }, 10);
            } else {
                socket.write(frame.subarray(0, 2));
                setTimeout(() => {
                    socket.write(frame.subarray(2, 2 + Math.floor((frame.length - 2) / 2)));
                    setTimeout(() => socket.end(frame.subarray(2 + Math.floor((frame.length - 2) / 2))), 10);
                }, 10);
            }
        });
    });
    redirectTcpPort53(testContext, mockPort);
    const port = await listenServerForTest(testContext);

    const prefixSplit = await request(port,
        '/dns-query-tool/api/query?name=prefix-split.example.com&server=8.8.8.8&tcp=1');
    assert.match(prefixSplit.body, /203\.0\.114\.10/);

    const bodySplit = await request(port,
        '/dns-query-tool/api/query?name=body-split.example.com&server=8.8.8.8&tcp=1');
    assert.match(bodySplit.body, /203\.0\.114\.10/);

    const multipleFrames = await request(port,
        '/dns-query-tool/api/query?name=example.com&server=8.8.8.8&tcp=1&type=AXFR');
    assert.equal(multipleFrames.body.match(/first\.example\.com/g)?.length, 1);
    assert.equal(multipleFrames.body.match(/second\.example\.com/g)?.length, 1);
    assert.doesNotMatch(multipleFrames.body, /incomplete\.example\.com/);
});

test('TCP応答は1メッセージ受信後に直ちに返し、接続を保持し続ける相手を待たない', async (testContext) => {
    const mockPort = await startMockTcpDnsServer(testContext, (socket) => {
        let buffer = Buffer.alloc(0);
        socket.on('data', (data) => {
            buffer = Buffer.concat([buffer, data]);
            if (buffer.length < 2 || buffer.length < buffer.readUInt16BE(0) + 2) return;
            const query = dnsPacket.streamDecode(buffer);
            socket.write(dnsPacket.streamEncode({
                type: 'response', id: query.id, flags: 0, questions: query.questions,
                answers: [{ type: 'A', name: 'example.com', class: 'IN', ttl: 60, data: '93.184.216.34' }]
            }));
            // 応答後も接続を閉じず、追加データを送り続ける
            socket.write(Buffer.alloc(1024));
        });
    });
    redirectTcpPort53(testContext, mockPort);
    const port = await listenServerForTest(testContext);

    const startedAt = Date.now();
    const response = await request(port, '/dns-query-tool/api/query?name=example.com&server=8.8.8.8&tcp=1');
    assert.ok(Date.now() - startedAt < 3000);
    assert.match(response.body, /93\.184\.216\.34/);
    assert.equal(response.body.match(/93\.184\.216\.34/g).length >= 1, true);
});

test('AXFR応答の各メッセージは1回ずつ表示し、上限サイズを超えたら受信を打ち切る', async (testContext) => {
    let mode = 'normal';
    const mockPort = await startMockTcpDnsServer(testContext, (socket) => {
        let buffer = Buffer.alloc(0);
        socket.on('data', (data) => {
            buffer = Buffer.concat([buffer, data]);
            if (buffer.length < 2 || buffer.length < buffer.readUInt16BE(0) + 2) return;
            const query = dnsPacket.streamDecode(buffer);
            const soa = { type: 'SOA', name: 'example.com', class: 'IN', ttl: 60, data: { mname: 'ns.example.com', rname: 'admin.example.com', serial: 1, refresh: 1, retry: 1, expire: 1, minimum: 1 } };
            const message = (answers) => dnsPacket.streamEncode({ type: 'response', id: query.id, flags: 0, questions: query.questions, answers });
            if (mode === 'normal') {
                socket.write(Buffer.concat([
                    message([soa, { type: 'A', name: 'first.example.com', class: 'IN', ttl: 60, data: '203.0.114.1' }]),
                    message([{ type: 'A', name: 'second.example.com', class: 'IN', ttl: 60, data: '203.0.114.2' }, soa])
                ]));
                socket.end();
                return;
            }
            const filler = message([soa, { type: 'TXT', name: 'big.example.com', class: 'IN', ttl: 60, data: Array.from({ length: 230 }, () => 'x'.repeat(250)) }]);
            const sendForever = () => {
                if (socket.destroyed) return;
                if (socket.write(filler)) setImmediate(sendForever); else socket.once('drain', sendForever);
            };
            sendForever();
        });
    });
    redirectTcpPort53(testContext, mockPort);
    const port = await listenServerForTest(testContext);

    const response = await request(port, '/dns-query-tool/api/query?name=example.com&server=8.8.8.8&tcp=1&type=AXFR');
    assert.equal(response.body.match(/first\.example\.com/g).length, 1);
    assert.equal(response.body.match(/second\.example\.com/g).length, 1);

    mode = 'flood';
    const flooded = await request(port, '/dns-query-tool/api/query?name=example.com&server=8.8.8.8&tcp=1&type=AXFR');
    assert.match(flooded.body, /応答サイズが上限 \(4194304 バイト\) を超えたため、受信を打ち切りました/);
});

test('DNSサーバー名はホスト名として不正な文字を含む場合に拒否する', () => {
    for (const value of ['<script>.example', 'a b.example', 'evil.example\r\nX-Injected: 1', 'a&b.example', '-bad.example', 'a..example', '.']) {
        assert.equal(isInvalidDnsServer(value), true, JSON.stringify(value));
    }
    for (const value of ['dns.google', 'dns.google.', '_dns.resolver.arpa', 'a-1.example']) {
        assert.equal(isInvalidDnsServer(value), false, value);
    }
});

test('入力値はHTMLエスケープ前の値で問い合わせに使い、出力時に1回だけエスケープする', async (testContext) => {
    const https = require('node:https');
    const originalRequest = https.request;
    const requestedPaths = [];
    https.request = (options, callback) => {
        requestedPaths.push(options.path);
        const request = new EventEmitter();
        let body = Buffer.alloc(0);
        request.write = (chunk) => { body = Buffer.concat([body, chunk]); };
        request.end = () => {
            const query = dnsPacket.decode(body);
            const response = new EventEmitter();
            response.statusCode = 200;
            callback(response);
            response.emit('data', dnsPacket.encode({
                type: 'response', id: query.id, flags: 0, questions: query.questions,
                answers: [{ type: 'A', name: query.questions[0].name, class: 'IN', ttl: 60, data: '93.184.216.34' }]
            }));
            response.emit('end');
        };
        request.destroy = () => {};
        return request;
    };
    testContext.after(() => { https.request = originalRequest; });
    const port = await listenServerForTest(testContext);

    const query = new URLSearchParams({ name: 'a&b.example', server: '8.8.8.8', https: '1', httpspath: '/dns-query?x=1&y=2' });
    const response = await request(port, `/dns-query-tool/api/query?${query}`);
    assert.deepEqual(requestedPaths, ['/dns-query?x=1&y=2']);
    assert.match(response.body, /<code>a&amp;b\.example<\/code>/);
    assert.doesNotMatch(response.body, /&amp;amp;/);
    assert.match(response.body, /httpspath=%2Fdns-query%3Fx%3D1%26y%3D2/);

    const [invalidClass, invalidUdpSize, invalidServer] = await Promise.all([
        request(port, '/dns-query-tool/api/query?name=example.com&class=%3Cimg%20src%3Dx%3E'),
        request(port, '/dns-query-tool/api/query?name=example.com&udpsize=%3Cimg%20src%3Dx%3E'),
        request(port, '/dns-query-tool/api/query?name=example.com&server=%3Cimg%20src%3Dx%3E')
    ]);
    for (const { body } of [invalidClass, invalidUdpSize, invalidServer]) {
        assert.match(body, /&lt;IMG SRC=X&gt;|&lt;img src=x&gt;/);
        assert.doesNotMatch(body, /<img/i);
    }
});

test('DNSサーバー名の解決は問い合わせ回数の上限で打ち切る', async () => {
    let queryCount = 0;
    const glue = Array.from({ length: 200 }, (_, i) => ({ type: 'A', name: 'ns.slow.example', data: `203.0.114.${i % 250 + 1}` }));
    const mockQueryServer = async (serverAddress) => {
        queryCount++;
        if (serverAddress === '198.41.0.4') {
            return {
                answers: [],
                authorities: [{ type: 'NS', name: 'slow.example', data: 'ns.slow.example' }],
                additionals: glue
            };
        }
        throw new Error(`${serverAddress} から UDP 応答がありませんでした。`);
    };

    await assert.rejects(
        resolveDnsServerAddress('target.slow.example', false, 0, mockQueryServer),
        /DNSサーバー名の解決が上限 \(10 秒・問い合わせ 50 回\) を超えたため中止しました/
    );
    assert.equal(queryCount, 50);
});

test('DNSサーバー名の解決は全体の時間上限で打ち切る', async () => {
    const neverRespond = () => new Promise(() => {});
    const startedAt = Date.now();
    await assert.rejects(
        resolveDnsServerAddress('target.slow.example', false, 0, neverRespond, false, createResolutionBudget(100, 50)),
        /DNSサーバー名の解決が上限 \(0\.1 秒・問い合わせ 50 回\) を超えたため中止しました/
    );
    assert.ok(Date.now() - startedAt < 1000);
});
