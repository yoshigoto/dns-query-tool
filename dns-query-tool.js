const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');
const dgram = require('dgram');
const dnsPacket = require('dns-packet');	// https://github.com/mafintosh/dns-packet
const dnsTypes = require('dns-packet/types');

const RCODE_NAMES = {
    0: 'NOERROR',
    1: 'FORMERR',
    2: 'SERVFAIL',
    3: 'NXDOMAIN',
    4: 'NOTIMP',
    5: 'REFUSED',
    6: 'YXDOMAIN',
    7: 'YXRRSET',
    8: 'NXRRSET',
    9: 'NOTAUTH',
    10: 'NOTZONE',
    16: 'BADVERS',
    17: 'BADKEY',
    18: 'BADTIME',
    19: 'BADMODE',
    20: 'BADNAME',
    21: 'BADALG',
    22: 'BADTRUNC',
    23: 'BADCOOKIE'
};

const EXTENDED_RCODE_NAMES = {
    16: 'BADVERS / BADSIG',
    17: 'BADKEY',
    18: 'BADTIME',
    19: 'BADMODE',
    20: 'BADNAME',
    21: 'BADALG',
    22: 'BADTRUNC',
    23: 'BADCOOKIE'
};

const OPCODE_NAMES = {
    0: 'QUERY',
    1: 'IQUERY',
    2: 'STATUS',
    4: 'NOTIFY',
    5: 'UPDATE'
};

const getOpcodeName = (response) => {
    const opcode = response.opcode;
    if (typeof opcode === 'string') return opcode.toUpperCase();
    if (Number.isInteger(opcode)) return OPCODE_NAMES[opcode] || `OPCODE_${opcode}`;
    return 'QUERY';
};

const getRcodeNumber = (rcode) => {
    if (Number.isInteger(rcode)) return rcode;
    const entry = Object.entries(RCODE_NAMES).find(([, name]) => name === rcode);
    if (entry) return Number(entry[0]);
    const match = /^RCODE_(\d+)$/.exec(String(rcode));
    return match ? Number(match[1]) : 0;
};

const getResponseRcodeNumber = (response) => {
    const baseRcode = getRcodeNumber(response.rcode);
    const optRecord = response.additionals?.find((record) => record.type === 'OPT' && record.name === '.');
    const extendedRcode = Number.isInteger(optRecord?.extendedRcode) ? optRecord.extendedRcode : 0;
    return (extendedRcode << 4) | baseRcode;
};

const getResponseRcode = (response) => {
    const rcodeNumber = getResponseRcodeNumber(response);
    return RCODE_NAMES[rcodeNumber] || `RCODE_${rcodeNumber}`;
};

const checkOptRdataAnomalies = (buf) => {
    if (!Buffer.isBuffer(buf) || buf.length < 12) {
        return [];
    }
    const parseDomainName = (b, offset) => {
        let curr = offset;
        let jumped = false;
        let count = 0;
        while (curr < b.length) {
            if (count++ > 200) break;
            const len = b[curr];
            if (len === 0) {
                if (!jumped) offset = curr + 1;
                break;
            }
            if ((len & 0xc0) === 0xc0) {
                if (!jumped) offset = curr + 2;
                break;
            }
            curr += 1 + len;
        }
        return offset;
    };

    let offset = 12;
    const qdcount = buf.readUInt16BE(4);
    const ancount = buf.readUInt16BE(6);
    const nscount = buf.readUInt16BE(8);
    const arcount = buf.readUInt16BE(10);

    for (let i = 0; i < qdcount; i++) {
        if (offset >= buf.length) break;
        offset = parseDomainName(buf, offset);
        offset += 4;
    }

    const totalRr = ancount + nscount + arcount;
    const errors = [];

    for (let i = 0; i < totalRr; i++) {
        if (offset >= buf.length) break;
        offset = parseDomainName(buf, offset);
        if (offset + 10 > buf.length) break;
        const type = buf.readUInt16BE(offset);
        const rdlength = buf.readUInt16BE(offset + 8);
        offset += 10;

        if (type === 41) {
            const rdataStart = offset;
            const actualRdataLen = Math.min(rdlength, buf.length - rdataStart);
            let optOffset = 0;
            while (optOffset < actualRdataLen) {
                if (optOffset + 4 > actualRdataLen) {
                    errors.push(`EDNS Option ヘッダー (4バイト) に対し、RDATA の残りが ${actualRdataLen - optOffset} バイトしかありません`);
                    break;
                }
                const optCode = buf.readUInt16BE(rdataStart + optOffset);
                const optLen = buf.readUInt16BE(rdataStart + optOffset + 2);
                const remainingData = actualRdataLen - (optOffset + 4);
                if (optLen > remainingData) {
                    errors.push(`EDNS Option (コード ${optCode}) の OPTION-LENGTH (${optLen} バイト) が RDATA の残り長さ (${remainingData} バイト) を超過しています`);
                    break;
                }
                optOffset += 4 + optLen;
            }
        }
        offset += rdlength;
    }
    return errors;
};

const getOptPseudoSectionStatusHtml = (response, rawBuf = null) => {
    const buf = rawBuf || (response && response._rawBuf);
    const optRecords = (response.additionals || []).filter(record => record.type === 'OPT' && record.name === '.');

    let malformed = false;
    let reasons = [];

    if (buf) {
        const rawErrors = checkOptRdataAnomalies(buf);
        if (rawErrors.length > 0) {
            malformed = true;
            reasons.push(...rawErrors);
        }
    }

    if (optRecords.length === 0 && !malformed) {
        return '';
    }

    for (const record of optRecords) {
        const options = Array.isArray(record.options) ? record.options : [];
        if (options.length === 0) {
            continue;
        }

        for (const option of options) {
            if (!option || typeof option !== 'object') {
                malformed = true;
                reasons.push('OPT レコードの OPTION が不正です');
                continue;
            }

            const data = option.data;
            if (typeof option.code !== 'number') {
                malformed = true;
                reasons.push('OPTION コードが不正です');
                continue;
            }

            if (option.code === 15 && Buffer.isBuffer(data) && data.length >= 2) {
                const infoCode = data.readUInt16BE(0);
                if (infoCode === 22) {
                    malformed = true;
                    reasons.push('EDE (OPTION 15) が BADTRUNC を示しており、DNSメッセージの本来の姿から乖離しています');
                }
            }
        }
    }

    if (!malformed) {
        return '';
    }

    const uniqueReasons = [...new Set(reasons)].filter(Boolean);
    const reasonText = uniqueReasons.length > 0 ? uniqueReasons.join(' / ') : 'OPT 疑似セクションの内部データが不完全です';
    return `<p style="color: red; margin: 0;">OPT疑似セクションとして破損しています: <code>${escapeHtml(reasonText)}</code></p>`;
};

const getNegativeCacheHtml = (response) => {
    if (response.authorities && response.authorities.length > 0) {
        const soaRecord = response.authorities.find(at => at.type === 'SOA');
        if (soaRecord && soaRecord.data && typeof soaRecord.data.minimum === 'number') {
            const soaTtl = parseInt(soaRecord.ttl, 10);
            const minimum = parseInt(soaRecord.data.minimum, 10);
            const negTtl = Math.min(soaTtl, minimum);
            return `<p style="color: #555555; margin: 0;">※RFC 2308 (Negative Caching): ネガティブキャッシュ有効期間 (TTL) は <code>${negTtl}秒</code> (MINIMUM: ${minimum}秒, SOA TTL: ${soaTtl}秒 の最小値) です。</p>`;
        }
    }
    return '';
};

// RFC 8914 に定義されている INFO-CODE のマッピング表
const EDE_ERRORS = {
    0: 'Other Error',
    1: 'Unsupported DNSKEY Algorithm',
    2: 'Unsupported DS Digest Type',
    3: 'Stale Answer',
    4: 'Forged Answer',
    5: 'DNSSEC Indeterminate',
    6: 'DNSSEC Bogus',
    7: 'Signature Expired',
    8: 'Signature Not Yet Valid',
    9: 'DNSKEY Missing',
    10: 'RRSIGs Missing',
    11: 'No Zone Key Bit Set',
    12: 'NSEC Missing',
    13: 'Cached Error',
    14: 'Not Ready',
    15: 'Blocked',
    16: 'Censored',
    17: 'Filtered',
    18: 'Prohibited',
    19: 'Stale NXDOMAIN Answer',
    20: 'Not Authoritative',
    21: 'Not Supported',
    22: 'No Reachable Authority',
    23: 'Network Error',
    24: 'Invalid Data',
    25: 'Signature Expired Before Valid',
    26: 'Too Early',
    27: 'Unsupported NSEC3 Iterations Value',
    28: 'Unable to conform to policy',
    29: 'Synthesized',
    30: 'Invalid Query Type',
    31: 'Rate Limited',
    32: 'Over Quota',
    33: 'Negative Trust Anchor',
    34: 'New Delegation Only',
    35: 'Blocked by Upstream DNS Server'
};

const getEdeErrorName = (infoCode) => {
    const errorName = EDE_ERRORS[infoCode] || 'Unknown Error';
    if (!Object.hasOwn(EDE_ERRORS, infoCode)) {
        return escapeHtml(errorName);
    }
    const errorUrl = 'https://www.iana.org/assignments/dns-parameters#extended-dns-error-codes';
    return `<a href="${errorUrl}" target="_blank" rel="noopener noreferrer">${escapeHtml(errorName)}</a>`;
};

// HTMLエスケープ処理 (XSSインジェクション対策)
const escapeHtml = (str) => {
    if (str === null || typeof str === 'undefined') return '';
    return String(str).replace(/[&<>"']/g, (match) => {
        const escapes = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return escapes[match];
    });
};

const addLinkToDisplayData = (origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
    sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, displayData, button=false, extraQuery='') => {
    const query = new URLSearchParams({
        server: dnsServer,
        name: domainName,
        type: queryType,
        rd: recursionDesired ? '1' : '0',
        cd: checkingDisabled ? '1' : '0',
        tcp: sendTcp ? '1' : '0',
        ipv6: sendIpv6 ? '1' : '0',
        edns0: edns0Enable ? '1' : '0',
        dnssec: dnssecOk ? '1' : '0',
        udpsize: udpSize,
        nsid: nsidEnable ? '1' : '0',
        mqtype: mQType,
        qmini: qnameMinimisation ? '1' : '0',
        qposi: qnamePosition,
        qtype: qnameType
    });
    if (extraQuery === '&reset=1') {
        query.set('reset', '1');
    }

    let html = '<a ';
    if (button) {
        html += 'class="a-button" ';
    }
    html += `data-dns-query-link href="${escapeHtml(`.${pathname}?${query.toString()}`)}">${escapeHtml(displayData)}</a>`;
    return html;
};

const replaceUnknownRrTypeToKnown = (type) => {
    switch (type) {
        case 'UNKNOWN_63': return 'ZONEMD';
        case 'UNKNOWN_64': return 'SVCB';
        case 'UNKNOWN_65': return 'HTTPS';
    }
    return type;
};

const replaceKnownToUnknownRrType = (type) => {
    switch (type) {
        case 'ZONEMD': return 'UNKNOWN_63';
        case 'SVCB': return 'UNKNOWN_64';
        case 'HTTPS': return 'UNKNOWN_65';
    }
    return type;
};

const replaceUnknownRrTypeList = (rrtypes) => {
    return rrtypes.map(item => {
        return replaceUnknownRrTypeToKnown(item);
    });
};

const decodeResourceRecord = (type, msg) => {
    let displayData = '';
    if (type === 'TXT') {
        // TXTレコードはBufferまたは'text'の配列か、Bufferか'text'で返ってくる
        if (Array.isArray(msg)) {
            displayData = msg.map(buf => Buffer.isBuffer(buf) ? buf.toString('utf8') : buf).join('');
        } else if (Buffer.isBuffer(msg)) {
            displayData = msg.toString('utf8');
        } else {
            displayData = msg;
        }
    } else if (type === 'CAA') {
        displayData = `flags: ${msg.flags}, tag: ${msg.tag}, value: ${msg.value}, issuerCritical: ${msg.issuerCritical}`;
    } else if (type === 'DNSKEY') {
        // dns-packet では DNSKEYリソースレコードの Protocol は 3 固定
        displayData = `flags: ${msg.flags}, protocol: 3, algorithm: ${msg.algorithm}, key: ${msg.key.toString('base64')}`;
    } else if (type === 'DS') {
        displayData = `keyTag: ${msg.keyTag}, algorithm: ${msg.algorithm}, digestType: ${msg.digestType}, digest: ${msg.digest.toString('hex').toLowerCase()}`;
    } else if (type === 'NSEC') {
        const rrtypes = replaceUnknownRrTypeList(msg.rrtypes);
        displayData = `nextDomain: ${msg.nextDomain}, rrtypes: ${rrtypes.join(' ')}`;
    } else if (type === 'NSEC3') {
        const rrtypes = replaceUnknownRrTypeList(msg.rrtypes);
        displayData = `algorithm: ${msg.algorithm}, flags: ${msg.flags}, iterations: ${msg.iterations}, salt: ${msg.salt.toString('base64')}, `
        displayData += `nextDomain: ${msg.nextDomain.toString('base64')}, rrtypes: ${rrtypes.join(' ')}`;
    } else if (type === 'RRSIG') {
        const expiration = new Date(msg.expiration * 1000);
        const inception = new Date(msg.inception * 1000);
        displayData = `typeCovered: ${msg.typeCovered}, algorithm: ${msg.algorithm}, labels: ${msg.labels}, originalTTL: ${msg.originalTTL}, expiration: ${expiration.toISOString()}, `;
        displayData += `inception: ${inception.toISOString()}, keyTag: ${msg.keyTag}, signersName: ${msg.signersName}, signature: ${msg.signature.toString('base64')}`;
    } else if (type === 'SOA') {
        displayData = `mname: ${msg.mname}, rname: ${msg.rname}, serial: ${msg.serial}, refresh: ${msg.refresh}, retry: ${msg.retry}, expire: ${msg.expire}, minimum: ${msg.minimum}`;
    } else if (type === 'SRV') {
        displayData = `priority: ${msg.priority}, weight: ${msg.weight}, port: ${msg.port}, target: ${msg.target}`;
    } else if (type === 'TLSA') {
        const usageNames = { 0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE' };
        const selectorNames = { 0: 'Cert', 1: 'SPKI' };
        const matchingTypeNames = { 0: 'Full', 1: 'SHA-256', 2: 'SHA-512' };
        const usageStr = usageNames[msg.usage] !== undefined ? usageNames[msg.usage] : msg.usage;
        const selectorStr = selectorNames[msg.selector] !== undefined ? selectorNames[msg.selector] : msg.selector;
        const matchingTypeStr = matchingTypeNames[msg.matchingType] !== undefined ? matchingTypeNames[msg.matchingType] : msg.matchingType;
        const certHex = Buffer.isBuffer(msg.certificate) ? msg.certificate.toString('hex') : (msg.certificate || (Buffer.isBuffer(msg.data) ? msg.data.toString('hex') : msg.data || ''));
        displayData = `usage: ${usageStr}, selector: ${selectorStr}, matchingType: ${matchingTypeStr}, certificate: ${certHex}`;
    } else if (type === 'SSHFP') {
        const algoNames = { 1: 'RSA', 2: 'DSA', 3: 'ECDSA', 4: 'Ed25519' };
        const fpTypeNames = { 1: 'SHA-1', 2: 'SHA-256' };
        const algo = algoNames[msg.algorithm] !== undefined ? algoNames[msg.algorithm] : msg.algorithm;
        const fpTypeVal = msg.fpType !== undefined ? msg.fpType : msg.type;
        const fpTypeStr = fpTypeNames[fpTypeVal] !== undefined ? fpTypeNames[fpTypeVal] : fpTypeVal;
        const fpHex = Buffer.isBuffer(msg.fingerprint) ? msg.fingerprint.toString('hex') : (msg.fingerprint || (Buffer.isBuffer(msg.data) ? msg.data.toString('hex') : msg.data || ''));
        displayData = `algorithm: ${algo}, fpType: ${fpTypeStr}, fingerprint: ${fpHex}`;
    } else if (type === 'NAPTR') {
        displayData = `order: ${msg.order}, preference: ${msg.preference}, flags: ${msg.flags}, services: ${msg.services}, regexp: ${msg.regexp}, replacement: ${msg.replacement}`;
    } else if (replaceUnknownRrTypeToKnown(type) === 'SVCB' || replaceUnknownRrTypeToKnown(type) === 'HTTPS' ) {
        let offset = 0;
        const priority = msg.readUInt16BE(offset);
        offset += 2;

        let startOffset = offset;
        const labels = [];
        while (true) {
            const len = msg[startOffset];
            startOffset += 1;
            if (len === 0) break; // ヌルバイトで終了
            const label = msg.toString('utf8', startOffset, startOffset + len);
            labels.push(label);
            startOffset += len;
        }
        const domainName = labels.length === 0 ? '.' : labels.join('.') + '.';

        offset += startOffset - offset;
        let paramString = '';
        while (offset < msg.length) {
            const paramKey = msg.readUInt16BE(offset);
            offset += 2;
            const paramLen = msg.readUInt16BE(offset);
            offset += 2;
            const paramValBuffer = msg.subarray(offset, offset + paramLen);
            offset += paramLen;
            switch (paramKey) {
                case 1: // Additional supported protocols (文字列のリストであり各文字列の前に 1バイトの長さ)
                    const alpnList = [];
                    let idx = 0;
                    while (idx < paramValBuffer.length) {
                        const len = paramValBuffer[idx];
                        idx += 1;
                        alpnList.push(paramValBuffer.toString('utf8', idx, idx + len));
                        idx += len;
                    }
                    paramString += `alpn=${alpnList}, `;
                    break;
                case 3: // Port for alternative endpoint (2バイトの整数)
                    paramString += `port=${paramValBuffer.readUInt16BE(0)}, `;
                    break;
                case 4: // IPv4 address hints (4バイトの整数のリスト)
                    let ipv4List = [];
                    for (let i = 0; i < paramValBuffer.length; i += 4) {
                        const num = paramValBuffer.readUInt32BE(i); 
                        const ipv4str = [
                            (num >>> 24) & 255,
                            (num >>> 16) & 255,
                            (num >>> 8) & 255,
                            num & 255
                        ].join('.');
                        ipv4List.push(ipv4str);
                    }
                    paramString += `ipv4hint=${ipv4List}, `;
                    break;
                case 5: // TLS Encrypted ClientHello Config
                    paramString += `ech=${paramValBuffer.toString('hex')}, `;
                    break;
                case 6: // IPv6 address hints (16バイトの整数のリスト)
                    let ipv6List = [];
                    for (let i = 0; i < paramValBuffer.length; i += 16) {
                        const hex = paramValBuffer.toString('hex', i);
                        const blocks = [];
                        for (let j = 0; j < 16; j += 2) {
                            blocks.push(hex.slice(j * 2, j * 2 + 4));
                        }
                        const ipv6str = compressIPv6(blocks.join(':'));
                        ipv6List.push(ipv6str);
                    }
                    paramString += `ipv6hint=${ipv6List}, `;
                    break;
                case 7: // DNS over HTTPS path template (文字列)
                    paramString += `dohpath=${paramValBuffer.toString('utf8')}, `;
                    break;
                default: // その他は Hexで表示
                    paramString += `other(${paramKey})=${paramValBuffer.toString('hex')}, `;
            }
        }
        if (paramString.length > 2) {
            paramString = paramString.slice(0, -2);
        }
        displayData = `priority: ${priority}, targetName: ${domainName}, params: [ ${paramString} ]`;
    }
    return escapeHtml(displayData);
}

const buildWarningSectionHtml = (warningHtml) => {
    if (!warningHtml || !String(warningHtml).trim()) {
        return '';
    }
    return `<p><strong>WARNING SECTION:</strong></p><div style="border-left: 4px solid #ff8c00; padding-left: 10px; color: #8a4b00;">${warningHtml}</div>`;
};

const wrapSectionNoticeHtml = (noticeHtml) => {
    if (!noticeHtml || !String(noticeHtml).trim()) {
        return '';
    }
    return `<div style="border-left: 4px solid #ff8c00; padding-left: 10px; color: #8a4b00;">${noticeHtml}</div>`;
};

const makeHtmlFromDns = (response, bytesRead, origin, pathname, dnsServer, dnsServerIp, domainName, queryType, queryId, recursionDesired, checkingDisabled,
    sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, packetWarningHtml = '', rawBuf = null) => {
    let html = '';
    let questionName = '';
    let questionType = '';

    html += '<div class="result"><h3>--- DNSレスポンス解析結果 ---</h3>';
    html += '<p><strong>基本情報:</strong></p>';
    html += '<ul>';
    html += `<li>プロトコル: <code>${sendTcp ? 'TCP' : 'UDP'}</code> / 応答サイズ: <code>${bytesRead}</code>byte</li>`;
    html += `<li>応答したサーバー: <code>${escapeHtml(dnsServer)} (${escapeHtml(dnsServerIp)})</code></li>`;
    html += `<li>クエリーID: <code>${queryId} (${response.id === queryId ? '一致' : '<span style="color: red;">不一致</span>'})</code></li>`;
    const opcodeStr = getOpcodeName(response);
    html += `<li>Opcode: <code>${escapeHtml(opcodeStr)}</code>${opcodeStr !== 'QUERY' ? ' <span style="color: orange;">(QUERY 以外の Opcode です)</span>' : ''}</li>`;
    if (response.type === 'query') {
        html += `<li style="color: orange;">QR: <code>0 (Query)</code> - 応答メッセージですが QR ビットが 0 (Query) になっています</li>`;
    }

    if (response.questions && response.questions.length > 0) {
        response.questions.forEach((question) => {
            questionName = question.name;
            questionType = replaceUnknownRrTypeToKnown(question.type);
            html += `<li>クエリー名: <code>${escapeHtml(questionName)}</code>${qnameMinimisation ? `<span style="font-size: 90%;"> (ラベル位置: <code>${escapeHtml(qnamePosition)}</code>)</span>` : ''}</li>`;
            html += `<li>クエリータイプ: <code>${escapeHtml(questionType)}</code></li>`;
        });
    } else {
        html += `<li style="color: red;">クエリー名: <code>${escapeHtml(domainName)}</code> - 応答に QUESTION SECTION が存在しません</li>`;
        html += `<li style="color: red;">クエリータイプ: <code>${escapeHtml(queryType)}</code> - 応答に QUESTION SECTION が存在しません</li>`;
    }

    // 応答コード (rcode) の取得。Extended RCODE は OPT の TTL 上位オクテットから合成する。
    const rcode = getResponseRcode(response);
    html += `<li>応答ステータス (rcode): <code>${escapeHtml(rcode)}</code></li>`;

    // フラグの取得
    let flagString = '';
    if (response.flags & dnsPacket.RECURSION_DESIRED) {
        flagString += '<span title="Recursion Desired">RD</span> ';
    }
    if (response.flags & dnsPacket.RECURSION_AVAILABLE) {
        flagString += '<span title="Recursion Available">RA</span> ';
    }
    if (response.flags & dnsPacket.TRUNCATED_RESPONSE) {
        flagString += '<span title="Truncated Response">TC</span> ';
    }
    if (response.flags & dnsPacket.AUTHORITATIVE_ANSWER) {
        flagString += '<span title="Authoritative Answer">AA</span> ';
    }
    if (response.flags & dnsPacket.AUTHENTIC_DATA) {
        flagString += '<span title="Authentic Data">AD</span> ';
    }
    if (response.flags & dnsPacket.CHECKING_DISABLED) {
        flagString += '<span title="Checking Disabled">CD</span> ';
    }
    if (response.flags & 0x0040) {
        flagString += '<span title="Reserved">Z</span> ';
    }
    if (flagString !== '') {
        flagString = flagString.slice(0, -1);
    }
    html += `<li>フラグ (flags): <code>${flagString}</code></li>`;
    if (!sendTcp && (response.flags & dnsPacket.TRUNCATED_RESPONSE)) {
        const displayData = addLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
            true, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'こちら');
        html += `<ul><li style="color: blue; margin: 0;">TCフラグが立っているので TCPでの再確認を推奨します。${displayData} をクリックしてみてください。</li></ul>`;
    }
    html += '</ul>';

    // Answerセクションについて応答コードに応じた条件分岐
    html += `<p><strong style="color: ${response.answers.length > 0 ? '#dd0000' : '#0000dd'};">ANSWER SECTION (${response.answers.length} 個) :</strong></p>`;
    let answerNoticeHtml = '';
    if (rcode === 'SERVFAIL') {
        answerNoticeHtml += `<p style="color: red; margin: 0;">SERVFAIL: 応答したサーバー <code>${escapeHtml(dnsServer)}</code> で一時的なエラーが発生したか、設定に問題があります。</p>`;
        if (recursionDesired && !checkingDisabled) {
            const displayData = addLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, true,
                sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'こちら');
            answerNoticeHtml += `<p style="color: orange; margin: 0;">※DNSSEC検証に失敗した可能性があります。${displayData} をクリックしてみてください。</p>`;
        }
    } else if (rcode === 'REFUSED') {
        answerNoticeHtml += `<p style="color: red; margin: 0;">REFUSED: 応答したサーバー <code>${escapeHtml(dnsServer)}</code> のポリシーによりクエリーが拒否されました。</p>`;
    } else if (rcode === 'FORMERR') {
        answerNoticeHtml += `<p style="color: red; margin: 0;">FORMERR: DNSメッセージの形式に問題があると、応答したサーバー <code>${escapeHtml(dnsServer)}</code> が判断しました。</p>`;
    } else if (rcode === 'NXDOMAIN') {
        answerNoticeHtml += `<p style="color: red; margin: 0;">NXDOMAIN: 問い合わせたドメイン名 <code>${escapeHtml(questionName)}</code> は存在しませんでした。</p>`;
        const negHtml = getNegativeCacheHtml(response);
        if (negHtml) {
            answerNoticeHtml += negHtml;
        }
        if (qnameMinimisation) {
            if (qnamePosition > 0) {
                qnamePosition--;
                const displayData = addLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
                    sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'こちら');
                if (response.authorities && response.authorities.length > 0) {
                    const soaRr = response.authorities.find(at => at.type === 'SOA');
                    if (soaRr) {
                        if (soaRr.name !== questionName) {
                            answerNoticeHtml += `<p style="color: red; margin: 0;">※応答したサーバー <code>${escapeHtml(dnsServer)}</code> が RFC 8020 に対応していないようです。</p>`;
                            answerNoticeHtml += `<p style="color: orange; margin: 0;">※Empty Non-Terminal かもしれません。${displayData} をクリックしてみてください。</p>`;
                        } else {
                            answerNoticeHtml += `<p style="color: orange; margin: 0;">※QNAME minimisation が有効になっていますので ${displayData} をクリックしてみてください。</p>`;
                        }
                    }
                }
            }
        }
    } else if (rcode === 'NOERROR') {
        // 正常応答の場合
        if (!response.answers || response.answers.length === 0) {
            // rcodeはNOERRORだが、該当レコードが空 (例: AAAAを引いたがAレコードしか持っていない場合など)
            answerNoticeHtml += `<p style="color: green; margin: 0;">NOERROR: 指定されたタイプ <code>${escapeHtml(questionType)}</code> に対するレコード (回答) は見つかりませんでした。</p>`;
            const negHtml = getNegativeCacheHtml(response);
            if (negHtml) {
                answerNoticeHtml += negHtml;
            }
            if (qnameMinimisation) {
                if (qnamePosition > 0) {
                    qnamePosition--;
                    const displayData = addLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'こちら');
                    if (response.authorities && response.authorities.length > 0) {
                        const soaRr = response.authorities.find(at => at.type === 'SOA');
                        if (soaRr) {
                            if (soaRr.name !== questionName) {
                                answerNoticeHtml += `<p style="color: orange; margin: 0;">※Empty Non-Terminal かもしれません。${displayData} をクリックしてみてください。</p>`;
                            } else {
                                answerNoticeHtml += `<p style="color: orange; margin: 0;">※QNAME minimisation が有効になっていますので ${displayData} をクリックしてみてください。</p>`;
                            }
                        }
                    }
                }
            }
        }
    } else {
        answerNoticeHtml += `<p style="color: gray; margin: 0;">その他の応答コード: ${escapeHtml(rcode)}</p>`;
    }
    if (answerNoticeHtml) {
        html += wrapSectionNoticeHtml(answerNoticeHtml);
    }
    if (response.answers && response.answers.length > 0) {
        html += '<ul>';
        if (qnameMinimisation && qnamePosition > 0) {
            qnamePosition--;
        }
        response.answers.forEach((answer) => {
            let displayData = decodeResourceRecord(answer.type, answer.data);
            if (displayData.length === 0) {
                if (answer.type === 'CNAME') {
                    // CNAMEレコードはデータを検索対象ドメイン名として扱い、後続の検索ができるようにする
                    displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, queryType, false, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                } else if (answer.type === 'NS') {
                    if (qnameMinimisation) {
                        if (answer.name === domainName) {
                            displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'A', false, checkingDisabled,
                                sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                        } else {
                            displayData = addLinkToDisplayData(origin, pathname, answer.data, domainName, queryType, recursionDesired, checkingDisabled,
                                sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, answer.data);
                        }
                    } else {
                        // NSが、自身の IPアドレスの情報を持っていない場合がある (例： ns014-fc9tjt3ao0p42dr4.f.d-53.info)
                        displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'A', false, checkingDisabled,
                            sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                    }
                } else if (answer.type === 'MX') {
                    displayData = `preference: ${answer.data.preference}, exchange: `;
                    displayData += addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data.exchange, 'A', false, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data.exchange);
                } else if (answer.type === 'PTR') {
                    displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'A', false, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, false, 255, qnameType, answer.data);
                } else if (answer.type === 'A' || answer.type === 'AAAA') {
                    displayData = addLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'PTR-x', false, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, false, 255, qnameType, answer.data);
                } else if (typeof answer.data === 'object') {
                    // オブジェクト構造を持つデータ用
                    displayData = escapeHtml(JSON.stringify(answer.data));
                } else {
                    // Aレコード (文字列のIPアドレス) など通常データ用
                    displayData = escapeHtml(answer.data);
                }
            }
            const answerType = replaceUnknownRrTypeToKnown(escapeHtml(answer.type));
            html += `<li><span style="color: #dd0000;"><strong>[${answerType}]</strong> ${escapeHtml(answer.name)}</span> &rarr; <code>${displayData}</code> (TTL: ${parseInt(answer.ttl, 10)}秒)</li>`;
        });
        html += '</ul>';
    }

    // Authorityが返ってきた場合
    html += `<p><strong>AUTHORITY SECTION (${response.authorities.length} 個) :</strong></p>`;
    if (response.authorities && response.authorities.length > 0) {
        html += '<ul>';
        response.authorities.forEach((authorities) => {
            let displayData = decodeResourceRecord(authorities.type, authorities.data);
            if (displayData.length === 0) {
                if (authorities.type === 'NS') {
                    displayData = addLinkToDisplayData(origin, pathname, authorities.data, domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, authorities.data);
                } else if (typeof authorities.data === 'object') {
                    // オブジェクト構造を持つデータ用
                    displayData = escapeHtml(JSON.stringify(authorities.data));
                } else {
                    // Aレコード (文字列のIPアドレス) など通常データ用
                    displayData = escapeHtml(authorities.data);
                }
            }
            const authoritiesType = replaceUnknownRrTypeToKnown(escapeHtml(authorities.type));
            html += `<li><strong>[${authoritiesType}]</strong> ${escapeHtml(authorities.name)} &rarr; <code>${displayData}</code> (TTL: ${parseInt(authorities.ttl, 10)}秒)</li>`;
        });
        html += '</ul>';
    } else {
        html += wrapSectionNoticeHtml('<p style="color: orange; margin: 0;">権威サーバーの情報は見つかりませんでした。</p>');
    }

    // Additionalが返ってきた場合
    html += `<p><strong>ADDITIONAL SECTION (${response.additionals.length} 個) :</strong></p>`;
    if (response.additionals && response.additionals.length > 0) {
        let optPseudo = '';
        let optError = '';
        html += '<ul>';
        response.additionals.forEach((additionals) => {
            let displayData = decodeResourceRecord(additionals.type, additionals.data);
            if (displayData.length === 0) {
                if (additionals.type === 'A' || additionals.type === 'AAAA') {
                    displayData = addLinkToDisplayData(origin, pathname, additionals.data, domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, additionals.data);
                } else if (additionals.type === 'OPT') {
                    if (additionals.name === '.') {
                        // EDNS0
                        const optRecord = additionals;
                        let flagString = '';
                        let nsidString = '';
                        let nsidFound = false;
                        let edeString = '';
                        let optionString = '';
                        let mQTypeString = '';
                        let mQTypeResponseFound = false;
                        let mQTypeResponseInvalid = false;
                        let mQTypeResponseCount = 0;
                        let mQTypeQueryFound = false;
                        if (optRecord.flags & dnsPacket.DNSSEC_OK) {
                            flagString = 'DO';
                        }
                        for (const option of optRecord.options) {
                            const optionData = Buffer.isBuffer(option.data) ? option.data : Buffer.from(option.data || '');
                            const optionName = escapeHtml(option.type || `OPTION_${option.code}`);
                            const optionHex = escapeHtml(optionData.toString('hex'));
                            if (option.code === 3) {
                                nsidFound = true;
                                nsidString = optionHex;
                            } else if (option.code === 8 && Buffer.isBuffer(option.data)) {
                                const buffer = option.data;
                                if (buffer.length >= 4) {
                                    const family = buffer.readUInt16BE(0);
                                    const sourcePrefix = buffer[2];
                                    const scopePrefix = buffer[3];
                                    const addrBytes = buffer.subarray(4);
                                    let addrStr = '';
                                    if (family === 1) { // IPv4
                                        const octets = [0, 0, 0, 0];
                                        for (let i = 0; i < Math.min(addrBytes.length, 4); i++) {
                                            octets[i] = addrBytes[i];
                                        }
                                        addrStr = octets.join('.');
                                    } else if (family === 2) { // IPv6
                                        const hex = Buffer.alloc(16);
                                        addrBytes.copy(hex, 0, 0, Math.min(addrBytes.length, 16));
                                        const hexStr = hex.toString('hex');
                                        const blocks = [];
                                        for (let j = 0; j < 16; j += 2) {
                                            blocks.push(hexStr.slice(j * 2, j * 2 + 4));
                                        }
                                        addrStr = compressIPv6(blocks.join(':'));
                                    } else {
                                        addrStr = addrBytes.toString('hex');
                                    }
                                    const familyStr = family === 1 ? '1 (IPv4)' : family === 2 ? '2 (IPv6)' : `${family}`;
                                    optionString += `<li><strong>[ECS]</strong> <code>family: ${familyStr}, sourcePrefix: ${sourcePrefix}, scopePrefix: ${scopePrefix}, address: ${escapeHtml(addrStr)}</code></li>`;
                                } else {
                                    optionString += `<li><strong>[EDNS Option]</strong> <code>${optionName} (${escapeHtml(option.code)}): ${optionHex || '(empty)'}</code></li>`;
                                }
                            } else if (option.code === 10 && Buffer.isBuffer(option.data)) {
                                const buffer = option.data;
                                if (buffer.length >= 8) {
                                    const clientCookie = buffer.subarray(0, 8).toString('hex');
                                    const serverCookie = buffer.length > 8 ? buffer.subarray(8).toString('hex') : '(none)';
                                    optionString += `<li><strong>[Cookie]</strong> <code>Client Cookie: ${clientCookie}, Server Cookie: ${serverCookie}</code></li>`;
                                } else {
                                    optionString += `<li><strong>[EDNS Option]</strong> <code>${optionName} (${escapeHtml(option.code)}): ${optionHex || '(empty)'}</code></li>`;
                                }
                            } else if (option.code === 12 && Buffer.isBuffer(option.data)) {
                                optionString += `<li><strong>[Padding]</strong> <code>length: ${option.data.length} bytes</code></li>`;
                            } else if (option.code === 15 && Buffer.isBuffer(option.data)) {
                                const buffer = option.data;
                                if (buffer.length < 2) {
                                    optionString += `<li><strong>[${optionName}]</strong> <code>code: ${escapeHtml(option.code)}, data: ${optionHex}</code></li>`;
                                    continue;
                                }
                            } else if (option.code === 20) {
                                mQTypeQueryFound = true;
                            } else if (option.code !== 21) {
                                optionString += `<li><strong>[EDNS Option]</strong> <code>${optionName} (${escapeHtml(option.code)}): ${optionHex || '(empty)'}</code></li>`;
                            }
                            if (option.code === 15 && Buffer.isBuffer(option.data)) {
                                const buffer = option.data;
                                if (buffer.length < 2) continue;

                                const infoCode = buffer.readUInt16BE(0);
                                const errorName = getEdeErrorName(infoCode);
                                let edeTemp = ''; 
                                edeTemp = `${escapeHtml(infoCode)} (${errorName})`;

                                if (buffer.length > 2) {
                                    const extraText = buffer.toString('utf8', 2);
                                    edeTemp += `: (${escapeHtml(extraText)})`;
                                }
                                edeString += `<li><strong>[EDE]</strong> <code>${edeTemp}</code></li>`;
                            }
                            if (option.code === 21 && Buffer.isBuffer(option.data)) {
                                mQTypeResponseFound = true;
                                mQTypeResponseCount++;
                                const buffer = option.data;
                                if (buffer.length % 2 !== 0) {
                                    mQTypeResponseInvalid = true;
                                    continue;
                                }
                                const primaryTypeCode = response.questions && response.questions.length > 0
                                    ? getDnsTypeCode(response.questions[0].type)
                                    : -1;
                                const responseTypes = [];
                                for (let offset = 0; offset < buffer.length; offset += 2) {
                                    const type = buffer.readUInt16BE(offset);
                                    if (responseTypes.includes(type) || type === primaryTypeCode || type === 0 || (type >= 128 && type <= 255)) {
                                        mQTypeResponseInvalid = true;
                                    }
                                    responseTypes.push(type);
                                    mQTypeString += `${dnsTypes.toString(type)},`;
                                }
                                if (mQTypeString !== '') {
                                    mQTypeString = mQTypeString.slice(0, -1);
                                }
                            }
                        }
                        if (mQTypeResponseCount > 1) {
                            mQTypeResponseInvalid = true;
                        }
                        if (mQType !== '' && !mQTypeResponseFound) {
                            optError = '<p style="color: orange; margin: 0;">MQTYPE-Response がありません。サーバーが RFC 10029 に対応していない可能性があります。</p>';
                        }
                        if (mQTypeResponseInvalid) {
                            optError = '<p style="color: red; margin: 0;">MQTYPE-Response が RFC 10029 の形式に適合していません。</p>';
                        }
                        if (mQTypeQueryFound) {
                            mQTypeResponseInvalid = true;
                            optError = '<p style="color: red; margin: 0;">応答に MQTYPE-Query が含まれているため、RFC 10029 の形式に適合していません。</p>';
                        }
                        const extendedRcode = optRecord.extendedRcode || 0;
                        const extendedRcodeName = EXTENDED_RCODE_NAMES[getResponseRcodeNumber(response)];
                        const extendedRcodeDisplay = extendedRcodeName
                            ? `${extendedRcode} (${extendedRcodeName})`
                            : `${extendedRcode}`;
                        optPseudo = `<li><strong>[EDNS]</strong> <code>Extended RCODE: ${extendedRcodeDisplay}, Version: ${optRecord.version || 0}, flags: ${flagString}, UDP payload size: ${optRecord.udpPayloadSize}</code></li>`;
                        if (nsidFound) {
                            optPseudo += `<li><strong>[NSID]</strong> <code>${nsidString || '(empty)'}</code></li>`;
                        }
                        if (optionString !== '') {
                            optPseudo += optionString;
                        }
                        if (edeString !== '') {
                            optPseudo += `${edeString}`;
                        }
                        if (mQTypeResponseFound) {
                            optPseudo += `<li><strong>[MQTYPE-Response]</strong> <code>${mQTypeString || '(empty)'}</code></li>`;
                        }
                    } else {
                        optError = `<p style="color: red; margin: 0;">不明なオプション情報です。(name: ${escapeHtml(additionals.name)})</p>`;
                    }
                } else if (typeof additionals.data === 'object') {
                    // オブジェクト構造を持つデータ用
                    displayData = escapeHtml(JSON.stringify(additionals.data));
                } else {
                    // 通常データ用
                    displayData = escapeHtml(additionals.data);
                }
            }
            if (additionals.type !== 'OPT') {
                // EDNS0 は下で表示する
                const additionalsType = replaceUnknownRrTypeToKnown(escapeHtml(additionals.type));
                html += `<li><strong>[${additionalsType}]</strong> ${escapeHtml(additionals.name)} &rarr; <code>${displayData}</code> (TTL: ${parseInt(additionals.ttl, 10)}秒)</li>`;
            }
        });
        html += '</ul>';
        if (optPseudo.length > 0) {
            if (response.additionals.length === 1) {
                html += wrapSectionNoticeHtml('<p style="color: orange; margin: 0;">追加の情報は見つかりませんでしたがオプション情報が見つかりました。</p>');
            }
            html += `<p><strong>OPT PSEUDOSECTION:</strong></p>`;
            html += `<ul>${optPseudo}</ul>`;
            if (optError.length > 0) {
                html += wrapSectionNoticeHtml(optError);
            }
        }
    } else {
        html += wrapSectionNoticeHtml('<p style="color: orange; margin: 0;">追加の情報は見つかりませんでした。</p>');
    }

    const warningHtml = getOptPseudoSectionStatusHtml(response, rawBuf);
    if (warningHtml) {
        html += buildWarningSectionHtml(warningHtml);
    }
    if (packetWarningHtml) {
        html += buildWarningSectionHtml(packetWarningHtml);
    }

    html += '</div>';

    return html;
};

const analyzeDnsPacketError = (rawBuf, originalError, tcpFramed = false) => {
    if (!Buffer.isBuffer(rawBuf) || rawBuf.length === 0) {
        return '<p>メッセージデータが存在しないか空です。</p>';
    }

    let buf = rawBuf;
    if (tcpFramed || (originalError && rawBuf.length >= 2 && ((rawBuf.readUInt16BE(0) + 2) === rawBuf.length))) {
        buf = rawBuf.subarray(2);
    }

    if (buf.length < 12) {
        return `<p>メッセージサイズ (<code>${buf.length}</code> バイト) が DNS ヘッダーの最小長 (12 バイト) 未満です。</p>`;
    }

    const id = buf.readUInt16BE(0);
    const flags = buf.readUInt16BE(2);
    const qdcount = buf.readUInt16BE(4);
    const ancount = buf.readUInt16BE(6);
    const nscount = buf.readUInt16BE(8);
    const arcount = buf.readUInt16BE(10);

    const rcodeNum = flags & 0x0f;
    const rcodeStr = RCODE_NAMES[rcodeNum] || `RCODE_${rcodeNum}`;

    let html = '<p><strong>【DNSメッセージ異常の分析結果】</strong></p>';
    html += '<ul>';
    html += `<li><strong>ヘッダー宣言値:</strong> ID: <code>${id}</code>, RCODE: <code>${rcodeStr}</code>, QDCOUNT: <code>${qdcount}</code>, ANCOUNT: <code>${ancount}</code>, NSCOUNT: <code>${nscount}</code>, ARCOUNT: <code>${arcount}</code> (受信メッセージ長: <code>${buf.length}</code> バイト)</li>`;

    let anomalyReason = '';
    let offset = 12;

    const readName = (b, startOffset) => {
        let visited = new Set();
        let curr = startOffset;
        let jumped = false;
        let nextOff = startOffset;
        let labels = [];

        while (true) {
            if (curr >= b.length) {
                throw new Error(`ドメイン名の解読中にメッセージ末尾 (オフセット ${curr} / メッセージ長 ${b.length}) に達しました (Buffer Overflow)`);
            }
            if (visited.has(curr)) {
                throw new Error(`ドメイン名の圧縮ポインタが循環参照 (無限ループ) しています (オフセット 0x${curr.toString(16)})`);
            }
            visited.add(curr);

            const len = b[curr];
            if (len === 0) {
                if (!jumped) nextOff = curr + 1;
                break;
            }
            if ((len & 0xc0) === 0xc0) {
                if (curr + 1 >= b.length) {
                    throw new Error(`圧縮ポインタの読み込み中にメッセージ末尾 (オフセット ${curr}) に達しました`);
                }
                const pointer = ((len & 0x3f) << 8) | b[curr + 1];
                if (pointer < 12) {
                    throw new Error(`圧縮ポインタ参照先 (0x${pointer.toString(16)}) が DNS ヘッダー領域内を指しています`);
                }
                if (pointer >= b.length) {
                    throw new Error(`圧縮ポインタ参照先 (0x${pointer.toString(16)}) がメッセージ長 (${b.length} バイト) を超えています`);
                }
                if (!jumped) nextOff = curr + 2;
                curr = pointer;
                jumped = true;
            } else {
                if (len > 63) {
                    throw new Error(`ラベル長 (${len} バイト) が RFC 1035 の最大長 (63 バイト) を超えています`);
                }
                if (curr + 1 + len > b.length) {
                    throw new Error(`ラベル (長さ ${len} バイト) の読み込み中にメッセージ末尾に達しました (Buffer Overflow)`);
                }
                labels.push(b.toString('utf8', curr + 1, curr + 1 + len));
                curr += 1 + len;
                if (!jumped) nextOff = curr;
            }
        }
        return { name: labels.join('.') || '.', nextOffset: nextOff };
    };

    const validateRecordRdata = (sectionName, name, type, rdataBuf) => {
        if (type === 16) {
            let rOffset = 0;
            while (rOffset < rdataBuf.length) {
                const txtLen = rdataBuf[rOffset];
                if (rOffset + 1 + txtLen > rdataBuf.length) {
                    if (rOffset === 0) {
                        throw new Error(`${sectionName} (${escapeHtml(name)}) の TXT レコードにおいて、TXT 文字列長オクテット (${txtLen} バイト) が RDATA 長 (${rdataBuf.length} バイト) を超過しています`);
                    } else {
                        throw new Error(`${sectionName} (${escapeHtml(name)}) の TXT レコードにおいて、TXT 文字列長オクテット (${txtLen} バイト) が残りの RDATA 長 (${rdataBuf.length - rOffset} バイト) を超過しています`);
                    }
                }
                rOffset += 1 + txtLen;
            }
        }
    };

    try {
        for (let i = 0; i < qdcount; i++) {
            if (offset >= buf.length) {
                throw new Error(`QUESTION SECTION の ${i + 1} 個目のレコードを読み込もうとしましたが、メッセージ末尾に達しました (ヘッダー宣言 QDCOUNT: ${qdcount} に対し、実際に解読できた Question は ${i} 個です)`);
            }
            const { name, nextOffset } = readName(buf, offset);
            offset = nextOffset;
            if (offset + 4 > buf.length) {
                throw new Error(`QUESTION SECTION (${escapeHtml(name)}) の TYPE/CLASS 読み込み中にメッセージ末尾に達しました`);
            }
            offset += 4;
        }

        for (let i = 0; i < ancount; i++) {
            if (offset >= buf.length) {
                throw new Error(`ANSWER SECTION の ${i + 1} 個目のレコードを読み込もうとしましたが、メッセージ末尾に達しました (ヘッダー宣言 ANCOUNT: ${ancount} に対し、実際に解読できた Answer は ${i} 個です)`);
            }
            const { name, nextOffset } = readName(buf, offset);
            offset = nextOffset;
            if (offset + 10 > buf.length) {
                throw new Error(`ANSWER SECTION (${escapeHtml(name)}) のヘッダー情報 (TYPE/CLASS/TTL/RDLENGTH) 読み込み中にメッセージ末尾に達しました`);
            }
            const type = buf.readUInt16BE(offset);
            const rdlength = buf.readUInt16BE(offset + 8);
            offset += 10;
            if (offset + rdlength > buf.length) {
                throw new Error(`ANSWER SECTION (${escapeHtml(name)}) のレコードデータ (RDLENGTH: ${rdlength} バイト) 読み込み中にメッセージ末尾に達しました`);
            }
            validateRecordRdata('ANSWER SECTION', name, type, buf.subarray(offset, offset + rdlength));
            offset += rdlength;
        }

        for (let i = 0; i < nscount; i++) {
            if (offset >= buf.length) {
                throw new Error(`AUTHORITY SECTION の ${i + 1} 個目のレコードを読み込もうとしましたが、メッセージ末尾に達しました (ヘッダー宣言 NSCOUNT: ${nscount} に対し、実際に解読できた Authority は ${i} 個です)`);
            }
            const { name, nextOffset } = readName(buf, offset);
            offset = nextOffset;
            if (offset + 10 > buf.length) {
                throw new Error(`AUTHORITY SECTION (${escapeHtml(name)}) のヘッダー情報 (TYPE/CLASS/TTL/RDLENGTH) 読み込み中にメッセージ末尾に達しました`);
            }
            const type = buf.readUInt16BE(offset);
            const rdlength = buf.readUInt16BE(offset + 8);
            offset += 10;
            if (offset + rdlength > buf.length) {
                throw new Error(`AUTHORITY SECTION (${escapeHtml(name)}) のレコードデータ (RDLENGTH: ${rdlength} バイト) 読み込み中にメッセージ末尾に達しました`);
            }
            validateRecordRdata('AUTHORITY SECTION', name, type, buf.subarray(offset, offset + rdlength));
            offset += rdlength;
        }

        for (let i = 0; i < arcount; i++) {
            if (offset >= buf.length) {
                throw new Error(`ADDITIONAL SECTION の ${i + 1} 個目のレコードを読み込もうとしましたが、メッセージ末尾に達しました (ヘッダー宣言 ARCOUNT: ${arcount} に対し、実際に解読できた Additional は ${i} 個です)`);
            }
            const { name, nextOffset } = readName(buf, offset);
            offset = nextOffset;
            if (offset + 10 > buf.length) {
                throw new Error(`ADDITIONAL SECTION (${escapeHtml(name)}) のヘッダー情報 (TYPE/CLASS/TTL/RDLENGTH) 読み込み中にメッセージ末尾に達しました`);
            }
            const type = buf.readUInt16BE(offset);
            const rdlength = buf.readUInt16BE(offset + 8);
            offset += 10;
            if (offset + rdlength > buf.length) {
                throw new Error(`ADDITIONAL SECTION (${escapeHtml(name)}) のレコードデータ (RDLENGTH: ${rdlength} バイト) 読み込み中にメッセージ末尾に達しました`);
            }
            validateRecordRdata('ADDITIONAL SECTION', name, type, buf.subarray(offset, offset + rdlength));
            offset += rdlength;
        }

        if (offset < buf.length) {
            const declaredResourceRecordCount = ancount + nscount + arcount;
            const remainingBytes = buf.length - offset;
            throw new Error(`ヘッダー宣言のリソースレコード総数 (ANCOUNT + NSCOUNT + ARCOUNT: ${declaredResourceRecordCount} 個) に対し、実際のリソースレコードは ${declaredResourceRecordCount + 1} 個です。ANCOUNT、NSCOUNT、ARCOUNT のいずれかが実際の件数より小さく、1 個の余剰レコードがあります。さらに、ヘッダーで指定された RR をすべて読んだ後も、メッセージ末尾に ${remainingBytes} バイトの未消費データが残っています (extra bytes at end)。`);
        }
    } catch (e) {
        anomalyReason = e.message;
    }

    if (anomalyReason) {
        html += `<li><strong>異常理由:</strong> <span style="color: red;">${escapeHtml(anomalyReason)}</span></li>`;
    } else if (!originalError) {
        return '';
    } else {
        html += `<li><strong>異常理由:</strong> 本ツールの走査機能では検出できないメッセージ構造でした (${escapeHtml(originalError ? originalError.message : '未知のエラー')})。</li>`;
    }
    html += '</ul>';
    return html;
};

const reverseIPv4 = (ip) => {
    if (typeof ip !== 'string') return '';

    const parts = ip.trim().split('.');
    if (parts.length !== 4) return '';
    if (!parts.every(part => /^\d+$/.test(part))) return '';

    const octets = parts.map(part => Number(part));
    if (octets.some(octet => octet < 0 || octet > 255)) return '';

    return octets.reverse().join('.');
};

const expandIPv6 = (ip) => {
    if (typeof ip !== 'string') return [];

    const normalized = ip.trim().toLowerCase();
    if (!isValidIPv6(normalized)) return [];

    const [leftPart = '', rightPart = ''] = normalized.split('::');
    const left = leftPart ? leftPart.split(':').filter(Boolean) : [];
    const right = rightPart ? rightPart.split(':').filter(Boolean) : [];
    const missing = Math.max(0, 8 - (left.length + right.length));
    const expanded = [...left, ...Array(missing).fill('0'), ...right];

    return expanded.map(part => part.padStart(4, '0'));
};

const reverseIPv6 = (ip) => {
    const expanded = expandIPv6(ip);
    if (expanded.length === 0) return '';

    return expanded
        .join('')
        .split('')
        .reverse()
        .join('.');
};

const compressIPv6 = (ip) => {
    if (typeof ip !== 'string') return '';

    const normalized = ip.trim().toLowerCase();
    if (!isValidIPv6(normalized)) return '';

    const expanded = expandIPv6(normalized);
    const normalizedGroups = expanded.map(part => part.replace(/^0+(?=[0-9a-f])/, '') || '0');

    let bestStart = -1;
    let bestLength = 0;
    let currentStart = -1;
    let currentLength = 0;

    for (let i = 0; i < normalizedGroups.length; i++) {
        if (normalizedGroups[i] === '0') {
            if (currentStart === -1) {
                currentStart = i;
            }
            currentLength += 1;
        } else {
            if (currentLength > bestLength) {
                bestStart = currentStart;
                bestLength = currentLength;
            }
            currentStart = -1;
            currentLength = 0;
        }
    }

    if (currentLength > bestLength) {
        bestStart = currentStart;
        bestLength = currentLength;
    }

    if (bestLength <= 1) {
        return normalizedGroups.join(':');
    }

    const leftCompressed = normalizedGroups.slice(0, bestStart).join(':');
    const rightCompressed = normalizedGroups.slice(bestStart + bestLength).join(':');

    if (leftCompressed && rightCompressed) return `${leftCompressed}::${rightCompressed}`;
    if (leftCompressed) return `${leftCompressed}::`;
    if (rightCompressed) return `::${rightCompressed}`;
    return '::';
};

const isIpv6Loopback = (ip) => {
    if (!isValidIPv6(ip)) {
        return false;
    }

    if (compressIPv6(ip) === '::1') {
        return true;
    }
    return false;
};

const isValidIPv6 = (ip) => {
    if (typeof ip !== 'string') return false;
    return net.isIP(ip.trim()) === 6;
};

const isValidIPv4 = (ip) => {
    if (typeof ip !== 'string') return false;
    return net.isIP(ip.trim()) === 4;
};

const isLoopbackIPv4 = (ip) => {
    if (!isValidIPv4(ip)) return false;
    return Number.parseInt(ip.split('.')[0], 10) === 127;
};

const isPrivateIPv4 = (ip) => {
    if (!isValidIPv4(ip)) return false;

    const [a, b] = ip.split('.').map(Number);
    return a === 10 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168);
};

const isPrivateIPv6 = (ip) => {
    if (!isValidIPv6(ip)) return false;

    const expanded = expandIPv6(ip);
    if (expanded.length === 0) return false;

    const first = parseInt(expanded[0], 16);
    return (first >= 0xfc00 && first <= 0xfdff) || (first >= 0xfe80 && first <= 0xfebf);
};

const isInvalidDnsServer = (dnsServer) => {
    const value = (dnsServer || '').trim();
    return value === '' ||
        value === 'localhost' ||
        isLoopbackIPv4(value) ||
        isPrivateIPv4(value) ||
        isIpv6Loopback(value) ||
        isPrivateIPv6(value);
};

const isInvalidUdpSize = (udpSize) => {
    const numeric = Number(udpSize);
    return !Number.isInteger(numeric) || numeric < 512 || 65535 < numeric;
};

const isInvalidQueryType = (queryType) => {
    const allowedTypes = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'CNAME', 'DNAME', 'CAA', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'RRSIG', 'SRV', 'HTTPS', 'SVCB', 'PTR', 'PTR-x', 'ANY', 'VERSION', 'TLSA', 'SSHFP', 'NAPTR'];
    if (allowedTypes.includes(queryType)) {
        return false;
    }

    if (/^UNKNOWN_\d+$/.test(queryType)) {
        return true;
    }

    const typeCode = dnsTypes.toType(replaceKnownToUnknownRrType(queryType));
    return !Number.isInteger(typeCode) || typeCode < 1 || typeCode > 65535;
};

const validateDomainName = (name) => {
    if (typeof name !== 'string' || name.trim() === '') {
        return 'ドメイン名が空です';
    }

    const trimmed = name.trim();
    if (trimmed === '.') {
        return null;
    }

    if (trimmed.startsWith('.')) {
        return '空のラベルが含まれています (先頭のピリオド等)';
    }

    let wireLength = 1; // 終端ルートラベル (0x00)
    let currentLabelBytes = 0;
    let inEscape = false;
    let labelCount = 0;

    for (let i = 0; i < trimmed.length; i++) {
        const char = trimmed[i];

        if (inEscape) {
            inEscape = false;
            if (/^[0-9]$/.test(char)) {
                if (i + 2 >= trimmed.length || !/^[0-9]{2}$/.test(trimmed.slice(i + 1, i + 3))) {
                    return '不正なエスケープシーケンスです';
                }
                const num = parseInt(trimmed.slice(i, i + 3), 10);
                if (num > 255) {
                    return '不正なエスケープシーケンスです';
                }
                currentLabelBytes += 1;
                i += 2;
            } else {
                const charBuf = Buffer.from(char, 'utf8');
                currentLabelBytes += charBuf.length;
            }
            if (currentLabelBytes > 63) {
                return 'ラベルが長すぎます (最大63バイト)';
            }
            continue;
        }

        if (char === '\\') {
            inEscape = true;
            continue;
        }

        if (char === '.') {
            if (currentLabelBytes === 0) {
                return '空のラベルが含まれています (連続したピリオド等)';
            }
            wireLength += 1 + currentLabelBytes;
            if (wireLength > 255) {
                return 'ドメイン名が長すぎます (最大255バイト)';
            }
            currentLabelBytes = 0;
            labelCount++;
            continue;
        }

        const code = char.charCodeAt(0);
        if (code <= 0x20 || code === 0x7f) {
            return '不正な文字が含まれています';
        }

        const charBuf = Buffer.from(char, 'utf8');
        currentLabelBytes += charBuf.length;
        if (currentLabelBytes > 63) {
            return 'ラベルが長すぎます (最大63バイト)';
        }
    }

    if (inEscape) {
        return '不正なエスケープシーケンスです';
    }

    if (currentLabelBytes > 0) {
        wireLength += 1 + currentLabelBytes;
        labelCount++;
    }

    if (wireLength > 255) {
        return 'ドメイン名が長すぎます (最大255バイト)';
    }

    if (labelCount === 0) {
        return '空のラベルが含まれています';
    }

    return null;
};

const getDnsTypeCode = (type) => {
    const normalizedType = type.trim().toUpperCase();
    if (/^\d+$/.test(normalizedType)) {
        return Number(normalizedType);
    }
    return dnsTypes.toType(replaceKnownToUnknownRrType(normalizedType));
};

const validateMQType = (value, primaryType, qClass) => {
    if (value === 'EMPTY') {
        return '';
    }

    const types = value.split(',').map(type => type.trim());
    if (types.length === 0 || types.some(type => type === '')) {
        return 'MQTYPE-Query の QTYPE リストが空です。';
    }

// ↓ このツールは DNSテスト用なので制限を緩和してある
//    if (qClass !== 'IN' || primaryType === 'ANY' || primaryType === 'VERSION') {
    if (qClass !== 'IN' || primaryType === 'VERSION') {
        return 'MQTYPE-Query には IN クラスの data RRTYPE のクエリーが必要です。';
    }

    const typeCodes = types.map(getDnsTypeCode);
// ↓ このツールは DNSテスト用なので制限を緩和してある
//    if (typeCodes.some(type => !Number.isInteger(type) || type < 1 || type > 65535 || type === 41 || (type >= 249 && type <= 255))) {
    if (typeCodes.some(type => !Number.isInteger(type) || type < 1 || type > 65535)) {
        return 'MQTYPE-Query に無効な QTYPE が含まれています。';
    }

// ↓ このツールは DNSテスト用なので制限を緩和してある
/*    const primaryTypeCode = getDnsTypeCode(primaryType);
    if (new Set(typeCodes).size !== typeCodes.length || typeCodes.includes(primaryTypeCode)) {
        return 'MQTYPE-Query に重複した QTYPE、または主 QTYPE と同じ QTYPE が含まれています。';
    } */
    return '';
};

const buildDnsFlags = (recursionDesired, checkingDisabled) => {
    return (recursionDesired ? dnsPacket.RECURSION_DESIRED : 0) |
           (checkingDisabled ? dnsPacket.CHECKING_DISABLED : 0);
};

const ROOT_SERVERS = [
    '198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13',
    '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53',
    '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
    '202.12.27.33'
];

const normalizeDnsName = (name) => name.replace(/\.$/, '').toLowerCase();

const queryAuthoritativeServerOverTcp = (serverAddress, query) => new Promise((resolve, reject) => {
    const client = new net.Socket({ family: net.isIP(serverAddress) === 6 ? 6 : 4 });
    let responseBuffer = Buffer.alloc(0);
    let expectedLength = null;
    let settled = false;
    const finish = (callback) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        client.destroy();
        callback();
    };
    const timeoutId = setTimeout(() => {
        finish(() => reject(new Error(`${serverAddress} から TCP 応答がありませんでした。`)));
    }, 2000);

    client.once('connect', () => {
        client.write(dnsPacket.streamEncode(query));
    });
    client.on('data', (data) => {
        responseBuffer = Buffer.concat([responseBuffer, data]);
        if (expectedLength === null && responseBuffer.length >= 2) {
            expectedLength = responseBuffer.readUInt16BE(0) + 2;
        }
        if (expectedLength !== null && responseBuffer.length >= expectedLength) {
            finish(() => {
                try {
                    resolve(dnsPacket.streamDecode(responseBuffer));
                } catch (error) {
                    reject(error);
                }
            });
        }
    });
    client.once('error', (error) => {
        finish(() => reject(error));
    });
    client.connect(53, serverAddress);
});

const queryAuthoritativeServer = (serverAddress, name, type, createSocket = dgram.createSocket,
    queryOverTcp = queryAuthoritativeServerOverTcp) => new Promise((resolve, reject) => {
    const client = createSocket(net.isIP(serverAddress) === 6 ? 'udp6' : 'udp4');
    const query = {
        type: 'query',
        id: Math.floor(Math.random() * 65535),
        questions: [{ name, type, class: 'IN' }]
    };
    const packet = dnsPacket.encode(query);
    const timeoutId = setTimeout(() => {
        client.close();
        reject(new Error(`${serverAddress} から UDP 応答がありませんでした。`));
    }, 2000);

    client.once('message', (message) => {
        clearTimeout(timeoutId);
        client.close();
        try {
            const response = dnsPacket.decode(message);
            if (response.flags & dnsPacket.TRUNCATED_RESPONSE) {
                queryOverTcp(serverAddress, query).then(resolve, reject);
                return;
            }
            resolve(response);
        } catch (error) {
            reject(error);
        }
    });
    client.once('error', (error) => {
        clearTimeout(timeoutId);
        client.close();
        reject(error);
    });
    client.send(packet, 53, serverAddress, (error) => {
        if (error) {
            clearTimeout(timeoutId);
            client.close();
            reject(error);
        }
    });
});

const resolveDnsServerAddress = async (dnsServer, preferIpv6, resolutionDepth = 0,
    queryServer = queryAuthoritativeServer) => {
    try {
        return await resolveDnsServerAddressByType(dnsServer, preferIpv6, resolutionDepth, queryServer);
    } catch (error) {
        if (preferIpv6) {
            throw error;
        }
        return resolveDnsServerAddressByType(dnsServer, true, resolutionDepth, queryServer);
    }
};

const resolveDnsServerAddressByType = async (dnsServer, preferIpv6, resolutionDepth = 0,
    queryServer = queryAuthoritativeServer) => {
    if (net.isIP(dnsServer)) return dnsServer;
    if (resolutionDepth >= 5) {
        throw new Error('DNSサーバー名の解決で入れ子の委任が上限を超えました。');
    }

    const queryType = preferIpv6 ? 'AAAA' : 'A';
    let queryName = normalizeDnsName(dnsServer);
    let nameServers = ROOT_SERVERS;

    for (let depth = 0; depth < 20; depth++) {
        let response;
        for (const nameServer of nameServers) {
            try {
                response = await queryServer(nameServer, queryName, queryType);
                break;
            } catch (error) {
                // 同じ委任先の次の権威サーバーを試す。
            }
        }
        if (!response) {
            throw new Error('権威サーバーからDNSサーバー名を解決できませんでした。');
        }

        const answer = response.answers.find(record => record.type === queryType && normalizeDnsName(record.name) === queryName);
        if (answer && net.isIP(answer.data) && !isInvalidDnsServer(answer.data)) {
            return answer.data;
        }
        const cname = response.answers.find(record => record.type === 'CNAME' && record.name.toLowerCase() === queryName);
        if (cname) {
            queryName = normalizeDnsName(cname.data);
            nameServers = ROOT_SERVERS;
            continue;
        }

        const delegation = response.authorities.find(record => record.type === 'NS');
        if (!delegation) {
            throw new Error(`DNSサーバー名 ${dnsServer} の A/AAAA レコードが見つかりませんでした。`);
        }
        const delegatedZone = normalizeDnsName(delegation.name);
        const delegatedNames = response.authorities
            .filter(record => record.type === 'NS' && normalizeDnsName(record.name) === delegatedZone)
            .map(record => normalizeDnsName(record.data));
        const glueAddresses = response.additionals
            .filter(record => record.type === queryType && delegatedNames.includes(normalizeDnsName(record.name)) && net.isIP(record.data))
            .map(record => record.data)
            .filter(address => !isInvalidDnsServer(address));
        const directGlueAddress = response.additionals
            .find(record => record.type === queryType && normalizeDnsName(record.name) === queryName && net.isIP(record.data));
        if (directGlueAddress && !isInvalidDnsServer(directGlueAddress.data)) {
            return directGlueAddress.data;
        }
        if (glueAddresses.length === 0) {
            let resolvedNameServerAddress;
            for (const delegatedName of delegatedNames) {
                try {
                    resolvedNameServerAddress = await resolveDnsServerAddress(delegatedName, preferIpv6, resolutionDepth + 1, queryServer);
                    break;
                } catch (error) {
                    // 他の委任先NSの名前解決を試す。
                }
            }
            if (!resolvedNameServerAddress) {
                throw new Error(`委任先 ${delegatedZone} のIPアドレスを取得できませんでした。`);
            }
            nameServers = [resolvedNameServerAddress];
            continue;
        }
        nameServers = glueAddresses;
    }
    throw new Error('DNSサーバー名の解決で委任を辿る回数が上限を超えました。');
};

const APPLICATION_PATH = process.env.APPLICATION_PATH || '/dnsquerytool';

const server = http.createServer(async (req, res) => {
    if (req.url === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
    }

    // WHATWG URL API を使用、req.url は相対パスのため第2引数にダミーのベースURLを設定
    const parsedUrl = new URL(req.url, `http://${req.headers.host}/`);
    if (parsedUrl.pathname === APPLICATION_PATH || parsedUrl.pathname.startsWith(`${APPLICATION_PATH}/`)) {
        parsedUrl.pathname = parsedUrl.pathname.slice(APPLICATION_PATH.length) || '/';
    }
    const staticFiles = {
        '/': { file: 'index.html', contentType: 'text/html; charset=utf-8' },
        '/index.html': { file: 'index.html', contentType: 'text/html; charset=utf-8' },
        '/dns-query-tool-client.js': { file: 'dns-query-tool-client.js', contentType: 'application/javascript; charset=utf-8' }
    };
    const staticFile = staticFiles[parsedUrl.pathname];
    if (staticFile) {
        fs.readFile(path.join(__dirname, staticFile.file), (err, content) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
                res.end('静的ファイルを読み込めませんでした。');
                return;
            }
            res.writeHead(200, { 'Content-Type': staticFile.contentType });
            res.end(content);
        });
        return;
    }
    if (parsedUrl.pathname !== '/api/query') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Not Found');
        return;
    }
    const params = parsedUrl.searchParams;

    // .get() メソッドでパラメータを取得
    const rawDnsServer = params.get('server') || 'a.root-servers.net';
    const rawDomainName = params.get('name') || '';
    const rawQueryType = params.get('type') || 'A';
    const recursionDesired = params.get('rd') === '1';
    const checkingDisabled = params.get('cd') === '1';
    const qnameMinimisation = params.get('qmini') === '1';
    const rawQnamePosition = params.get('qposi') || '255';
    const rawQnameType = params.get('qtype') || 'A';
    const edns0Enable = params.get('edns0') === '1';
    const dnssecOk = params.get('dnssec') === '1';
    const rawUdpSize = params.get('udpsize') || '1232';
    const nsidEnable = params.get('nsid') === '1';
    const rawMQtype = params.get('mqtype') || '';
    const sendTcp = params.get('tcp') === '1';
    const sendIpv6 = params.get('ipv6') === '1';

    // 画面表示用にすべての入力値をエスケープ (サニタイズ)
    const dnsServer = escapeHtml(rawDnsServer.trim());
    let domainName = escapeHtml(rawDomainName.trim());
    let queryType = escapeHtml(rawQueryType);
    let qnamePosition = escapeHtml(rawQnamePosition.trim());
    const qnameType = escapeHtml(rawQnameType) === 'NS' ? 'NS' : 'A';
    const udpSize = escapeHtml(rawUdpSize.trim());
    const mQType = escapeHtml(rawMQtype.trim());
    let html = '';

    if (queryType === 'VERSION') {
        domainName = 'version.bind';
    }
    if (!domainName || !dnsServer) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<div class="result error"><p>エラー: 対象ドメイン名とDNSサーバーを入力してください。</p></div>');
        return;
    }

    // 対象ドメイン名としてURLが渡された場合の変換
    try {
        const urlObj = new URL(domainName);
        if (urlObj && urlObj.hostname) {
            domainName = urlObj.hostname;
        }
    } catch (e) {
    }

    // クエリータイプのホワイトリストチェック
    if (isInvalidQueryType(queryType)) {
        html += `<div class="result error"><p>エラー: 不正なクエリータイプです (${queryType} は不正です)。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    // 対象ドメイン名のバリデーションチェック (PTR-x 以外)
    if (queryType !== 'PTR-x') {
        const domainValidationError = validateDomainName(domainName);
        if (domainValidationError) {
            html += `<div class="result error"><p>エラー: 不正なドメイン名です ('${escapeHtml(domainName)}' は無効なドメイン名です: ${escapeHtml(domainValidationError)})。</p></div>`;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
            return;
        }
    }

    // 対象DNSサーバーのチェック
    if (isInvalidDnsServer(dnsServer)) {
        html += `<div class="result error"><p>エラー: DNSサーバーを選択し直してください (${escapeHtml(dnsServer)} は不正です)。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    // UDP Payload Sizeのチェック
    if (isInvalidUdpSize(udpSize)) {
        html += `<div class="result error"><p>エラー: UDPメッセージサイズを入力し直してください (${udpSize} は不正です)。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    let dnsServerAddress;
    try {
        dnsServerAddress = await resolveDnsServerAddress(dnsServer, sendIpv6);
    } catch (error) {
        html += `<div class="result error"><p>エラー: DNSサーバー名を解決できませんでした: ${escapeHtml(error.message)}</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    // DNSクエリーメッセージの構築
    let qType = replaceKnownToUnknownRrType(queryType);
    let qClass = 'IN';
    let qName = domainName;
    const qId = Math.floor(Math.random() * 65535);
    if (qName !== '.' && qName.endsWith('.')) {
        qName = qName.slice(0, -1);	// 最後の '.' を削除
    }
    if (queryType === 'VERSION') {
        qType = 'TXT';
        qClass = 'CH';
    } else if (queryType === 'PTR-x') {
        qType = 'PTR';
        if (isValidIPv4(domainName)) {
            qName = `${reverseIPv4(domainName)}.in-addr.arpa`;
        } else if (isValidIPv6(domainName)) {
            qName = `${reverseIPv6(domainName)}.ip6.arpa`;
        } else {
            html += `<div class="result error"><p>エラー: PTR-xクエリーの対象ドメイン名は IPv4か IPv6のアドレスである必要があります。</p></div>`;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
            return;
        }
        // PTR-xクエリーのときは、qType を PTR に書き換え、qName を変換した後の値を domainName に反映させる
        domainName = qName;
        queryType = qType;
    }

    if (qnameMinimisation) {
        if (!Number.isInteger(Number(qnamePosition))) {
            html += `<div class="result error"><p>エラー: QNAME minimisationを無効にして試してください。</p></div>`;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
            return;
        }

        let parsedQName = qName.split('.');
        if (qnamePosition < 0 || parsedQName.length <= qnamePosition) {
            qnamePosition = parsedQName.length - 1;
            if (parsedQName[0] === '') {
                // domainName (qName) が '.' の場合、 split() は '.' の両側を '' 文字として配列に格納するため
                // parsedQName.length は 2 になり、qnamePosition は 1 になる
                // ここでは一文字目が '' の場合は qnamePosition を 0 にして、再検索をしないようにする
                qnamePosition = 0;
            }
        }
        if (qnamePosition > 0) {
            // 例えば parsedQName -> [ 'www', 'example', 'com' ] とすると
            // parsedQName.length` は 3 であり qnamePosition は 0 から 2 までの数字になる
            qName = '';
            for (let i = 0; i < parsedQName.length; i++) {
                // もし qnamePosition が 1 の場合、'www' が除去される
                if (i < qnamePosition) {
                    continue;
                }
                qName += `${parsedQName[i]}.`;
            }
            if (qName !== '.' && qName.endsWith('.')) {
                qName = qName.slice(0, -1);	// 最後の '.' を削除
            }
            if ((qnameType === 'A' && qType === 'AAAA') !== true) {
                // qnameType が A で qType が AAAA のときは、qType は AAAA のままにする (この if文には入らない)
                // それ以外のときは、qnameType の値を qType に反映させる (例えば qnameType が NS のときは、qType がなんであっても NS にする)
                // なお、元のクエリータイプは queryType 変数に保持されているので、qType を書き換えても問題ない
                qType = qnameType;
            }
        }
    }
    const dnsFlags = buildDnsFlags(recursionDesired, checkingDisabled);
    let queryPacket = {
        type: 'query',
        id: qId,
        flags: dnsFlags,
        questions: [{
            type: qType,
            class: qClass,
            name: qName
        }]
    };
    if (edns0Enable) {
        const edns0Option = {
            type: 'OPT',
            name: '.',
            udpPayloadSize: udpSize,
            flags: dnssecOk ? dnsPacket.DNSSEC_OK : 0
        };
        if (nsidEnable) {
            const option = { code: 3, data: Buffer.alloc(0) };
            if (typeof edns0Option.options === "undefined") {
                edns0Option.options = new Array();
            }
            edns0Option.options.push(option);
        }
        if (mQType !== '') {
            const option = { code: 20 };
            if (mQType === 'EMPTY') {
                option.data = Buffer.alloc(0);
            } else {
                const mqtypeError = validateMQType(mQType, queryType, qClass);
                if (mqtypeError !== '') {
                    html += `<div class="result error"><p>エラー: ${escapeHtml(mqtypeError)}</p></div>`;
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(html);
                    return;
                }
                const mQTypeArray = mQType.split(',');
                const mQlength = mQTypeArray.length * 2;
                const mQdata = { data: Buffer.alloc(mQlength) };
                let offset = 0;
                for (const type of mQTypeArray) {
                    mQdata.data.writeUInt16BE(getDnsTypeCode(type), offset);
                    offset += 2;
                }
                option.data = mQdata.data;
            }
            if (typeof edns0Option.options === "undefined") {
                edns0Option.options = new Array();
            }
            edns0Option.options.push(option);
        }
        if (typeof queryPacket.additionals === "undefined") {
            queryPacket.additionals = new Array();
        }
        queryPacket.additionals.push(edns0Option);
    }

    let buf;
    try {
        if (!sendTcp) {
            buf = dnsPacket.encode(queryPacket);
        } else {
            buf = dnsPacket.streamEncode(queryPacket);
        }
    } catch (e) {
        html += `<div class="result error"><p>エラー: 入力されたドメイン名の形式が正しくありません。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    if (sendTcp) {
        let resultHtml = '';
        let expectedLength = 0
        let receivedBuffer = null
        let isResponded = false;
        let finished = false;
        var tcpClient;

        // TCPソケットを作成して送信
        if (isValidIPv6(dnsServerAddress)) {
            tcpClient = new net.Socket({ family: 6 });
        } else {
            tcpClient = new net.Socket({ family: 4 });
        }

        // タイムアウト処理 (5秒間応答がない場合は通信を打ち切る)
        const timeoutId = setTimeout(() => {
            if (!isResponded) {
                isResponded = true;
                html += `<div class="result error"><p>タイムアウト: サーバー <strong>${escapeHtml(dnsServer)}</strong> から応答がありませんでした。</p>`;
                if (qnameMinimisation) {
                    const resetQMiniHtml = addLinkToDisplayData(parsedUrl.origin, parsedUrl.pathname, 'a.root-servers.net', domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, '255', qnameType, 'こちら');
                    html += `<p>※問い合わせたのは <strong>${escapeHtml(qName)}</strong> でした。${resetQMiniHtml} で QNAME minimisation の状態をリセットしてみてください。</p>`;
                }
                html += `</div>`;
                finished = true;
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(html);
                tcpClient.destroy();
            }
        }, 5000);

        tcpClient.connect(53, dnsServerAddress, () => {
            tcpClient.write(buf);
        });

        tcpClient.on('data', data => {
            // TCPの場合、アプリケーションへはいくつかの区切りで転送される (イベントが発生する) ので、受信バッファー (receivedBuffer) は外に確保しておく
            if (receivedBuffer == null) {
                if (data.byteLength > 1) {
                    const plen = data.readUInt16BE(0);
                    expectedLength = plen + 2;	// TCPペイロードの中の DNSメッセージの先頭 2バイトに DNSメッセージのサイズが格納されているので、その分を足す
                    receivedBuffer = Buffer.from(data);
                }
            } else {
                receivedBuffer = Buffer.concat([receivedBuffer, data]);
            }

            if (receivedBuffer.byteLength >= expectedLength) {
                isResponded = true;
                clearTimeout(timeoutId);
                try {
                    const response = dnsPacket.streamDecode(receivedBuffer);
                    const anomalyHtml = analyzeDnsPacketError(receivedBuffer, null, true);
                    const hasResidualBytesWarning = /未消費データ|extra bytes|残っています/i.test(anomalyHtml || '');
                    if (anomalyHtml && !hasResidualBytesWarning) {
                        throw new Error('ヘッダーのセクション件数と実際のリソースレコード数が一致しません');
                    }
                    const bytesRead = dnsPacket.streamDecode.bytes;
                    resultHtml += makeHtmlFromDns(response, bytesRead, parsedUrl.origin, parsedUrl.pathname, dnsServer, dnsServerAddress, domainName, queryType, qId, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, anomalyHtml, receivedBuffer);
                } catch (err) {
                    html += `<div class="result error"><p>エラー: メッセージの解析に失敗しました: ${escapeHtml(err.message)}</p>${analyzeDnsPacketError(receivedBuffer, err, true)}</div>`;
                } finally {
                    tcpClient.end();	// AWS (Route 53) は、TCPリソース解放をすぐに行う目的で DNSデータの送信後に RSTを送ってくるので、end() では read ECONNRESET が発生してしまうが、あえてこのようにしている
                }
            }
        });

        tcpClient.on('error', (err) => {
            clearTimeout(timeoutId);
            if (!isResponded) {
                isResponded = true;
                html += `<div class="result error"><p>エラー: TCP通信に失敗しました: ${escapeHtml(err.message)}</p></div>`;
            }
            // このイベントの直後に、'close'イベントが呼び出される
        });

        tcpClient.on('close', (hadError) => {
            clearTimeout(timeoutId);
            if (finished) {
                return;
            }
            finished = true;
            if (!hadError || resultHtml !== '') {
                html += resultHtml;
            }
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
        });
    } else {
        let isResponded = false;
        var udpClient;

        // UDPソケットを作成して送信
        if (isValidIPv6(dnsServerAddress)) {
            udpClient = dgram.createSocket('udp6');
        } else {
            udpClient = dgram.createSocket('udp4');
        }

        // タイムアウト処理 (5秒間応答がない場合は通信を打ち切る)
        const timeoutId = setTimeout(() => {
            if (!isResponded) {
                html += `<div class="result error"><p>タイムアウト: サーバー <strong>${escapeHtml(dnsServer)}</strong> から応答がありませんでした。</p>`;
                if (qnameMinimisation) {
                    const resetQMiniHtml = addLinkToDisplayData(parsedUrl.origin, parsedUrl.pathname, 'a.root-servers.net', domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, '255', qnameType, 'こちら');
                    html += `<p>※問い合わせたのは <strong>${escapeHtml(qName)}</strong> でした。${resetQMiniHtml} で QNAME minimisation の状態をリセットしてみてください。</p>`;
                }
                html += `</div>`;
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(html);
                udpClient.close();
            }
        }, 5000);

        udpClient.on('message', (msg) => {
            isResponded = true;
            clearTimeout(timeoutId);

            try {
                const response = dnsPacket.decode(msg);
                const anomalyHtml = analyzeDnsPacketError(msg);
                const hasResidualBytesWarning = /未消費データ|extra bytes|残っています/i.test(anomalyHtml || '');
                if (anomalyHtml && !hasResidualBytesWarning) {
                    throw new Error('ヘッダーのセクション件数と実際のリソースレコード数が一致しません');
                }
                const bytesRead = dnsPacket.decode.bytes;
                html += makeHtmlFromDns(response, bytesRead, parsedUrl.origin, parsedUrl.pathname, dnsServer, dnsServerAddress, domainName, queryType, qId, recursionDesired, checkingDisabled,
                    sendTcp, sendIpv6, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, anomalyHtml, msg);
            } catch (err) {
                html += `<div class="result error"><p>エラー: メッセージの解析に失敗しました: ${escapeHtml(err.message)}</p>${analyzeDnsPacketError(msg, err)}</div>`;
            } finally {
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(html);
                udpClient.close();
            }
        });

        udpClient.on('error', (err) => {
            isResponded = true;
            clearTimeout(timeoutId);
            html += `<div class="result error"><p>エラー: UDP通信に失敗しました: ${escapeHtml(err.message)}</p></div>`;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
            udpClient.close();
        });

        // 指定されたサーバーIPの53番ポートへ送信
        udpClient.send(buf, 0, buf.length, 53, dnsServerAddress, (err) => {
            if (err) {
                isResponded = true;
                clearTimeout(timeoutId);
                html += `<div class="result error"><p>エラー: 送信に失敗しました: ${escapeHtml(err.message)}</p></div>`;
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(html);
                udpClient.close();
            }
        });
    }
});

const PORT = 3000;
if (require.main === module) {
    server.listen(PORT, () => {
        console.log(`Webサーバーが起動しました: http://localhost:${PORT}`);
    });

    server.on('error', (err) => {
        console.error(`Webサーバーエラー: ${err.message}`);
    });
}

module.exports = {
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
};
