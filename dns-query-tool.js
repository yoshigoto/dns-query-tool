const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');
const dgram = require('dgram');
const https = require('https');
const tls = require('tls');
const dnsPacket = require('dns-packet');	// https://github.com/mafintosh/dns-packet
const dnsTypes = require('dns-packet/types');
const dnsClasses = require('dns-packet/classes');

const DNSSEC_OK = dnsPacket.DNSSEC_OK || 0x8000; // RFC 3225 DNSSEC OK flag
const COMPACT_ANSWERS_OK = dnsPacket.COMPACT_ANSWERS_OK || 0x4000; // RFC 9824 Compact Answers OK flag

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
    16: 'BADVERS',
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

const getEdnsOptionDataError = (option) => {
    const data = option.data;
    if (!Buffer.isBuffer(data)) {
        return `EDNS Option (${option.code}) の OPTION-DATA が不正です`;
    }
    if (option.code === 8) {
        if (data.length < 4) return 'malformed ECS OPTION-DATA (RFC 7871)';
        const family = data.readUInt16BE(0);
        const addressBits = family === 1 ? 32 : family === 2 ? 128 : 0;
        const sourcePrefix = data[2];
        const scopePrefix = data[3];
        const unusedBits = (8 - sourcePrefix % 8) % 8;
        if (addressBits === 0 || sourcePrefix > addressBits || scopePrefix > addressBits ||
            data.length !== 4 + Math.ceil(sourcePrefix / 8) ||
            (sourcePrefix > 0 && (data[data.length - 1] & ((1 << unusedBits) - 1)) !== 0)) {
            return 'malformed ECS OPTION-DATA (RFC 7871)';
        }
    } else if (option.code === 10) {
        if (data.length !== 8 && (data.length < 16 || data.length > 40)) {
            return 'malformed Cookie OPTION-DATA (RFC 7873)';
        }
    } else if (option.code === 15 && data.length < 2) {
        return 'malformed EDE OPTION-DATA (RFC 8914)';
    }
    return '';
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

            if (typeof option.code !== 'number') {
                malformed = true;
                reasons.push('OPTION コードが不正です');
                continue;
            }
            const dataError = getEdnsOptionDataError(option);
            if (dataError) {
                malformed = true;
                reasons.push(dataError);
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
            return `<p style="color: #555555; margin: 0;">※ネガティブキャッシュ有効期間 (TTL) は <code>${negTtl}秒</code> (MINIMUM: ${minimum}秒, SOA TTL: ${soaTtl}秒 の最小値) です。</p>`;
        }
    }
    return '';
};

// RFC 8914 および後続の IANA 登録に基づく INFO-CODE
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
    sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, displayData, queryClass='IN', sendDot=false, linkClass='', ixfrSerial=null) => {
    const query = new URLSearchParams({
        server: dnsServer,
        name: domainName,
        type: queryType,
        class: queryClass,
        rd: recursionDesired ? '1' : '0',
        cd: checkingDisabled ? '1' : '0',
        tcp: sendTcp ? '1' : '0',
        ipv6: sendIpv6 ? '1' : '0',
        https: sendHttps ? '1' : '0',
        dot: sendDot ? '1' : '0',
        httpspath: httpsPath,
        edns0: edns0Enable ? '1' : '0',
        dnssec: dnssecOk ? '1' : '0',
        udpsize: udpSize,
        nsid: nsidEnable ? '1' : '0',
        mqtype: mQType,
        qmini: qnameMinimisation ? '1' : '0',
        qposi: qnamePosition,
        qtype: qnameType
    });
    if (queryType === 'IXFR' && ixfrSerial !== null) {
        query.set('ixfrserial', String(ixfrSerial));
    }
    let html = '<a ';
    if (linkClass) {
        html = `<a class="${escapeHtml(linkClass)}" `;
    }
    html += `data-dns-query-link href="${escapeHtml(`.${pathname}?${query.toString()}`)}">${escapeHtml(displayData)}</a>`;
    return html;
};

const replaceUnknownRrTypeToKnown = (type) => {
    switch (type) {
        case 'UNKNOWN_63': return 'ZONEMD';
        case 'UNKNOWN_64': return 'SVCB';
        case 'UNKNOWN_65': return 'HTTPS';
        case 'UNKNOWN_128': return 'NXNAME';
    }
    return type;
};

const replaceKnownToUnknownRrType = (type) => {
    switch (type) {
        case 'ZONEMD': return 'UNKNOWN_63';
        case 'SVCB': return 'UNKNOWN_64';
        case 'HTTPS': return 'UNKNOWN_65';
        case 'NXNAME': return 'UNKNOWN_128';
    }
    return type;
};

const replaceUnknownRrTypeList = (rrtypes) => {
    return rrtypes.map(item => {
        return replaceUnknownRrTypeToKnown(item);
    });
};

const encodeBase32Hex = (buffer) => {
    const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
    let value = 0;
    let bits = 0;
    let result = '';
    for (const byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            result += alphabet[(value >>> bits) & 31];
        }
        value &= (1 << bits) - 1;
    }
    if (bits > 0) result += alphabet[(value << (5 - bits)) & 31];
    return result;
};

const formatDnsOctets = (buffer, extraEscapes = '') => {
    return Array.from(buffer, byte => {
        const character = String.fromCharCode(byte);
        if (byte >= 0x21 && byte <= 0x7e && !'\\"();'.includes(character) && !extraEscapes.includes(character)) {
            return character;
        }
        return `\\${String(byte).padStart(3, '0')}`;
    }).join('');
};

const decodeResourceRecord = (type, msg, formatSoaMname = escapeHtml) => {
    let displayData = '';
    const malformed = (recordType) => escapeHtml(`malformed ${recordType} RDATA`);
    const hasFields = (value, fields) => value && typeof value === 'object' && !Buffer.isBuffer(value) &&
        fields.every(field => Object.hasOwn(value, field));
    const decodeCharacterStrings = (buffer) => {
        const strings = [];
        let offset = 0;
        while (offset < buffer.length) {
            const length = buffer[offset++];
            if (offset + length > buffer.length) {
                return null;
            }
            strings.push(buffer.toString('utf8', offset, offset + length));
            offset += length;
        }
        return strings;
    };

    if (type === 'TXT') {
        // TXTレコードはBufferまたは'text'の配列か、Bufferか'text'で返ってくる
        if (Array.isArray(msg)) {
            displayData = msg.map(buf => Buffer.isBuffer(buf) ? buf.toString('utf8') : buf).join('');
        } else if (Buffer.isBuffer(msg)) {
            const strings = decodeCharacterStrings(msg);
            displayData = strings === null ? msg.toString('utf8') : strings.join('');
        } else {
            displayData = msg;
        }
    } else if (type === 'SPF') {
        if (!Buffer.isBuffer(msg)) {
            return malformed('SPF');
        }
        const strings = decodeCharacterStrings(msg);
        if (strings === null) {
            return malformed('SPF');
        }
        displayData = `strings: ${strings.join('')}`;
    } else if (type === 'NSEC3PARAM') {
        if (!Buffer.isBuffer(msg) || msg.length < 5) {
            return escapeHtml('malformed NSEC3PARAM RDATA');
        }
        const saltLength = msg[4];
        if (5 + saltLength !== msg.length) {
            return escapeHtml('malformed NSEC3PARAM RDATA');
        }
        displayData = `algorithm: ${msg[0]}, flags: ${msg[1]}, iterations: ${msg.readUInt16BE(2)}, salt: ${msg.subarray(5).toString('hex') || '-'}`;
    } else if (type === 'CDS') {
        if (!Buffer.isBuffer(msg) || msg.length < 4) {
            return escapeHtml('malformed CDS RDATA');
        }
        displayData = `keyTag: ${msg.readUInt16BE(0)}, algorithm: ${msg[2]}, digestType: ${msg[3]}, digest: ${msg.subarray(4).toString('hex').toLowerCase()}`;
    } else if (type === 'CDNSKEY') {
        if (!Buffer.isBuffer(msg) || msg.length < 4) {
            return escapeHtml('malformed CDNSKEY RDATA');
        }
        displayData = `flags: ${msg.readUInt16BE(0)}, protocol: ${msg[2]}, algorithm: ${msg[3]}, key: ${msg.subarray(4).toString('base64')}`;
    } else if (type === 'CAA') {
        if (!hasFields(msg, ['flags', 'tag', 'value'])) {
            return malformed('CAA');
        }
        displayData = `flags: ${msg.flags}, tag: ${msg.tag}, value: ${msg.value}, issuerCritical: ${msg.issuerCritical}`;
    } else if (type === 'DNSKEY') {
        // dns-packet では DNSKEYリソースレコードの Protocol は 3 固定
        if (!hasFields(msg, ['flags', 'algorithm', 'key']) || !Buffer.isBuffer(msg.key)) {
            return malformed('DNSKEY');
        }
        let keyTag;
        if (msg.algorithm === 1) {
            if (msg.key.length === 0) {
                return malformed('DNSKEY');
            }
            let exponentLength = msg.key[0];
            let exponentOffset = 1;
            if (exponentLength === 0) {
                if (msg.key.length < 3) {
                    return malformed('DNSKEY');
                }
                exponentLength = msg.key.readUInt16BE(1);
                exponentOffset = 3;
            }
            const modulusOffset = exponentOffset + exponentLength;
            if (modulusOffset + 3 > msg.key.length) {
                return malformed('DNSKEY');
            }
            keyTag = msg.key.readUInt16BE(msg.key.length - 3);
        } else {
            const rdata = Buffer.alloc(4 + msg.key.length);
            rdata.writeUInt16BE(msg.flags, 0);
            rdata[2] = 3;
            rdata[3] = msg.algorithm;
            msg.key.copy(rdata, 4);
            let accumulator = 0;
            for (let i = 0; i < rdata.length; i++) {
                accumulator += i & 1 ? rdata[i] : rdata[i] << 8;
            }
            accumulator += accumulator >>> 16;
            keyTag = accumulator & 0xffff;
        }
        displayData = `keyTag: ${keyTag}, flags: ${msg.flags}, protocol: 3, algorithm: ${msg.algorithm}, key: ${msg.key.toString('base64')}`;
    } else if (type === 'DS') {
        if (!hasFields(msg, ['keyTag', 'algorithm', 'digestType', 'digest']) || !Buffer.isBuffer(msg.digest)) {
            return malformed('DS');
        }
        displayData = `keyTag: ${msg.keyTag}, algorithm: ${msg.algorithm}, digestType: ${msg.digestType}, digest: ${msg.digest.toString('hex').toLowerCase()}`;
    } else if (type === 'NSEC') {
        if (!hasFields(msg, ['nextDomain', 'rrtypes']) || !Array.isArray(msg.rrtypes)) {
            return malformed('NSEC');
        }
        const rrtypes = replaceUnknownRrTypeList(msg.rrtypes);
        displayData = `nextDomain: ${msg.nextDomain}, rrtypes: ${rrtypes.join(' ')}`;
    } else if (type === 'NSEC3') {
        if (!hasFields(msg, ['algorithm', 'flags', 'iterations', 'salt', 'nextDomain', 'rrtypes']) ||
            !Buffer.isBuffer(msg.salt) || !Buffer.isBuffer(msg.nextDomain) || !Array.isArray(msg.rrtypes)) {
            return malformed('NSEC3');
        }
        const rrtypes = replaceUnknownRrTypeList(msg.rrtypes);
        displayData = `algorithm: ${msg.algorithm}, flags: ${msg.flags}, iterations: ${msg.iterations}, salt: ${msg.salt.toString('hex') || '-'}, `
        displayData += `nextDomain: ${encodeBase32Hex(msg.nextDomain)}, rrtypes: ${rrtypes.join(' ')}`;
    } else if (type === 'RRSIG') {
        if (!hasFields(msg, ['typeCovered', 'algorithm', 'labels', 'originalTTL', 'expiration', 'inception', 'keyTag', 'signersName', 'signature']) ||
            !Buffer.isBuffer(msg.signature)) {
            return malformed('RRSIG');
        }
        const expiration = new Date(msg.expiration * 1000);
        const inception = new Date(msg.inception * 1000);
        if (Number.isNaN(expiration.getTime()) || Number.isNaN(inception.getTime())) {
            return malformed('RRSIG');
        }
        const typeCovered = replaceUnknownRrTypeToKnown(msg.typeCovered);
        displayData = `typeCovered: ${typeCovered}, algorithm: ${msg.algorithm}, labels: ${msg.labels}, originalTTL: ${msg.originalTTL}, expiration: ${expiration.toISOString()}, `;
        displayData += `inception: ${inception.toISOString()}, keyTag: ${msg.keyTag}, signersName: ${msg.signersName}, signature: ${msg.signature.toString('base64')}`;
    } else if (type === 'SOA') {
        if (!hasFields(msg, ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum'])) {
            return malformed('SOA');
        }
        return `mname: ${formatSoaMname(msg.mname)}` +
            escapeHtml(`, rname: ${msg.rname}, serial: ${msg.serial}, refresh: ${msg.refresh}, retry: ${msg.retry}, expire: ${msg.expire}, minimum: ${msg.minimum}`);
    } else if (type === 'SRV') {
        if (!hasFields(msg, ['priority', 'weight', 'port', 'target'])) {
            return malformed('SRV');
        }
        displayData = `priority: ${msg.priority}, weight: ${msg.weight}, port: ${msg.port}, target: ${msg.target}`;
    } else if (type === 'TLSA') {
        if (!hasFields(msg, ['usage', 'selector', 'matchingType']) || !Buffer.isBuffer(msg.certificate)) {
            return malformed('TLSA');
        }
        const usageNames = { 0: 'PKIX-TA', 1: 'PKIX-EE', 2: 'DANE-TA', 3: 'DANE-EE' };
        const selectorNames = { 0: 'Cert', 1: 'SPKI' };
        const matchingTypeNames = { 0: 'Full', 1: 'SHA-256', 2: 'SHA-512' };
        const usageStr = usageNames[msg.usage] !== undefined ? usageNames[msg.usage] : msg.usage;
        const selectorStr = selectorNames[msg.selector] !== undefined ? selectorNames[msg.selector] : msg.selector;
        const matchingTypeStr = matchingTypeNames[msg.matchingType] !== undefined ? matchingTypeNames[msg.matchingType] : msg.matchingType;
        const certHex = msg.certificate.toString('hex');
        displayData = `usage: ${usageStr}, selector: ${selectorStr}, matchingType: ${matchingTypeStr}, certificate: ${certHex}`;
    } else if (type === 'SSHFP') {
        if (!hasFields(msg, ['algorithm', 'hash']) || typeof msg.fingerprint !== 'string') {
            return malformed('SSHFP');
        }
        const algoNames = { 1: 'RSA', 2: 'DSA', 3: 'ECDSA', 4: 'Ed25519' };
        const fpTypeNames = { 1: 'SHA-1', 2: 'SHA-256' };
        const algo = algoNames[msg.algorithm] !== undefined ? algoNames[msg.algorithm] : msg.algorithm;
        const fpTypeStr = fpTypeNames[msg.hash] !== undefined ? fpTypeNames[msg.hash] : msg.hash;
        const fpHex = msg.fingerprint.toLowerCase();
        displayData = `algorithm: ${algo}, fpType: ${fpTypeStr}, fingerprint: ${fpHex}`;
    } else if (type === 'NAPTR') {
        if (!hasFields(msg, ['order', 'preference', 'flags', 'services', 'regexp', 'replacement'])) {
            return malformed('NAPTR');
        }
        displayData = `order: ${msg.order}, preference: ${msg.preference}, flags: ${msg.flags}, services: ${msg.services}, regexp: ${msg.regexp}, replacement: ${msg.replacement}`;
    } else if (replaceUnknownRrTypeToKnown(type) === 'SVCB' || replaceUnknownRrTypeToKnown(type) === 'HTTPS' ) {
        let offset = 0;
        if (!Buffer.isBuffer(msg) || msg.length < 3) {
            return escapeHtml('malformed SVCB/HTTPS RDATA');
        }
        const priority = msg.readUInt16BE(offset);
        offset += 2;

        let startOffset = offset;
        const labels = [];
        let targetNameTerminated = false;
        while (startOffset < msg.length) {
            const len = msg[startOffset];
            startOffset += 1;
            if (len === 0) {
                targetNameTerminated = true;
                break; // ヌルバイトで終了
            }
            if (len > 63 || startOffset + len > msg.length) {
                return escapeHtml('malformed SVCB/HTTPS TargetName');
            }
            const label = formatDnsOctets(msg.subarray(startOffset, startOffset + len), '.');
            labels.push(label);
            startOffset += len;
        }
        if (!targetNameTerminated) {
            return escapeHtml('malformed SVCB/HTTPS TargetName');
        }
        if (startOffset - 2 > 255) {
            return malformed('SVCB/HTTPS TargetName');
        }
        const domainName = labels.length === 0 ? '.' : labels.join('.') + '.';

        offset += startOffset - offset;
        let paramString = '';
        const paramNames = ['mandatory', 'alpn', 'no-default-alpn', 'port', 'ipv4hint', 'ech', 'ipv6hint', 'dohpath'];
        const paramKeys = new Set();
        const mandatoryKeys = [];
        let previousParamKey = -1;
        while (offset < msg.length) {
            if (offset + 4 > msg.length) {
                return escapeHtml('malformed SVCB/HTTPS SvcParam');
            }
            const paramKey = msg.readUInt16BE(offset);
            offset += 2;
            if (paramKey <= previousParamKey || paramKey === 65535) {
                return malformed('SVCB/HTTPS SvcParamKey');
            }
            previousParamKey = paramKey;
            paramKeys.add(paramKey);
            const paramLen = msg.readUInt16BE(offset);
            offset += 2;
            if (offset + paramLen > msg.length) {
                return escapeHtml('malformed SVCB/HTTPS SvcParam');
            }
            const paramValBuffer = msg.subarray(offset, offset + paramLen);
            offset += paramLen;
            switch (paramKey) {
                case 0:
                    if (paramValBuffer.length === 0 || paramValBuffer.length % 2 !== 0) {
                        return malformed('SVCB/HTTPS mandatory SvcParam');
                    }
                    for (let i = 0; i < paramValBuffer.length; i += 2) {
                        const key = paramValBuffer.readUInt16BE(i);
                        if (key === 0 || key === 65535 ||
                            (mandatoryKeys.length > 0 && key <= mandatoryKeys[mandatoryKeys.length - 1])) {
                            return malformed('SVCB/HTTPS mandatory SvcParam');
                        }
                        mandatoryKeys.push(key);
                    }
                    paramString += `mandatory=${mandatoryKeys.map(key => paramNames[key] || `key${key}`).join(',')}, `;
                    break;
                case 1: // Additional supported protocols (文字列のリストであり各文字列の前に 1バイトの長さ)
                    if (paramValBuffer.length === 0) {
                        return malformed('SVCB/HTTPS ALPN SvcParam');
                    }
                    const alpnList = [];
                    let idx = 0;
                    while (idx < paramValBuffer.length) {
                        const len = paramValBuffer[idx];
                        idx += 1;
                        if (len === 0 || idx + len > paramValBuffer.length) {
                            return escapeHtml('malformed SVCB/HTTPS ALPN SvcParam');
                        }
                        // RFC 9460 Appendix A: list escaping precedes character-string escaping.
                        const alpnValue = [];
                        for (const byte of paramValBuffer.subarray(idx, idx + len)) {
                            if (byte === 44 || byte === 92) alpnValue.push(92);
                            alpnValue.push(byte);
                        }
                        alpnList.push(formatDnsOctets(Buffer.from(alpnValue)));
                        idx += len;
                    }
                    paramString += `alpn=${alpnList}, `;
                    break;
                case 2:
                    if (paramValBuffer.length !== 0) {
                        return malformed('SVCB/HTTPS no-default-alpn SvcParam');
                    }
                    paramString += 'no-default-alpn, ';
                    break;
                case 3: // Port for alternative endpoint (2バイトの整数)
                    if (paramValBuffer.length !== 2) {
                        return escapeHtml('malformed SVCB/HTTPS port SvcParam');
                    }
                    paramString += `port=${paramValBuffer.readUInt16BE(0)}, `;
                    break;
                case 4: // IPv4 address hints (4バイトの整数のリスト)
                    if (paramValBuffer.length === 0 || paramValBuffer.length % 4 !== 0) {
                        return escapeHtml('malformed SVCB/HTTPS ipv4hint SvcParam');
                    }
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
                    paramString += `ech=${paramValBuffer.toString('base64')}, `;
                    break;
                case 6: // IPv6 address hints (16バイトの整数のリスト)
                    if (paramValBuffer.length === 0 || paramValBuffer.length % 16 !== 0) {
                        return escapeHtml('malformed SVCB/HTTPS ipv6hint SvcParam');
                    }
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
        if (priority > 0 && (mandatoryKeys.some(key => !paramKeys.has(key)) ||
            (paramKeys.has(2) && !paramKeys.has(1)))) {
            return malformed('SVCB/HTTPS SvcParam self-consistency');
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
    return `<p><strong>WARNING SECTION:</strong></p><div class="section-notice" style="border-left: 4px solid #ff8c00; padding-left: 10px; color: #8a4b00;">${warningHtml}</div>`;
};

const wrapSectionNoticeHtml = (noticeHtml) => {
    if (!noticeHtml || !String(noticeHtml).trim()) {
        return '';
    }
    return `<div class="section-notice" style="border-left: 4px solid #ff8c00; padding-left: 10px; color: #8a4b00;">${noticeHtml}</div>`;
};

const makeHtmlFromDns = (response, bytesRead, origin, pathname, dnsServer, dnsServerIp, domainName, queryType, queryId, recursionDesired, checkingDisabled,
    sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, rawBuf = null, queryClass = 'IN', sendDot = false, ixfrSerial = null) => {
    let html = '';
    let questionName = '';
    let questionType = '';
    let questionClass = '';
    const addQueryLinkToDisplayData = (...args) => addLinkToDisplayData(...args, queryClass, sendDot, '', ixfrSerial);
    const addQueryActionLinkToDisplayData = (...args) => addLinkToDisplayData(...args, queryClass, sendDot, 'notice-action', ixfrSerial);
    const formatSoaMname = (mname) => addLinkToDisplayData(origin, pathname, 'a.root-servers.net', mname, 'A', false, checkingDisabled,
        sendTcp, sendIpv6, false, '', edns0Enable, dnssecOk, udpSize, nsidEnable, '', qnameMinimisation, 255, qnameType, mname, queryClass);
    const authorityNsRecords = (response.authorities || []).filter(record => record.type === 'NS');
    const nameServerAuthorities = new Map();
    let fallbackAuthority = null;
    let fallbackAuthorityLabelCount = -1;
    for (const authority of authorityNsRecords) {
        const normalizedNameServer = normalizeDnsName(authority.data);
        if (!nameServerAuthorities.has(normalizedNameServer)) {
            nameServerAuthorities.set(normalizedNameServer, authority);
        }
        const labelCount = normalizeDnsName(authority.name).split('.').length;
        if (labelCount > fallbackAuthorityLabelCount) {
            fallbackAuthority = authority;
            fallbackAuthorityLabelCount = labelCount;
        }
    }
    const classifyNsRelationship = (zoneName, nameServerName) => {
        const zone = normalizeDnsName(zoneName) || '.';
        const nameServer = normalizeDnsName(nameServerName) || '.';
        const labels = zone === '.' ? [] : zone.split('.');
        const parentZone = labels.length > 1 ? labels.slice(1).join('.') : '.';
        const isWithin = (name, ancestor) => ancestor === '.' || name === ancestor || name.endsWith(`.${ancestor}`);

        if (isWithin(nameServer, zone)) return 'in-domain';
        if (isWithin(nameServer, parentZone)) return 'sibling domain';
        return 'unrelated';
    };
    const getAdditionalRelationship = (record) => {
        const matchingNameServer = nameServerAuthorities.get(normalizeDnsName(record.name));
        const authority = matchingNameServer || fallbackAuthority;
        if (!authority) return '';
        const nameServerName = matchingNameServer ? matchingNameServer.data : record.name;
        return classifyNsRelationship(authority.name, nameServerName);
    };

    html += '<div class="result dns-response" style="text-autospace: normal;"><h3>--- DNSレスポンス解析結果 ---</h3>';
    html += '<h4 class="dns-section-title basic-info-title">基本情報</h4>';
    html += '<dl class="basic-info">';
    html += `<div class="basic-info-item basic-info-item-wide"><dt>対象ドメイン名</dt><dd><code>${escapeHtml(domainName)}</code></dd></div>`;
    if (queryType === 'IXFR' && ixfrSerial !== null) {
        html += `<div class="basic-info-item"><dt>IXFR シリアル番号</dt><dd><code>${escapeHtml(ixfrSerial)}</code></dd></div>`;
    }
    html += `<div class="basic-info-item basic-info-item-wide"><dt>応答したサーバー</dt><dd><code>${escapeHtml(dnsServer)} (${escapeHtml(dnsServerIp)})</code></dd></div>`;
    html += `<div class="basic-info-item"><dt>応答サイズ</dt><dd><code>${bytesRead}</code> byte</dd></div>`;
    html += `<div class="basic-info-item"><dt>プロトコル</dt><dd><code>${sendHttps ? 'HTTPS' : (sendDot ? 'DoT' : (sendTcp ? 'TCP' : 'UDP'))}</code></dd></div>`;
    html += `<div class="basic-info-item"><dt>クエリーID</dt><dd><code>${queryId}</code> <span class="basic-info-status ${response.id === queryId ? 'status-ok' : 'status-warning'}">${response.id === queryId ? '一致' : '不一致'}</span></dd></div>`;
    const opcodeStr = getOpcodeName(response);
    html += `<div class="basic-info-item"><dt>Opcode</dt><dd><code>${escapeHtml(opcodeStr)}</code>${opcodeStr !== 'QUERY' ? ' <span class="basic-info-inline-warning">QUERY 以外の Opcode です</span>' : ''}</dd></div>`;

    // 応答コード (rcode) の取得。Extended RCODE は OPT の TTL 上位オクテットから合成する。
    const rcode = getResponseRcode(response);
    html += `<div class="basic-info-item"><dt>応答ステータス (rcode)</dt><dd><code>${escapeHtml(rcode)}</code></dd></div>`;

    // フラグの取得
    let flagString = '';
    if (response.type === 'response') {
        flagString += '<span class="dns-flag" title="Query / Response">QR</span> ';
    }
    if (response.flags & dnsPacket.RECURSION_DESIRED) {
        flagString += '<span class="dns-flag" title="Recursion Desired">RD</span> ';
    }
    if (response.flags & dnsPacket.RECURSION_AVAILABLE) {
        flagString += '<span class="dns-flag" title="Recursion Available">RA</span> ';
    }
    if (response.flags & dnsPacket.TRUNCATED_RESPONSE) {
        flagString += '<span class="dns-flag dns-flag-warning" title="Truncated Response">TC</span> ';
    }
    if (response.flags & dnsPacket.AUTHORITATIVE_ANSWER) {
        flagString += '<span class="dns-flag" title="Authoritative Answer">AA</span> ';
    }
    if (response.flags & dnsPacket.AUTHENTIC_DATA) {
        flagString += '<span class="dns-flag" title="Authentic Data">AD</span> ';
    }
    if (response.flags & dnsPacket.CHECKING_DISABLED) {
        flagString += '<span class="dns-flag" title="Checking Disabled">CD</span> ';
    }
    if (response.flags & 0x0040) {
        flagString += '<span class="dns-flag dns-flag-warning" title="Reserved">Z</span> ';
    }
    if (flagString !== '') {
        flagString = flagString.slice(0, -1);
    }
    html += `<div class="basic-info-item"><dt>フラグ (flags)</dt><dd class="basic-info-flags">${flagString || '<span class="basic-info-empty">なし</span>'}</dd></div>`;
    html += '</dl>';
    let basicInfoNoticeHtml = '';
    if (!sendTcp && !sendHttps && !sendDot && (response.flags & dnsPacket.TRUNCATED_RESPONSE)) {
        const displayData = addQueryActionLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
            true, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'TCPで再確認');
        basicInfoNoticeHtml += `<aside class="basic-info-notice notice-info" role="note">TCフラグが立っているので TCPでの再確認を推奨します。${displayData}</aside>`;
    }
    if (response.type === 'query') {
        basicInfoNoticeHtml += '<aside class="basic-info-notice notice-warning" role="note">応答 (response) メッセージなのに QRフラグが立っていませんでした。</aside>';
    }
    if (queryType === 'AXFR' && !sendTcp && !sendHttps && !sendDot) {
        const displayData = addLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
            true, sendIpv6, false, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType,
            'TCPで再確認', queryClass, false, 'notice-action', ixfrSerial);
        basicInfoNoticeHtml += `<aside class="basic-info-notice notice-warning" role="note">AXFR クエリーでは TCP での送受信が求められます。RFC 5936 で規定されているため、TCPでの再確認を推奨します。${displayData}</aside>`;
    }
    html += basicInfoNoticeHtml;

    // QUESTION SECTION
    html += `<h4 class="dns-section-title dns-section-question">QUESTION SECTION <span class="section-count">${response.questions?.length || 0} 件</span></h4>`;
    if (response.questions && response.questions.length > 0) {
        html += '<div class="rr-table-wrap"><table class="rr-table rr-table-question"><thead><tr><th scope="col">TYPE</th><th scope="col">NAME</th><th scope="col">CLASS</th></tr></thead><tbody>';
        let questionNoticeHtml = '';
        response.questions.forEach((question) => {
            questionName = question.name;
            questionType = replaceUnknownRrTypeToKnown(question.type);
            questionClass = question.class || 'IN';
            const qnameAnnotation = qnameMinimisation
                ? `<span class="rr-annotation">先頭からのラベル削除数: <code>${escapeHtml(qnamePosition)}</code>個 (QNAME minimisation)</span>`
                : '';
            html += `<tr><th scope="row" data-label="TYPE"><span class="rr-type rr-type-question">${escapeHtml(questionType)}</span></th><td data-label="NAME"><code class="rr-value">${escapeHtml(questionName)}</code>${qnameAnnotation}</td><td data-label="CLASS"><code class="rr-value">${escapeHtml(questionClass)}</code></td></tr>`;
            if (normalizeDnsName(questionName) !== normalizeDnsName(domainName) && !qnameMinimisation) {
                questionNoticeHtml += `<p style="color: red; margin: 0;">QUESTION SECTION のドメイン名が「対象ドメイン名」<code>${escapeHtml(domainName)}</code> と一致しませんでした。</p>`;
            }
        });
        html += '</tbody></table></div>';
        if (questionNoticeHtml) {
            html += wrapSectionNoticeHtml(questionNoticeHtml);
        }
        if (response.questions.length > 1) {
            html += wrapSectionNoticeHtml('<p style="color: red; margin: 0;">QUESTION SECTION に複数の質問が含まれています。</p>');
        }
    } else {
        html += wrapSectionNoticeHtml(`<p style="color: red; margin: 0;">応答に QUESTION SECTION が存在しませんでした。</p>`);
    }

    // ANSWER SECTION について応答コードに応じた条件分岐
    html += `<h4 class="dns-section-title dns-section-answer">ANSWER SECTION <span class="section-count">${response.answers.length} 件</span></h4>`;
    let answerNoticeHtml = '';
    if (rcode === 'SERVFAIL') {
        answerNoticeHtml += `<p style="color: red; margin: 0;">SERVFAIL: 応答したサーバー <code>${escapeHtml(dnsServer)}</code> で一時的なエラーが発生したか、設定に問題があります。</p>`;
        if (recursionDesired && !checkingDisabled) {
            const displayData = addQueryActionLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, true,
                sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'CDフラグで再確認');
            answerNoticeHtml += `<p style="color: #E65C00; margin: 0;">※DNSSEC検証に失敗した可能性があります。${displayData}</p>`;
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
                if (response.authorities && response.authorities.length > 0) {
                    const soaRr = response.authorities.find(at => at.type === 'SOA');
                    if (soaRr) {
                        if (soaRr.name !== questionName) {
                            answerNoticeHtml += `<p style="color: red; margin: 0;">※応答したサーバー <code>${escapeHtml(dnsServer)}</code> が RFC 8020 に対応していないようです。</p>`;
                        }
                        const displayData = addQueryActionLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
                            sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'ラベルを増やして確認');
                        answerNoticeHtml += `<p style="color: #E65C00; margin: 0;">※QNAME minimisation が有効になっています。${displayData}</p>`;
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
                    if (response.authorities && response.authorities.length > 0) {
                        const soaRr = response.authorities.find(at => at.type === 'SOA');
                        if (soaRr) {
                            const displayData = addQueryActionLinkToDisplayData(origin, pathname, dnsServer, domainName, queryType, recursionDesired, checkingDisabled,
                                sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, 'ラベルを増やして確認');
                            answerNoticeHtml += `<p style="color: #E65C00; margin: 0;">※QNAME minimisation が有効になっています。${displayData}</p>`;
                        }
                    }
                }
            }
        }
    } else {
        answerNoticeHtml += `<p style="color: gray; margin: 0;">その他の応答コード: ${escapeHtml(rcode)}</p>`;
    }
    if (response.answers && response.answers.length > 0) {
        html += '<div class="rr-table-wrap"><table class="rr-table"><thead><tr><th scope="col">TYPE</th><th scope="col">NAME</th><th scope="col">CLASS</th><th scope="col">DATA</th><th scope="col">TTL</th></tr></thead><tbody>';
        if (qnameMinimisation && qnamePosition > 0) {
            qnamePosition--;
        }
        response.answers.forEach((answer) => {
            let displayData = decodeResourceRecord(answer.type, answer.data, formatSoaMname);
            if (displayData.length === 0) {
                if (answer.type === 'CNAME') {
                    // CNAMEレコードはデータを検索対象ドメイン名として扱い、後続の検索ができるようにする
                    displayData = addQueryLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, queryType, false, checkingDisabled,
                        sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                    if (rcode === 'NXDOMAIN') {
                        answerNoticeHtml += `<p style="color: red; margin: 0;">※<b>CNAME</b> を辿った最終的な情報を、応答したサーバー <code>${escapeHtml(dnsServer)}</code> は保持していませんでした (RFC 8020)。</p>`;
                    }
                } else if (answer.type === 'NS') {
                    if (qnameMinimisation) {
                        if (normalizeDnsName(answer.name) === normalizeDnsName(domainName)) {
                            displayData = addQueryLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'A', false, checkingDisabled,
                                sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                        } else {
                            displayData = addQueryLinkToDisplayData(origin, pathname, answer.data, domainName, queryType, recursionDesired, checkingDisabled,
                                sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, answer.data);
                        }
                    } else {
                        // NSが、自身の IPアドレスの情報を持っていない場合がある (例： ns014-fc9tjt3ao0p42dr4.f.d-53.info)
                        displayData = addQueryLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'A', false, checkingDisabled,
                            sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data);
                    }
                } else if (answer.type === 'MX') {
                    displayData = `preference: ${answer.data.preference}, exchange: `;
                    displayData += addQueryLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data.exchange, 'A', false, checkingDisabled,
                        sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, 255, qnameType, answer.data.exchange);
                } else if (answer.type === 'PTR') {
                    displayData = addQueryLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'A', false, checkingDisabled,
                        sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, false, 255, qnameType, answer.data);
                } else if (answer.type === 'A' || answer.type === 'AAAA') {
                    displayData = addQueryLinkToDisplayData(origin, pathname, 'a.root-servers.net', answer.data, 'PTR-x', false, checkingDisabled,
                        sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, false, 255, qnameType, answer.data);
                } else if (typeof answer.data === 'object') {
                    // オブジェクト構造を持つデータ用
                    displayData = escapeHtml(JSON.stringify(answer.data));
                } else {
                    // Aレコード (文字列のIPアドレス) など通常データ用
                    displayData = escapeHtml(answer.data);
                }
            }
            const answerType = replaceUnknownRrTypeToKnown(escapeHtml(answer.type));
            const answerClass = answer.class || 'IN';
            html += `<tr><th scope="row" data-label="TYPE"><span class="rr-type rr-type-answer">${answerType}</span></th><td data-label="NAME"><code class="rr-value">${escapeHtml(answer.name)}</code></td><td data-label="CLASS"><code class="rr-value">${escapeHtml(answerClass)}</code></td><td data-label="DATA"><code class="rr-value">${displayData}</code></td><td data-label="TTL"><span class="rr-ttl">${parseInt(answer.ttl, 10)}秒</span></td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    if (answerNoticeHtml) {
        html += wrapSectionNoticeHtml(answerNoticeHtml);
    }

    // AUTHORITY が返ってきた場合
    html += `<h4 class="dns-section-title dns-section-authority">AUTHORITY SECTION <span class="section-count">${response.authorities.length} 件</span></h4>`;
    if (response.authorities && response.authorities.length > 0) {
        html += '<div class="rr-table-wrap"><table class="rr-table"><thead><tr><th scope="col">TYPE</th><th scope="col">NAME</th><th scope="col">CLASS</th><th scope="col">DATA</th><th scope="col">TTL</th></tr></thead><tbody>';
        response.authorities.forEach((authorities) => {
            let displayData = decodeResourceRecord(authorities.type, authorities.data, formatSoaMname);
            if (displayData.length === 0) {
                if (authorities.type === 'NS') {
                    displayData = addQueryLinkToDisplayData(origin, pathname, authorities.data, domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, authorities.data);
                } else if (typeof authorities.data === 'object') {
                    // オブジェクト構造を持つデータ用
                    displayData = escapeHtml(JSON.stringify(authorities.data));
                } else {
                    // Aレコード (文字列のIPアドレス) など通常データ用
                    displayData = escapeHtml(authorities.data);
                }
            }
            const authoritiesType = replaceUnknownRrTypeToKnown(escapeHtml(authorities.type));
            const authoritiesClass = authorities.class || 'IN';
            const relationship = authorities.type === 'NS'
                ? `<span class="rr-annotation">RFC 9499: ${classifyNsRelationship(authorities.name, authorities.data)}</span>`
                : '';
            html += `<tr><th scope="row" data-label="TYPE"><span class="rr-type">${authoritiesType}</span></th><td data-label="NAME"><code class="rr-value">${escapeHtml(authorities.name)}</code></td><td data-label="CLASS"><code class="rr-value">${escapeHtml(authoritiesClass)}</code></td><td data-label="DATA"><code class="rr-value">${displayData}</code>${relationship}</td><td data-label="TTL"><span class="rr-ttl">${parseInt(authorities.ttl, 10)}秒</span></td></tr>`;
        });
        html += '</tbody></table></div>';
    } else {
        html += wrapSectionNoticeHtml('<p style="color: #E65C00; margin: 0;">権威サーバーの情報は見つかりませんでした。</p>');
    }

    // ADDITIONAL が返ってきた場合
    const additionalRecordCount = response.additionals.filter((record) => record.type !== 'OPT').length;
    html += `<h4 class="dns-section-title dns-section-additional">ADDITIONAL SECTION <span class="section-count">${additionalRecordCount} 件</span></h4>`;
    if (response.additionals && response.additionals.length > 0) {
        let optPseudoItems = [];
        let optError = '';
        if (additionalRecordCount > 0) {
            html += '<div class="rr-table-wrap"><table class="rr-table"><thead><tr><th scope="col">TYPE</th><th scope="col">NAME</th><th scope="col">CLASS</th><th scope="col">DATA</th><th scope="col">TTL</th></tr></thead><tbody>';
        }
        response.additionals.forEach((additionals) => {
            let displayData = decodeResourceRecord(additionals.type, additionals.data, formatSoaMname);
            if (displayData.length === 0) {
                if (additionals.type === 'A' || additionals.type === 'AAAA') {
                    displayData = addQueryLinkToDisplayData(origin, pathname, additionals.data, domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, additionals.data);
                } else if (additionals.type === 'OPT') {
                    if (additionals.name === '.') {
                        // EDNS0
                        const optRecord = additionals;
                        let flagString = '';
                        let nsidString = '';
                        let nsidFound = false;
                        const edeItems = [];
                        const optionItems = [];
                        let mQTypeString = '';
                        let mQTypeResponseFound = false;
                        let mQTypeResponseInvalid = false;
                        let mQTypeResponseCount = 0;
                        let mQTypeQueryFound = false;
                        const ednsFlags = [];
                        if (optRecord.flags & DNSSEC_OK) {
                            ednsFlags.push('<span class="dns-flag" title="DNSSEC OK">DO</span>');
                        }
                        if (optRecord.flags & COMPACT_ANSWERS_OK) {
                            ednsFlags.push('<span class="dns-flag" title="Compact Answers OK">CO</span>');
                        }
                        flagString = ednsFlags.join(' ');
                        for (const option of optRecord.options) {
                            const optionData = Buffer.isBuffer(option.data) ? option.data : Buffer.from(option.data || '');
                            const optionName = escapeHtml(option.type || `OPTION_${option.code}`);
                            const optionHex = escapeHtml(optionData.toString('hex'));
                            if (getEdnsOptionDataError(option)) {
                                optionItems.push(`<li><strong>EDNS Option</strong><code>${optionName} (${escapeHtml(option.code)}): ${optionHex || '(empty)'}</code></li>`);
                                continue;
                            }
                            if (option.code === 3) {
                                nsidFound = true;
                                nsidString = `text: ${escapeHtml(optionData.toString('utf8'))}, hex: ${optionData.toString('hex')}`;
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
                                    optionItems.push(`<li><strong>ECS</strong><code>family: ${familyStr}, sourcePrefix: ${sourcePrefix}, scopePrefix: ${scopePrefix}, address: ${escapeHtml(addrStr)}</code></li>`);
                                } else {
                                    optionItems.push(`<li><strong>EDNS Option</strong><code>${optionName} (${escapeHtml(option.code)}): ${optionHex || '(empty)'}</code></li>`);
                                }
                            } else if (option.code === 10 && Buffer.isBuffer(option.data)) {
                                const buffer = option.data;
                                if (buffer.length >= 8) {
                                    const clientCookie = buffer.subarray(0, 8).toString('hex');
                                    const serverCookie = buffer.length > 8 ? buffer.subarray(8).toString('hex') : '(none)';
                                    optionItems.push(`<li><strong>Cookie</strong><code>Client Cookie: ${clientCookie}, Server Cookie: ${serverCookie}</code></li>`);
                                } else {
                                    optionItems.push(`<li><strong>EDNS Option</strong><code>${optionName} (${escapeHtml(option.code)}): ${optionHex || '(empty)'}</code></li>`);
                                }
                            } else if (option.code === 12 && Buffer.isBuffer(option.data)) {
                                optionItems.push(`<li><strong>Padding</strong><code>length: ${option.data.length} bytes</code></li>`);
                            } else if (option.code === 15 && Buffer.isBuffer(option.data)) {
                                const buffer = option.data;
                                if (buffer.length < 2) {
                                    optionItems.push(`<li><strong>${optionName}</strong><code>code: ${escapeHtml(option.code)}, data: ${optionHex}</code></li>`);
                                    continue;
                                }
                            } else if (option.code === 20) {
                                mQTypeQueryFound = true;
                            } else if (option.code !== 21) {
                                optionItems.push(`<li><strong>EDNS Option</strong><code>${optionName} (${escapeHtml(option.code)}): ${optionHex || '(empty)'}</code></li>`);
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
                                edeItems.push(`<li><strong>EDE</strong><code>${edeTemp}</code></li>`);
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
                                const responseTypes = new Set();
                                for (let offset = 0; offset < buffer.length; offset += 2) {
                                    const type = buffer.readUInt16BE(offset);
                                    if (responseTypes.has(type) || type === primaryTypeCode || type === 0 || type === 41 ||
                                        type === 65535 || (type >= 128 && type <= 255)) {
                                        mQTypeResponseInvalid = true;
                                    }
                                    responseTypes.add(type);
                                    mQTypeString += `${replaceUnknownRrTypeToKnown(dnsTypes.toString(type))},`;
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
                            optError = '<p style="color: #E65C00; margin: 0;">MQTYPE-Response がありません。サーバーが RFC 10029 に対応していない可能性があります。</p>';
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
                        optPseudoItems = [`<li><strong>EDNS</strong><code>Extended RCODE: ${extendedRcodeDisplay}, Version: ${optRecord.ednsVersion ?? 0}, flags: ${flagString}, UDP payload size: ${optRecord.udpPayloadSize}</code></li>`];
                        if (nsidFound) {
                            optPseudoItems.push(`<li><strong>NSID</strong><code>${nsidString || '(empty)'}</code></li>`);
                        }
                        optPseudoItems.push(...optionItems, ...edeItems);
                        if (mQTypeResponseFound) {
                            optPseudoItems.push(`<li><strong>MQTYPE-Response</strong><code>${mQTypeString || '(empty)'}</code></li>`);
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
                const additionalsClass = additionals.class || 'IN';
                const additionalRelationship = ['A', 'AAAA'].includes(additionals.type)
                    ? getAdditionalRelationship(additionals)
                    : '';
                const relationship = additionalRelationship ? `<span class="rr-annotation">RFC 9499: ${additionalRelationship}</span>` : '';
                html += `<tr><th scope="row" data-label="TYPE"><span class="rr-type">${additionalsType}</span></th><td data-label="NAME"><code class="rr-value">${escapeHtml(additionals.name)}</code></td><td data-label="CLASS"><code class="rr-value">${escapeHtml(additionalsClass)}</code></td><td data-label="DATA"><code class="rr-value">${displayData}</code>${relationship}</td><td data-label="TTL"><span class="rr-ttl">${parseInt(additionals.ttl, 10)}秒</span></td></tr>`;
            }
        });
        if (additionalRecordCount > 0) {
            html += '</tbody></table></div>';
        }
        if (optPseudoItems.length > 0) {
            if (response.additionals.length === 1) {
                html += wrapSectionNoticeHtml('<p style="color: #E65C00; margin: 0;">追加の情報は見つかりませんでしたがオプション情報が見つかりました。</p>');
            }
            html += `<h4 class="dns-section-title dns-section-opt">OPT PSEUDOSECTION <span class="section-count">${optPseudoItems.length} 項目</span></h4>`;
            html += `<ul class="opt-pseudo-list">${optPseudoItems.join('')}</ul>`;
            if (optError.length > 0) {
                html += wrapSectionNoticeHtml(optError);
            }
        }
    } else {
        html += wrapSectionNoticeHtml('<p style="color: #E65C00; margin: 0;">追加の情報は見つかりませんでした。</p>');
    }

    const tcpFramed = (sendTcp || sendDot) && !sendHttps;
    const warningHtml = getOptPseudoSectionStatusHtml(response, rawBuf && tcpFramed ? rawBuf.subarray(2) : rawBuf);
    if (warningHtml) {
        html += buildWarningSectionHtml(warningHtml);
    }
    const packetWarning = rawBuf ? analyzeDnsPacketError(rawBuf, null, tcpFramed) : '';
    if (packetWarning) {
        html += buildWarningSectionHtml(packetWarning);
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
        } else if (type === 64 || type === 65) {
            const recordType = type === 64 ? 'SVCB' : 'HTTPS';
            if (rdataBuf.length < 3) {
                throw new Error(`${sectionName} (${escapeHtml(name)}) の ${recordType} レコードの RDATA が短すぎます`);
            }

            let rOffset = 2;
            while (true) {
                if (rOffset >= rdataBuf.length) {
                    throw new Error(`${sectionName} (${escapeHtml(name)}) の ${recordType} レコードの TargetName に終端ラベルがありません`);
                }
                const labelLength = rdataBuf[rOffset++];
                if (labelLength === 0) break;
                if (labelLength > 63) {
                    throw new Error(`${sectionName} (${escapeHtml(name)}) の ${recordType} レコードの TargetName のラベル長 (${labelLength} バイト) が RFC 1035 の最大長 (63 バイト) を超えています`);
                }
                if (rOffset + labelLength > rdataBuf.length) {
                    throw new Error(`${sectionName} (${escapeHtml(name)}) の ${recordType} レコードの TargetName のラベル長 (${labelLength} バイト) が残りの RDATA 長 (${rdataBuf.length - rOffset} バイト) を超過しています`);
                }
                rOffset += labelLength;
            }

            while (rOffset < rdataBuf.length) {
                if (rOffset + 4 > rdataBuf.length) {
                    throw new Error(`${sectionName} (${escapeHtml(name)}) の ${recordType} レコードの SvcParam ヘッダー (4 バイト) に対し、RDATA の残りが ${rdataBuf.length - rOffset} バイトしかありません`);
                }
                const paramLength = rdataBuf.readUInt16BE(rOffset + 2);
                rOffset += 4;
                if (rOffset + paramLength > rdataBuf.length) {
                    throw new Error(`${sectionName} (${escapeHtml(name)}) の ${recordType} レコードの SvcParam の長さ (${paramLength} バイト) が残りの RDATA 長 (${rdataBuf.length - rOffset} バイト) を超過しています`);
                }
                rOffset += paramLength;
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

const isValidIPv6 = (ip) => {
    if (typeof ip !== 'string') return false;
    return net.isIP(ip.trim()) === 6;
};

const isValidIPv4 = (ip) => {
    if (typeof ip !== 'string') return false;
    return net.isIP(ip.trim()) === 4;
};

// SSRF 対策: 問い合わせ先はグローバルに到達可能なユニキャストアドレスのみ許可する (許可リスト方式)
// IPv6 はグローバルユニキャスト (2000::/3) 以外をすべて拒否するため、::、::1、::ffff:0:0/96 (IPv4射影)、
// ::/96 (IPv4互換)、64:ff9b::/96 (NAT64)、fc00::/7、fe80::/10、fec0::/10、ff00::/8 なども拒否される
const GLOBAL_UNICAST_IPV6 = new net.BlockList();
GLOBAL_UNICAST_IPV6.addSubnet('2000::', 3, 'ipv6');

const NON_PUBLIC_ADDRESSES = new net.BlockList();
[
    ['0.0.0.0', 8],         // "this network" (0.0.0.0 はループバックに到達する)
    ['10.0.0.0', 8],        // プライベート
    ['100.64.0.0', 10],     // CGNAT 共有アドレス (クラウドの内部DNSを含む)
    ['127.0.0.0', 8],       // ループバック
    ['169.254.0.0', 16],    // リンクローカル (クラウドのメタデータ・内部DNSを含む)
    ['172.16.0.0', 12],     // プライベート
    ['192.0.0.0', 24],      // IETF プロトコル割り当て
    ['192.0.2.0', 24],      // 文書用 (TEST-NET-1)
    ['192.88.99.0', 24],    // 6to4 リレーエニーキャスト (廃止)
    ['192.168.0.0', 16],    // プライベート
    ['198.18.0.0', 15],     // ベンチマーク用
    ['198.51.100.0', 24],   // 文書用 (TEST-NET-2)
    ['203.0.113.0', 24],    // 文書用 (TEST-NET-3)
    ['224.0.0.0', 4],       // マルチキャスト
    ['240.0.0.0', 4]        // 予約 (255.255.255.255 を含む)
].forEach(([address, prefix]) => NON_PUBLIC_ADDRESSES.addSubnet(address, prefix, 'ipv4'));
[
    ['2001::', 23],         // IETF プロトコル割り当て (Teredo、ORCHID、ベンチマーク等)
    ['2001:db8::', 32],     // 文書用
    ['2002::', 16],         // 6to4 (内部の IPv4 アドレスを埋め込める)
    ['3fff::', 20]          // 文書用 (RFC 9637)
].forEach(([address, prefix]) => NON_PUBLIC_ADDRESSES.addSubnet(address, prefix, 'ipv6'));

const isPublicUnicastAddress = (ip) => {
    if (typeof ip !== 'string') return false;
    const value = ip.trim();
    // ゾーンID付きアドレス (fe80::1%eth0 等) は拒否
    if (value.includes('%')) return false;
    const family = net.isIP(value);
    if (family === 4) {
        return !NON_PUBLIC_ADDRESSES.check(value, 'ipv4');
    }
    if (family === 6) {
        return GLOBAL_UNICAST_IPV6.check(value, 'ipv6') && !NON_PUBLIC_ADDRESSES.check(value, 'ipv6');
    }
    return false;
};

const DNS_SERVER_HOSTNAME_PATTERN = /^(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.?$/;

const isInvalidDnsServer = (dnsServer) => {
    const value = (typeof dnsServer === 'string' ? dnsServer : '').trim();
    if (value === '') return true;
    if (net.isIP(value) || value.includes('%')) {
        return !isPublicUnicastAddress(value);
    }
    // ホスト名は英数字・ハイフン・アンダースコアのラベルのみ許可する (SNI/Hostヘッダーにも使用するため)
    if (!DNS_SERVER_HOSTNAME_PATTERN.test(value) || value.replace(/\.$/, '').length > 253) {
        return true;
    }
    const hostName = value.toLowerCase().replace(/\.$/, '');
    return hostName === 'localhost' || hostName.endsWith('.localhost');
};

const isInvalidUdpSize = (udpSize) => {
    const numeric = Number(udpSize);
    return !Number.isInteger(numeric) || numeric < 512 || 65535 < numeric;
};

const isInvalidHttpsPath = (httpsPath) => {
    return !/^\/[!-~]*$/.test(httpsPath) || httpsPath.length > 512;
};

const { SUPPORTED_QUERY_TYPES, SUPPORTED_QUERY_CLASSES } = require('./dns-query-options');

const isInvalidQueryType = (queryType) => {
    return !SUPPORTED_QUERY_TYPES.includes(queryType);
};

const isInvalidQueryClass = (queryClass) => {
    return !SUPPORTED_QUERY_CLASSES.includes(queryClass) || dnsClasses.toClass(queryClass) === 0;
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
//    if (qClass !== 'IN' || primaryType === 'ANY') {
    if (qClass !== 'IN') {
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

const isMatchingDnsResponse = (response, query) => {
    if (!response || response.id !== query.id) {
        return false;
    }
    const question = response.questions?.[0];
    if (!question) {
        return true;
    }
    return question.type === query.questions[0].type &&
        question.class === query.questions[0].class &&
        normalizeDnsName(question.name) === normalizeDnsName(query.questions[0].name);
};

const queryAuthoritativeServerOverTcp = (serverAddress, query) => new Promise((resolve, reject) => {
    const client = new net.Socket({ family: net.isIP(serverAddress) === 6 ? 6 : 4 });
    let responseBuffer = Buffer.alloc(0);
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
        while (responseBuffer.length >= 2) {
            const messageLength = responseBuffer.readUInt16BE(0);
            if (responseBuffer.length < messageLength + 2) {
                return;
            }
            const frame = responseBuffer.subarray(0, messageLength + 2);
            responseBuffer = responseBuffer.subarray(messageLength + 2);
            try {
                const response = dnsPacket.streamDecode(frame);
                if (!isMatchingDnsResponse(response, query)) {
                    continue;
                }
                finish(() => resolve(response));
                return;
            } catch (error) {
                finish(() => reject(error));
                return;
            }
        }
    });
    client.once('error', (error) => {
        finish(() => reject(error));
    });
    client.once('close', (hadError) => {
        finish(() => {
            reject(new Error(`${serverAddress} から TCP 接続が切断されました。`));
        });
    });
    client.connect(53, serverAddress);
});

const queryAuthoritativeServerOverTls = (serverAddress, serverName, query, connect = tls.connect) => new Promise((resolve, reject) => {
    const options = { host: serverAddress, port: 853 };
    if (!net.isIP(serverName)) {
        options.servername = serverName;
    }
    const client = connect(options);
    let responseBuffer = Buffer.alloc(0);
    let expectedLength = 0;
    let settled = false;
    const finish = (callback) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);
        client.destroy();
        callback();
    };
    const timeoutId = setTimeout(() => {
        finish(() => reject(new Error(`${serverName} から DoT 応答がありませんでした。`)));
    }, 5000);

    client.once('secureConnect', () => {
        client.write(dnsPacket.streamEncode(query));
    });
    client.on('data', (data) => {
        responseBuffer = Buffer.concat([responseBuffer, data]);
        if (expectedLength === 0 && responseBuffer.length >= 2) {
            expectedLength = responseBuffer.readUInt16BE(0) + 2;
        }
        if (expectedLength > 0 && responseBuffer.length >= expectedLength) {
            const frame = responseBuffer.subarray(0, expectedLength);
            try {
                const response = dnsPacket.streamDecode(frame);
                finish(() => resolve({ response, rawBuffer: frame }));
            } catch (error) {
                finish(() => reject(error));
            }
        }
    });
    client.once('error', (error) => {
        finish(() => reject(error));
    });
});

const queryAuthoritativeServer = (serverAddress, name, type, createSocket = dgram.createSocket,
    queryOverTcp = queryAuthoritativeServerOverTcp, sendTcp = false, queryClass = 'IN') => new Promise((resolve, reject) => {
    const query = {
        type: 'query',
        id: Math.floor(Math.random() * 65535),
        questions: [{ name, type, class: queryClass }]
    };
    if (sendTcp) {
        queryOverTcp(serverAddress, query).then(resolve, reject);
        return;
    }
    const client = createSocket(net.isIP(serverAddress) === 6 ? 'udp6' : 'udp4');
    const packet = dnsPacket.encode(query);
    const timeoutId = setTimeout(() => {
        client.close();
        reject(new Error(`${serverAddress} から UDP 応答がありませんでした。`));
    }, 2000);

    client.on('message', (message, rinfo) => {
        if (rinfo && rinfo.address !== serverAddress) {
            return;
        }
        try {
            const response = dnsPacket.decode(message);
            if (!isMatchingDnsResponse(response, query)) {
                return;
            }
            clearTimeout(timeoutId);
            client.close();
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

// 応答しない委任先を細工したドメイン名で 1リクエストが長時間・大量の問い合わせを行わないよう、
// DNSサーバー名の解決全体 (入れ子の解決や IPv6 へのフォールバックを含む) で時間と問い合わせ回数に上限を設ける
const DNS_SERVER_RESOLUTION_DEADLINE_MS = 10000;
const DNS_SERVER_RESOLUTION_MAX_QUERIES = 50;

class ResolutionBudgetExceededError extends Error {}

const createResolutionBudget = (deadlineMs = DNS_SERVER_RESOLUTION_DEADLINE_MS, maxQueries = DNS_SERVER_RESOLUTION_MAX_QUERIES) => ({
    deadline: Date.now() + deadlineMs,
    deadlineMs,
    maxQueries,
    remainingQueries: maxQueries
});

const queryWithinBudget = (budget, runQuery) => {
    const message = `DNSサーバー名の解決が上限 (${budget.deadlineMs / 1000} 秒・問い合わせ ${budget.maxQueries} 回) を超えたため中止しました。`;
    const remainingMs = budget.deadline - Date.now();
    if (remainingMs <= 0 || budget.remainingQueries <= 0) {
        return Promise.reject(new ResolutionBudgetExceededError(message));
    }
    budget.remainingQueries--;
    let timerId;
    const deadline = new Promise((_, reject) => {
        timerId = setTimeout(() => reject(new ResolutionBudgetExceededError(message)), remainingMs);
    });
    return Promise.race([Promise.resolve().then(runQuery), deadline]).finally(() => clearTimeout(timerId));
};

const resolveDnsServerAddress = async (dnsServer, preferIpv6, resolutionDepth = 0,
    queryServer = queryAuthoritativeServer, sendTcp = false, budget = createResolutionBudget()) => {
    try {
        return await resolveDnsServerAddressByType(dnsServer, preferIpv6, resolutionDepth, queryServer, sendTcp, budget);
    } catch (error) {
        if (preferIpv6 || error instanceof ResolutionBudgetExceededError) {
            throw error;
        }
        try {
            return await resolveDnsServerAddressByType(dnsServer, true, resolutionDepth, queryServer, sendTcp, budget);
        } catch (subError) {
            throw error;
        }
    }
};

const resolveDnsServerAddressByType = async (dnsServer, preferIpv6, resolutionDepth = 0,
    queryServer = queryAuthoritativeServer, sendTcp = false, budget = createResolutionBudget()) => {
    if (net.isIP(dnsServer)) return dnsServer;
    if (resolutionDepth >= 5) {
        throw new Error('DNSサーバー名の解決で入れ子の委任が上限を超えました。');
    }

    const queryType = preferIpv6 ? 'AAAA' : 'A';
    let queryName = normalizeDnsName(dnsServer);
    let nameServers = ROOT_SERVERS;

    for (let depth = 0; depth < 20; depth++) {
        let response;
        let lastError;
        for (const nameServer of nameServers) {
            try {
                response = await queryWithinBudget(budget,
                    () => queryServer(nameServer, queryName, queryType, dgram.createSocket, queryAuthoritativeServerOverTcp, sendTcp));
                break;
            } catch (error) {
                if (error instanceof ResolutionBudgetExceededError) {
                    throw error;
                }
                lastError = error;
                // 同じ委任先の次の権威サーバーを試す。
            }
        }
        if (!response) {
            if (lastError) {
                throw lastError;
            }
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
            let lastSubError;
            for (const delegatedName of delegatedNames) {
                try {
                    resolvedNameServerAddress = await resolveDnsServerAddress(delegatedName, preferIpv6, resolutionDepth + 1, queryServer, sendTcp, budget);
                    break;
                } catch (error) {
                    if (error instanceof ResolutionBudgetExceededError) {
                        throw error;
                    }
                    lastSubError = error;
                    // 他の委任先NSの名前解決を試す。
                }
            }
            if (!resolvedNameServerAddress) {
                if (lastSubError) {
                    throw lastSubError;
                }
                throw new Error(`委任先 ${delegatedZone} のIPアドレスを取得できませんでした。`);
            }
            nameServers = [resolvedNameServerAddress];
            continue;
        }
        nameServers = glueAddresses;
    }
    throw new Error('DNSサーバー名の解決で委任を辿る回数が上限を超えました。');
};

const APPLICATION_PATH = process.env.APPLICATION_PATH || '/dns-query-tool';

// DNSメッセージは TCP の長さプレフィックス (2バイト) を含めても 65537 バイトを超えない
const MAX_DNS_MESSAGE_BYTES = 65535;
const MAX_DNS_TCP_FRAME_BYTES = MAX_DNS_MESSAGE_BYTES + 2;
// AXFR/IXFR は複数メッセージで返されるため上限を別に設ける
const MAX_ZONE_TRANSFER_RESPONSE_BYTES = 4 * 1024 * 1024;
const DNS_RESPONSE_TIMEOUT_MS = 5000;
// 応答を少しずつ送り続ける相手に接続を占有されないよう、通信全体の上限時間を設ける
const DNS_SESSION_DEADLINE_MS = 15000;

const SECURITY_HEADERS = Object.freeze({
    'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin'
});

const server = http.createServer((req, res) => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
        res.setHeader(name, value);
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8', 'Allow': 'GET, HEAD' });
        res.end('Method Not Allowed');
        return;
    }
    handleRequest(req, res).catch((error) => {
        // 想定外の例外でプロセスが停止しないようにし、詳細はクライアントへ返さずログにのみ残す
        console.error(`リクエスト処理中の予期しないエラー: ${String(error && error.stack || error).replace(/[\r\n]+/g, ' | ')}`);
        if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end('<div class="result error"><p>エラー: 内部エラーが発生しました。</p></div>');
        } else {
            res.destroy();
        }
    });
});

const handleRequest = async (req, res) => {
    if (req.url === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
    }

    // WHATWG URL API を使用、req.url は相対パスのため第2引数に固定のダミーベースURLを設定
    // (Hostヘッダーは利用者が任意に指定でき、不正な値だと例外になるため使用しない)
    const parsedUrl = new URL(req.url, 'http://localhost/');
    if (parsedUrl.pathname === APPLICATION_PATH || parsedUrl.pathname.startsWith(`${APPLICATION_PATH}/`)) {
        parsedUrl.pathname = parsedUrl.pathname.slice(APPLICATION_PATH.length) || '/';
    }
    const staticFiles = {
        '/': { file: 'index.html', contentType: 'text/html; charset=utf-8' },
        '/index.html': { file: 'index.html', contentType: 'text/html; charset=utf-8' },
        '/dig.html': { file: 'dig.html', contentType: 'text/html; charset=utf-8' },
        '/dns-query-tool.css': { file: 'dns-query-tool.css', contentType: 'text/css; charset=utf-8' },
        '/dns-query-options.js': { file: 'dns-query-options.js', contentType: 'application/javascript; charset=utf-8' },
        '/dig-command.js': { file: 'dig-command.js', contentType: 'application/javascript; charset=utf-8' },
        '/dig-client.js': { file: 'dig-client.js', contentType: 'application/javascript; charset=utf-8' },
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
    const rawQueryClass = params.get('class') || 'IN';
    const rawIxfrSerial = params.get('ixfrserial');
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
    const sendHttps = params.get('https') === '1';
    const sendDot = params.get('dot') === '1';
    const rawHttpsPath = params.get('httpspath') || '/dns-query';

    // 入力値は生の値のまま検証・DNS問い合わせに使い、HTMLへ出力する箇所で escapeHtml() する
    const dnsServer = rawDnsServer.trim();
    let domainName = rawDomainName.trim().replace(/\\/g, '');
    let queryType = rawQueryType;
    const queryClass = rawQueryClass.trim().toUpperCase();
    let qnamePosition = rawQnamePosition.trim();
    const qnameType = rawQnameType === 'NS' ? 'NS' : 'A';
    const udpSize = rawUdpSize.trim();
    const mQType = rawMQtype.trim();
    const httpsPath = rawHttpsPath.trim() || '/dns-query';
    let html = '';

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
        html += `<div class="result error"><p>エラー: 不正なクエリータイプです (${escapeHtml(queryType)} は不正です)。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    if (isInvalidQueryClass(queryClass)) {
        html += `<div class="result error"><p>エラー: 不正なクエリークラスです (${escapeHtml(queryClass)} は不正です)。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    let ixfrSerial = null;
    if (queryType === 'IXFR') {
        if (rawIxfrSerial === null || !/^[0-9]+$/.test(rawIxfrSerial) || Number(rawIxfrSerial) > 0xffffffff) {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end('<div class="result error"><p>エラー: IXFR シリアル番号を 0～4294967295 の整数で指定してください。</p></div>');
            return;
        }
        ixfrSerial = Number(rawIxfrSerial);
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
        html += `<div class="result error"><p>エラー: UDPメッセージサイズを入力し直してください (${escapeHtml(udpSize)} は不正です)。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    // DoHエンドポイントパスのチェック
    if (sendHttps && isInvalidHttpsPath(httpsPath)) {
        html += `<div class="result error"><p>エラー: DoHエンドポイントパスを入力し直してください (${escapeHtml(httpsPath)} は不正です)。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    let dnsServerAddress;
    try {
        dnsServerAddress = await resolveDnsServerAddress(dnsServer, sendIpv6, 0, queryAuthoritativeServer, sendTcp);
    } catch (error) {
        html += `<div class="result error"><p>エラー: DNSサーバー名を解決できませんでした: ${escapeHtml(error.message)}</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    // DNSクエリーメッセージの構築
    let qType = replaceKnownToUnknownRrType(queryType);
    let qClass = queryClass;
    let qName = domainName;
    const qId = Math.floor(Math.random() * 65535);
    if (qName !== '.' && qName.endsWith('.')) {
        qName = qName.slice(0, -1);	// 最後の '.' を削除
    }
    if (queryType === 'PTR-x') {
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
    if (qType === 'IXFR') {
        // RFC 1995: SERIAL 以外の SOA RDATA フィールドは 0 / ルート名で送信する。
        queryPacket.authorities = [{
            type: 'SOA',
            name: qName,
            class: qClass,
            ttl: 0,
            data: {
                mname: '.',
                rname: '.',
                serial: ixfrSerial,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0
            }
        }];
    }
    if (edns0Enable) {
        const edns0Option = {
            type: 'OPT',
            name: '.',
            udpPayloadSize: udpSize,
            flags: dnssecOk ? DNSSEC_OK : 0
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
        if ((sendTcp || sendDot) && !sendHttps) {
            buf = dnsPacket.streamEncode(queryPacket);
        } else {
            buf = dnsPacket.encode(queryPacket);
        }
    } catch (e) {
        html += `<div class="result error"><p>エラー: 入力されたドメイン名の形式が正しくありません。</p></div>`;
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
        return;
    }

    if (sendHttps) {
        let isResponded = false;
        const respondOnce = (fragment) => {
            if (isResponded) return false;
            isResponded = true;
            clearTimeout(deadlineId);
            html += fragment;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
            return true;
        };

        // DoH (DNS over HTTPS) は IPアドレスへ直接接続しつつ、SNI/Hostヘッダーは元のサーバー名を使う (dig +https と同様)
        const requestOptions = {
            hostname: dnsServerAddress,
            port: 443,
            path: httpsPath,
            method: 'POST',
            headers: {
                'Content-Type': 'application/dns-message',
                'Accept': 'application/dns-message',
                'Content-Length': buf.length
            },
            timeout: DNS_RESPONSE_TIMEOUT_MS
        };
        if (!isValidIPv4(dnsServer) && !isValidIPv6(dnsServer)) {
            requestOptions.servername = dnsServer;
            requestOptions.headers.Host = dnsServer;
        }

        const httpsReq = https.request(requestOptions, (httpsRes) => {
            const chunks = [];
            let receivedBytes = 0;
            httpsRes.on('data', (chunk) => {
                if (isResponded) return;
                receivedBytes += chunk.length;
                if (receivedBytes > MAX_DNS_MESSAGE_BYTES) {
                    respondOnce(`<div class="result error"><p>エラー: DoHサーバーの応答サイズが上限 (${MAX_DNS_MESSAGE_BYTES} バイト) を超えたため、受信を打ち切りました。</p></div>`);
                    httpsReq.destroy();
                    return;
                }
                chunks.push(chunk);
            });
            httpsRes.on('error', () => {
                // 中断時のエラーは httpsReq 側または respondOnce で処理済み
            });
            httpsRes.on('end', () => {
                if (isResponded) {
                    return;
                }
                if (httpsRes.statusCode !== 200) {
                    respondOnce(`<div class="result error"><p>エラー: DoHサーバーからエラー応答が返されました (HTTP ${escapeHtml(String(httpsRes.statusCode))})。</p></div>`);
                    return;
                }
                const msg = Buffer.concat(chunks);
                let resultHtml = '';
                try {
                    const response = dnsPacket.decode(msg);
                    const anomalyHtml = analyzeDnsPacketError(msg);
                    const hasResidualBytesWarning = /未消費データ|extra bytes|残っています/i.test(anomalyHtml || '');
                    if (anomalyHtml && !hasResidualBytesWarning) {
                        throw new Error('ヘッダーのセクション件数と実際のリソースレコード数が一致しません');
                    }
                    const bytesRead = dnsPacket.decode.bytes;
                    resultHtml = makeHtmlFromDns(response, bytesRead, parsedUrl.origin, parsedUrl.pathname, dnsServer, dnsServerAddress, domainName, queryType, qId, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, msg, qClass, sendDot, ixfrSerial);
                } catch (err) {
                    resultHtml = `<div class="result error"><p>エラー: メッセージの解析に失敗しました: ${escapeHtml(err.message)}</p>${analyzeDnsPacketError(msg, err)}</div>`;
                } finally {
                    respondOnce(resultHtml);
                }
            });
        });

        const timeoutHtml = `<div class="result error"><p>タイムアウト: サーバー <strong>${escapeHtml(dnsServer)}</strong> から応答がありませんでした。</p></div>`;
        const deadlineId = setTimeout(() => {
            respondOnce(timeoutHtml);
            httpsReq.destroy();
        }, DNS_SESSION_DEADLINE_MS);

        httpsReq.on('timeout', () => {
            respondOnce(timeoutHtml);
            httpsReq.destroy();
        });

        httpsReq.on('error', (err) => {
            respondOnce(`<div class="result error"><p>エラー: HTTPS通信に失敗しました: ${escapeHtml(err.message)}</p></div>`);
        });

        httpsReq.write(buf);
        httpsReq.end();
    } else if (sendDot) {
        queryAuthoritativeServerOverTls(dnsServerAddress, dnsServer, queryPacket).then(({ response, rawBuffer }) => {
            try {
                const anomalyHtml = analyzeDnsPacketError(rawBuffer, null, true);
                const hasResidualBytesWarning = /未消費データ|extra bytes|残っています/i.test(anomalyHtml || '');
                if (anomalyHtml && !hasResidualBytesWarning) {
                    throw new Error('ヘッダーのセクション件数と実際のリソースレコード数が一致しません');
                }
                const bytesRead = dnsPacket.streamDecode.bytes;
                html += makeHtmlFromDns(response, bytesRead, parsedUrl.origin, parsedUrl.pathname, dnsServer, dnsServerAddress, domainName, queryType, qId, recursionDesired, checkingDisabled,
                    sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, rawBuffer, qClass, sendDot, ixfrSerial);
            } catch (error) {
                html += `<div class="result error"><p>エラー: メッセージの解析に失敗しました: ${escapeHtml(error.message)}</p>${analyzeDnsPacketError(rawBuffer, error, true)}</div>`;
            }
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
        }).catch((error) => {
            html += `<div class="result error"><p>エラー: DoT通信に失敗しました: ${escapeHtml(error.message)}</p><p>接続先がDoTに対応していない、またはTLS証明書を検証できない可能性があります。DoTを無効にして再試行してください。</p></div>`;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
        });
    } else if (sendTcp) {
        const isZoneTransfer = qType === 'AXFR' || qType === 'IXFR';
        const maxResponseBytes = isZoneTransfer ? MAX_ZONE_TRANSFER_RESPONSE_BYTES : MAX_DNS_TCP_FRAME_BYTES;
        let resultHtml = '';
        let receivedBuffer = Buffer.alloc(0);
        let totalReceivedBytes = 0;
        let receivedFrameCount = 0;
        let finished = false;

        // TCPソケットを作成して送信
        const tcpClient = new net.Socket({ family: isValidIPv6(dnsServerAddress) ? 6 : 4 });

        const finish = (extraHtml = '') => {
            if (finished) return;
            finished = true;
            clearTimeout(timeoutId);
            clearTimeout(deadlineId);
            tcpClient.destroy();
            html += resultHtml + extraHtml;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
        };

        // タイムアウト処理 (5秒間応答がない場合は通信を打ち切る)
        const timeoutId = setTimeout(() => {
            let timeoutHtml = `<div class="result error"><p>タイムアウト: サーバー <strong>${escapeHtml(dnsServer)}</strong> から応答がありませんでした。</p>`;
            if (qnameMinimisation) {
                const resetQMiniHtml = addLinkToDisplayData(parsedUrl.origin, parsedUrl.pathname, 'a.root-servers.net', domainName, queryType, recursionDesired, checkingDisabled,
                    sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, '255', qnameType, 'こちら', qClass, sendDot, '', ixfrSerial);
                timeoutHtml += `<p>※問い合わせたのは <strong>${escapeHtml(qName)}</strong> でした。${resetQMiniHtml} で QNAME minimisation の状態をリセットしてみてください。</p>`;
            }
            timeoutHtml += `</div>`;
            finish(timeoutHtml);
        }, DNS_RESPONSE_TIMEOUT_MS);

        // 応答を受信し始めた後も、通信全体の上限時間を超えたら打ち切る
        const deadlineId = setTimeout(() => {
            finish(`<div class="result error"><p>エラー: 通信時間が上限 (${DNS_SESSION_DEADLINE_MS / 1000} 秒) を超えたため、受信を打ち切りました。</p></div>`);
        }, DNS_SESSION_DEADLINE_MS);

        tcpClient.connect(53, dnsServerAddress, () => {
            tcpClient.write(buf);
        });

        tcpClient.on('data', data => {
            if (finished) return;
            // TCPの場合、アプリケーションへはいくつかの区切りで転送される (イベントが発生する) ので、受信バッファー (receivedBuffer) は外に確保しておく
            totalReceivedBytes += data.byteLength;
            receivedBuffer = Buffer.concat([receivedBuffer, data]);

            // DNSメッセージの先頭 2バイトに DNSメッセージのサイズが格納されているので、揃ったフレームから 1つずつ処理する
            while (!finished && receivedBuffer.byteLength >= 2) {
                const frameLength = receivedBuffer.readUInt16BE(0) + 2;
                if (receivedBuffer.byteLength < frameLength) {
                    break;
                }
                const frame = receivedBuffer.subarray(0, frameLength);
                receivedBuffer = receivedBuffer.subarray(frameLength);
                receivedFrameCount++;
                clearTimeout(timeoutId);
                try {
                    const response = dnsPacket.streamDecode(frame);
                    const anomalyHtml = analyzeDnsPacketError(frame, null, true);
                    const hasResidualBytesWarning = /未消費データ|extra bytes|残っています/i.test(anomalyHtml || '');
                    if (anomalyHtml && !hasResidualBytesWarning) {
                        throw new Error('ヘッダーのセクション件数と実際のリソースレコード数が一致しません');
                    }
                    const bytesRead = dnsPacket.streamDecode.bytes;
                    resultHtml += makeHtmlFromDns(response, bytesRead, parsedUrl.origin, parsedUrl.pathname, dnsServer, dnsServerAddress, domainName, queryType, qId, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, frame, qClass, sendDot, ixfrSerial);
                } catch (err) {
                    finish(`<div class="result error"><p>エラー: メッセージの解析に失敗しました: ${escapeHtml(err.message)}</p>${analyzeDnsPacketError(frame, err, true)}</div>`);
                    return;
                }
                if (!isZoneTransfer) {
                    finish();
                    return;
                }
                if (receivedFrameCount === 1) {
                    // AXFR/IXFR は複数メッセージが続くため、送信側のみ閉じてサーバーが接続を閉じるまで受信を続ける
                    tcpClient.end();
                }
            }

            if (!finished && totalReceivedBytes > maxResponseBytes) {
                finish(`<div class="result error"><p>エラー: 応答サイズが上限 (${maxResponseBytes} バイト) を超えたため、受信を打ち切りました。</p></div>`);
            }
        });

        tcpClient.on('error', (err) => {
            // AWS (Route 53) は DNSデータの送信後に RST を送ってくるため、受信済みの応答があれば結果を表示する
            if (receivedFrameCount === 0) {
                finish(`<div class="result error"><p>エラー: TCP通信に失敗しました: ${escapeHtml(err.message)}</p></div>`);
            } else {
                finish();
            }
        });

        tcpClient.on('close', () => {
            if (receivedFrameCount === 0) {
                finish(`<div class="result error"><p>エラー: サーバー <strong>${escapeHtml(dnsServer)}</strong> から応答を受信する前に TCP 接続が切断されました。</p></div>`);
            } else {
                finish();
            }
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
                isResponded = true;
                html += `<div class="result error"><p>タイムアウト: サーバー <strong>${escapeHtml(dnsServer)}</strong> から応答がありませんでした。</p>`;
                if (qnameMinimisation) {
                    const resetQMiniHtml = addLinkToDisplayData(parsedUrl.origin, parsedUrl.pathname, 'a.root-servers.net', domainName, queryType, recursionDesired, checkingDisabled,
                        sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, '255', qnameType, 'こちら', qClass, sendDot, '', ixfrSerial);
                    html += `<p>※問い合わせたのは <strong>${escapeHtml(qName)}</strong> でした。${resetQMiniHtml} で QNAME minimisation の状態をリセットしてみてください。</p>`;
                }
                html += `</div>`;
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(html);
                udpClient.close();
            }
        }, DNS_RESPONSE_TIMEOUT_MS);

        // 問い合わせ先以外のアドレスから届いたデータグラム (なりすまし応答) は無視する
        const udpServerFamily = isValidIPv6(dnsServerAddress) ? 'ipv6' : 'ipv4';
        const expectedUdpSource = new net.BlockList();
        expectedUdpSource.addAddress(dnsServerAddress, udpServerFamily);

        udpClient.on('message', (msg, rinfo) => {
            if (isResponded) return;
            if (rinfo && !expectedUdpSource.check(rinfo.address, udpServerFamily)) return;
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
                    sendTcp, sendIpv6, sendHttps, httpsPath, edns0Enable, dnssecOk, udpSize, nsidEnable, mQType, qnameMinimisation, qnamePosition, qnameType, msg, qClass, sendDot, ixfrSerial);
            } catch (err) {
                html += `<div class="result error"><p>エラー: メッセージの解析に失敗しました: ${escapeHtml(err.message)}</p>${analyzeDnsPacketError(msg, err)}</div>`;
            } finally {
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(html);
                udpClient.close();
            }
        });

        udpClient.on('error', (err) => {
            if (isResponded) return;
            isResponded = true;
            clearTimeout(timeoutId);
            html += `<div class="result error"><p>エラー: UDP通信に失敗しました: ${escapeHtml(err.message)}</p></div>`;
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
            udpClient.close();
        });

        // 指定されたサーバーIPアドレスの53番ポートへ送信
        udpClient.send(buf, 0, buf.length, 53, dnsServerAddress, (err) => {
            if (err && !isResponded) {
                isResponded = true;
                clearTimeout(timeoutId);
                html += `<div class="result error"><p>エラー: 送信に失敗しました: ${escapeHtml(err.message)}</p></div>`;
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(html);
                udpClient.close();
            }
        });
    }
};

const HOST = '127.0.0.1';
const PORT = 3000;
if (require.main === module) {
    server.listen(PORT, HOST, () => {
        console.log(`Webサーバーが起動しました: http://${HOST}:${PORT}`);
    });

    server.on('error', (err) => {
        console.error(`Webサーバーエラー: ${err.message}`);
    });
}

module.exports = {
    analyzeDnsPacketError,
    buildDnsFlags,
    createResolutionBudget,
    getDnsTypeCode,
    isInvalidDnsServer,
    isInvalidHttpsPath,
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
};
