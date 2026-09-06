const assert = require('node:assert/strict');
const test = require('node:test');
const dnsTypes = require('dns-packet/types');
const { getDnsTypeCode } = require('./dns-query-tool');

const buildMQTypeOptionData = (value) => {
    const types = value.split(',');
    const data = Buffer.alloc(types.length * 2);
    types.forEach((type, offset) => data.writeUInt16BE(getDnsTypeCode(type), offset * 2));
    return data;
};

const parseMQTypeResponse = (data) => {
    const types = [];
    for (let offset = 0; offset < data.length; offset += 2) {
        types.push(dnsTypes.toString(data.readUInt16BE(offset)));
    }
    return types;
};

test('MQTYPEオプションをネットワークバイト順で構築する', () => {
    assert.deepEqual(buildMQTypeOptionData('A'), Buffer.from([0, 1]));
    assert.deepEqual(buildMQTypeOptionData('A,AAAA,MX'), Buffer.from([0, 1, 0, 28, 0, 15]));
    assert.deepEqual(buildMQTypeOptionData('A,AAAA,MX,NS,TXT,CNAME'),
        Buffer.from([0, 1, 0, 28, 0, 15, 0, 2, 0, 16, 0, 5]));
});

test('MQTYPEレスポンスのOPTION-DATAを型名へ変換する', () => {
    const responseData = Buffer.from([0, 1, 0, 28, 0, 15]);
    assert.deepEqual(parseMQTypeResponse(responseData), ['A', 'AAAA', 'MX']);
});
