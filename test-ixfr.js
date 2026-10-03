const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const dnsPacket = require('dns-packet');
const { server } = require('./dns-query-tool');

const request = (port, params) => new Promise((resolve, reject) => {
    http.get({
        host: '127.0.0.1',
        port,
        path: `/dnsquerytool/api/query?${new URLSearchParams({ server: '8.8.8.8', name: 'example.com.', ...params })}`
    }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => { body += chunk; });
        response.on('end', () => resolve(body));
    }).on('error', reject);
});

test('IXFR の入力検証、SOA の送信、再問い合わせリンクを確認する', async (t) => {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())));
    const port = server.address().port;
    const sentPackets = [];
    const respond = (buffer, tcp) => {
        const query = tcp ? dnsPacket.streamDecode(buffer) : dnsPacket.decode(buffer);
        sentPackets.push(query);
        const response = {
            type: 'response',
            id: query.id,
            flags: dnsPacket.TRUNCATED_RESPONSE,
            questions: query.questions,
            authorities: [{ name: 'example.com', type: 'NS', ttl: 60, data: 'ns.example.com' }]
        };
        return tcp ? dnsPacket.streamEncode(response) : dnsPacket.encode(response);
    };
    t.mock.method(dgram, 'createSocket', () => {
        const socket = new EventEmitter();
        socket.close = () => {};
        socket.send = (buffer, offset, length, dnsPort, address, callback) => {
            assert.equal(dnsPort, 53);
            assert.equal(address, '8.8.8.8');
            const response = respond(buffer, false);
            callback(null);
            process.nextTick(() => socket.emit('message', response));
        };
        return socket;
    });
    t.mock.method(net, 'Socket', function () {
        const socket = new EventEmitter();
        socket.connect = (dnsPort, address, callback) => {
            assert.equal(dnsPort, 53);
            assert.equal(address, '8.8.8.8');
            process.nextTick(callback);
        };
        socket.write = (buffer) => {
            const response = respond(buffer, true);
            process.nextTick(() => socket.emit('data', response));
        };
        socket.end = () => process.nextTick(() => socket.emit('close', false));
        socket.destroy = () => {};
        return socket;
    });

    for (const serial of [undefined, '', '-1', '1.5', '4294967296', '1e3', 'NaN', ' 1', '<script>']) {
        const params = { type: 'IXFR' };
        if (serial !== undefined) params.ixfrserial = serial;
        const html = await request(port, params);
        assert.match(html, /エラー: IXFR シリアル番号を/);
        assert.doesNotMatch(html, /<script>/);
    }
    assert.equal(sentPackets.length, 0);

    for (const tcp of [false, true]) {
        for (const serial of ['0', '2026100301', '4294967295']) {
            const html = await request(port, { type: 'IXFR', ixfrserial: serial, class: 'CH', tcp: tcp ? '1' : '0', edns0: '1' });
            const query = sentPackets.at(-1);
            assert.deepEqual(query.questions, [{ name: 'example.com', type: 'IXFR', class: 'CH' }]);
            assert.deepEqual(query.authorities, [{
                name: 'example.com', type: 'SOA', class: 'CH', ttl: 0, flush: false,
                data: { mname: '.', rname: '.', serial: Number(serial), refresh: 0, retry: 0, expire: 0, minimum: 0 }
            }]);
            assert.equal(query.additionals[0].type, 'OPT');
            assert.match(html, new RegExp(`IXFR シリアル番号</dt><dd><code>${serial}</code>`));
            assert.match(html, new RegExp(`ixfrserial=${serial}`));
            if (!tcp) assert.match(html, new RegExp(`tcp=1[^"]*ixfrserial=${serial}[^"]*">TCPで再確認`));
        }
    }

    await request(port, { type: 'A', ixfrserial: 'invalid' });
    assert.deepEqual(sentPackets.at(-1).authorities, []);
    await request(port, { type: 'IXFR', ixfrserial: '42', qmini: '1', qposi: '255', qtype: 'NS' });
    assert.equal(sentPackets.at(-1).questions[0].type, 'NS');
    assert.deepEqual(sentPackets.at(-1).authorities, []);
    await request(port, { type: 'IXFR', ixfrserial: '42', qmini: '1', qposi: '0' });
    assert.equal(sentPackets.at(-1).questions[0].type, 'IXFR');
    assert.equal(sentPackets.at(-1).authorities[0].data.serial, 42);
});

test('IXFR の入力欄は選択・URL 復元・履歴・リンクに追従する', () => {
    const control = (properties = {}) => ({
        value: '',
        checked: false,
        disabled: false,
        listeners: {},
        addEventListener(event, callback) { this.listeners[event] = callback; },
        ...properties
    });
    const controls = Object.fromEntries(['tcp', 'https', 'dot', 'httpspath', 'type', 'ixfrserial', 'server', 'qposi', 'name']
        .map((name) => [name, control()]));
    controls.type.value = 'A';
    controls.namedItem = (name) => controls[name];
    const elements = {
        search: control({ elements: controls }),
        results: control({ replaceChildren() {} }),
        description: control(),
        'search-panel': control(),
        'search-toggle': control(),
        'qmini-reset': control(),
        'ixfr-serial-option': control()
    };
    const windowListeners = {};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'dns-query-tool-client.js'), 'utf8'), {
        document: { baseURI: 'http://localhost/dnsquerytool/', getElementById: (id) => elements[id] },
        URL, URLSearchParams,
        RadioNodeList: class {},
        location: { search: '?type=IXFR&ixfrserial=4294967295' },
        window: { addEventListener: (event, callback) => { windowListeners[event] = callback; } },
        history: { pushState() {} },
        fetch: async () => ({ ok: true, text: async () => '' })
    });
    assert.equal(controls.ixfrserial.value, '4294967295');
    assert.equal(controls.ixfrserial.required, true);
    assert.equal(controls.ixfrserial.disabled, false);
    assert.equal(elements['ixfr-serial-option'].hidden, false);

    controls.type.value = 'A';
    controls.type.listeners.change();
    assert.equal(controls.ixfrserial.required, false);
    assert.equal(controls.ixfrserial.disabled, true);
    assert.equal(elements['ixfr-serial-option'].hidden, true);

    elements.results.listeners.click({
        target: { closest: () => ({ href: 'http://localhost/dnsquerytool/?type=IXFR&ixfrserial=0' }) },
        preventDefault() {}
    });
    assert.equal(controls.ixfrserial.value, '0');
    assert.equal(controls.ixfrserial.required, true);
    windowListeners.popstate();
    assert.equal(controls.ixfrserial.value, '4294967295');

    elements.results.listeners.click({
        target: { closest: () => ({ href: 'http://localhost/dnsquerytool/?type=A' }) },
        preventDefault() {}
    });
    assert.equal(controls.ixfrserial.value, '');
    assert.equal(controls.ixfrserial.disabled, true);

    const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
    assert.match(html, /id="ixfr-serial-option" hidden/);
    assert.match(html, /type="number"[^>]*name="ixfrserial"[^>]*min="0" max="4294967295" step="1" disabled/);
});
