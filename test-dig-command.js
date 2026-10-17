const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const http = require('node:http');
const dgram = require('node:dgram');
const { EventEmitter } = require('node:events');
const dnsPacket = require('dns-packet');
const { parseDigCommand, formatDigCommand } = require('./dig-command');
const { SUPPORTED_QUERY_TYPES, SUPPORTED_QUERY_CLASSES } = require('./dns-query-options');
const { server } = require('./dns-query-tool');

const ignored = (parsed) => parsed.tokens.filter((token) => token.ignored).map((token) => token.value);

test('ユーザーのdig入力例を全て有効な設定へ変換する', () => {
    const parsed = parseDigCommand('dig in a @a.root-servers.net www.on-link.jp -6 +rd +cd +dnssec');
    assert.deepEqual(Object.fromEntries(parsed.params), {
        server: 'a.root-servers.net', name: 'www.on-link.jp', type: 'A', class: 'IN',
        rd: '1', edns0: '1', udpsize: '1232', qposi: '255', qtype: 'A',
        ipv6: '1', cd: '1', dnssec: '1'
    });
    assert.deepEqual(ignored(parsed), []);
});

test('引数順序、大文字小文字、コマンド名の省略、連結した短いオプションを扱う', () => {
    for (const command of [
        'dig ch txt @8.8.8.8 version.bind',
        '@8.8.8.8 version.bind TXT CH',
        'dig -tTXT -cCH -qversion.bind @8.8.8.8',
        'dig -q version.bind -c ch @8.8.8.8 -t txt'
    ]) {
        const parsed = parseDigCommand(command);
        assert.equal(parsed.params.get('name'), 'version.bind');
        assert.equal(parsed.params.get('type'), 'TXT');
        assert.equal(parsed.params.get('class'), 'CH');
        assert.equal(parsed.params.get('server'), '8.8.8.8');
        assert.deepEqual(ignored(parsed), []);
    }
});

test('dig寄りの既定値と通常画面の対応タイプ・クラスを共有する', () => {
    const defaults = parseDigCommand('dig').params;
    assert.equal(defaults.get('name'), '.');
    assert.equal(defaults.get('type'), 'NS');
    assert.equal(defaults.get('rd'), '1');
    assert.equal(defaults.get('edns0'), '1');
    assert.equal(parseDigCommand('example.com').params.get('type'), 'A');
    for (const type of SUPPORTED_QUERY_TYPES.filter((type) => !['IXFR', 'PTR-x'].includes(type))) {
        const parsed = parseDigCommand(`dig example.com -t ${type.toLowerCase()}`);
        assert.equal(parsed.params.get('type'), type);
        assert.deepEqual(ignored(parsed), []);
    }
    for (const queryClass of SUPPORTED_QUERY_CLASSES) {
        assert.equal(parseDigCommand(`dig example.com -c ${queryClass}`).params.get('class'), queryClass);
    }
});

test('フラグの無効化と再指定、EDNS0の依存関係を反映する', () => {
    const params = parseDigCommand('dig example.com -6 -4 +rd +norecurse +cdflag +nocd +dnssec +nodnssec +nsid +nonsid +qmin +noqmin +noedns').params;
    for (const key of ['ipv6', 'rd', 'cd', 'dnssec', 'nsid', 'qmini', 'edns0']) assert.equal(params.get(key), '0');
    for (const option of ['+dnssec', '+nsid', '+bufsize=4096', '+edns=0']) {
        assert.equal(parseDigCommand(`dig example.com +noedns ${option}`).params.get('edns0'), '1');
    }
    assert.equal(parseDigCommand('delv example.com +qmin').params.get('qmini'), '1');
    assert.equal(parseDigCommand('dig example.com +bufsize=65535').params.get('udpsize'), '65535');
    assert.equal(parseDigCommand('dig example.com +bufsize=512').params.get('udpsize'), '512');
});

test('通信方式は排他的に指定し、HTTPSのパスも反映する', () => {
    const params = parseDigCommand('dig example.com +tcp +tls +https=/custom-dns').params;
    assert.equal(params.get('tcp'), '0');
    assert.equal(params.get('dot'), '0');
    assert.equal(params.get('https'), '1');
    assert.equal(params.get('httpspath'), '/custom-dns');
    assert.equal(parseDigCommand('dig example.com +https +vc').params.get('tcp'), '1');
    assert.equal(parseDigCommand('dig example.com +tls +notls').params.get('dot'), '0');
    assert.equal(parseDigCommand('dig example.com +vc +novc').params.get('tcp'), '0');
});

test('未対応のオプションと値を一緒に無視し、ドメイン名と誤認しない', () => {
    const parsed = parseDigCommand('dig -p 5353 -b192.0.2.1 -f queries.txt -k keyfile -y hmac:secret example.com +short +trace +time=1 +subnet=192.0.2.0/24');
    assert.equal(parsed.params.get('name'), 'example.com');
    assert.deepEqual(ignored(parsed), [
        '-p', '5353', '-b192.0.2.1', '-f', 'queries.txt', '-k', 'keyfile', '-y', 'hmac:secret',
        '+short', '+trace', '+time=1', '+subnet=192.0.2.0/24'
    ]);
    assert.ok(parsed.tokens.filter((token) => token.ignored).every((token) => token.reason));
    assert.deepEqual(ignored(parseDigCommand('delv -a anchors -d 3 example.com')), ['-a', 'anchors', '-d', '3']);
});

test('無効なタイプ・クラス・オプション値は赤字対象として元の有効値を保つ', () => {
    const parsed = parseDigCommand('dig example.com -t MX -t TSIG -c CH -c CLASS999 +bufsize=511 +bufsize=65536 +edns=1 +rd=1 +foo');
    assert.equal(parsed.params.get('type'), 'MX');
    assert.equal(parsed.params.get('class'), 'CH');
    assert.equal(parsed.params.get('udpsize'), '1232');
    assert.deepEqual(ignored(parsed), [
        '-t', 'TSIG', '-c', 'CLASS999', '+bufsize=511', '+bufsize=65536', '+edns=1', '+rd=1', '+foo'
    ]);
});

test('引用符やエスケープを解釈し、元の表示用の範囲と空白を保持する', () => {
    const command = '  dig\t-q "example.com" +short \n';
    const parsed = parseDigCommand(command);
    assert.equal(parsed.command, command);
    assert.equal(parsed.params.get('name'), 'example.com');
    assert.equal(command.slice(parsed.tokens[2].start, parsed.tokens[2].end), '"example.com"');
    assert.equal(parseDigCommand("dig -q 'example.com'").params.get('name'), 'example.com');
    assert.equal(parseDigCommand('dig example\\.com').params.get('name'), 'example.com');
    assert.equal(parseDigCommand('dig "$(hostname)"').params.get('name'), '$(hostname)');
});

test('逆引きとIXFR、AXFRを既存設定へ変換する', () => {
    for (const address of ['192.0.2.1', '2001:db8::1']) {
        const params = parseDigCommand(`dig -x ${address}`).params;
        assert.equal(params.get('type'), 'PTR-x');
        assert.equal(params.get('name'), address);
    }
    for (const serial of ['0', '4294967295']) {
        const parsed = parseDigCommand(`dig example.com ixfr=${serial}`);
        assert.equal(parsed.params.get('type'), 'IXFR');
        assert.equal(parsed.params.get('ixfrserial'), serial);
        assert.equal(parsed.params.get('tcp'), '1');
        assert.deepEqual(ignored(parsed), []);
    }
    assert.equal(parseDigCommand('dig example.com AXFR').params.get('tcp'), '1');
    assert.equal(parseDigCommand('dig example.com AXFR +notcp').params.get('tcp'), '0');
    assert.equal(parseDigCommand('dig example.com ixfr=1 -t A').params.has('ixfrserial'), false);
    assert.deepEqual(ignored(parseDigCommand('dig example.com ixfr=4294967296')), ['ixfr=4294967296']);
});

test('不完全な構文は送信前のエラーにする', () => {
    for (const command of ['', '  ', 'dig -t', 'dig -c +rd', 'dig -q ""', 'dig @', 'dig "example.com', 'dig example.com\\', 'dig example.com IXFR']) {
        assert.throws(() => parseDigCommand(command), Error, command);
    }
});

test('追加の問い合わせは無視する', () => {
    const parsed = parseDigCommand('dig example.com A example.net AAAA');
    assert.equal(parsed.params.get('name'), 'example.com');
    assert.equal(parsed.params.get('type'), 'A');
    assert.deepEqual(ignored(parsed), ['example.net', 'AAAA']);
});

test('ブラウザーでも共通パーサーを読み込める', () => {
    const context = vm.createContext({ URLSearchParams });
    for (const file of ['dns-query-options.js', 'dig-command.js']) {
        vm.runInContext(fs.readFileSync(path.join(__dirname, file), 'utf8'), context);
    }
    assert.equal(context.DigCommand.parseDigCommand('dig example.com +cd').params.get('cd'), '1');
});

test('保存したDNS設定から、未対応引数を含まないコマンドを再構成する', () => {
    for (const command of [
        'dig',
        'dig in a @a.root-servers.net www.on-link.jp -6 +rd +cd +dnssec -y hmac:TEST_SECRET',
        'dig example.com +noedns +nsid +noedns +qmin +nord -4',
        'dig example.com ixfr=42 +notcp',
        'dig -x 2001:db8::1 +tls',
        'dig example.com +https=/custom-dns +bufsize=4096',
        'dig -q "name\'with quote.example" +short',
        'dig -q "example.com +rd -y TEST_SECRET"'
    ]) {
        const parsed = parseDigCommand(command);
        const restored = parseDigCommand(formatDigCommand(parsed.params));
        assert.deepEqual(Object.fromEntries(restored.params), Object.fromEntries(parsed.params), command);
        assert.deepEqual(ignored(restored), []);
    }
    const params = new URLSearchParams('name=example.com&command=TEST_SECRET&unknown=TEST_SECRET');
    const command = formatDigCommand(params);
    assert.doesNotMatch(command, /TEST_SECRET|unknown|command=/);
});

const createDigClient = (search = '') => {
    const element = () => ({
        value: '', textContent: '', hidden: false, children: [], listeners: {},
        addEventListener(event, callback) { this.listeners[event] = callback; },
        replaceChildren(...children) { this.children = children; },
        append(...children) { this.children.push(...children); },
        querySelectorAll() { return []; }
    });
    const elements = Object.fromEntries([
        'dig-search', 'command', 'dig-summary', 'parsed-command', 'ignored-options',
        'parsed-settings', 'results', 'form-link'
    ].map((id) => [id, element()]));
    const location = new URL(`http://localhost/dns-query-tool/dig.html${search}`);
    const histories = [];
    const requests = [];
    const windowListeners = {};
    const recordHistory = (method) => (state, title, url) => {
        histories.push({ method, state, url: String(url) });
        location.href = new URL(url, location).href;
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'dig-client.js'), 'utf8'), {
        document: {
            baseURI: location.href,
            getElementById: (id) => elements[id],
            createElement: element
        },
        DigCommand: { parseDigCommand, formatDigCommand },
        URL, URLSearchParams, AbortController, location,
        history: { pushState: recordHistory('push'), replaceState: recordHistory('replace') },
        window: { addEventListener: (event, callback) => { windowListeners[event] = callback; } },
        fetch: async (url) => {
            requests.push(String(url));
            return { ok: true, text: async () => '<p>DNS response</p>' };
        }
    });
    return {
        elements, location, histories, requests, windowListeners,
        submit(command) {
            elements.command.value = command;
            elements['dig-search'].listeners.submit({ preventDefault() {} });
        }
    };
};

test('TSIGキー・未対応の値・元コマンドはURL、履歴state、APIへ保存・送信しない', async () => {
    for (const key of ['-y hmac-sha256:key:TEST_SECRET', '-yhmac-sha256:key:TEST_SECRET']) {
        const client = createDigClient();
        client.submit(`dig @8.8.8.8 example.com +cd ${key} -k PRIVATE_FILE +unknown=PRIVATE_VALUE`);
        await new Promise((resolve) => setImmediate(resolve));
        const saved = JSON.stringify({ history: client.histories, requests: client.requests, url: client.location.href });
        assert.doesNotMatch(saved, /TEST_SECRET|PRIVATE_FILE|PRIVATE_VALUE|command=|unknown/);
        assert.equal(client.requests.length, 1);
        assert.equal(client.location.searchParams.get('name'), 'example.com');
        assert.equal(client.location.searchParams.get('cd'), '1');
        assert.match(client.elements['parsed-command'].children
            .map((child) => typeof child === 'string' ? child : child.textContent).join(''), /TEST_SECRET/);
        assert.equal(client.elements['ignored-options'].children.length, key.startsWith('-y ') ? 5 : 4);
    }
});

test('再読み込みと履歴では保存設定だけを復元し、不明なURLパラメーターを破棄する', async () => {
    const initial = createDigClient();
    initial.submit('dig example.com +dnssec +noedns +https=/custom -y key:TEST_SECRET');
    const restored = createDigClient(initial.location.search + '&unknown=PRIVATE_VALUE#PRIVATE_FRAGMENT');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(restored.requests.length, 1);
    assert.deepEqual(
        Object.fromEntries(new URL(restored.requests[0]).searchParams),
        Object.fromEntries(new URL(initial.requests[0]).searchParams)
    );
    assert.doesNotMatch(JSON.stringify(restored.histories), /TEST_SECRET|PRIVATE_VALUE|PRIVATE_FRAGMENT/);
    assert.doesNotMatch(restored.elements.command.value, /TEST_SECRET|-y/);
    assert.equal(restored.elements['ignored-options'].children.length, 0);

    restored.location.search = '?name=example.net&type=AAAA&rd=0';
    restored.windowListeners.popstate();
    assert.equal(new URL(restored.requests.at(-1)).searchParams.get('name'), 'example.net');
    assert.equal(new URL(restored.requests.at(-1)).searchParams.get('type'), 'AAAA');
    assert.equal(new URL(restored.requests.at(-1)).searchParams.get('rd'), '0');
    restored.location.search = '';
    restored.windowListeners.popstate();
    assert.equal(restored.elements.command.value, '');
    assert.equal(restored.elements['dig-summary'].hidden, true);
});

test('旧command URLは実行せずURLから除去し、再入力を案内する', () => {
    const client = createDigClient(`?command=${encodeURIComponent('dig example.com -y key:TEST_SECRET')}`);
    assert.equal(client.requests.length, 0);
    assert.equal(client.location.search, '');
    assert.equal(client.elements.command.value, '');
    assert.doesNotMatch(JSON.stringify(client.histories), /TEST_SECRET|command=/);
    assert.match(client.elements.results.children[0].children[0].textContent, /旧形式URL.*再入力/);
});

test('JavaScriptが読み込めない場合もフォームから生コマンドを送信しない', () => {
    const html = fs.readFileSync(path.join(__dirname, 'dig.html'), 'utf8');
    assert.match(html, /<input type="text" id="command"[^>]*autocomplete="off"/);
    assert.doesNotMatch(html, /<input[^>]*name=/);
});

const request = (port, pathname) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: pathname }, (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => { body += chunk; });
        response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body }));
    }).on('error', reject);
});

test('dig画面・共通資産の配信と、パースした設定によるDNSパケット送信を確認する', async (context) => {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    context.after(() => new Promise((resolve) => server.close(resolve)));
    const port = server.address().port;
    for (const prefix of ['', '/dns-query-tool']) {
        for (const file of ['dig.html', 'dns-query-options.js', 'dig-command.js', 'dig-client.js', 'dns-query-tool.css']) {
            const response = await request(port, `${prefix}/${file}`);
            assert.equal(response.status, 200, `${prefix}/${file}`);
            assert.ok(response.body.length > 0);
            assert.match(response.headers['content-security-policy'], /script-src 'self'/);
        }
    }
    const sent = [];
    context.mock.method(dgram, 'createSocket', (family) => {
        const socket = new EventEmitter();
        socket.close = () => {};
        socket.send = (buffer, offset, length, dnsPort, address, callback) => {
            const query = dnsPacket.decode(buffer);
            sent.push({ query, family, dnsPort, address });
            callback(null);
            process.nextTick(() => socket.emit('message', dnsPacket.encode({
                type: 'response', id: query.id, questions: query.questions
            })));
        };
        return socket;
    });
    const { params } = parseDigCommand('dig in a @2001:4860:4860::8888 www.on-link.jp -6 +rd +cd +dnssec +nsid +bufsize=4096 +short');
    const response = await request(port, `/dns-query-tool/api/query?${params}`);
    assert.equal(response.status, 200);
    assert.match(response.body, /QUESTION/);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].family, 'udp6');
    assert.equal(sent[0].address, '2001:4860:4860::8888');
    assert.equal(sent[0].dnsPort, 53);
    const query = sent[0].query;
    assert.deepEqual(query.questions, [{ name: 'www.on-link.jp', type: 'A', class: 'IN' }]);
    assert.ok(query.flags & dnsPacket.RECURSION_DESIRED);
    assert.ok(query.flags & dnsPacket.CHECKING_DISABLED);
    assert.equal(query.additionals[0].udpPayloadSize, 4096);
    assert.ok(query.additionals[0].flags & dnsPacket.DNSSEC_OK);
    assert.ok(query.additionals[0].options.some((option) => option.code === 3));
});
