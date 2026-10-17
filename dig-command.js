(function (root) {
    const { SUPPORTED_QUERY_TYPES, SUPPORTED_QUERY_CLASSES } =
        typeof module === 'object' && module.exports ? require('./dns-query-options') : root.DnsQueryOptions;

    const tokenize = (command) => {
        const tokens = [];
        let position = 0;
        while (position < command.length) {
            if (/\s/.test(command[position])) {
                position++;
                continue;
            }
            const start = position;
            let value = '';
            let quote = '';
            while (position < command.length) {
                const char = command[position];
                if (!quote && /\s/.test(char)) break;
                position++;
                if (char === '\\' && quote !== "'") {
                    if (position === command.length) throw new Error('末尾のバックスラッシュに続く文字がありません。');
                    value += command[position++];
                } else if (char === quote) {
                    quote = '';
                } else if (!quote && (char === '"' || char === "'")) {
                    quote = char;
                } else {
                    value += char;
                }
            }
            if (quote) throw new Error('引用符が閉じられていません。');
            tokens.push({ value, start, end: position, ignored: false, reason: '' });
        }
        return tokens;
    };

    const parseDigCommand = (command) => {
        const tokens = tokenize(command);
        if (!tokens.length) throw new Error('dig コマンドまたは引数を入力してください。');
        const params = new URLSearchParams({
            server: 'a.root-servers.net', name: '.', type: 'NS', class: 'IN',
            rd: '1', edns0: '1', udpsize: '1232', qposi: '255', qtype: 'A'
        });
        const ignore = (token, reason = '本ツールでは未対応のため無視します。') => {
            token.ignored = true;
            token.reason = reason;
        };
        const setType = (token, value) => {
            const type = value.toUpperCase();
            const ixfr = /^IXFR=(\d+)$/.exec(type);
            if (ixfr && Number(ixfr[1]) <= 0xffffffff) {
                params.set('type', 'IXFR');
                params.set('ixfrserial', ixfr[1]);
            } else if (SUPPORTED_QUERY_TYPES.includes(type)) {
                params.set('type', type);
                params.delete('ixfrserial');
            } else {
                ignore(token, '未対応または不正なクエリータイプです。');
                return false;
            }
            return true;
        };
        const setClass = (token, value) => {
            const queryClass = value.toUpperCase();
            if (!SUPPORTED_QUERY_CLASSES.includes(queryClass)) {
                ignore(token, '未対応のクエリークラスです。');
                return false;
            }
            params.set('class', queryClass);
            return true;
        };
        const setTransport = (transport, enabled) => {
            if (enabled) {
                for (const key of ['tcp', 'dot', 'https']) params.set(key, key === transport ? '1' : '0');
            } else {
                params.set(transport, '0');
            }
        };
        let hasName = false;
        let hasType = false;
        let hasClass = false;
        const start = /^(dig|delv)$/i.test(tokens[0].value) ? 1 : 0;
        for (let index = start; index < tokens.length; index++) {
            const token = tokens[index];
            const value = token.value;
            if (value.startsWith('@')) {
                if (value.length === 1) throw new Error('@ の後にDNSサーバーを指定してください。');
                params.set('server', value.slice(1));
            } else if (value.startsWith('+')) {
                const match = /^\+(no)?([a-z0-9-]+)(?:=(.*))?$/i.exec(value);
                if (!match) {
                    ignore(token);
                    continue;
                }
                const enabled = !match[1];
                const option = match[2].toLowerCase();
                const argument = match[3];
                const flags = {
                    rd: 'rd', recurse: 'rd', cd: 'cd', cdflag: 'cd',
                    dnssec: 'dnssec', nsid: 'nsid', qmin: 'qmini'
                };
                if (Object.hasOwn(flags, option) && argument === undefined) {
                    params.set(flags[option], enabled ? '1' : '0');
                    if (enabled && ['dnssec', 'nsid'].includes(option)) params.set('edns0', '1');
                } else if (['tcp', 'vc', 'tls'].includes(option) && argument === undefined) {
                    setTransport(option === 'tls' ? 'dot' : 'tcp', enabled);
                } else if (option === 'https' && (argument === undefined || (enabled && argument.startsWith('/')))) {
                    setTransport('https', enabled);
                    if (enabled) params.set('httpspath', argument || '/dns-query');
                } else if (option === 'edns' && ((!enabled && argument === undefined) ||
                    (enabled && (argument === undefined || argument === '0')))) {
                    params.set('edns0', enabled ? '1' : '0');
                } else if (option === 'bufsize' && enabled && /^\d+$/.test(argument || '') &&
                    Number(argument) >= 512 && Number(argument) <= 65535) {
                    params.set('udpsize', argument);
                    params.set('edns0', '1');
                } else {
                    ignore(token, '未対応のオプション、値、またはEDNSバージョンのため無視します。');
                }
            } else if (value.startsWith('-')) {
                if (value === '-4' || value === '-6') {
                    params.set('ipv6', value === '-6' ? '1' : '0');
                    continue;
                }
                const option = value.slice(0, 2);
                // Unsupported options with operands must not turn their operands into query names.
                const takesValue = ['-t', '-c', '-q', '-x', '-p', '-b', '-f', '-k', '-y', '-w', '-a', '-d'];
                if (takesValue.includes(option)) {
                    const operand = value.length > 2 ? token : tokens[index + 1];
                    if (!operand || (operand !== token && /^[+@-]/.test(operand.value))) {
                        throw new Error(`${option} の値がありません。`);
                    }
                    const argument = operand === token ? value.slice(2) : operand.value;
                    if (operand !== token) index++;
                    if (option === '-t') {
                        if (setType(operand, argument)) hasType = true;
                    } else if (option === '-c') {
                        if (setClass(operand, argument)) hasClass = true;
                    } else if (option === '-q' || option === '-x') {
                        if (!argument) throw new Error(`${option} の値が空です。`);
                        params.set('name', argument);
                        hasName = true;
                        if (option === '-x') {
                            params.set('type', 'PTR-x');
                            params.set('class', 'IN');
                            hasType = true;
                        }
                    } else {
                        ignore(token);
                        ignore(operand);
                    }
                    if (operand.ignored) ignore(token, operand.reason);
                } else {
                    ignore(token);
                }
            } else {
                const upper = value.toUpperCase();
                if (!hasType && (SUPPORTED_QUERY_TYPES.includes(upper) || /^IXFR=/i.test(value) ||
                    /^(TYPE\d+|OPT|TSIG|TKEY|MAILA|MAILB|AXFR|IXFR)$/i.test(value))) {
                    if (setType(token, value)) hasType = true;
                } else if (!hasClass && (SUPPORTED_QUERY_CLASSES.includes(upper) || /^CLASS\d+$/i.test(value))) {
                    if (setClass(token, value)) hasClass = true;
                } else if (!hasName) {
                    if (!value) throw new Error('対象ドメイン名が空です。');
                    params.set('name', value);
                    hasName = true;
                } else {
                    ignore(token, '複数の問い合わせには対応していません。追加の引数を無視します。');
                }
            }
        }
        if (hasName && !hasType) params.set('type', 'A');
        if (params.get('type') === 'IXFR' && !params.has('ixfrserial')) {
            throw new Error('IXFR は ixfr=N 形式でシリアル番号を指定してください。');
        }
        if (['AXFR', 'IXFR'].includes(params.get('type')) && !params.has('tcp') &&
            params.get('dot') !== '1' && params.get('https') !== '1') {
            params.set('tcp', '1');
        }
        return { command, tokens, params };
    };

    const formatDigCommand = (params) => {
        const quote = (value) => `'${value.replace(/'/g, "'\\''")}'`;
        const type = params.get('type') || 'A';
        const command = ['dig', `@${quote(params.get('server') || 'a.root-servers.net')}`];
        command.push(type === 'PTR-x' ? '-x' : '-q', quote(params.get('name') || '.'));
        if (type !== 'PTR-x') {
            command.push('-t', quote(type === 'IXFR' ? `ixfr=${params.get('ixfrserial') || ''}` : type));
        }
        command.push('-c', quote(params.get('class') || 'IN'));
        if (params.has('ipv6')) command.push(params.get('ipv6') === '1' ? '-6' : '-4');
        for (const [key, option] of Object.entries({ rd: 'rd', cd: 'cd', dnssec: 'dnssec', nsid: 'nsid', qmini: 'qmin' })) {
            if (params.has(key)) command.push(`+${params.get(key) === '1' ? '' : 'no'}${option}`);
        }
        for (const enabled of [false, true]) {
            for (const [key, option] of Object.entries({ tcp: 'tcp', dot: 'tls', https: 'https' })) {
                if (!params.has(key) || (params.get(key) === '1') !== enabled) continue;
                command.push(key === 'https' && enabled ?
                    quote(`+https=${params.get('httpspath') || '/dns-query'}`) : `+${enabled ? '' : 'no'}${option}`);
            }
        }
        if (params.has('udpsize')) command.push(quote(`+bufsize=${params.get('udpsize')}`));
        // Restore EDNS last: DNSSEC, NSID and bufsize otherwise enable it.
        if (params.has('edns0')) command.push(params.get('edns0') === '1' ? '+edns=0' : '+noedns');
        return command.join(' ');
    };

    if (typeof module === 'object' && module.exports) module.exports = { parseDigCommand, formatDigCommand };
    else root.DigCommand = { parseDigCommand, formatDigCommand };
})(globalThis);
