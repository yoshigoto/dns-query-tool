(() => {
    const form = document.getElementById('dig-search');
    const input = document.getElementById('command');
    const summary = document.getElementById('dig-summary');
    const commandDisplay = document.getElementById('parsed-command');
    const ignoredOptions = document.getElementById('ignored-options');
    const settings = document.getElementById('parsed-settings');
    const results = document.getElementById('results');
    const formLink = document.getElementById('form-link');
    const applicationUrl = new URL('./', document.baseURI);
    const apiUrl = new URL('api/query', applicationUrl);
    let activeRequest;

    const showError = (message) => {
        const box = document.createElement('div');
        box.className = 'result error';
        const text = document.createElement('p');
        text.textContent = `エラー: ${message}`;
        box.append(text);
        results.replaceChildren(box);
    };

    const runCommand = async (updateHistory = true) => {
        activeRequest?.abort();
        const request = new AbortController();
        activeRequest = request;
        let parsed;
        try {
            parsed = DigCommand.parseDigCommand(input.value);
        } catch (error) {
            summary.hidden = true;
            formLink.href = applicationUrl.href;
            showError(error.message);
            return;
        }
        commandDisplay.replaceChildren();
        ignoredOptions.replaceChildren();
        let cursor = 0;
        for (const token of parsed.tokens) {
            commandDisplay.append(parsed.command.slice(cursor, token.start));
            const span = document.createElement('span');
            span.textContent = parsed.command.slice(token.start, token.end);
            if (token.ignored) {
                span.className = 'dig-ignored';
                span.title = token.reason;
                const item = document.createElement('li');
                item.textContent = `${span.textContent}: ${token.reason}`;
                ignoredOptions.append(item);
            }
            commandDisplay.append(span);
            cursor = token.end;
        }
        commandDisplay.append(parsed.command.slice(cursor));
        settings.textContent = [...parsed.params].map(([key, value]) => `${key}=${value}`).join('\n');
        formLink.href = `${applicationUrl}?${parsed.params}`;
        summary.hidden = false;
        if (updateHistory) {
            const url = new URL(location.href);
            url.search = new URLSearchParams({ command: parsed.command }).toString();
            history.pushState(null, '', url);
        }
        results.textContent = 'DNS クエリーを送信しています...';
        try {
            const response = await fetch(`${apiUrl}?${parsed.params}`, { signal: request.signal });
            const html = await response.text();
            if (request.signal.aborted) return;
            // The API returns its validation errors as HTML, including HTTP 400 responses.
            if (!response.ok && response.status !== 400) throw new Error(`HTTP ${response.status}`);
            results.innerHTML = html;
            for (const link of results.querySelectorAll('a[data-dns-query-link]')) {
                link.href = `${applicationUrl}?${new URL(link.href).searchParams}`;
            }
        } catch (error) {
            if (request.signal.aborted) return;
            showError(`リクエストに失敗しました: ${error.message}`);
        }
    };

    form.addEventListener('submit', (event) => {
        event.preventDefault();
        runCommand();
    });
    const restore = () => {
        const params = new URLSearchParams(location.search);
        input.value = params.get('command') || '';
        if (params.has('command')) runCommand(false);
        else {
            activeRequest?.abort();
            summary.hidden = true;
            results.replaceChildren();
            formLink.href = applicationUrl.href;
        }
    };
    window.addEventListener('popstate', restore);
    restore();
})();
