(() => {
    const form = document.getElementById('search');
    const results = document.getElementById('results');
    const description = document.getElementById('description');
    const searchPanel = document.getElementById('search-panel');
    const toggle = document.getElementById('search-toggle');
    const applicationUrl = new URL('./', document.baseURI);
    const apiUrl = new URL('api/query', applicationUrl);

    const tcpCheckbox = form.elements.namedItem('tcp');
    const httpsCheckbox = form.elements.namedItem('https');
    const dotCheckbox = form.elements.namedItem('dot');
    const httpsPathInput = form.elements.namedItem('httpspath');

    const syncTransportControls = (changedControl = null) => {
        if (changedControl?.checked) {
            for (const control of [tcpCheckbox, httpsCheckbox, dotCheckbox]) {
                if (control !== changedControl) control.checked = false;
            }
        } else {
            const selectedControl = [httpsCheckbox, dotCheckbox, tcpCheckbox].find((control) => control.checked);
            for (const control of [tcpCheckbox, httpsCheckbox, dotCheckbox]) {
                if (control !== selectedControl) control.checked = false;
            }
        }
        httpsPathInput.disabled = !httpsCheckbox.checked;
        tcpCheckbox.disabled = httpsCheckbox.checked || dotCheckbox.checked;
        httpsCheckbox.disabled = dotCheckbox.checked;
        dotCheckbox.disabled = httpsCheckbox.checked;
    };

    const restoreForm = (params) => {
        for (const [name, value] of params) {
            const control = form.elements.namedItem(name);
            if (!control) continue;
            if (control instanceof RadioNodeList) {
                const option = [...control].find((item) => item.value === value);
                if (option) option.checked = true;
            } else if (control.type === 'checkbox') {
                control.checked = value === '1';
            } else {
                control.value = value;
            }
        }
        syncTransportControls();
    };

    const setPanelVisible = (visible) => {
        searchPanel.hidden = !visible;
        toggle.textContent = visible ? '入力欄非表示' : '入力欄再表示';
    };

    const runQuery = async (params, updateHistory = true, hidePanel = true) => {
        results.innerHTML = '<p>DNS クエリーを送信しています...</p>';
        description.hidden = true;
        if (hidePanel) setPanelVisible(false);
        const query = params.toString();
        if (updateHistory) history.pushState(null, '', query ? `?${query}` : applicationUrl.pathname);
        try {
            const response = await fetch(`${apiUrl}?${query}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            results.innerHTML = await response.text();
        } catch (error) {
            results.innerHTML = `<div class="result error"><p>エラー: リクエストに失敗しました: ${error.message}</p></div>`;
        }
    };

    form.addEventListener('submit', (event) => {
        event.preventDefault();
        const params = new URLSearchParams(new FormData(form));
        runQuery(params);
    });

    document.getElementById('qmini-reset').addEventListener('click', () => {
        form.elements.server.value = 'a.root-servers.net';
        form.elements.qposi.value = '255';
        const params = new URLSearchParams(new FormData(form));
        if (!params.get('name')) {
            results.replaceChildren();
            description.hidden = false;
            setPanelVisible(true);
            history.pushState(null, '', applicationUrl.pathname);
            return;
        }
        runQuery(params, true, false);
    });

    toggle.addEventListener('click', () => setPanelVisible(searchPanel.hidden));

    tcpCheckbox.addEventListener('change', () => syncTransportControls(tcpCheckbox));
    httpsCheckbox.addEventListener('change', () => syncTransportControls(httpsCheckbox));
    dotCheckbox.addEventListener('change', () => syncTransportControls(dotCheckbox));
    syncTransportControls();

    results.addEventListener('click', (event) => {
        const link = event.target.closest('a[data-dns-query-link]');
        if (!link) return;
        event.preventDefault();
        const params = new URL(link.href).searchParams;
        restoreForm(params);
        runQuery(params);
    });

    window.addEventListener('popstate', () => {
        const params = new URLSearchParams(location.search);
        restoreForm(params);
        if (params.has('name')) runQuery(params, false);
        else {
            results.replaceChildren();
            description.hidden = false;
            setPanelVisible(true);
        }
    });

    const initialParams = new URLSearchParams(location.search);
    restoreForm(initialParams);
    if (initialParams.has('name')) runQuery(initialParams, false);
})();
