'use strict';
(() => {
  const $ = id => document.getElementById(id);
  let sessionToken = '', publicKey = '', chainId = '', accountAddress = '', reviewToken = '', watch = null, busy = false, privateExpectedPublic = '';
  const say = (message = '', isError = false) => { $('message').textContent = message; $('message').classList.toggle('error', isError); };
  function unitText(node, text, unit, className) {
    const offset = text.lastIndexOf(unit);
    node.textContent = text.slice(0, offset);
    const label = document.createElement('span');
    label.className = className; label.textContent = unit; node.append(label);
    if (offset + unit.length < text.length) {
      const suffix = document.createElement('span');
      suffix.textContent = text.slice(offset + unit.length); node.append(suffix);
    }
  }
  function clearReview() {
    reviewToken = '';
    $('review-panel').hidden = true;
    $('review-fields').replaceChildren();
    $('review-technical-fields').replaceChildren();
    $('review-details').hidden = true;
    $('review-fee-help').hidden = true;
    $('review-details').open = false;
    $('review-data').hidden = true;
    $('review-data').open = false;
    $('review-data-summary').textContent = 'Data';
    $('review-data-hex').textContent = '';
    $('review-message').hidden = true;
    $('review-message-text').textContent = '';
    $('review-bytes').hidden = true;
    $('review-bytes').open = false;
    $('review-body-hex').textContent = '';
    $('signed-panel').hidden = true;
    $('raw').value = '';
    $('txid').textContent = '';
  }
  function networkView(data = {}) {
    if (Object.hasOwn(data, 'chain_id')) chainId = data.chain_id || '';
    accountAddress = data.address || '';
    watch = data.watch || null;
    $('network-current').textContent = chainId || 'Not set';
    $('network-form').hidden = !!chainId;
    $('network-change').hidden = !chainId;
    $('network-chain').value = chainId;
    $('address').textContent = accountAddress || 'Set the network to show this account’s address.';
    buttons();
  }
  function buttons() {
    $('copy-address').disabled = busy || !accountAddress;
    $('export-public').disabled = busy || !accountAddress || watch?.format !== 'hashstash-watch-v2';
  }
  function showWallet(key, context) {
    publicKey = key || '';
    $('public-key').textContent = publicKey;
    $('unlock-panel').hidden = !!key;
    $('wallet').hidden = !key;
    $('lock').hidden = !key;
    $('passphrase').value = '';
    $('private-key').value = '';
    $('private-file').value = '';
    privateExpectedPublic = '';
    $('unsigned').value = '';
    $('unsigned-file').value = '';
    clearReview();
    networkView(context);
  }
  async function api(path, body = {}) {
    const response = await fetch(`/api/${path}`, {
      method:'POST',cache:'no-store',credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-Hashstash-Cold-Token':sessionToken},
      body:JSON.stringify(body)
    });
    let value;
    try { value = await response.json(); } catch { throw new Error('Signer unavailable'); }
    if (!response.ok) throw new Error(value.error || 'Request failed');
    return value;
  }
  async function action(work) {
    if (busy) return;
    busy = true;
    document.querySelectorAll('button,input,textarea,select').forEach(element => { element.disabled = true; });
    say();
    try { await work(); } catch (error) { say(error.message, true); }
    finally {
      busy = false;
      document.querySelectorAll('button,input,textarea,select').forEach(element => { element.disabled = false; });
      buttons();
    }
  }
  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], {type}));
    const link = document.createElement('a');
    link.href = url; link.download = name; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function copy(text) {
    await navigator.clipboard.writeText(text);
    say('Copied');
  }
  async function setNetwork(value) {
    const selected = String(value || '').trim();
    clearReview();
    if (!/^[a-f0-9]{64}$/i.test(selected)) throw new Error('Chain ID must contain 64 hexadecimal characters');
    networkView(await api('network', {chain_id:selected}));
  }
  $('network-change').addEventListener('click', () => action(async () => {
    clearReview(); await api('cancel'); $('network-form').hidden = false;
  }));
  $('network-form').addEventListener('submit', event => {
    event.preventDefault(); action(() => setNetwork($('network-chain').value));
  });
  $('network-chain').addEventListener('input', () => {
    const hadReview = !!reviewToken; clearReview();
    if (hadReview) action(() => api('cancel'));
  });
  $('network-file').addEventListener('change', () => action(async () => {
    clearReview(); await api('cancel');
    try {
      const file = $('network-file').files[0]; if (!file) return;
      if (file.size > 4096) throw new Error('Network file is too large');
      const descriptor = JSON.parse(await file.text());
      if (descriptor.format !== 'hashstash-network-v1' || Object.keys(descriptor).some(name => !['format','chain_id'].includes(name))) throw new Error('Import a Hashstash network file');
      await setNetwork(descriptor.chain_id);
    } finally { $('network-file').value = ''; }
  }));
  $('import-method').addEventListener('change', () => {
    const privateMode = $('import-method').value === 'private';
    $('phrase-fields').hidden = privateMode; $('private-fields').hidden = !privateMode;
    $('passphrase').required = !privateMode; $('private-key').required = privateMode;
    $('passphrase').value = ''; $('private-key').value = ''; $('private-file').value = '';
    privateExpectedPublic = ''; say();
  });
  $('private-key').addEventListener('input', () => { privateExpectedPublic = ''; });
  $('private-file').addEventListener('change', () => action(async () => {
    $('private-key').value = ''; privateExpectedPublic = '';
    const file = $('private-file').files[0]; if (!file) return;
    try {
      if (file.size > 4096) throw new Error('Private key file is too large');
      let value = (await file.text()).trim(), expected = '';
      if (value.startsWith('{')) {
        const backup = JSON.parse(value);
        const modern = backup.format === 'hashstash-private-v1';
        const allowed = modern ? ['format','private_key','public_key'] : ['secret','public'];
        if (Object.keys(backup).some(name => !allowed.includes(name))) throw new Error('Invalid private key file');
        expected = modern ? backup.public_key : backup.public;
        value = modern ? backup.private_key : backup.secret;
        if (typeof expected !== 'string' || !/^[0-9a-f]{64}$/i.test(expected)) throw new Error('Invalid public key in backup');
      }
      if (typeof value !== 'string' || !/^[0-9a-f]{64}$/i.test(value)) throw new Error('Invalid private key file');
      $('private-key').value = value; privateExpectedPublic = expected.toLowerCase();
    } finally { $('private-file').value = ''; }
  }));
  $('unlock-form').addEventListener('submit', event => {
    event.preventDefault();
    action(async () => {
      const privateMode = $('import-method').value === 'private';
      const credentials = privateMode ? {private_key:$('private-key').value} : {passphrase:$('passphrase').value};
      const expected = privateExpectedPublic;
      showWallet(null);
      const result = await api(privateMode ? 'import' : 'unlock', credentials);
      if (expected && expected !== result.public_key) { await api('lock'); throw new Error('Backup public key does not match its private key'); }
      showWallet(result.public_key, result);
    });
  });
  $('lock').addEventListener('click', () => action(async () => {
    const result = await api('lock');
    showWallet(null, result);
    say('Wallet locked');
  }));
  $('unsigned').addEventListener('input', () => {
    const hadReview = !!reviewToken;
    clearReview();
    say();
    if (hadReview) action(() => api('cancel'));
  });
  $('unsigned-file').addEventListener('change', () => action(async () => {
    clearReview();
    await api('cancel');
    const file = $('unsigned-file').files[0];
    if (!file) return;
    $('unsigned').value = await file.text();
  }));
  $('review-form').addEventListener('submit', event => {
    event.preventDefault();
    action(async () => {
      clearReview();
      let envelope;
      try { envelope = JSON.parse($('unsigned').value); }
      catch { await api('cancel'); throw new Error('Invalid unsigned transaction JSON'); }
      const result = await api('review', envelope);
      networkView(result);
      const fragment = document.createDocumentFragment(), technical = document.createDocumentFragment();
      let hasTechnical = false, dataBytes = '', dataHex = '';
      for (const field of result.fields) {
        if (field.label === 'Data bytes') { dataBytes = field.value; continue; }
        if (field.label === 'Data hex') { dataHex = field.value; continue; }
        const name = document.createElement('dt'), value = document.createElement('dd');
        name.textContent = field.label; value.textContent = field.value;
        if (field.label.endsWith('compact target')) {
          technical.append(name, value); hasTechnical = true; continue;
        }
        if (field.label === 'Action' && field.value === 'Redeem') value.textContent = 'Withdraw';
        if (/· hashes$/.test(field.label)) {
          name.textContent = field.label.replace(/ · hashes$/, '');
          value.textContent = `${HashstashAmounts.exactInput(field.value)} EH`;
          value.title = value.textContent;
        } else if (/· HASH$/.test(field.label)) {
          name.textContent = field.label.replace(/ · HASH$/, '');
          value.className = 'hash-amount';
          const display = `${HashstashAmounts.exactInput(field.value)} hash`;
          unitText(value, display, 'hash', 'hash-unit');
          value.title = display;
        } else if (/shares/i.test(field.label)) {
          const label = field.label === 'Shares' ? 'Amount · stash' : field.label.replace(/shares/gi, 'stash');
          unitText(name, label, 'stash', 'stash-unit');
          value.className = 'stash-amount';
          value.textContent = HashstashShares.exactInput(field.value);
          value.title = `${field.value} stash atoms`;
          const atomName = document.createElement('dt'), atomValue = document.createElement('dd');
          unitText(atomName, 'stash atoms', 'stash', 'stash-unit');
          atomValue.textContent = field.value;
          atomValue.className = 'stash-amount';
          technical.append(atomName, atomValue);
          hasTechnical = true;
        }
        fragment.append(name, value);
      }
      if (dataBytes || dataHex) {
        if (!/^[1-9][0-9]*$/.test(dataBytes) || !/^(?:[0-9a-f]{2})+$/i.test(dataHex) || String(dataHex.length / 2) !== dataBytes) throw new Error('Invalid transaction data preview');
        if (dataHex.toLowerCase().startsWith('6861736873746173682e6d61696c2f')) {
          const name = document.createElement('dt'), value = document.createElement('dd');
          name.textContent = 'Encrypted mail';
          value.textContent = 'Subject and message are sealed. This signer cannot verify their plaintext. Check the recipient, attached hashes and fee above; signing authorizes the exact encrypted bytes below.';
          fragment.append(name, value);
        } else {
          try {
            const bytes = new Uint8Array(dataHex.length / 2);
            for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(dataHex.slice(i * 2, i * 2 + 2), 16);
            const message = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
            if (message.trim() && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(message)) {
              $('review-message-text').textContent = message;
              $('review-message').hidden = false;
            }
          } catch { /* Binary data remains available as exact hex below. */ }
        }
        $('review-data-summary').textContent = `Data · ${dataBytes} ${dataBytes === '1' ? 'byte' : 'bytes'} · hex`;
        $('review-data-hex').textContent = dataHex;
        $('review-data').hidden = false;
      }
      if (result.body) {
        if (!/^(?:[0-9a-f]{2})+$/i.test(result.body)) throw new Error('Invalid signing bytes');
        $('review-body-hex').textContent = result.body;
        $('review-bytes').hidden = false;
      }
      $('review-fee-help').hidden = !result.fields.some(field => field.label === 'Fee · HASH');
      $('review-fields').replaceChildren(fragment);
      $('review-technical-fields').replaceChildren(technical);
      $('review-details').hidden = !hasTechnical;
      reviewToken = result.review_token;
      $('review-panel').hidden = false;
      $('review-panel').scrollIntoView({behavior:'smooth',block:'start'});
    });
  });
  $('sign').addEventListener('click', () => action(async () => {
    if (!reviewToken) throw new Error('Review the transaction first');
    const pending = reviewToken;
    clearReview();
    const result = await api('sign', {review_token:pending});
    $('raw').value = result.raw;
    $('txid').textContent = result.txid;
    $('signed-panel').hidden = false;
    $('signed-panel').scrollIntoView({behavior:'smooth',block:'start'});
  }));
  $('copy-public').addEventListener('click', () => action(() => copy(publicKey)));
  $('copy-address').addEventListener('click', () => action(() => {
    if (!accountAddress) throw new Error('Set the network first');
    return copy(accountAddress);
  }));
  $('export-public').addEventListener('click', () => {
    if (!accountAddress || watch?.format !== 'hashstash-watch-v2') { say('Set the network first', true); return; }
    download('hashstash-watch.json', JSON.stringify(watch,null,2)+'\n','application/json');
  });
  $('copy-raw').addEventListener('click', () => action(() => copy($('raw').value)));
  $('export-raw').addEventListener('click', () => download('hashstash-signed.txt', $('raw').value+'\n','text/plain'));
  action(async () => {
    const response = await fetch('/api/session', {cache:'no-store',credentials:'same-origin'});
    if (!response.ok) throw new Error('Signer unavailable');
    const session = await response.json();
    sessionToken = session.token;
    showWallet(session.public_key, session);
  });
})();
