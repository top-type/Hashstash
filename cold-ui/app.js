'use strict';
(() => {
  const $ = id => document.getElementById(id);
  let sessionToken = '', publicKey = '', chainId = '', accountAddress = '', reviewToken = '', watch = null, busy = false, privateExpectedPublic = '';
  // A generated key's only backup, held until the operator confirms saving it.
  let pendingBackup = null, lifetimeRequired = false, maxReviewBytes = 64 * 1024 * 1024;
  const PASSPHRASE_V1 = 'hashstash-passphrase-v1', PASSPHRASE_V2 = 'hashstash-passphrase-v2';
  const TOKEN_KEY = 'hashstash-cold-token', IDLE_LOCKED = 'Wallet locked after a period without use; open it again.';
  const NO_SESSION = 'This page has no signer session. Open the address the signer printed when it started; it ends in #token=….';
  const say = (message = '', isError = false) => { $('message').textContent = message; $('message').classList.toggle('error', isError); };
  // Loopback is shared by every local account, so the signer never serves its
  // session token. The launch URL carries it in the fragment, which browsers
  // never send; keep it for reloads of this tab and clear the address bar.
  function launchToken() {
    const launched = /^#token=([0-9a-f]{64})$/.exec(location.hash || '')?.[1];
    if (launched) {
      try { sessionStorage.setItem(TOKEN_KEY, launched); } catch { /* This tab then needs its launch URL again after a reload. */ }
      try { history.replaceState(null, '', location.pathname + location.search); } catch { /* The fragment stays only in this tab's address bar. */ }
      return launched;
    }
    let saved = '';
    try { saved = sessionStorage.getItem(TOKEN_KEY) || ''; } catch { /* No saved session in this tab. */ }
    return /^[0-9a-f]{64}$/.test(saved) ? saved : '';
  }
  // Warnings for attached proposal text, by the signer's Rationale verdict.
  const RATIONALE_WARNINGS = {
    'Matches the hash but is not publishable plain text': 'This text matches the signed description hash, but the node publishes a rationale only as plain UTF-8 text of at most 2,048 bytes without leading or trailing whitespace or control characters, so it will not be shown as the rationale.',
    mismatch: 'This text is not the proposal’s committed description: its hash differs from the signed description hash, so it will not be published as the rationale.'
  };
  const reviewLimitText = () => `Unsigned transaction exceeds this signer’s ${maxReviewBytes}-byte review limit; start hashstash-cold with a larger --max-review-bytes to review it`;
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
    $('review-message-title').textContent = 'Public message';
    $('review-rationale-warning').hidden = true;
    $('review-rationale-warning').textContent = '';
    $('review-message-text').textContent = '';
    lifetimeRequired = false;
    $('review-lifetime').hidden = true;
    $('lifetime-confirm').checked = false;
    $('lifetime-confirm-text').textContent = 'I accept this lifetime';
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
    // An unsaved new key must not be funded: no address or key until backup.
    $('address').textContent = pendingBackup ? 'Save the backup and confirm it to show this account’s address.' : accountAddress || 'Set the network to show this account’s address.';
    $('public-key').textContent = pendingBackup ? '' : publicKey;
    $('unsigned-panel').hidden = !!pendingBackup;
    buttons();
  }
  function buttons() {
    $('copy-address').disabled = busy || !accountAddress || !!pendingBackup;
    $('export-public').disabled = busy || !accountAddress || watch?.format !== 'hashstash-watch-v2' || !!pendingBackup;
    $('copy-public').disabled = busy || !publicKey || !!pendingBackup;
  }
  function showWallet(key, context, backup = null) {
    publicKey = key || '';
    pendingBackup = key ? backup : null;
    $('backup-panel').hidden = !pendingBackup;
    $('unlock-panel').hidden = !!key;
    $('wallet').hidden = !key;
    $('lock').hidden = !key;
    $('passphrase').value = '';
    $('legacy-confirm').checked = false;
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
      body:typeof body === 'string' ? body : JSON.stringify(body)
    });
    // The size limit answers before the signer does, without a JSON body.
    if (response.status === 413) throw new Error(path === 'review' ? reviewLimitText() : 'Request is too large');
    let value;
    try { value = await response.json(); } catch { throw new Error('Signer unavailable'); }
    if (response.status === 403) throw new Error(NO_SESSION);
    if (!response.ok) throw new Error(value.error || 'Request failed');
    return value;
  }
  // The signer locks a wallet left unused; stop showing it once that happened.
  // The session endpoint reports only whether a wallet is open, never which.
  async function followLock() {
    if (!publicKey) return;
    try {
      const response = await fetch('/api/session', {cache:'no-store',credentials:'same-origin'});
      const session = await response.json();
      if (response.ok && session.unlocked === false) showWallet(null, session);
    } catch { /* The reported error already explains the failure. */ }
  }
  async function action(work) {
    if (busy) return;
    busy = true;
    document.querySelectorAll('button,input,textarea,select').forEach(element => { element.disabled = true; });
    say();
    try { await work(); } catch (error) { say(error.message, true); await followLock(); }
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
    const result = await api('network', {chain_id:selected});
    if (publicKey && !result.public_key) {
      // The signer locks a v2 passphrase account when another network is
      // selected, and any wallet left unused.
      showWallet(null, result);
      say(result.idle_locked ? IDLE_LOCKED : 'Wallet locked: a v2 passphrase account belongs to the network it was opened for.');
    } else networkView(result);
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
    const method = $('import-method').value, privateMode = method === 'private', phraseMode = method === 'passphrase' || method === 'legacy';
    $('phrase-fields').hidden = !phraseMode; $('private-fields').hidden = !privateMode; $('generate-fields').hidden = method !== 'generate';
    $('v2-hint').hidden = method !== 'passphrase'; $('legacy-fields').hidden = method !== 'legacy';
    $('passphrase').required = phraseMode; $('private-key').required = privateMode;
    $('passphrase').value = ''; $('private-key').value = ''; $('private-file').value = ''; $('legacy-confirm').checked = false;
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
      // Without its token the page cannot know the signer's network either.
      if (!sessionToken) throw new Error(NO_SESSION);
      const method = $('import-method').value;
      if (method === 'generate') {
        showWallet(null);
        const result = await api('generate');
        showWallet(result.public_key, result, result.backup || null);
        say('New key created. Download its backup before using this account.');
        return;
      }
      const privateMode = method === 'private';
      if (method === 'legacy' && !$('legacy-confirm').checked) throw new Error('Confirm that you are restoring an existing v1 account');
      if (method === 'passphrase' && !chainId) throw new Error('Set the network first: a v2 passphrase account belongs to one network');
      const credentials = privateMode ? {private_key:$('private-key').value} : {passphrase:$('passphrase').value,scheme:method === 'legacy' ? PASSPHRASE_V1 : PASSPHRASE_V2};
      const expected = privateExpectedPublic;
      showWallet(null);
      const result = await api(privateMode ? 'import' : 'unlock', credentials);
      if (expected && expected !== result.public_key) { await api('lock'); throw new Error('Backup public key does not match its private key'); }
      showWallet(result.public_key, result);
    });
  });
  $('download-backup').addEventListener('click', () => {
    if (!pendingBackup) return;
    // Encode the file into bytes wiped once the browser holds its own copy,
    // with no other string of the whole document; the key text cannot be wiped.
    const {format, private_key, public_key} = pendingBackup, encoder = new TextEncoder();
    const parts = [`{\n  "format": ${JSON.stringify(format)},\n  "private_key": "`, private_key, `",\n  "public_key": ${JSON.stringify(public_key)}\n}\n`];
    if (!parts.every(part => /^[\x00-\x7f]*$/.test(part))) { say('Invalid private key backup', true); return; }
    const bytes = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) offset += encoder.encodeInto(part, bytes.subarray(offset)).written;
    try { download('hashstash-private-key.json', bytes, 'application/json'); } finally { bytes.fill(0); }
  });
  $('backup-done').addEventListener('click', () => action(async () => {
    const result = await api('backup', {saved:true});
    pendingBackup = null; $('backup-panel').hidden = true; networkView(result);
    say('Backup confirmed. The signer will not show this private key again.');
  }));
  $('lock').addEventListener('click', () => action(async () => {
    const result = await api('lock');
    showWallet(null, result);
    say('Wallet locked');
  }));
  $('lifetime-confirm').addEventListener('change', () => say());
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
    try {
      if (file.size > maxReviewBytes) throw new Error(reviewLimitText());
      $('unsigned').value = await file.text();
    } finally { $('unsigned-file').value = ''; }
  }));
  $('review-form').addEventListener('submit', event => {
    event.preventDefault();
    action(async () => {
      clearReview();
      let envelope;
      try { envelope = JSON.parse($('unsigned').value); }
      catch { await api('cancel'); throw new Error('Invalid unsigned transaction JSON'); }
      // Pasted text gets the same size check as an imported file.
      const request = JSON.stringify(envelope);
      if (request.length > maxReviewBytes) { await api('cancel'); throw new Error(reviewLimitText()); }
      const result = await api('review', request);
      networkView(result);
      const fragment = document.createDocumentFragment(), technical = document.createDocumentFragment();
      let hasTechnical = false, dataBytes = '', dataHex = '';
      const proposal = result.fields.some(field => field.label === 'Action' && field.value === 'Propose');
      const rationale = result.fields.find(field => field.label === 'Rationale')?.value;
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
          value.textContent = HashstashAmounts.formatExactWork(field.value);
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
              // Proposal text is the rationale only when it matches the signed description hash.
              if (proposal) {
                const committed = rationale === 'Matches the description hash';
                $('review-message-title').textContent = committed ? 'Proposal rationale' : 'Attached text · not the committed rationale';
                $('review-rationale-warning').textContent = committed ? '' : RATIONALE_WARNINGS[rationale] || RATIONALE_WARNINGS.mismatch;
                $('review-rationale-warning').hidden = committed;
              }
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
      const longLifetime = result.confirm_lifetime === true;
      const lifetime = result.fields.find(field => field.label === 'Valid for · blocks')?.value || '';
      if (longLifetime && !/^[1-9][0-9]*$/.test(lifetime)) throw new Error('Invalid transaction lifetime');
      $('review-fee-help').hidden = !result.fields.some(field => field.label === 'Fee · HASH');
      $('review-fields').replaceChildren(fragment);
      $('review-technical-fields').replaceChildren(technical);
      $('review-details').hidden = !hasTechnical;
      lifetimeRequired = longLifetime;
      if (longLifetime) {
        $('lifetime-confirm-text').textContent = `I accept that this signature stays valid for ${lifetime} blocks`;
        $('review-lifetime').hidden = false;
      }
      reviewToken = result.review_token;
      $('review-panel').hidden = false;
      $('review-panel').scrollIntoView({behavior:'smooth',block:'start'});
    });
  });
  $('sign').addEventListener('click', () => action(async () => {
    if (!reviewToken) throw new Error('Review the transaction first');
    if (lifetimeRequired && !$('lifetime-confirm').checked) throw new Error('Confirm the long transaction lifetime before signing');
    const pending = reviewToken, request = lifetimeRequired ? {review_token:pending,confirm_lifetime:true} : {review_token:pending};
    clearReview();
    const result = await api('sign', request);
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
    sessionToken = launchToken();
    // Limits and lock state need no token; the open account and network do.
    const response = await fetch('/api/session', {cache:'no-store',credentials:'same-origin'});
    if (!response.ok) throw new Error('Signer unavailable');
    const session = await response.json();
    if (Number.isSafeInteger(session.max_review_bytes) && session.max_review_bytes > 0) maxReviewBytes = session.max_review_bytes;
    const idle = session.idle_lock_seconds;
    $('idle-lock-hint').textContent = Number.isSafeInteger(idle) && idle > 0 ? ` An open wallet locks after ${idle % 60 ? `${idle} seconds` : idle === 60 ? '1 minute' : `${idle / 60} minutes`} without use.` : '';
    if (!sessionToken) { showWallet(null, session); throw new Error(NO_SESSION); }
    let status;
    try { status = await api('status'); } catch (error) { showWallet(null, session); throw error; }
    // A generated key's backup is shown once. After a reload it is gone, so
    // the unconfirmed (and so unfunded) key is discarded, never re-served.
    if (status.public_key && status.backup_pending === true) {
      showWallet(null, await api('lock'));
      say('The new key was discarded because its backup was not confirmed. Generate a new key and save its backup.', true);
      return;
    }
    showWallet(status.public_key, status);
    if (status.idle_locked) say(IDLE_LOCKED);
  });
})();
