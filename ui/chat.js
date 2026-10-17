(function (root, factory) {
  'use strict';
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.HashstashChat = api;
})(globalThis, function (root) {
  'use strict';
  const PAGE_SIZE = 20, MAX_PAGES = 10;
  const validId = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  // A literal copy of src/chat.rs BLANK: Unicode White_Space plus
  // Default_Ignorable_Code_Point. String.prototype.trim uses a different set
  // (it strips U+FEFF but not U+200B), so the node and the feed could disagree.
  const BLANK = [
    [0x0009, 0x000D], [0x0020, 0x0020], [0x0085, 0x0085], [0x00A0, 0x00A0], [0x00AD, 0x00AD], [0x034F, 0x034F],
    [0x061C, 0x061C], [0x115F, 0x1160], [0x1680, 0x1680], [0x17B4, 0x17B5], [0x180B, 0x180F], [0x2000, 0x200F],
    [0x2028, 0x202F], [0x205F, 0x206F], [0x3000, 0x3000], [0x3164, 0x3164], [0xFE00, 0xFE0F], [0xFEFF, 0xFEFF],
    [0xFFA0, 0xFFA0], [0xFFF0, 0xFFF8], [0x1BCA0, 0x1BCA3], [0x1D173, 0x1D17A], [0xE0000, 0xE0FFF],
  ];
  const blankText = new RegExp(`^[${BLANK.map(([low, high]) => `\\u{${low.toString(16)}}-\\u{${high.toString(16)}}`).join('')}]*$`, 'u');
  const isBlank = text => typeof text === 'string' && blankText.test(text);
  function validateText(text) {
    if (typeof text !== 'string' || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(text)) throw new Error('Message contains invalid Unicode.');
    if (/[\u0000-\u0008\u000B-\u000C\u000E-\u001F\u007F-\u009F]/u.test(text)) throw new Error('Messages allow line breaks and tabs, but no other control characters.');
    if (isBlank(text)) throw new Error('Message is empty.');
  }
  // Explicit embeddings, overrides and isolates can make a message display in
  // a different order from its signed text. Show them as visible escapes, as
  // the explorer's raw data view does.
  const visibleControls = text => text.replace(/[‪-‮⁦-⁩]/gu, c => `\\u${c.charCodeAt(0).toString(16)}`);
  const unsigned = value => /^(0|[1-9]\d{0,19})$/.test(String(value)) && BigInt(value) <= 18446744073709551615n;
  const chronological = (left, right) => {
    for (const field of ['height', 'position']) {
      const a = BigInt(left[field]), b = BigInt(right[field]);
      if (a !== b) return a < b ? -1 : 1;
    }
    return left.txid.localeCompare(right.txid);
  };
  const kindLabels = { transfer: 'Payment', deposit: 'Stash purchase', redeem: 'Stash sale', propose: 'Proposal', support: 'Proposal support', refund: 'Refund' };
  // Every address on a network shares its HRP and separator, and the last six
  // characters are only the checksum. Show key data as the wallet does.
  const shortAddress = value => { const start = value.lastIndexOf('1') + 1; return `hsh…${value.slice(start, start + 10)}…${value.slice(-6)}`; };
  function displayMessage(text) {
    const prefix = 'Automated Demo · ';
    const label = /^Automated Demo · ([^\r\n]+?) — /u.exec(text);
    if (label && label[1].trim()) return { automated: true, text: text.slice(prefix.length) };
    const native = /^([^·—\r\n]+?) · Automated — /u.exec(text);
    return native && native[1].trim()
      ? { automated: true, text: `${native[1]} — ${text.slice(native[0].length)}` }
      : { automated: false, text };
  }
  function create({ rpc, document = root.document, location = root.location, storage = root.localStorage, amountText }) {
    const $ = id => document.getElementById(id);
    let context = {}, chain = '', sequence = 0, loading = false, lastTip = null, lastAt = 0, observedTip = null, observedAt = Date.now();
    let items = [], pending = [], next = null, pages = 1, muted = new Set(), rendered = '', loadError = '', indexReady = true, skipped = 0;
    const active = () => location.hash.split('?')[0] === '#chat';
    const setText = (id, value) => { const node = $(id); if (node.textContent !== value) node.textContent = value; };
    const add = (parent, tag, className, value) => { const node = document.createElement(tag); node.className = className; if (value !== undefined) node.textContent = value; parent.appendChild(node); return node; };
    function link(parent, kind, value, label) { const node = add(parent, 'a', 'chat-link', label); node.href = `#explorer?${kind}=${encodeURIComponent(value)}`; return node; }
    function selectChain(value) {
      if (chain === value) return;
      sequence++; chain = value || '';
      items = []; pending = []; next = null; pages = 1; lastTip = null; lastAt = 0; loading = false; rendered = ''; muted = new Set();
      loadError = ''; indexReady = true; skipped = 0; observedTip = null; observedAt = Date.now();
      try {
        const saved = JSON.parse(storage.getItem(`hashstash-chat-muted:${chain}`) || '[]');
        if (Array.isArray(saved)) muted = new Set(saved.filter(value => {
          try { root.HashstashAddress.decode(value, 'hsh' + chain.slice(0, 16)); return true; } catch { return false; }
        }).slice(0, 500));
      } catch { /* Invalid local settings have no authority over chain messages. */ }
      render();
    }
    function mute(sender, value) {
      if (value) muted.add(sender); else muted.delete(sender);
      try { storage.setItem(`hashstash-chat-muted:${chain}`, JSON.stringify([...muted])); } catch {}
      render();
    }
    function render() {
      const signature = JSON.stringify([items, pending, [...muted]]);
      if (signature === rendered) return;
      rendered = signature;
      for (const [id, records, unconfirmed] of [['chat-pending', pending, true], ['chat-messages', items, false]]) {
        const list = $(id); list.replaceChildren();
        for (const item of records) {
          if (muted.has(item.sender)) continue;
          const display = displayMessage(item.text);
          const row = add(list, 'article', 'chat-message'); row.dataset.txid = item.txid;
          const head = add(row, 'div', 'chat-message-head');
          const author = add(head, 'div', 'chat-message-author');
          const senderLink = link(author, 'account', item.sender, shortAddress(item.sender)); senderLink.title = item.sender;
          if (display.automated) {
            const badge = add(author, 'span', 'chat-automated', 'Automated');
            badge.title = 'Self-description from the signed message; not a verified sender identity.';
            badge.setAttribute('aria-label', 'Automated, self-described');
          }
          const transaction = link(head, 'tx', item.txid, unconfirmed ? 'Pending' : `Block ${String(item.height).replace(/\B(?=(\d{3})+(?!\d))/g, ',')}`);
          if (!unconfirmed) transaction.title = `Transaction ${BigInt(item.position) + 1n} in this block`;
          if (display.automated) {
            transaction.title = `${transaction.title ? transaction.title + '\n' : ''}Original signed message:\n${visibleControls(item.text)}`;
            transaction.setAttribute('aria-label', `${transaction.textContent} · view original signed message`);
          }
          add(row, 'p', 'chat-message-text', visibleControls(display.text));
          const foot = add(row, 'div', 'chat-message-foot');
          const details = add(foot, 'span', 'chat-transaction'); add(details, 'span', '', kindLabels[item.kind] || 'Transaction');
          if (item.amount != null) {
            const amount = add(details, 'span', '');
            if (item.asset === 'stash') { amountText(amount, `${root.HashstashShares.formatAmount(item.amount)} stash`); amount.title = `${root.HashstashShares.exactInput(item.amount)} stash`; }
            else { amountText(amount, root.HashstashAmounts.formatHash(item.amount)); amount.title = root.HashstashAmounts.formatExactHash(item.amount); }
          }
          const actions = add(foot, 'div', 'chat-message-actions');
          const hide = add(actions, 'button', 'small-link', 'Mute'); hide.type = 'button'; hide.setAttribute('aria-label', `Mute ${item.sender}`); hide.addEventListener('click', () => mute(item.sender, true));
        }
      }
      $('chat-pending-section').hidden = !pending.some(item => !muted.has(item.sender));
      $('chat-empty').hidden = items.some(item => !muted.has(item.sender));
      const settings = $('chat-muted-list'); settings.replaceChildren();
      for (const sender of muted) {
        const row = add(settings, 'div', 'chat-muted-row'); link(row, 'account', sender, shortAddress(sender)).title = sender;
        const button = add(row, 'button', 'small-link', 'Unmute'); button.type = 'button'; button.addEventListener('click', () => mute(sender, false));
      }
      $('chat-muted').hidden = !muted.size; setText('chat-muted-count', `Muted (${muted.size})`);
    }
    function validate(record, unconfirmed) {
      if (!record || !validId(record.txid) || typeof record.sender !== 'string' || typeof record.kind !== 'string' || !/^[a-z_]{1,32}$/.test(record.kind)) throw new Error('Invalid chat response.');
      root.HashstashAddress.decode(record.sender, 'hsh' + chain.slice(0, 16));
      if (record.recipient != null) root.HashstashAddress.decode(record.recipient, 'hsh' + chain.slice(0, 16));
      if (record.amount != null && (typeof record.amount !== 'string' || !/^(0|[1-9]\d{0,159})$/.test(record.amount) || !['hash', 'stash'].includes(record.asset))) throw new Error('Invalid message amount.');
      if (record.amount == null && record.asset != null) throw new Error('Invalid message amount.');
      // Historical records can exceed today's governed capacity. The node has
      // already validated their size against the block that included them.
      validateText(record.text);
      if (!unsigned(record.confirmations) || (unconfirmed ? record.status !== 'pending' || record.height != null || record.position != null : record.status !== 'confirmed' || !unsigned(record.height) || !unsigned(record.position))) throw new Error('Invalid message status.');
      return record;
    }
    // One malformed record must not hide the rest of the page, or every later
    // page behind it: skip it and report how many were left out.
    function accept(records, unconfirmed, counter) {
      return records.flatMap(record => { try { return [validate(record, unconfirmed)]; } catch { counter.skipped++; return []; } });
    }
    function statusView() {
      const omitted = skipped ? `${skipped} message${skipped === 1 ? '' : 's'} could not be displayed.` : '';
      let value = !context.ready ? 'Offline · messages may be out of date.' : !context.available ? 'Chat is unavailable on this network.' : loadError || (!indexReady ? 'Indexing messages…' : [Date.now() - observedAt > 120000 ? 'No recent block observed. Messages may remain pending.' : '', omitted].filter(Boolean).join(' '));
      setText('chat-status', value); $('chat-status').hidden = !value;
      $('chat-more').hidden = !next || pages >= MAX_PAGES; $('chat-more').disabled = loading || !context.ready;
      $('chat-history-note').hidden = !next || pages < MAX_PAGES;
    }
    async function load(more = false, force = false) {
      if (!context.ready || !context.available || !active() || loading || more && (!next || pages >= MAX_PAGES)) return;
      if (!force && !more && context.tip === lastTip && Date.now() - lastAt < 6000) return;
      const request = ++sequence, capturedChain = chain, capturedTip = context.tip, cursor = more ? next : null;
      const current = () => sequence === request && chain === capturedChain && context.tip === capturedTip && context.ready && context.available && active();
      loading = true; statusView();
      try {
        const result = await rpc('explorer_chat', { limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) });
        if (!current()) return;
        if (result.chain_id !== chain || !validId(result.tip) || !Array.isArray(result.items) || !Array.isArray(result.pending) || result.items.length > PAGE_SIZE || result.pending.length > 50) throw new Error('Invalid chat response.');
        if (result.tip !== capturedTip) throw new Error('Message index changed. Refreshing again shortly.');
        if (more && lastTip && result.tip !== lastTip) throw new Error('Message index changed. Refreshing again shortly.');
        if (result.next_cursor != null && (typeof result.next_cursor !== 'string' || result.next_cursor.length > 256)) throw new Error('Invalid message cursor.');
        indexReady = result.ready !== false; loadError = '';
        if (!indexReady) { lastAt = Date.now(); statusView(); return; }
        const counter = { skipped: 0 }, confirmed = accept(result.items, false, counter), waiting = accept(result.pending, true, counter);
        let nextCursor = result.next_cursor, loadedPages = 1;
        // Refresh the already-open history as well, so polling neither collapses
        // older messages nor retains messages removed by a reorganization.
        while (!more && nextCursor && loadedPages < pages) {
          const page = await rpc('explorer_chat', { limit: PAGE_SIZE, cursor: nextCursor });
          if (!current()) return;
          if (page.chain_id !== chain || page.tip !== result.tip || page.ready === false || !Array.isArray(page.items) || page.items.length > PAGE_SIZE) throw new Error('Message index changed. Refreshing again shortly.');
          if (page.next_cursor != null && (typeof page.next_cursor !== 'string' || page.next_cursor.length > 256)) throw new Error('Invalid message cursor.');
          confirmed.push(...accept(page.items, false, counter));
          nextCursor = page.next_cursor; loadedPages++;
        }
        const unique = new Map((more ? [...items, ...confirmed] : confirmed).map(item => [item.txid, item]));
        items = [...unique.values()].sort(chronological); pending = [...new Map(waiting.filter(item => !unique.has(item.txid)).map(item => [item.txid, item])).values()];
        next = typeof nextCursor === 'string' && nextCursor.length <= 256 ? nextCursor : null;
        pages = more ? pages + 1 : loadedPages;
        skipped = more ? skipped + counter.skipped : counter.skipped;
        lastTip = result.tip; lastAt = Date.now(); render(); statusView();
      } catch (error) { if (current()) { loadError = `Messages unavailable: ${error.message}`; statusView(); lastAt = Date.now(); } }
      finally { if (request === sequence) { loading = false; statusView(); } }
    }
    $('chat-more').addEventListener('click', () => load(true));
    return {
      update(nextContext) {
        const previous = context;
        context = nextContext; selectChain(context.chain_id);
        if (context.tip && observedTip !== context.tip) { observedTip = context.tip; observedAt = Date.now(); }
        if (!context.ready || !context.available || previous.tip !== context.tip) { sequence++; loading = false; }
        statusView(); if (active()) load();
      },
      route() { sequence++; loading = false; if (active()) { statusView(); load(false, true); } },
    };
  }
  return Object.freeze({ create, isBlank });
});
