'use strict';
((root) => {
  const validHash = value => typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value);
  const integer = value => /^(0|[1-9][0-9]*)$/.test(String(value ?? ''));
  const grouped = value => integer(value) ? String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ',') : '—';
  const short = value => typeof value === 'string' && value.length > 24 ? `${value.slice(0, 12)}…${value.slice(-8)}` : String(value ?? '—');
  const labels = { Transfer: 'Transfer', TransferExact: 'Transfer', Deposit: 'Stash deposit', Redeem: 'Stash withdrawal', Propose: 'Proposal', Support: 'Proposal backing', Refund: 'Auction refund', transfer: 'Transfer', deposit: 'Stash deposit', redeem: 'Stash withdrawal', propose: 'Proposal', support: 'Proposal backing', refund: 'Auction refund', mining_reward: 'Mining reward', governance_grant: 'Governance grant' };
  const effects = { conditional: 'Unresolved', survived: 'Applied', discarded: 'Discarded', orphaned: 'Orphaned', pending: 'Pending', common: 'Both outcomes' };
  function operationOf(tx) { const op = tx.operation; return op && typeof op === 'object' && Object.keys(op).length === 1 ? Object.values(op)[0] || {} : op || {}; }
  function outcomeLabel(value) {
    const outcome = value.outcome || operationOf(value).outcome, effect = effects[value.settlement?.effect];
    return [outcome ? String(outcome).toUpperCase() : '', effect || '', {full:'Filled',partial:'Partial fill',unfilled:'Unfilled'}[value.fill_status] || ''].filter(Boolean).join(' · ');
  }
  function href(kind, value) { return `#explorer?${kind}=${encodeURIComponent(String(value))}`; }
  function create({ rpc, amountText, document = root.document, location = root.location }) {
    const $ = id => document.getElementById(id), content = $('explorer-content');
    let context = { ready: false }, version = 0, lastRoute = '', lastTip = '', lastAt = 0, loading = false, failed = false, lastRendered = '';
    const node = (tag, className = '', text) => {
      const result = document.createElement(tag); result.className = className;
      if (text !== undefined) result.textContent = String(text);
      return result;
    };
    function add(parent, tag, className, text) { const result = node(tag, className, text); parent.appendChild(result); return result; }
    function link(parent, kind, value, label = short(value), className = 'explorer-link') {
      if (kind === 'account' && (Array.isArray(value) || validHash(value))) {
        const key = Array.isArray(value) ? value.map(v => v.toString(16).padStart(2, '0')).join('') : value;
        try { const address = root.HashstashAddress.encode(key, `hsh${context.chain_id.slice(0, 16)}`); if (label === short(value)) label = short(address); value = address; }
        catch { return add(parent, 'span', '', '—'); }
      }
      if (value === null || value === undefined || value === '') return add(parent, 'span', '', '—');
      const result = add(parent, 'a', className, label); result.href = href(kind, value); result.title = String(value);
      return result;
    }
    function amount(parent, value, asset = 'hash', denominator) {
      const result = add(parent, 'span', 'explorer-amount');
      try {
        const display = (asset === 'stash' || asset === 'shares') ? `${root.HashstashShares.formatAmount(value)} stash` : root.HashstashAmounts.formatHash(value, denominator);
        amountText(result, display); result.title = (asset === 'stash' || asset === 'shares') ? `${root.HashstashShares.exactInput(value)} stash` : root.HashstashAmounts.formatExactHash(value, denominator);
      } catch { result.textContent = '—'; }
      return result;
    }
    function price(parent, ratio) {
      // Price ratios use monetary atoms per share atom.
      amount(parent, BigInt(ratio.numerator) * root.HashstashShares.DISPLAY_SCALE, 'hash', ratio.denominator);
      amountText(add(parent, 'span', ''), '/stash');
    }
    function work(parent, value) {
      const result = add(parent, 'span', 'explorer-amount');
      try {
        result.textContent = root.HashstashAmounts.formatWork(value);
        result.title = root.HashstashAmounts.formatExactWork(value);
      } catch { result.textContent = '—'; }
      return result;
    }
    function status(parent, value) {
      const known = { confirmed: 'Confirmed', pending: 'Pending', orphaned: 'Orphaned' };
      return add(parent, 'span', `explorer-status ${known[value] ? value : ''}`, known[value] || 'Unknown');
    }
    function message(value, error = false) {
      $('explorer-message').textContent = value; $('explorer-message').hidden = !value;
      $('explorer-message').classList.toggle('error', error);
    }
    function panel(title, subtitle) {
      const result = add(content, 'article', 'panel explorer-panel');
      const heading = add(result, 'div', 'section-heading'); add(heading, 'h2', '', title);
      if (subtitle) add(heading, 'span', 'explorer-subtitle', subtitle);
      return result;
    }
    function empty(parent, text) { add(parent, 'p', 'explorer-empty', text); }
    function details(parent, title) { const result = add(parent, 'details', 'explorer-disclosure'); add(result, 'summary', '', title); return result; }
    function record(parent, pairs) {
      const list = add(parent, 'dl', 'explorer-details');
      for (const [label, value] of pairs) {
        if (value === undefined || value === null) continue;
        const row = add(list, 'div', ''); add(row, 'dt', '', label); const cell = add(row, 'dd', '');
        if (typeof value === 'function') value(cell); else cell.textContent = String(value);
      }
      return list;
    }
    function table(parent, headings) {
      const wrap = add(parent, 'div', 'explorer-table-wrap'), table = add(wrap, 'table', 'explorer-table');
      const head = add(table, 'thead', ''), row = add(head, 'tr', '');
      headings.forEach(label => { const cell = add(row, 'th', '', label); cell.scope = 'col'; });
      return add(table, 'tbody', '');
    }
    function pagination(kind, value, label = 'Older') {
      if (value === null || value === undefined) return;
      const foot = add(content, 'div', 'explorer-pagination'); link(foot, kind, value, `${label} →`, 'button button-light');
    }
    function sectionPage(parent, query, key, cursor, label) {
      if (cursor === null || cursor === undefined) return;
      const next = new URLSearchParams(query); next.set(key, String(cursor));
      const item = add(add(parent, 'div', 'explorer-section-page'), 'a', 'text-link', `${label} →`);
      item.href = `#explorer?${next.toString()}`;
    }
    function back(kind = 'view', value = 'blocks', text = 'Blocks') {
      link(content, kind, value, `← ${text}`, 'text-link explorer-back');
    }
    function transactionAmount(tx) {
      if (tx.amount !== undefined && tx.amount !== null) return { value: tx.amount, asset: tx.asset || 'hash' };
      const op = operationOf(tx);
      if (op.shares !== undefined) return { value: op.shares, asset: 'stash' };
      const value = op.amount ?? op.support ?? tx.amount;
      return value === undefined || value === null ? null : { value, asset: tx.asset || 'hash' };
    }
    function transactions(parent, rows, { emptyText = 'No transactions.', showBlock = true } = {}) {
      if (!rows?.length) { empty(parent, emptyText); return; }
      const body = table(parent, ['Transaction', 'Action', 'Amount', showBlock ? 'Block' : 'Status']);
      for (const tx of rows) {
        const row = add(body, 'tr', ''); link(add(row, 'td', ''), 'tx', tx.txid, short(tx.txid));
        const action = add(row, 'td', 'explorer-kind', labels[tx.kind] || tx.kind || 'Transaction');
        const outcome = outcomeLabel(tx);
        if (outcome) add(action, 'small', 'explorer-secondary', outcome);
        const cell = add(row, 'td', ''), value = transactionAmount(tx);
        if (value) amount(cell, value.value, value.asset); else cell.textContent = '—';
        const block = add(row, 'td', '');
        if (showBlock && tx.status === 'confirmed' && tx.height !== undefined) link(block, 'block', tx.height, grouped(tx.height));
        else status(block, tx.status);
      }
    }
    function blocks(data) {
      const parent = panel('Latest blocks', `Height ${grouped(data.height)}`);
      if (!data.blocks?.length) empty(parent, 'No blocks.');
      else {
        const body = table(parent, ['Block', 'Miner', 'Transactions', 'Work']);
        for (const block of data.blocks) {
          const row = add(body, 'tr', ''), blockCell = add(row, 'td', '');
          link(blockCell, 'block', block.height, grouped(block.height));
          const hash = add(blockCell, 'small', 'explorer-secondary'); link(hash, 'block', block.hash);
          const miner = add(row, 'td', ''); if (block.height === 0) miner.textContent = 'Genesis'; else link(miner, 'account', block.miner);
          add(row, 'td', 'explorer-count', grouped(block.transaction_count));
          work(add(row, 'td', ''), block.expected_hashes);
        }
      }
      pagination('before_height', data.next_before_height);
    }
    function block(data, query) {
      const b = data.block; if (!b) throw new Error('Block not found.');
      back();
      const parent = panel(`Block ${grouped(b.height)}`); status(parent, b.status);
      record(parent, [
        ['Hash', cell => link(cell, 'block', b.hash, b.hash, 'explorer-link explorer-full')],
        ['Miner', b.miner ? cell => link(cell, 'account', b.miner, b.miner, 'explorer-link explorer-full') : '—'],
        ['Transactions', grouped(b.transaction_count)],
        ['Work', cell => work(cell, b.expected_hashes)],
        ['Subsidy', b.subsidy !== undefined ? cell => amount(cell, b.subsidy) : undefined],
        ['Size', b.body_bytes !== undefined ? `${grouped(b.body_bytes)} bytes` : undefined],
        ['Previous block', b.height > 0 && b.previous ? cell => link(cell, 'block', b.previous) : undefined],
        ['Phase', b.phase],
      ]);
      const technical = details(parent, 'Block details');
      record(technical, [['State commitment', b.state_root], ['Difficulty', typeof b.difficulty === 'number' ? b.difficulty.toLocaleString('en-US', { maximumSignificantDigits: 4 }) : b.difficulty]]);
      if (b.header) add(technical, 'pre', 'explorer-raw', JSON.stringify(b.header, null, 2));
      const allocation = b.rewards;
      if (allocation) {
        const rewards = details(parent, b.status === 'orphaned' ? 'Recorded rewards' : 'Rewards and fees');
        const rewardLabels = { subsidy: 'Block subsidy', transaction_fees: 'Transaction fees', extra_fees: 'Above minimum', minimum_fees: 'Minimum fees', miner_fees: 'Miner fee allocation', revenue_fees: 'Revenue fee allocation', miner_total: 'Miner total' };
        record(rewards, Object.entries(rewardLabels).filter(([key]) => allocation[key] !== undefined).map(([key, label]) => [label, cell => amount(cell, allocation[key])]));
      }
      transactions(panel('Transactions'), data.transactions, { showBlock: false });
      if (data.next_tx_offset !== null && data.next_tx_offset !== undefined) {
        const foot = add(content, 'div', 'explorer-pagination'); const next = add(foot, 'a', 'button button-light', 'More transactions →');
        next.href = `${href('block', query.get('block'))}&offset=${encodeURIComponent(data.next_tx_offset)}`;
      }
    }
    function dataField(parent, raw) {
      if (typeof raw !== 'string' || !raw || !/^(?:[a-f0-9]{2})+$/i.test(raw)) return;
      const field = details(parent, `Data · ${grouped(raw.length / 2)} bytes`); add(field, 'pre', 'explorer-raw', raw.toLowerCase());
      try {
        const bytes = Uint8Array.from(raw.match(/../g), v => parseInt(v, 16));
        const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        const text = decoded.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
        const plain = details(field, 'UTF-8 text'); add(plain, 'pre', 'explorer-raw explorer-data-text', text);
      } catch { /* Binary data remains available as exact hexadecimal bytes. */ }
    }
    function transaction(data) {
      const tx = data.transaction; if (!tx) throw new Error('Transaction not found.');
      back('view', 'transactions', 'Transactions');
      const parent = panel(labels[tx.kind] || tx.kind || 'Transaction'); status(parent, tx.status);
      const value = transactionAmount(tx), operation = operationOf(tx);
      record(parent, [
        ['Transaction', cell => link(cell, 'tx', tx.txid, tx.txid, 'explorer-link explorer-full')],
        ['Block', tx.height !== undefined && tx.height !== null ? cell => link(cell, 'block', tx.block_hash || tx.height, grouped(tx.height)) : undefined],
        ['Confirmations', tx.status === 'confirmed' ? grouped(tx.confirmations) : undefined],
        ['From', tx.sender ? cell => link(cell, 'account', tx.sender, tx.sender, 'explorer-link explorer-full') : undefined],
        ['To', tx.recipient ? cell => link(cell, 'account', tx.recipient, tx.recipient, 'explorer-link explorer-full') : undefined],
        [tx.input_filled !== undefined ? 'Filled input' : ['deposit','redeem','Deposit','Redeem'].includes(tx.kind) ? 'Requested input' : 'Amount', value ? cell => amount(cell, value.value, value.asset) : undefined],
        ['Fill', {full:'Filled',partial:'Partial fill',unfilled:'Unfilled'}[tx.fill_status]],
        ['Requested input', tx.input_filled !== undefined ? cell => amount(cell, tx.input_requested, tx.asset || 'hash') : undefined],
        ['Unfilled input returned', tx.input_unfilled !== undefined ? cell => amount(cell, tx.input_unfilled, tx.asset || 'hash') : undefined],
        ['Received', tx.output !== undefined ? cell => amount(cell, tx.output, tx.output_asset || 'hash') : undefined],
        [tx.status === 'orphaned' ? 'Recorded fee' : tx.status === 'pending' ? 'Signed fee' : 'Fee paid', tx.fee !== null && tx.fee !== undefined ? cell => amount(cell, tx.fee) : undefined],
        [tx.fee_estimated ? 'Current minimum fee' : 'Minimum fee', tx.minimum_fee !== null && tx.minimum_fee !== undefined ? cell => amount(cell, tx.minimum_fee) : undefined],
        ['Above minimum', tx.extra_fee !== null && tx.extra_fee !== undefined ? cell => amount(cell, tx.extra_fee) : undefined],
        ['Transaction number', grouped(tx.nonce)],
        ['Outcome', operation.outcome ? String(operation.outcome).toUpperCase() : undefined],
        ['Settlement', effects[tx.settlement?.effect]],
        ['Resolved outcome', tx.settlement?.resolved_outcome ? String(tx.settlement.resolved_outcome).toUpperCase() : undefined],
      ]);
      if (validHash(tx.decision)) record(parent, [['Decision', cell => link(cell, 'governance', tx.decision)]]);
      if (validHash(operation.proposal)) record(parent, [['Proposal', cell => link(cell, 'governance', operation.proposal)]]);
      dataField(parent, tx.data_hex);
      const technical = details(parent, 'Transaction details');
      record(technical, [['Size', `${grouped(tx.size_bytes)} bytes`], ['Anchor block', validHash(tx.anchor) ? cell => link(cell, 'block', tx.anchor, tx.anchor, 'explorer-link explorer-full') : undefined], ['Valid for · blocks', grouped(tx.expiry_blocks)]]);
      add(technical, 'pre', 'explorer-raw', JSON.stringify(tx.operation, null, 2));
    }
    function account(data, query) {
      back(); const parent = panel('Account');
      const addressNode = add(parent, 'div', 'explorer-account-address'); link(addressNode, 'account', data.address, data.address, 'explorer-link explorer-full');
      if (!data.account) empty(parent, 'This account has not received hashes.');
      else {
        const balances = add(parent, 'dl', 'explorer-balances');
        const values = [
          ['Available for payments', data.payment_available_hash, 'hash'],
          ...(!data.pass_account ? [['stash', data.account.shares, 'stash']] : []),
        ];
        for (const [label, value, asset] of values) {
          const row = add(balances, 'div', ''); add(row, 'dt', '', label); amount(add(row, 'dd', ''), value, asset);
        }
        if (data.pass_account) {
          for (const [label, account, marked, withdrawal] of [['PASS', data.pass_account, data.pass_stash_value_hash, data.pass_stash_withdrawal_hash], ['FAIL', data.account, data.stash_value_hash, data.stash_withdrawal_hash]]) {
            const outcome = add(parent, 'section', 'explorer-account-outcome'); add(outcome, 'h3', '', label);
            record(outcome, [['hashes', cell => amount(cell, account.ordinary)], ['stash', cell => amount(cell, account.shares, 'stash')], ['Estimated stash value', marked ? cell => amount(cell, marked.numerator, 'hash', marked.denominator) : undefined], ['Uncapped redemption value', withdrawal !== undefined ? cell => amount(cell, withdrawal) : undefined]]);
          }
        }
        record(parent, [
          ['Estimated stash value', !data.pass_account && data.stash_value_hash ? cell => amount(cell, data.stash_value_hash.numerator, 'hash', data.stash_value_hash.denominator) : undefined],
          ['Uncapped redemption value', !data.pass_account && data.stash_withdrawal_hash !== undefined ? cell => amount(cell, data.stash_withdrawal_hash) : undefined],
          ['Transaction counter', grouped(data.account.nonce)],
        ]);
        if (data.stash_withdrawal_hash !== undefined || data.pass_stash_withdrawal_hash !== undefined) {
          add(parent, 'p', 'explorer-secondary', 'Uncapped redemption value follows the curve for all held stash, before fees and the block price limit. It is not an executable withdrawal quote.');
        }
      }
      if (data.pending?.length) transactions(panel('Pending transactions'), data.pending);
      const history = panel('History');
      if (!data.history?.length) empty(history, 'No recorded activity.');
      else {
        const body = table(history, ['Block', 'Activity', 'Amount', 'Reference']);
        for (const entry of data.history) {
          const row = add(body, 'tr', ''); link(add(row, 'td', ''), 'block', entry.block_hash || entry.height, grouped(entry.height));
          const action = add(row, 'td', 'explorer-kind', labels[entry.kind] || entry.kind || 'Activity');
          const role = { sender: 'Sent', recipient: 'Received' }[entry.role] || entry.role;
          if (role || outcomeLabel(entry)) add(action, 'small', 'explorer-secondary', [role, outcomeLabel(entry)].filter(Boolean).join(' · '));
          const value = add(row, 'td', ''); if (entry.amount !== undefined && entry.amount !== null) amount(value, entry.amount, entry.asset || 'hash'); else value.textContent = '—';
          const tx = add(row, 'td', '');
          if (entry.txid) link(tx, 'tx', entry.txid);
          else if (entry.proposal) link(tx, 'governance', entry.proposal, 'Proposal');
          else tx.textContent = '—';
        }
      }
      if (data.next_cursor) {
        const next = add(add(content, 'div', 'explorer-pagination'), 'a', 'button button-light', 'Older activity →');
        next.href = `${href('account', query.get('account'))}&before=${encodeURIComponent(data.next_cursor)}`;
      }
    }
    function actionName(action) {
      if (action?.Grant) return 'Grant';
      if (action?.Parameter) return `${String(action.Parameter.parameter).replace(/([a-z])([A-Z])/g, '$1 $2')}`;
      return 'Proposal';
    }
    function governance(data, query) {
      const selected = query.get('governance');
      if (selected) back('view', 'governance', 'Governance');
      const proposals = data.proposals || [], decisions = data.decisions || [];
      const parent = selected && !proposals.length && decisions.length ? null : panel(selected ? 'Proposal' : 'Proposals', typeof data.phase === 'string' ? data.phase : undefined);
      if (!proposals.length && !decisions.length) empty(parent, selected ? 'Proposal not found.' : 'No proposals or decisions yet.');
      const proposalRows = !selected && proposals.length ? table(parent, ['Proposal', 'Backing', 'Created']) : null;
      for (const proposal of proposals) {
        if (proposalRows) {
          const row = add(proposalRows, 'tr', ''), main = add(row, 'td', '');
          link(main, 'governance', proposal.id, actionName(proposal.action));
          add(main, 'small', 'explorer-secondary', `Round ${grouped(proposal.round)} · ${short(proposal.id)}`);
          amount(add(row, 'td', ''), proposal.support);
          link(add(row, 'td', ''), 'block', proposal.created_height, grouped(proposal.created_height));
          continue;
        }
        const section = add(parent, 'section', 'explorer-proposal');
        link(section, 'governance', proposal.id, actionName(proposal.action), 'explorer-link explorer-proposal-title');
        record(section, [
          ['ID', cell => link(cell, 'governance', proposal.id)], ['Round', grouped(proposal.round)],
          ['Backing', cell => amount(cell, proposal.support)],
          ['Created', proposal.created_height !== undefined ? cell => link(cell, 'block', proposal.created_height, `Block ${grouped(proposal.created_height)}`) : undefined],
        ]);
        if (selected) {
          const grant = proposal.action?.Grant, parameter = proposal.action?.Parameter;
          if (grant) { record(section, [['Grant total', cell => amount(cell, grant.payments.reduce((sum,payment)=>sum+BigInt(payment.amount),0n).toString())]]);for(const payment of grant.payments)record(section,[['Recipient',cell=>link(cell,'account',payment.recipient)],['Amount',cell=>amount(cell,payment.amount)]]); }
          if (parameter) {
            const unit = parameter.parameter === 'DecisionBlocks' ? ' blocks' : ['Interval', 'Lead', 'Rest'].includes(parameter.parameter) ? ' seconds' : '';
            record(section, [['Change', `${grouped(parameter.old)}${unit} → ${grouped(parameter.new)}${unit}`]]);
          }
          const explanation = root.HashstashProposalData?.verifiedText(proposal.description_text, proposal.description);
          add(section, 'p', 'proposal-detail', explanation || 'No verified explanation published.');
          if (proposal.description) { const description = details(section, 'Description commitment'); add(description, 'code', 'explorer-full', proposal.description); }
        }
      }
      sectionPage(parent, query, 'proposal_before', data.proposal_next_cursor, 'Older proposals');
      if (decisions.length) {
        const decisionPanel = panel('Decisions');
        const decisionRows = !selected ? table(decisionPanel, ['Decision', 'Outcome', 'Started', 'Resolved']) : null;
        for (const decision of decisions) {
          const proposal = typeof decision.proposal === 'string' ? decision.proposal : decision.id;
          if (decisionRows) {
            const row = add(decisionRows, 'tr', ''); link(add(row, 'td', ''), 'governance', proposal);
            add(row, 'td', '', decision.outcome ? String(decision.outcome).toUpperCase() : 'In progress');
            link(add(row, 'td', ''), 'block', decision.started_height, grouped(decision.started_height));
            const resolved = add(row, 'td', ''); if (decision.ended_height !== null && decision.ended_height !== undefined) link(resolved, 'block', decision.ended_height, grouped(decision.ended_height)); else resolved.textContent = '—';
            continue;
          }
          const section = add(decisionPanel, 'section', 'explorer-proposal');
          if (proposal) link(section, 'governance', proposal, short(proposal));
          record(section, [
            ['Outcome', decision.outcome ? String(decision.outcome).toUpperCase() : 'In progress'],
            ['Started', cell => link(cell, 'block', decision.started_height, `Block ${grouped(decision.started_height)}`)],
            ['Resolved', decision.ended_height !== null && decision.ended_height !== undefined ? cell => link(cell, 'block', decision.ended_height, `Block ${grouped(decision.ended_height)}`) : undefined],
            ['PASS leading blocks', decision.leading_blocks === undefined ? undefined : grouped(decision.leading_blocks)],
            ['Observed blocks', decision.observed_blocks === undefined ? undefined : grouped(decision.observed_blocks)],
            ['Decision length', decision.blocks === undefined ? undefined : `${grouped(decision.blocks)} blocks`],
            ['Remaining blocks', decision.blocks_remaining === undefined ? undefined : grouped(decision.blocks_remaining)],
            ['PASS margin', decision.pass_margin_bps !== undefined ? `${BigInt(decision.pass_margin_bps) / 100n}.${(BigInt(decision.pass_margin_bps) % 100n).toString().padStart(2, '0')}%` : undefined],
          ]);
        }
        sectionPage(decisionPanel, query, 'before_height', data.next_before_height, 'Older decisions');
      }
      if (data.contributions?.length) {
        const backing = panel('Backing transactions'), body = table(backing, ['Block', 'From', 'Amount', 'Transaction']);
        for (const entry of data.contributions) {
          const row = add(body, 'tr', ''); link(add(row, 'td', ''), 'block', entry.height, grouped(entry.height));
          link(add(row, 'td', ''), 'account', entry.sender); amount(add(row, 'td', ''), entry.amount); link(add(row, 'td', ''), 'tx', entry.txid);
        }
        sectionPage(backing, query, 'before', data.next_cursor, 'Older backing');
      }
    }
    async function search(query, current) {
      const value = query.get('q')?.trim() || '';
      if (/^\d+$/.test(value)) { if (!current()) return; location.hash = href('block', BigInt(value).toString()); return; }
      if (/^hsh[a-z0-9]+$/i.test(value)) { if (!current()) return; location.hash = href('account', value); return; }
      if (!validHash(value)) throw new Error('Enter an address, transaction ID, block hash or block height.');
      try { await rpc('explorer_block', { hash: value.toLowerCase(), limit: 1 }); if (current()) location.hash = href('block', value.toLowerCase()); }
      catch { await rpc('explorer_transaction', { txid: value.toLowerCase() }); if (current()) location.hash = href('tx', value.toLowerCase()); }
    }
    function active() { return location.hash.split('?')[0] === '#explorer'; }
    async function load(force = false) {
      if (!active()) return;
      const route = location.hash, changed = route !== lastRoute;
      const age = Date.now() - lastAt;
      if (!force && !changed && (loading || age < 3000 || !failed && context.tip === lastTip && age < 10000)) return;
      const request = ++version, chain = context.chain_id; lastRoute = route; lastTip = context.tip; lastAt = Date.now(); loading = true;
      const current = () => request === version && location.hash === route && context.ready && context.chain_id === chain;
      if (changed) { content.replaceChildren(); lastRendered = ''; }
      const query = new URLSearchParams(route.split('?').slice(1).join('?'));
      const view = query.has('tx') || query.get('view') === 'transactions' ? 'transactions' : query.has('governance') || query.get('view') === 'governance' ? 'governance' : 'blocks';
      document.querySelectorAll('[data-explorer-tab]').forEach(tab => {
        const selected = tab.dataset.explorerTab === view; tab.classList.toggle('selected', selected);
        if (selected) tab.setAttribute('aria-current', 'page'); else tab.removeAttribute('aria-current');
      });
      if (!context.ready) { message('Waiting for the node connection.'); loading = false; return; }
      message(changed || !content.children.length ? 'Loading…' : '');
      try {
        if (query.has('q')) { await search(query, current); return; }
        const limit = 20, params = { limit };
        let method = 'explorer_blocks', render = blocks;
        if (query.has('block')) {
          const value = query.get('block');
          if (integer(value)) { const height = Number(value); if (!Number.isSafeInteger(height)) throw new Error('Block height is too large.'); params.height = height; }
          else if (validHash(value)) params.hash = value.toLowerCase(); else throw new Error('Invalid block hash or height.');
          if (query.has('offset')) { const offset = Number(query.get('offset')); if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('Invalid page.'); params.tx_offset = offset; }
          method = 'explorer_block'; render = block;
        } else if (query.has('tx')) { if (!validHash(query.get('tx'))) throw new Error('Invalid transaction ID.'); method = 'explorer_transaction'; params.txid = query.get('tx').toLowerCase(); delete params.limit; render = transaction; }
        else if (query.has('account')) { method = 'explorer_account'; params.address = query.get('account'); render = account; }
        else if (view === 'transactions') {
          method = 'explorer_transactions'; render = data => {
            if (data.pending?.length && !query.has('before')) transactions(panel('Pending transactions'), data.pending);
            transactions(panel('Transactions'), data.transactions);
            if (data.next_cursor) { const next = add(add(content, 'div', 'explorer-pagination'), 'a', 'button button-light', 'Older transactions →'); next.href = `${href('view', 'transactions')}&before=${encodeURIComponent(data.next_cursor)}`; }
          };
        } else if (view === 'governance') { method = 'explorer_governance'; if (query.has('governance')) params.proposal = query.get('governance'); render = governance; }
        if (query.has('before')) params.before = query.get('before');
        if (query.has('proposal_before')) params.proposal_before = query.get('proposal_before');
        if (query.has('before_height')) { const height = Number(query.get('before_height')); if (!Number.isSafeInteger(height) || height < 0) throw new Error('Invalid page.'); params.before_height = height; }
        const data = await rpc(method, params);
        if (!current()) return;
        if (data.chain_id !== chain) throw new Error('Network changed. Refresh the page.');
        const rendered = JSON.stringify(data);
        if (rendered !== lastRendered) {
          const opened = new Set([...content.querySelectorAll('details')].filter(item => item.open).map(item => item.querySelector('summary')?.textContent));
          content.replaceChildren(); render(data, query);
          for (const item of content.querySelectorAll('details')) if (opened.has(item.querySelector('summary')?.textContent)) item.open = true;
          lastRendered = rendered;
        }
        message(''); failed = false;
      } catch (error) { if (current()) { failed = true; message(error.message || 'Explorer unavailable.', true); } }
      finally { if (request === version) loading = false; }
    }
    $('explorer-search').addEventListener('submit', event => {
      event.preventDefault(); const value = $('explorer-query').value.trim();
      if (value) { const target = href('q', value); if (location.hash === target) load(true); else location.hash = target; }
    });
    return {
      route() { if (!active()) { version++; loading = false; return; } load(true); },
      update(next) {
        const changed = context.chain_id !== next.chain_id, reconnected = !context.ready && next.ready;
        if (changed || !next.ready && context.ready) { version++; loading = false; if (changed) { content.replaceChildren(); lastRoute = ''; lastRendered = ''; } }
        context = { ...next };
        if (!next.ready) { if (active()) message('Waiting for the node connection.'); return; }
        if (active()) load(changed || reconnected);
      },
    };
  }
  root.HashstashExplorer = { create };
  if (typeof module === 'object' && module.exports) module.exports = root.HashstashExplorer;
})(typeof globalThis === 'object' ? globalThis : this);
