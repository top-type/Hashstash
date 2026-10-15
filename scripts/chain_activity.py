#!/usr/bin/env python3
"""Optional, explicitly profiled test-chain activity. Never reads a private key.

The installed node CLI prepares, signs offline, and validates/broadcasts raw
transactions. This process owns only public intent/receipt data. It is not a
miner and cannot change faucet configuration, quotas, or mining settings.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import sqlite3
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from activity_plan import (cash_guard, common_cash, full_cash_governance, world_cash,
                           validated_grant, NATIVE_PROFILE, NATIVE_PROFILES, PASS_PROFILE,
                           CAMPAIGN_COORDINATOR, CAMPAIGN_RECIPIENT, campaign_proposal, campaign_ready, proposal_description)

MAX_RESPONSE = 4 * 1024 * 1024


class Pause(Exception):
    """Temporary condition; keep every signed transaction intact."""


class Fault(Exception):
    """Ambiguous ownership/history requires operator review."""


class RpcError(Exception):
    pass


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def sha256d(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()


def key_bytes(value):
    raw = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
    if len(raw) != 32:
        raise ValueError('expected a 32-byte public identifier')
    return raw


def u64(n):
    n = int(n)
    if not 0 <= n < 1 << 64:
        raise ValueError('unsigned integer outside u64 range')
    if n <= 250:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfb' + struct.pack('<H', n)
    if n <= 0xffffffff:
        return b'\xfc' + struct.pack('<I', n)
    return b'\xfd' + struct.pack('<Q', n)


def read_u64(raw, offset):
    if offset >= len(raw):
        raise Fault('truncated compact integer')
    start = offset
    tag = raw[offset]
    offset += 1
    if tag <= 250:
        return tag, offset
    size = {251: 2, 252: 4, 253: 8}.get(tag)
    if size is None or len(raw) - offset < size:
        raise Fault('invalid compact integer')
    value = int.from_bytes(raw[offset:offset + size], 'little')
    offset += size
    if raw[start:offset] != u64(value):
        raise Fault('noncanonical compact integer')
    return value, offset


def vector(raw):
    return u64(len(raw)) + raw


def amount(n):
    n = int(n)
    if n < 0 or n.bit_length() > 512:
        raise ValueError('amount outside bounded range')
    return vector(n.to_bytes((n.bit_length() + 7) // 8, 'little'))


def option(value, encode):
    return b'\0' if value is None else b'\1' + encode(value)


def encode_operation(operation):
    """Current protocol wire subset: six direct operations with signed raw data."""
    if not isinstance(operation, dict) or len(operation) != 1:
        raise ValueError('one operation required')
    kind, p = next(iter(operation.items()))
    if kind == 'TransferExact':
        if set(p) != {'recipient', 'amount'}:
            raise ValueError('unexpected transfer fields')
        code, payload = 0, key_bytes(p['recipient']) + amount(p['amount'])
    elif kind in ('Deposit', 'Redeem'):
        a, minimum = ('amount', 'min_shares') if kind == 'Deposit' else ('shares', 'min_received')
        if (p.get('decision') is None) != (p.get('outcome') is None):
            raise ValueError('conditional decision/outcome mismatch')
        code = 1 if kind == 'Deposit' else 2
        payload = amount(p[a]) + amount(p[minimum])
        payload += option(p.get('decision'), key_bytes)
        payload += option(p.get('outcome'), lambda x: u64(['Pass', 'Fail'].index(x)))
    elif kind == 'Propose':
        if set(p['proposal']) != {'Grant'}:
                raise ValueError('activity may only propose registered grants')
        grant = p['proposal']['Grant']
        payments, _ = validated_grant(grant)
        code = 3
        payload = u64(p['round']) + key_bytes(p['description']) + u64(0)
        payload += u64(len(payments))
        payload += b''.join(key_bytes(recipient) + amount(value) for recipient, value in payments)
        payload += amount(p['support'])
    elif kind in ('Support', 'Refund'):
        code = 4 if kind == 'Support' else 5
        payload = u64(p['round']) + key_bytes(p['proposal'])
        if kind == 'Support':
            payload += amount(p['amount'])
    else:
        raise ValueError('unsupported activity operation')
    return u64(code) + payload


def make_body(chain, sender, nonce, fee, expiry, operation, data_hex=''):
    inner = encode_operation(operation)
    data = bytes.fromhex(data_hex)
    if len(data) > 1024:
        raise ValueError('activity data too large')
    body = dict(chain_id=list(key_bytes(chain)), sender=list(key_bytes(sender)),
                nonce=int(nonce), fee=str(fee), expiry_height=int(expiry),
                operation=operation, data=list(data))
    wire = key_bytes(chain) + key_bytes(sender) + u64(nonce) + amount(fee) + u64(expiry) + inner + vector(data)
    return body, wire


def verified_prepared(envelope, chain, sender, nonce, fee, operation, data_hex, height, expiry_blocks,
                      max_bytes=None):
    if envelope.get('format') != 'hashstash-unsigned-v1':
        raise Fault('unexpected unsigned format')
    raw = bytes.fromhex(envelope.get('body', ''))
    if len(raw) < 70 or (max_bytes is not None and
                       (type(max_bytes) is not int or max_bytes <= 0 or len(raw) + 64 > max_bytes)):
        raise Fault('invalid unsigned length')
    _, offset = read_u64(raw, 64)
    fee_length, offset = read_u64(raw, offset)
    if fee_length > 64 or offset + fee_length >= len(raw):
        raise Fault('invalid unsigned amount')
    expiry, _ = read_u64(raw, offset + fee_length)
    if not height < expiry <= height + expiry_blocks:
        raise Pause('prepared expiry moved; obtain a fresh snapshot')
    body, expected = make_body(chain, sender, nonce, fee, expiry, operation, data_hex)
    if raw != expected:
        raise Fault('prepared transaction differs from fixed intent')
    return body, raw


def signed_wire(signed, expected_body, unsigned):
    if signed.get('body') != expected_body:
        raise Fault('signed transaction changed the reviewed body')
    signature = signed.get('signature')
    if not isinstance(signature, list) or len(signature) != 64 or any(type(x) is not int or not 0 <= x <= 255 for x in signature):
        raise Fault('invalid signature encoding')
    return unsigned + bytes(signature)


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + '.tmp')
    with open(temp, 'w', encoding='utf-8') as f:
        f.write(compact(value) + '\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def save_new(path, value, text=False):
    path = Path(path)
    wanted = value if text else compact(value) + '\n'
    if path.exists():
        if path.read_text(encoding='utf-8') != wanted:
            raise Fault('existing signed artifact differs')
        return
    with open(path, 'x', encoding='utf-8') as f:
        f.write(wanted)
        f.flush()
        os.fsync(f.fileno())


def json_request(url, body=None, headers=None):
    request = urllib.request.Request(url, None if body is None else compact(body).encode(),
                                     {'Content-Type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as e:
        # Error bodies are not logged; a provider may echo sensitive request data.
        raise RpcError('HTTP request refused: ' + str(e.code)) from None
    if len(raw) > MAX_RESPONSE:
        raise RpcError('response exceeds bound')
    return json.loads(raw)


def rpc_call(url, method, params):
    value = json_request(url, {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
    if value.get('error') is not None:
        error = value['error']
        message = error.get('message', '') if isinstance(error, dict) else str(error)
        if 'unknown transaction' in message:
            raise RpcError('unknown transaction')
        raise RpcError('node request unavailable')
    if 'result' not in value:
        raise RpcError('missing RPC result')
    return value['result']


class Cli:
    def __init__(self, binary):
        self.binary = binary

    def run(self, args):
        try:
            result = subprocess.run([self.binary, *map(str, args)], capture_output=True, timeout=25, check=False)
        except subprocess.TimeoutExpired:
            raise Pause('CLI timed out; signed intent retained') from None
        if result.returncode:
            raise Pause('CLI request failed; signed intent retained')
        return result.stdout.decode('utf-8').strip()


class Ledger:
    def __init__(self, path, config):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS intents(id TEXT PRIMARY KEY,sender TEXT NOT NULL,created REAL NOT NULL,
            prepared_height INTEGER NOT NULL,action TEXT NOT NULL,state TEXT NOT NULL,
            body TEXT,raw TEXT,txid TEXT,nonce INTEGER,expiry INTEGER,receipt_height INTEGER,
            receipt_hash TEXT,confirmed REAL,receipt TEXT);
          CREATE UNIQUE INDEX IF NOT EXISTS active_sender ON intents(sender) WHERE state IN ('preparing','pending');
          CREATE TABLE IF NOT EXISTS funding(created REAL NOT NULL,recipient TEXT NOT NULL,result TEXT);
        ''')
        identity = {'schema': 1, 'chain_id': config['chain_id'], 'region': config['region'],
                    'accounts': [a['public_key'] for a in config['accounts']]}
        old = self.get('identity')
        if old is not None and old != identity:
            self.db.close()
            raise Fault('activity ledger belongs to another chain or account set')
        self.set('identity', identity)

    def get(self, key, default=None):
        row = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)', (key, compact(value)))

    def rows(self, states):
        return self.db.execute('SELECT * FROM intents WHERE state IN (' + ','.join('?' * len(states)) + ') ORDER BY created', states).fetchall()

    def update(self, ident, **values):
        with self.db:
            self.db.execute('UPDATE intents SET ' + ','.join(k + '=?' for k in values) + ' WHERE id=?', [*values.values(), ident])


def config_checked(config):
    c = dict(config)
    if {'max_grant_raw', 'max_grant_exposure_daily_raw'} & c.keys():
        raise ValueError('grant spending cap settings are not supported')
    c.setdefault('profile', 'bounded-v1')
    if c['profile'] not in ('bounded-v1', 'substantive-v1', *NATIVE_PROFILES):
        raise ValueError('unknown activity profile')
    native = c['profile'] in NATIVE_PROFILES
    substantive = c['profile'] in ('substantive-v1', *NATIVE_PROFILES)
    if native:
        for field in ('max_consumptive_daily_raw', 'max_actions_daily',
                      'max_fee_raw', 'fee_reserve_raw'):
            c.pop(field, None)
    key_bytes(c['chain_id'])
    if c['region'] not in ('fra', 'sgp', 'ewr') or len(c['accounts']) != 3:
        raise ValueError('one known region and exactly three accounts required')
    url = urllib.parse.urlsplit(c['rpc_url'])
    if url.scheme != 'http' or not ipaddress.ip_address(url.hostname).is_loopback or url.username or url.password:
        raise ValueError('activity RPC must be loopback')
    origin = urllib.parse.urlsplit(c['faucet_url'])
    if origin.scheme != 'https' or origin.path not in ('', '/') or origin.query or origin.fragment or origin.username or origin.password:
        raise ValueError('faucet must be an HTTPS origin')
    c['faucet_url'] = c['faucet_url'].rstrip('/')
    keys = [a['public_key'] for a in c['accounts']]
    if len(set(keys)) != 3:
        raise ValueError('distinct activity keys required')
    registry = c.get('registry', {})
    if set(registry) != {'fra', 'sgp', 'ewr'} or any(len(group) != 3 for group in registry.values()):
        raise ValueError('all three regional account registries are required')
    registered = {region: [entry if isinstance(entry, str) else entry['public_key'] for entry in group]
                  for region, group in registry.items()}
    every_key = [key for group in registered.values() for key in group]
    for key in every_key:
        key_bytes(key)
    if len(set(every_key)) != 9 or registered[c['region']] != keys:
        raise ValueError('nine unique registry identities must match this region')
    for a in c['accounts']:
        key_bytes(a['public_key'])
        if not Path(a['key_file']).is_absolute() or not a.get('address', '').startswith('hsh'):
            raise ValueError('absolute key paths and public addresses required')
    for field in ('binary', 'database', 'work_dir'):
        if not Path(c[field]).is_absolute():
            raise ValueError('absolute paths required')
    defaults = {'action_seconds': 20, 'chat_seconds': 90 if substantive else 300, 'mining_fresh_seconds': 180,
                'max_fee_raw': '1' if native else '1000000', 'fee_reserve_raw': '2' if native else '1000000000',
                'confirmations': 2, 'expiry_blocks': 20, 'max_actions_daily': 4320,
                'max_consumptive_daily_raw': '1000000000000000' if substantive else '200000000000000',
                'funding_seconds': 86400}
    for key, value in defaults.items():
        c.setdefault(key, value)
        if int(c[key]) <= 0:
            raise ValueError('positive activity limits required')
    if c['action_seconds'] < 20 or c['chat_seconds'] < (90 if substantive else 300) or c['funding_seconds'] < 86400:
        raise ValueError('activity cannot bypass cadence or funding limits')
    if substantive and not native and int(c['max_consumptive_daily_raw']) > 1_000_000_000_000_000:
        raise ValueError('substantive profile exceeds its authorized ceiling')
    if not native and (int(c['max_fee_raw']) > 1000000 or c['max_actions_daily'] > 4320):
        raise ValueError('activity limit exceeds fixed ceiling')
    if c['expiry_blocks'] > 20 or not 2 <= c['confirmations'] <= 100:
        raise ValueError('bounded expiry and confirmation depth required')
    if native:
        # Null records that these inherited budget knobs are inactive. Cadence,
        # identity, journaling and actual backing/fee checks remain mandatory.
        for field in ('max_consumptive_daily_raw', 'max_actions_daily'):
            c[field] = None
        c['fee_policy'] = 'live_quote_affordability'
    return c


class Activity:
    def __init__(self, config, planner, cli=None, rpc=None, http=None, clock=time.time):
        self.c = config_checked(config)
        self.planner, self.cli = planner, cli or Cli(self.c['binary'])
        self.rpc = rpc or (lambda method, params: rpc_call(self.c['rpc_url'], method, params))
        self.http, self.clock = http or json_request, clock
        self.work = Path(self.c['work_dir'])
        self.work.mkdir(parents=True, exist_ok=True)
        Path(self.c['database']).parent.mkdir(parents=True, exist_ok=True)
        self.ledger = Ledger(self.c['database'], self.c)
        self.observed_height = None
        self.advanced_at = None
        self.state = 'starting'
        self.diagnostic = None
        self.last_diagnostic_log = None

    def verify_keys(self):
        for a in self.c['accounts']:
            public = self.cli.run(['public-key', '--key', a['key_file']]).strip()
            if public != a['public_key']:
                raise Fault('configured signing key differs from registered public key')
            address = self.cli.run(['address', '--public-key', public, '--chain-id', self.c['chain_id']]).strip()
            if address != a['address']:
                raise Fault('funding address differs from registered activity account')

    def observe(self):
        keys = [a['public_key'] for a in self.c['accounts']]
        if self.c['profile'] == PASS_PROFILE:
            keys = [entry if isinstance(entry, str) else entry['public_key']
                    for group in self.c['registry'].values() for entry in group]
        snapshot = self.rpc('snapshot', {'keys': keys})
        status = snapshot['status']
        if status.get('chain_id') != self.c['chain_id']:
            raise Fault('activity is pinned to another chain')
        height = int(status['height'])
        if self.observed_height is not None and height > self.observed_height:
            self.advanced_at = self.clock()
        self.observed_height = height
        accounts = []
        pending = {r['sender'] for r in self.ledger.rows(('preparing', 'pending'))}
        for a in self.c['accounts']:
            info = dict(a)
            info.pop('key_file', None)
            balances = snapshot.get('balances', {}).get(a['public_key'], {})
            info['account'] = self.rpc('account', {'key': a['public_key']})['account'] if balances.get('account') is not None else None
            info['pass_account'] = self.rpc('account', {'key': a['public_key'], 'outcome': 'pass'})['account'] if balances.get('pass') is not None else None
            info['pending'] = a['public_key'] in pending
            accounts.append(info)
        if full_cash_governance(snapshot) and any(
                a['account'] is not None and world_cash(a) is None for a in accounts):
            raise Pause('waiting_for_consistent_outcome_accounts')
        if self.c['profile'] == PASS_PROFILE:
            snapshot['campaign'] = self.observe_campaign(snapshot)
        return snapshot, accounts

    def observe_campaign(self, snapshot):
        """Close only on a canonical, funded, strictly winning settled grant.

        This durable marker survives explorer pagination and daemon restarts.
        Its block anchor is rechecked on every observation; no planned/pending
        transaction or instantaneous quote can create completion.
        """
        previous = self.ledger.get('pass_campaign_completion')
        if previous:
            block = self.rpc('explorer_block', {'height': previous['height'], 'limit': 1})
            if (block.get('chain_id') != self.c['chain_id']
                    or block.get('block', {}).get('hash') != previous['block_hash']):
                raise Fault('campaign settlement was reorganized')
            return dict(checked=True, completed=True, proof=previous)
        decisions, before, complete_history, history_context = [], None, False, None
        for _ in range(16):
            params = {'limit': 50}  # explorer's hard page maximum
            if before is not None:
                params['before_height'] = before
            data = self.rpc('explorer_governance', params)
            if data.get('chain_id') != self.c['chain_id']:
                raise Fault('campaign history belongs to another chain')
            context = {key: data[key] for key in ('chain_id', 'tip', 'height', 'state_root')}
            if history_context is not None and context != history_context:
                raise Pause('campaign history snapshot moved')
            history_context = context
            decisions.extend(data.get('decisions', []))
            next_before = data.get('next_before_height')
            if next_before is None:
                complete_history = True
                break
            if type(next_before) is not int or next_before < 0 or before is not None and next_before >= before:
                raise Pause('campaign history cursor is inconsistent')
            before = next_before
        pending = False
        for decision in decisions:
            ended = decision.get('ended_height')
            if type(ended) is not int:
                continue
            rows = self.rpc('proposals', {'round': decision.get('round'), 'limit': 128})
            proposal = next((row['proposal'] for row in rows if row.get('id') == decision.get('proposal')), None)
            if proposal is None or not campaign_proposal(proposal, self.c['registry']):
                continue
            if int(snapshot['status']['height']) - ended + 1 < self.c['confirmations']:
                pending = True
                continue
            if decision.get('outcome') != 'pass':
                continue
            if (decision.get('funded') is not True
                    or int(decision['pass_integral']) * 10000 <= int(decision['fail_integral']) * (10000 + int(decision['pass_margin_bps']))):
                raise Fault('campaign settlement proof is inconsistent')
            block = self.rpc('explorer_block', {'height': ended, 'limit': 1})
            if block.get('chain_id') != self.c['chain_id'] or not block.get('block', {}).get('hash'):
                raise Pause('campaign settlement block unavailable')
            if {key: block.get(key) for key in ('chain_id', 'tip', 'height', 'state_root')} != history_context:
                raise Pause('campaign settlement snapshot moved')
            if history_context['height'] - ended + 1 < self.c['confirmations']:
                raise Pause('campaign settlement confirmations changed')
            payments, amount = validated_grant(proposal['action']['Grant'])
            proof = dict(chain_id=self.c['chain_id'], decision=decision['id'], proposal=decision['proposal'],
                         height=ended, block_hash=block['block']['hash'], amount_raw=str(amount),
                         recipient=payments[0][0], decision_record=decision, observed_context=history_context)
            self.ledger.set('pass_campaign_completion', proof)
            return dict(checked=True, completed=True, proof=proof)
        # A truncated history cannot establish that no campaign already passed.
        return dict(checked=complete_history, completed=False, settlement_pending=pending)

    def mining(self):
        return self.advanced_at is not None and 0 <= self.clock() - self.advanced_at <= self.c['mining_fresh_seconds']

    def reservations(self):
        # Expired signatures retain their reservation for this rolling day:
        # there is no finality guarantee that a reorg cannot restore validity.
        rows = [r for r in self.ledger.rows(('preparing', 'pending', 'confirmed', 'expired'))
                if r['state'] in ('preparing', 'pending') or r['created'] > self.clock() - 86400]
        used = sum(int(json.loads(row['action']).get('reserved_cost_raw', self.c['max_fee_raw']))
                   for row in rows)
        return rows, used

    def policy(self, snapshot=None):
        history = []
        for row in self.ledger.rows(('confirmed',)):
            item = json.loads(row['action'])
            item.update(txid=row['txid'], confirmed_at=row['confirmed'], height=row['receipt_height'])
            history.append(item)
        # Derive rotation from the durable confirmed ledger before bounding
        # context. Pending/expired actions never advance a persona's sequence.
        from activity_personas import confirmed_chat_counts
        chat_counts = confirmed_chat_counts(self.c['region'], history)
        rows = self.ledger.rows(('preparing', 'pending', 'confirmed', 'expired'))
        status = (snapshot or {}).get('status', {})
        decision, round_id = status.get('decision'), status.get('auction_round')
        if round_id is None:
            round_id = (snapshot or {}).get('governance', {}).get('phase', {}).get('Governance', {}).get('round')
        keep = [h for index, h in enumerate(history) if index >= len(history) - 512
                or h.get('kind') in ('propose_grant', 'support', 'refund')
                or decision is not None and h.get('decision') == decision
                or round_id is not None and h.get('round') == round_id]
        _, used = self.reservations()
        result = dict(self.c, history=keep, cursor=len(history),
                    confirmed_chat_count=sum(chat_counts), confirmed_chat_counts=chat_counts,
                    pending_actions=[json.loads(r['action']) for r in rows if r['state'] in ('preparing', 'pending')],
                    last_action_at=max((r['created'] for r in rows), default=0),
                    last_action_height=max((r['prepared_height'] for r in rows), default=-1),
                    last_chat_at=max((r['created'] for r in rows if json.loads(r['action']).get('kind') == 'chat'), default=0))
        if self.c['profile'] not in NATIVE_PROFILES:
            result['consumptive_budget_remaining_raw'] = str(max(0, int(self.c['max_consumptive_daily_raw']) - used))
        return result

    def recover_preparing(self):
        for row in self.ledger.rows(('preparing',)):
            directory = self.work / row['id']
            if (directory / 'signed.json').exists() and row['body']:
                self.finish_signature(row)
            else:
                # Nothing was broadcast. Never sign a stale pre-crash quote.
                self.ledger.update(row['id'], state='abandoned')

    def finish_signature(self, row):
        directory = self.work / row['id']
        envelope = json.loads((directory / 'unsigned.json').read_text(encoding='utf-8'))
        body = json.loads(row['body'])
        signed = json.loads((directory / 'signed.json').read_text(encoding='utf-8'))
        raw = signed_wire(signed, body, bytes.fromhex(envelope['body']))
        txid = sha256d(raw)
        save_new(directory / 'raw.hex', raw.hex() + '\n', text=True)
        self.ledger.update(row['id'], state='pending', raw=raw.hex(), txid=txid,
                           nonce=body['nonce'], expiry=body['expiry_height'])

    def check_anchors(self):
        # Latest receipt per sender catches a reorg through any earlier receipt.
        latest = {}
        for row in self.ledger.rows(('confirmed',)):
            latest[row['sender']] = row
        for row in latest.values():
            value = self.rpc('explorer_block', {'height': row['receipt_height'], 'limit': 1})
            if value.get('chain_id') != self.c['chain_id'] or value['block']['hash'] != row['receipt_hash']:
                raise Fault('a confirmed activity receipt was reorganized')

    def reconcile(self, snapshot, accounts):
        height = int(snapshot['status']['height'])
        by_key = {a['public_key']: a for a in accounts}
        for row in self.ledger.rows(('pending',)):
            raw = bytes.fromhex(row['raw'])
            if sha256d(raw) != row['txid']:
                raise Fault('signed journal integrity failure')
            try:
                result = self.rpc('explorer_transaction', {'txid': row['txid']})
            except RpcError as e:
                if str(e) != 'unknown transaction':
                    raise
                result = None
            if result is not None:
                if result.get('chain_id') != self.c['chain_id']:
                    raise Fault('receipt from another chain')
                tx = result['transaction']
                if tx.get('txid') != row['txid'] or tx.get('sender_public_key') != row['sender'] or tx.get('nonce') != row['nonce']:
                    raise Fault('transaction receipt differs from journal')
                if tx.get('status') == 'confirmed':
                    if tx.get('confirmations', 0) >= self.c['confirmations']:
                        self.ledger.update(row['id'], state='confirmed', receipt_height=tx['height'],
                                           receipt_hash=tx['block_hash'], confirmed=self.clock(), receipt=compact(tx))
                    continue
            account = by_key[row['sender']]['account']
            nonce = int(account['nonce']) if account else 0
            if nonce > row['nonce']:
                # Explorer and snapshot may cross a block boundary; require a
                # second stable snapshot before declaring ambiguous consumption.
                latest = self.rpc('snapshot', {'keys': []})['status']
                if latest.get('tip') != snapshot['status'].get('tip') or latest['height'] != height:
                    raise Pause('receipt snapshot moved')
                raise Fault('account nonce advanced without its recorded receipt')
            if height > row['expiry']:
                self.ledger.update(row['id'], state='expired')
            elif self.mining():
                try:
                    self.broadcast(row)
                except Pause:
                    # Admission can reject a now-conflicting proposal, or its
                    # response can be lost. Keep this signer occupied, but do
                    # not stall unrelated accounts while this intent expires.
                    pass

    def broadcast(self, row):
        path = self.work / row['id'] / 'raw.hex'
        if path.read_text(encoding='utf-8').strip() != row['raw']:
            raise Fault('broadcast artifact differs from durable journal')
        key = 'broadcast:' + row['txid']
        previous = self.ledger.get(key, {})
        if previous and self.clock() - previous['at'] < self.c['action_seconds']:
            return
        self.ledger.set(key, {'at': self.clock(), 'result': 'uncertain'})
        self.cli.run(['broadcast', '--url', self.c['rpc_url'], '--raw-file', path])
        self.ledger.set(key, {'at': self.clock(), 'result': 'submitted'})
        # Admission is not a receipt; state intentionally remains pending.

    def funding(self):
        recipient = self.c['accounts'][0]['address']
        latest = self.ledger.db.execute('SELECT MAX(created) FROM funding').fetchone()[0]
        if latest is not None and self.clock() - latest < self.c['funding_seconds']:
            return
        url = self.c['faucet_url']
        status = self.http(url + '/faucet/status?address=' + urllib.parse.quote(recipient), headers={'Origin': url})
        if status.get('chain_id') != self.c['chain_id']:
            raise Fault('faucet belongs to another chain')
        if not status.get('available') or status.get('state') != 'ready' or status.get('retry_after_seconds', 0) > 0:
            return
        # Reserve before HTTP. An uncertain request cannot cause another daily
        # claim or a different funding address after process restart.
        created = self.clock()
        with self.ledger.db:
            self.ledger.db.execute('INSERT INTO funding VALUES(?,?,NULL)', (created, recipient))
        result = self.http(url + '/faucet/claim', {'address': recipient}, {'Origin': url})
        safe = {k: result.get(k) for k in ('txid', 'status', 'chain_id', 'amount_hashes')}
        with self.ledger.db:
            self.ledger.db.execute('UPDATE funding SET result=? WHERE created=?', (compact(safe), created))

    def grant_check(self, operation, allowed, snapshot, fee=0):
        kind, op = next(iter(operation.items()))
        if kind not in ('Propose', 'Support'):
            return 0
        if kind == 'Propose':
            grant = op['proposal']['Grant']
        else:
            proposal_id = key_bytes(op['proposal']).hex()
            rows = self.rpc('proposals', {'round': op['round'], 'limit': 128})
            found = next((r['proposal'] for r in rows if r.get('id') == proposal_id), None)
            if not found or found.get('round') != op['round'] or set(found.get('action', {})) != {'Grant'}:
                raise Pause('support proposal is unavailable or outside grant scope')
            grant = found['action']['Grant']
        payments, n = validated_grant(grant)
        if any(recipient not in allowed for recipient, _ in payments):
            raise Fault('grant recipient outside activity registry')
        if not snapshot:
            raise Pause('fresh reserve state required for grant')
        world = snapshot['governance']['world']
        if self.c['profile'] == PASS_PROFILE:
            if kind != 'Propose' or self.c['region'] != CAMPAIGN_COORDINATOR:
                raise Fault('campaign has one coordinator and no extra support payments')
            recipient = self.c['registry'][CAMPAIGN_RECIPIENT][0]
            recipient = recipient if isinstance(recipient, str) else recipient['public_key']
            if payments != [(recipient, n)] or not campaign_ready(snapshot, self.c['registry'], max(1, fee)):
                raise Pause('campaign requires nine backed accounts with real buying power')
            if (snapshot.get('campaign', {}).get('checked') is not True
                    or snapshot.get('campaign', {}).get('completed') or snapshot.get('campaign', {}).get('settlement_pending')):
                raise Pause('campaign is already settled or awaiting confirmation')
        if n <= 0 or n > int(world['grant_capacity']):
            raise Pause('grant exceeds current backing')
        quote = self.rpc('grant_quote', {'amount': str(n)})
        if quote.get('feasible') is not True:
            raise Pause('grant cannot be funded by current reserve rules')
        return n

    def allowed_action(self, action, accounts, policy, snapshot=None):
        index = action.get('sender_index')
        if type(index) is not int or not 0 <= index < 3 or accounts[index]['pending']:
            raise Pause('selected activity account is busy')
        operation = action['operation']
        encode_operation(operation)
        self.check_cash(action, snapshot, accounts[index])
        allowed = {a['public_key'] for a in self.c['accounts']}
        for group in self.c.get('registry', {}).values():
            allowed.update(x if isinstance(x, str) else x['public_key'] for x in group)
        kind, op = next(iter(operation.items()))
        native = self.c['profile'] in NATIVE_PROFILES
        if self.c['profile'] == PASS_PROFILE:
            if kind == 'Propose' and index != 0:
                raise Fault('campaign proposal must use the existing coordinator account')
            if kind == 'Support':
                raise Fault('campaign does not amplify auction revenue with extra support')
            if full_cash_governance(snapshot or {}):
                # Campaign governance exposure is intentionally one-way. Normal
                # shared refuel/seed transfers remain possible if cash is needed.
                if ((kind == 'Deposit' and op.get('outcome') != 'Pass')
                        or (kind == 'Redeem' and op.get('outcome') != 'Fail')):
                    raise Fault('campaign only buys PASS and exits FAIL during governance')
                if kind in ('Deposit', 'Redeem'):
                    active = snapshot.get('governance', {}).get('phase', {}).get('Governance', {})
                    rows = self.rpc('proposals', {'round': active.get('round'), 'limit': 128})
                    proposal_id = bytes(active.get('proposal_id', [])).hex()
                    record = next((row['proposal'] for row in rows if row.get('id') == proposal_id), None)
                    if (record is None or not campaign_proposal(record, self.c['registry'])
                            or record['action'] != active.get('proposal')
                            or int(snapshot['governance']['pass']['grant_escrow']) != validated_grant(record['action']['Grant'])[1]):
                        raise Pause('campaign trade requires its exact funded proposal')
        spending = int(action['quoted_fee_raw']) if native else int(self.c['max_fee_raw'])
        if kind == 'TransferExact':
            recipient = key_bytes(op['recipient']).hex()
            if recipient not in allowed:
                raise Fault('activity recipient outside public test registry')
        if kind == 'Propose':
            grant = op['proposal']['Grant']
            payments, _ = validated_grant(grant)
            if any(recipient not in allowed for recipient, _ in payments):
                raise Fault('grant exceeds activity scope')
            spending += int(op['support'])
        elif kind == 'Support':
            spending += int(op['amount'])
        data = bytes.fromhex(action.get('data_hex', ''))
        if native and kind == 'Propose':
            expected = proposal_description(self.c['region'], op['round'], self.c['profile']).encode('utf-8')
            if data or hashlib.sha256(expected).digest() != key_bytes(op['description']):
                raise Fault('native proposal requires empty data and its regional round commitment')
        elif data and kind == 'Propose':
            # Preserve the existing demo identity and grant scope. The raw
            # explanation must be exactly the bytes committed by this proposal.
            expected = proposal_description(self.c['region'], op['round'], self.c['profile']).encode('utf-8')
            if data != expected or hashlib.sha256(data).digest() != key_bytes(op['description']):
                raise Fault('proposal data must match its signed demo description')
        elif data:
            if kind != 'TransferExact' or action.get('kind') != 'chat':
                raise Fault('activity data is restricted to labelled transfer chat')
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError as error:
                raise Fault('activity messages must be public UTF-8 text') from error
            if (len(data) > 512 or not text.strip() or text.startswith('hashstash.')
                    or any((ord(char) < 32 or 127 <= ord(char) <= 159) and char not in '\n\r\t' for char in text)
                    or 'automated' not in text.lower()):
                raise Fault('activity messages must be bounded plain text labelled automated')
            if self.clock() - policy['last_chat_at'] < self.c['chat_seconds']:
                raise Pause('chat cadence')
        recent, used = self.reservations()
        if not native and (len(recent) >= self.c['max_actions_daily'] or used + spending > int(self.c['max_consumptive_daily_raw'])):
            raise Pause('daily activity budget reached')
        action['reserved_cost_raw'] = str(spending)
        self.grant_check(operation, allowed, snapshot, int(action['quoted_fee_raw']))

    def check_cash(self, action, snapshot, account):
        native = self.c['profile'] in NATIVE_PROFILES
        fee = int(action['quoted_fee_raw']) if native else int(self.c['max_fee_raw'])
        reserve = fee * 2 if native else max(int(self.c['fee_reserve_raw']), fee * 2)
        reason = cash_guard(snapshot or {}, account, action['operation'], fee, reserve)
        if native and not full_cash_governance(snapshot or {}):
            kind, fields = next(iter(action['operation'].items()))
            debit = int(fields['amount']) if kind in ('TransferExact', 'Deposit', 'Support') else int(fields['support']) if kind == 'Propose' else 0
            credit = int(fields['min_received']) if kind == 'Redeem' else 0
            ordinary = int((account.get('account') or {}).get('ordinary', 0))
            if ordinary + credit - debit < fee + (reserve if debit else 0):
                reason = 'waiting_for_native_balance_and_fee'
        if reason:
            raise Pause(reason)

    def submit(self, action, snapshot, accounts):
        policy = self.policy(snapshot)
        self.allowed_action(action, accounts, policy, snapshot)
        index = action['sender_index']
        account = accounts[index]
        if not account['account'] or not self.planner.still_valid(action, snapshot, account):
            raise Pause('activity intent is no longer current')
        fee = int(action['quoted_fee_raw'])
        if fee < 0 or (self.c['profile'] not in NATIVE_PROFILES and fee > int(self.c['max_fee_raw'])):
            raise Pause('quoted fee exceeds activity budget')
        height = int(snapshot['status']['height'])
        nonce = int(account['account']['nonce'])
        ident = uuid.uuid4().hex
        directory = self.work / ident
        directory.mkdir()
        with self.ledger.db:
            self.ledger.db.execute('INSERT INTO intents(id,sender,created,prepared_height,action,state) VALUES(?,?,?,?,?,?)',
                (ident, account['public_key'], self.clock(), height, compact(action), 'preparing'))
        save_new(directory / 'operation.json', action['operation'])
        args = ['prepare', '--url', self.c['rpc_url'], '--sender', account['public_key'],
                '--operation-file', directory / 'operation.json', '--fee', str(fee),
                '--expiry-blocks', self.c['expiry_blocks'], '--out', directory / 'unsigned.json']
        if action.get('data_hex'):
            args += ['--data-hex', action['data_hex']]
        try:
            self.cli.run(args)
            envelope = json.loads((directory / 'unsigned.json').read_text(encoding='utf-8'))
            body, _ = verified_prepared(envelope, self.c['chain_id'], account['public_key'], nonce,
                fee, action['operation'], action.get('data_hex', ''), height, self.c['expiry_blocks'],
                max_bytes=int(snapshot['status']['settings']['block_bytes']))
            fresh, current = self.observe()
            if not self.mining() or not self.planner.still_valid(action, fresh, current[index]) or current[index]['account']['nonce'] != nonce:
                raise Pause('snapshot changed before signing')
            self.check_cash(action, fresh, current[index])
            if next(iter(action['operation'])) in ('Propose', 'Support'):
                allowed = {a['public_key'] for a in self.c['accounts']}
                for group in self.c['registry'].values():
                    allowed.update(x if isinstance(x, str) else x['public_key'] for x in group)
                self.grant_check(action['operation'], allowed, fresh, fee)
            save_new(directory / 'body.json', body)
            self.ledger.update(ident, body=compact(body), nonce=nonce, expiry=body['expiry_height'])
            self.cli.run(['sign', '--key', self.c['accounts'][index]['key_file'], '--body', directory / 'body.json', '--out', directory / 'signed.json'])
            row = self.ledger.db.execute('SELECT * FROM intents WHERE id=?', (ident,)).fetchone()
            self.finish_signature(row)
            row = self.ledger.db.execute('SELECT * FROM intents WHERE id=?', (ident,)).fetchone()
            self.broadcast(row)
        except Exception:
            if not (directory / 'signed.json').exists():
                self.ledger.update(ident, state='abandoned')
            raise

    def record_error(self, error):
        # Never serialize exception text, type names from subclasses, request
        # bodies, paths, signed bytes, or credentials into public diagnostics.
        category = ('rpc' if isinstance(error, RpcError) else
                    'filesystem_permission' if isinstance(error, PermissionError) else
                    'filesystem' if isinstance(error, OSError) else
                    'missing_field' if isinstance(error, KeyError) else
                    'invalid_type' if isinstance(error, TypeError) else 'invalid_value')
        now = self.clock()
        previous = self.diagnostic or {}
        self.diagnostic = {'category': category,
            'consecutive_errors': min(2_147_483_647, previous.get('consecutive_errors', 0) + 1),
            'first_at': previous.get('first_at', now), 'last_at': now}
        if self.last_diagnostic_log is None or now - self.last_diagnostic_log >= 60:
            print('activity diagnostic ' + compact(self.diagnostic), file=sys.stderr, flush=True)
            self.last_diagnostic_log = now

    def tick(self):
        if self.ledger.get('fault'):
            self.state = 'operator_review'
            self.write_status()
            return
        try:
            self.recover_preparing()
            snapshot, accounts = self.observe()
            self.check_anchors()
            self.reconcile(snapshot, accounts)
            if not self.mining():
                raise Pause('waiting_for_mining')
            policy = self.policy(snapshot)
            height = int(snapshot['status']['height'])
            if self.clock() - policy['last_action_at'] < self.c['action_seconds'] or height <= policy['last_action_height']:
                raise Pause('waiting_for_next_block')
            controller = accounts[0]['account']
            funding_floor = (max(1, int(snapshot['status'].get('settings', {}).get('minimum_fee_rate', 1))) * 2
                             if self.c['profile'] in NATIVE_PROFILES else int(self.c['fee_reserve_raw']))
            if controller is None or common_cash(snapshot, accounts[0]) < funding_floor:
                self.funding()
            action = self.planner.plan(snapshot, accounts, self.c.get('registry', {}), policy, self.clock(), self.rpc)
            if action:
                self.submit(action, snapshot, accounts)
                self.state = 'pending'
            else:
                self.state = ('waiting_for_cash_in_both_outcomes'
                    if full_cash_governance(snapshot) and all(
                        a.get('pending') or common_cash(snapshot, a) < int(self.c['max_fee_raw'])
                        for a in accounts) else 'waiting_for_eligible_action')
            self.diagnostic = None
        except Fault as e:
            self.ledger.set('fault', str(e))
            self.state = 'operator_review'
        except Pause as e:
            self.state = str(e)
            self.diagnostic = None
        except (RpcError, OSError, ValueError, KeyError, TypeError) as e:
            self.record_error(e)
            self.state = 'waiting_for_node'
        self.write_status()

    def write_status(self):
        counts = {r[0]: r[1] for r in self.ledger.db.execute('SELECT state,COUNT(*) FROM intents GROUP BY state')}
        _, spent = self.reservations()
        atomic_json(self.work / 'status.json', {'chain_id': self.c['chain_id'], 'region': self.c['region'],
            'observed_at': self.clock(), 'height': self.observed_height, 'mining_active': self.mining(),
            'state': self.state, 'counts': counts, 'fault': self.ledger.get('fault'),
            'diagnostic': self.diagnostic,
            'funding_requests': self.ledger.db.execute('SELECT COUNT(*) FROM funding').fetchone()[0],
            'profile': self.c['profile'], 'consumptive_reserved_24h_raw': str(spent),
            'campaign': self.ledger.get('pass_campaign_completion') if self.c['profile'] == PASS_PROFILE else None})


class SingleInstance:
    def __init__(self, path):
        self.file = open(path, 'a+b')
        if os.name == 'nt':
            import msvcrt
            if not self.file.tell():
                self.file.write(b'0')
                self.file.flush()
            self.file.seek(0)
            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    config = config_checked(json.loads(args.config.read_text(encoding='utf-8')))
    Path(config['work_dir']).mkdir(parents=True, exist_ok=True)
    lock = SingleInstance(Path(config['work_dir']) / 'activity.lock')
    import activity_plan
    activity = Activity(config, activity_plan)
    activity.verify_keys()
    stopped = False

    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopped:
            activity.tick()
            for _ in range(10):
                if stopped:
                    break
                time.sleep(0.5)
    finally:
        activity.state = 'stopped'
        activity.write_status()
        activity.ledger.db.close()
        lock.file.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Activity stopped: ' + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
