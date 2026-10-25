# Optional test faucet

The faucet transfers existing hashes from a dedicated account. It cannot issue
hashes, change consensus, access browser wallets, or select an arbitrary operation.
Run it only on a disposable test network with a limited funding balance.

Build `cargo build --release --locked --bin hashstash-faucet`, then run:

```text
hashstash-faucet --config /etc/hashstash-faucet/config.json
```

An example configuration for a local development website is:

```json
{
  "bind": "127.0.0.1:18484",
  "rpc_url": "http://127.0.0.1:18480/rpc",
  "chain_id": "REPLACE_WITH_THE_NETWORK_CHAIN_ID",
  "key_file": "/etc/hashstash-faucet/faucet.key",
  "database": "/var/lib/hashstash-faucet/claims.sqlite",
  "origins": ["http://127.0.0.1:18480"],
  "payout": "1000",
  "max_fee": "10",
  "cooldown_seconds": 86400,
  "subnet_cooldown_seconds": 60,
  "subnet_daily_claims": 10,
  "hourly_claims": 100,
  "daily_claims": 250,
  "lifetime_claims": 1000,
  "recent_block_seconds": 180,
  "confirmations": 2,
  "expiry_blocks": 2
}
```

Generate the dedicated key with `hashstash keygen --out PATH`. Give only the
faucet operating-system user access to that key and its database. Funding can be
an ordinary transfer or mining rewards paid to the faucet address. Never give
the faucet a visitor's key or the key to an account holding valuable funds.
The daemon accepts the usual key-file JSON, with `secret` and `public` fields.
It refuses a key file that is a symbolic link, and on Unix one readable or
writable by its group or other users (keep `keygen`'s 0600 mode). On Windows
it refuses one whose access list, read from the open file (account SIDs, the
same in every display language), lets in any account other than the faucet's
own, SYSTEM and Administrators; inherited entries count, so a key copied into
a folder that lets Users read is refused until it is restricted again
(`keygen` sets an owner-only list), and so is one on a FAT or exFAT volume,
which holds no access list. The key is read through the one opened handle the
other checks inspected, so a path replaced in between is refused: on Unix the
handle must have the inspected device and inode, and on Windows the path is
opened without following a symbolic link or junction, which is then refused.
The Windows access list is read through that same handle.
The node's peer identity files use the same reader. Parsed copies of the
secret are wiped, and stored subnet digests use a key derived from the signer,
never the signing key itself.
Changing the ledger's network or signer requires a separate ledger. Changing
`payout` applies to new claims after a restart; recorded payments keep their
original amounts, and all cooldowns and claim counts are preserved.
The ledger stores the amount of each payment alongside its claim record.

The example dispenses 1 hash per claim (1,000 raw hash atoms) and permits one claim
per address each day. Configuration and API amounts use integer raw hash atoms.
A shared IPv4 /24 or IPv6 /48 can make a new claim once per minute, so another
wallet on the same network does not inherit a full day's wait. The separate
`subnet_cooldown_seconds` setting defaults to 60 when omitted; both cooldowns
must be positive and at most one year. Each such network also receives at most
`subnet_daily_claims` claims in any 24 hours (default 10, at most 1,000,000), so
one host generating fresh addresses cannot take most of the global allowance.
IPv6 is grouped by /48, one site, as the node's network admission groups it: a
free tunnel broker or a VPS hands out a whole /48, and grouping by /56 would
give its one holder 256 daily shares, more than the example's whole daily
allowance. Customers of one provider whose delegations share a /48
share its allowance too, as visitors behind one IPv4 /24 do. A 6to4 address
(`2002::/16`) counts as the IPv4 /24 it embeds. At this payout, the
claim-count caps allow up to 100 hashes per hour, 250 hashes per day, and 1,000
hashes over the ledger's lifetime. The service additionally limits each exact
quoted fee to 0.01 hash.
This is a local spending allowance, not an encoded transaction cap. Pending
and expired claims consume the allowance too. When a passed MinimumFeeRate
increase or BlockBytes decrease takes effect within a claim's lifetime, the
node's quote reports it and the faucet refuses the claim before signing, so the
visitor can retry once the change is active instead of spending an allowance on
a payment with only one usable block. That includes a change the next block
passes when it resolves a decision, which with a zero rest that same block
activates. Changing the payout does not
reset these counts; historical payments retain the amounts paid at the time. This
limits the dispenser's exposure; IP limits are not proof of unique people. To
extend an exhausted lifetime allowance, raise `lifetime_claims` (up to
1,000,000) and restart; the ledger and its history are kept.

## Website and proxy

The daemon binds only to loopback and calls only a loopback node RPC. Keep that
RPC private. Expose only the two faucet routes through the existing HTTPS
reverse proxy. Configure the exact HTTPS website origins; wildcard origins
are unsupported. Every request must have an allowed Host and an `X-Real-IP`
header supplied by the trusted proxy. The proxy must **overwrite** that header
with the actual connecting IP, never preserve a visitor-provided value. Websites
may share one faucet authority and its quotas, or each use its own local faucet.
Independent faucets need separate funding accounts, keys, and ledgers; each
instance enforces its own quotas and spends only its own balance. A node may
direct its mining payout to that node's faucet account through node configuration.

To show **Get test hashes** in Wallet, the website must serve
`/faucet-config.json` with `{"url":"https://FAUCET_HOST","chain_id":"NETWORK_CHAIN_ID"}`.
The URL is the HTTPS origin without `/faucet`; the wallet app adds the API paths.
Use `Cache-Control: no-store`. The same-origin `/faucet/` route below works with
the node's built-in policy. The node sends a fixed Content-Security-Policy with
`connect-src 'self'`, and a second CSP header added by a proxy can only narrow
it. To use a faucet on another origin, the proxy must replace the node's header
(for example nginx `proxy_hide_header Content-Security-Policy;`) with a complete
copy of the node's policy that differs only by adding that exact origin to
`connect-src`. Keep every other directive, including `script-src 'self'`. Without
a matching descriptor the wallet hides the optional faucet controls. The wallet
queries faucet status, which names the selected address, only while Wallet is
open, so another view never reports an address to the faucet operator.

For example, the proxy can preserve its external Host and set:

```nginx
location /faucet/ {
    proxy_pass http://127.0.0.1:18484;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    client_max_body_size 1k;
}
```

Do not forward this endpoint through an additional proxy without explicitly
designing how the actual client address is authenticated. The service supports
CORS only for the exact configured website origins. POST also requires that
Origin and JSON content type. It stores keyed subnet digests, not literal IPs.
HTTP concurrency, request duration, and request-body size are bounded: 16
requests run at once, and one client network may hold at most four of them.
At most 64 connections are served at once. Each connection must send every
request head within five seconds of opening or of its previous response, so a
partial head or an idle keep-alive connection is closed unanswered. At the
limit a new connection takes the place of the one that has waited longest for
its next request, which is closed; only when all 64 are handling requests is
the new one closed as soon as it is accepted, before anything is read. A
request beyond the 16 that run at once is answered immediately, so few
connections stay busy for long, and connections held open, idle or with
partial heads, never keep the proxy out. A local program sending requests
without pause on every connection can still crowd it out, at the cost of
continuous work for itself and the faucet.

Status never waits for payments or node lookups. It answers from the state the
latest refresh or reservation published, reading cooldowns and claims through
its own read-only ledger connection. A refresh holds the claim engine only for
each local accounting step, never while it waits for the node (each node call
has a five-second timeout). A claim holds the engine from its eligibility checks
through its reservation, including the node's preparation of the transfer, so
the nonce, anchor and one pending payment cannot change meanwhile; the
broadcast that follows holds nothing. The claim's answer waits at most two
seconds for that broadcast, which a node usually accepts at once, and never
past one second before the 15-second request deadline below, so a claim
reserved in time is answered with its payment; a busy node's `Retry-After` and
resend (below), or a slow reply, continue in the background, and refreshes
retry the reserved bytes anyway. All ledger work, including its synchronous
commits, runs on blocking threads rather than the HTTP workers. A request still
waiting after 15 seconds receives HTTP 503: a claim queued behind other claims,
or whose preparation the node is slow to answer, can reach it before it is
reserved, and the visitor then reads the claim's outcome from status.

A node refusing a request on admission grounds answers 429 or 503 with
`Retry-After`; the request did not run. The faucet waits out a `Retry-After` of
up to five seconds and resends the request once. A longer wait, a refusal
without one, or a second refusal fails the request with the journal category
`node_busy` rather than `node_transport`, and the next refresh then waits as
long as the node asked, up to one minute. The faucet's own node RPC client
ignores `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`; it always connects
directly to the configured loopback node.

`GET /faucet/status` returns:

```json
{
  "enabled": true,
  "chain_id": "...",
  "amount_hashes": "1000",
  "available": true,
  "mining_active": true,
  "state": "ready",
  "cooldown_seconds": 86400,
  "address": "FAUCET_FUNDING_ADDRESS"
}
```

Other states are `waiting_for_mining`, `unfunded`, `pending`, `cooldown`, `quota_reached`,
`fee_cap_exceeded`, `capacity_exceeded`, and `unavailable`. `fee_cap_exceeded` means
the governed minimum fee for a payment to a new account now exceeds `max_fee`;
`capacity_exceeded` means that payment's weight exceeds the governed block
capacity, so no block could include it. The faucet computes both from the node
snapshot exactly as node preparation does. A payment to an existing account
omits the account-creation weight, so while either state holds such a claim is
still paid when its own exact quote fits the capacity and `max_fee`; a claim
that does not fit is refused before anything is signed or reserved. When even
an existing account's payment cannot fit, every claim is refused without
preparing a transaction. The wallet disables its claim button in either state.
Raise `max_fee`, or wait for capacity to be restored. Refresh errors and pause
reasons appear only in the operator journal as fixed categories, never in status.
Add `?address=RECIPIENT_ADDRESS` to receive an optional
`claim` object for that recipient. It contains `status`, `txid`, `chain_id`,
`amount_hashes`, and `retry_after_seconds`. The top-level amount is the current
payout; the nested claim amount is that payment's original amount.

For a selected address, status also supplies top-level `retry_after_seconds`:
the maximum remaining wait across that address and the trusted proxy's client
subnet. It is zero when neither cooldown applies. When a cooldown blocks an
otherwise available faucet, `state` is `cooldown`, `available` is false, and
`cooldown_scope` is `address` or `network`. No other recipient, claim, client IP,
or stored subnet digest is disclosed. Status queries do not reserve funds. Like
any per-network limit that reports its wait, a `network` wait tells a caller
that someone on the same /24 or /48 claimed recently or used that network's
daily share; the claim response reports the same wait.

`POST /faucet/claim` accepts only `{"address":"RECIPIENT_ADDRESS"}`. It returns
the same claim object with `pending`, `confirmed`, or `expired` status. A repeated
request during a pending payment or cooldown returns the recorded claim instead
of another payment. The recipient receives the fixed amount; the faucet pays
the actual transaction fee separately, including the account-creation weight
when needed. Unknown JSON fields are rejected. Errors return HTTP 400, 403,
422, 429, or 503 with an error response;
the UI should handle malformed-body errors without assuming a JSON payload.
An HTTP 429 cooldown response includes the actual remaining seconds in both
`retry_after_seconds` and the `Retry-After` header, plus `cooldown_scope`.
Global budget exhaustion remains separate and does not invent a cooldown
countdown. Changing the subnet cooldown preserves the entire existing claim
ledger, all address cooldowns, and hourly, daily, and lifetime budget usage.

## Payment and recovery rules

The service first checks eligibility, prepares a fixed exact transfer, and
checks the node and export network context, then independently verifies the signed
sender, recipient, amount, nonce, anchor and lifetime against its coherent node snapshot,
exact fee within its configured local spending allowance, and absence of arbitrary data. It commits the
signed bytes, transaction ID, and quota reservation in SQLite before broadcast.
Only one payment is outstanding per faucet instance. Network errors keep it pending;
subsequent polls and restarts retry identical signed bytes.

The default lifetime is two blocks after the signed anchor. An anchor at height
100 with `expiry_blocks: 2` permits inclusion at heights 101 or 102. Set a longer
positive lifetime explicitly when needed; retries keep the original anchor and
lifetime. The derived deadline must fit the faucet ledger's signed 64-bit SQLite
integer before the service signs a payment.

Confirmation requires locating that transaction in canonical block history and
the configured confirmation depth. A higher account nonce alone is insufficient.
The faucet uses the node's private `blockreceipt` RPC for this, so the faucet
needs a node from a release that provides it; run the faucet and node from the
same release. The RPC returns one canonical block hash and whether that block
holds the named transaction IDs (at most 64). No block is ever transferred or
parsed as JSON. A lookup that names no IDs reads only the node's canonical
index, and the node loads a block body only to check named IDs. The optional
`checked` parameter, `{"height":H,"hash":HASH}`, adds `checked_canonical` to
the reply: whether that block was canonical in the same read.

Every refresh accounts for the nonces the canonical chain consumed. Each nonce
can pay at most one recorded claim, so these automatic repairs can never pay
twice:

- The newest confirmed receipt is checked by its block hash alone, which commits
  to the payment and to all older receipts. If that block leaves the canonical
  chain, the claim is accounted again: found elsewhere it keeps a moved
  receipt. Otherwise, while no newer claim is pending, it is pending again and
  retried while still valid, and expires after its lifetime. A newer claim
  that is pending was signed on the abandoned branch, so its anchor is
  orphaned and it expires unpaid (next rule); the faucet keeps one pending
  payment, marks the reorganized claim expired at once and does not resend it
  itself. The nodes that switched branches return its transaction to their
  pools while its anchor and nonce allow, and if a later block includes it the
  claim is marked confirmed again (see below). Otherwise it stays expired, and
  its recipient waits out the address cooldown as after any expired claim.
- A pending claim whose anchor was orphaned, even by a one-block reorganization,
  or whose anchor lies above a shorter chain, keeps its exact bytes and expires
  once the canonical height reaches its expiry height with its nonce unused.
- A claim recorded as expired that a later branch includes is marked confirmed,
  and any other claim signed with the same nonce becomes expired.
- A consumed nonce is searched for among every unsettled claim signed with it.
  Only heights inside some claim's inclusion window are inspected, each for
  just the claims whose window covers it, so a long run of expired claims or an
  old expired claim never makes a lookup exceed the node's limit or widen the
  search. Each lookup confirms the previously inspected block in the same node
  read; if the chain switched branches in between, the search starts again.
- Inclusion searches resume across refreshes and make at most 64 block lookups
  per refresh. A completed search is not repeated while its blocks stay
  canonical: it then costs one lookup per refresh, which loads no block.
- Claims keep using the last snapshot whose payments were accounted for until
  a refresh finishes accounting for a new one. A refresh that fails, for
  example because a lookup timed out or the node was busy, pauses new claims in
  the same step that ends it, so no claim, even one already waiting, is
  prepared from a snapshot whose accounting failed; claims resume after the
  next refresh that succeeds. A claim reserved while a refresh
  waits for its lookups makes that refresh set aside what they found: a moved
  receipt is read again, and a search result is applied by the next refresh,
  against the ledger as it is then. Until then new claims pause with
  `verifying_payments`.

New claims pause, with state `unavailable`, only while a condition holds, and
resume by themselves once it clears. The journal names it with a fixed category:
`verifying_payments` while a search is incomplete, `node_behind_ledger` while
the node's chain is shorter than the newest receipt, `clock_behind_ledger` (see
below), and `nonce_conflict` when the faucet key's nonce was consumed by a
transaction the ledger never recorded. A conflict means the key signed
elsewhere, for example in a second instance or a restored ledger, and needs
review. The service never creates a replacement payment merely because
broadcast timed out. Preserve the SQLite database, including its WAL, when backing up or moving
the service; do not delete it to clear a pending claim.

`confirmations` may be 1. A receipt reorganized after confirmation is then
repaired as above, so the claim object can briefly report a payment that a
reorganization later moves or expires; use 2 or more to make that rarer.

Operator commands run against the configured ledger, print a JSON summary and
exit. Stop the service before running a command that changes the ledger:

```text
hashstash-faucet --config PATH --inspect
hashstash-faucet --config PATH --accept-spent-nonce NONCE
hashstash-faucet --config PATH --clamp-future-claims
```

`--inspect` reports claim counts, the pending claim, the newest receipt and the
recorded and current times without changing anything. After confirming that
the faucet key itself spent NONCE outside the ledger, `--accept-spent-nonce`
expires an unpaid pending claim at or below that nonce and records that those
nonces are settled, which clears `nonce_conflict`. All rows, receipts,
cooldowns and budget usage are kept.

Cooldowns and claim windows use the wall clock, but never move behind recorded
claims: if the clock is up to five minutes behind the newest claim, the newest
claim time is used instead. If it is further behind, for example after claims
were served while the host clock ran ahead, new claims pause with
`clock_behind_ledger` rather than extending every window until that false time
passes. Once the host clock is verified, `--clamp-future-claims` moves future
claim times to the present, so their cooldowns restart from now.

Upgrading from a release without these rules keeps every claim, receipt,
address cooldown and budget count. Stored subnet digests use the new derived
key and IPv6 /48 grouping, so network cooldowns and daily network shares start
afresh once. That includes upgrading from a release that grouped IPv6 by /56;
IPv4 network digests are unchanged.

Mining availability is an operational observation: the node's height must have
advanced recently and RPC must still respond. "Recently" means within the larger
of `recent_block_seconds` and twelve governed block intervals, so a governed
increase of the interval does not leave the faucet unavailable for most of each
interval. This adds no timestamps or clock rules to chain consensus. Startup
waits for a new block before serving claims.
When the chain stops, payouts pause. A pending transaction can still be pending
when mining stops; the faucet does not mine or purchase hashpower itself.

The faucet keeps its mined hashes as ordinary funds and does not trade Stash.
If funds are insufficient it pauses until a transfer or subsequent mining reward
funds it.

Run the faucet tests with `cargo test --locked --offline faucet::`.
