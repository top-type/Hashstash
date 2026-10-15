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
  "payout": "1000000000000000",
  "max_fee": "1000000",
  "cooldown_seconds": 86400,
  "subnet_cooldown_seconds": 60,
  "hourly_claims": 100,
  "daily_claims": 250,
  "lifetime_claims": 1000,
  "recent_block_seconds": 180,
  "confirmations": 2,
  "expiry_blocks": 20
}
```

Generate the dedicated key with `hashstash keygen --out PATH`. Give only the
faucet operating-system user access to that key and its database. Funding can be
an ordinary transfer or mining rewards paid to the faucet address. Never give
the faucet a visitor's key or the key to an account holding valuable funds.
The daemon accepts the usual key-file JSON, with `secret` and `public` fields.
Changing the ledger's network or signer requires a separate ledger. Changing
`payout` applies to new claims after a restart; recorded payments keep their
original amounts, and all cooldowns and claim counts are preserved.
The ledger stores the amount of each payment alongside its claim record.

The example dispenses 0.001 hash per claim (10¹⁵ raw hash atoms) and permits one claim
per address each day. Configuration and API amounts use integer raw hash atoms.
A shared IPv4 /24 or IPv6 /64 can make a new claim once per minute, so another
wallet on the same network does not inherit a full day's wait. The separate
`subnet_cooldown_seconds` setting defaults to 60 when omitted; both cooldowns
must be positive and at most one year. At this payout, the claim-count caps allow
up to 0.1 hash per hour, 0.25 hash per day, and 1 hash over the ledger's lifetime.
The service additionally limits each exact quoted fee to 0.000000000001 hash.
This is a local spending allowance, not an encoded transaction cap. Pending
and expired claims consume the allowance too. Changing the payout does not
reset these counts; historical payments retain the amounts paid at the time. This
limits the dispenser's exposure; IP limits are not proof of unique people.

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
Use `Cache-Control: no-store`. If the faucet uses another origin, add that exact
origin to the website's `connect-src` policy. Without a matching descriptor the
wallet hides the optional faucet controls.

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
HTTP concurrency, request duration, and request-body size are bounded.

`GET /faucet/status` returns:

```json
{
  "enabled": true,
  "chain_id": "...",
  "amount_hashes": "1000000000000000",
  "available": true,
  "mining_active": true,
  "state": "ready",
  "cooldown_seconds": 86400,
  "address": "FAUCET_FUNDING_ADDRESS"
}
```

Other states are `waiting_for_mining`, `unfunded`, `pending`, `cooldown`, `quota_reached`,
and `unavailable`. Add `?address=RECIPIENT_ADDRESS` to receive an optional
`claim` object for that recipient. It contains `status`, `txid`, `chain_id`,
`amount_hashes`, and `retry_after_seconds`. The top-level amount is the current
payout; the nested claim amount is that payment's original amount.

For a selected address, status also supplies top-level `retry_after_seconds`:
the maximum remaining wait across that address and the trusted proxy's client
subnet. It is zero when neither cooldown applies. When a cooldown blocks an
otherwise available faucet, `state` is `cooldown`, `available` is false, and
`cooldown_scope` is `address` or `network`. No other recipient, claim, client IP,
or stored subnet digest is disclosed. Status queries do not reserve funds.

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
independently verifies the chain, sender, recipient, amount, nonce, expiry,
exact fee within its configured local spending allowance, and absence of arbitrary data. It commits the
signed bytes, transaction ID, and quota reservation in SQLite before broadcast.
Only one payment is outstanding per faucet instance. Network errors keep it pending;
subsequent polls and restarts retry identical signed bytes.

Confirmation requires locating that transaction in canonical block history and
the configured confirmation depth. A higher account nonce alone is insufficient.
Reorganization of a confirmed receipt, a deep reorganization across a pending
claim's preparation height, or an unexplained consumed nonce pauses new payments
for operator review. The service suppresses stale confirmation claims after a
detected receipt reorganization. It never creates a replacement payment merely
because broadcast timed out. Preserve the SQLite database, including its WAL,
when backing up or moving the service; do not delete it to clear a pending claim.

Mining availability is an operational observation: the node's height must have
advanced recently and RPC must still respond. This adds no timestamps or clock
rules to chain consensus. Startup waits for a new block before serving claims.
When the chain stops, payouts pause. A pending transaction can still be pending
when mining stops; the faucet does not mine or purchase hashpower itself.

The faucet keeps its mined hashes as ordinary funds and does not trade Stash.
If funds are insufficient it pauses until a transfer or subsequent mining reward
funds it.

Run the faucet tests with `cargo test --locked --offline faucet::`.
