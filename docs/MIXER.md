# Optional trusted mixer

`hashstash-mixer` is an optional custodian service using ordinary payments and encrypted transaction data. It is not a consensus feature, anonymous cryptocurrency, CoinJoin, or a trustless contract. The custodian controls deposited coins and learns the sender-to-output mapping. Other observers see the custodian, payment amounts, timing and later address use. Distinct depositing accounts do not prove distinct people. The current Mail encryption has no forward secrecy.

## One deposit, one encrypted address list

The wallet sends a positive ordinary `TransferExact` to the published custodian account. Its Mail v2 envelope encrypts to the custodian key, uses subject `hashstash.mix/1`, and has this exact compact body with fields in this order:

```json
{"terms":"<64 lowercase hex characters>","addresses":["<chain-specific address>"]}
```

The actual transferred amount is the only budget. There is no extra amount field. Each address is one fixed-denomination payout slot. One to eight unique canonical addresses are allowed, subject to the existing Mail body limit of 768 UTF-8 bytes. Sender and custodian addresses are rejected. New receiving keys are generated and stored in the user's browser; the custodian never receives those keys. The same transaction signature authenticates payment, ciphertext and sender.

The service downloads the common `explorer_mail` stream incrementally and checks the full canonical signed transaction against its block. It only accepts payments to its own account. It decrypts locally, requires the bound terms ID, and creates a durable customer allocation. Invalid or unreadable Mail deposits to its account enter the refund queue. Unrelated payments without a recognized Mail envelope are not automatically spent or refunded.

## Terms and amounts

The descriptor contains `terms`, `terms_id` and `address`. Terms have exactly these fields:

```json
{"chain_id":"<chain ID>","confirmations":6,"denomination_atoms":"1000000000000000","max_addresses":8,"minimum_deposits":4,"payout_fee_cap_atoms":"1000000","public_key":"<custodian x-only key>","service_fee_bps":100,"timeout_seconds":3600,"version":1}
```

`terms_id` is single SHA256 of compact, ASCII JSON with sorted keys. Numeric amounts are canonical decimal strings. One displayed hash is 10^18 raw atoms. A signed deposit binds the exact published terms: changing terms while customer liabilities exist is unsupported. The same chain/key/terms/schema binding is also stored in the ledger.

For each successful denomination `D`, the service earns `ceil(D * service_fee_bps / 10000)`. It reserves the published network-fee allowance for every payout and one additional refund. This is the custodian's local spending bound: each transaction signs and pays its exact quoted fee, and contains no fee-cap field. Network fees include account-creation weight. The number of affordable slots is bounded by the customer's actual deposit and address list. Fees are never funded from another customer's allocation.

Exact signed fees are charged to the customer allocation when their canonical payments confirm. Unused reserved allowances remain customer money. Completed or timed-out requests refund the remaining balance to the original depositing account. Refunds use a fresh quote within the local fee allowance and sign that exact fee. A governed minimum increase can require expiry and retry; a minimum decrease does not reduce a fee already signed. Amounts too small to cover a network fee remain recorded as owed dust, not service income. There is no fee sweep or discretionary withdrawal operation.

## Shared batches and deadlines

At least `minimum_deposits` distinct confirmed depositing accounts with affordable slots are required to open a batch. Eligible slots are sealed into the batch and selected with unbiased OS randomness. The batch can finish after some participants have received all their slots; it does not require new arrivals for its last participant. Multiple addresses from one sender never satisfy the initial threshold. Payouts are ordinary transactions and the batch is not atomic. This obscures some relationships when there are other participants; random ordering alone does not guarantee anonymity.

Timeout starts when the service first accepts the confirmed deposit into its ledger, using the current chain's scheduled clock. It does **not** start at the browser's wall clock or promise a real-time deadline. Time advances by the governed target interval per block. Service downtime before initial acceptance postpones that start; downtime afterward does not reset it. After the deadline, unfilled slots are abandoned and the remaining allocation is refunded when fees and confirmations permit. No mining means no new confirmations or deadline progress.

The service can receive deposits from the start and never buys or sells Stash, proposes grants, or trades outcomes. It compares total customer liabilities with `payment_available_hash`, the ordinary amount spendable in both governance outcomes. The initial rest period does not block mixing. Payments still require funding, confirmations and the configured batch conditions.

## Durability and failure handling

The dedicated signer must not be used by another program. A private SQLite ledger records deposits, decrypted payout addresses, per-request balances, slots, fees and exact signed outgoing bytes. It journals before broadcast, permits only one outstanding nonce, and retries identical signed bytes. It waits for the configured canonical confirmations before debiting allocations. An expired transaction with an unused nonce can be retried with a fresh quote; an ambiguously consumed nonce, reorganized receipt, wrong chain or insolvency causes a persisted operator-review pause. Never delete or reset a ledger to clear a pause. Reconcile the recorded receipts and liabilities first.

On Unix, the key and ledger require owner-only permissions, and the ledger directory must be private (0700), protecting SQLite rollback journals as well. Exclusive SQLite locking prevents a second service instance. On Windows, use an equivalent private account and filesystem ACL. Public status contains only aggregate counts, operating state and the descriptor; no deposit IDs, payout addresses or linkage map. The ledger is sensitive and is not exposed through the node API.

This service trusts its local full node for the canonical chain and fee receipts. It verifies signed payment bytes and block membership but is not an independent SPV/full-consensus implementation. It scans at most fifty mail entries per poll, bounds response size, and submits at most one new transfer per poll. The configured ledger capacity is finite. Capacity exhaustion stops ingestion and requires operator attention; it does not silently discard obligations.

## Operation

Create a dedicated Unix user and private `/var/lib/hashstash-mixer` directory. Generate a fresh key once; `init-key` fails if the destination exists and prints only the public identity:

```sh
hashstash-mixer init-key --key-file /etc/hashstash-mixer/signer.json --chain-id CHAIN
hashstash-mixer describe --config /etc/hashstash-mixer/config.json
hashstash-mixer run --config /etc/hashstash-mixer/config.json --once
```

`run` is observe-only unless `--execute` is explicit. Observe mode may index deposits and maintain its ledger but never signs or broadcasts. The `deploy/linux/hashstash-mixer.service` template enables execution explicitly; installation does not automatically start or enable it. Configure `rpc_url` as a private loopback HTTP endpoint. Never send private keys in RPC or expose the private RPC publicly.

Configuration fields are `rpc_url`, `chain_id`, `key_file`, `database`, `status_file`, `denomination_atoms`, `service_fee_bps`, `payout_fee_cap_atoms`, `minimum_deposits`, `confirmations`, `timeout_seconds`, `poll_seconds`, `max_deposits`. Use a separate publicly readable status directory if exposing status; keep the ledger directory private. No listener or remote admin API is created by this service.

To advertise a custodian on the browser's Mixer page, serve only the JSON output of `describe` at the wallet site's same-origin `/mixer-config.json`, with `Content-Type: application/json` and `Cache-Control: no-store`. The wallet checks the chain, public key, address and terms hash before preparing a deposit, then reloads those terms before handing it to the ordinary signing flow. Never publish the service configuration, signer file or ledger. Several sites may advertise the same custodian; this does not create independent custodians. Own-node operators can omit this route or advertise their own independently operated service.

## Verification

Focused tests include interoperability with the independent browser crypto fixture, strict instructions and terms binding, per-customer reserves, signer intent validation, exclusive locking, restart journal recovery, actual-fee accounting, same-sender batch rejection, insolvency and reorganization pauses. An isolated real-node test signs encrypted deposits, indexes and decrypts them through the actual RPC, waits for the batch threshold, executes fixed-size payouts, restarts after broadcast, confirms receipts and refunds the exact remainder.
