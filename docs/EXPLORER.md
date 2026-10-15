# Explorer

Open **Explorer** in any node's website. It works without a wallet and offers links that can be shared directly to blocks, transactions, accounts, and governance proposals.

Search accepts a block height, block hash, transaction ID, or checksummed account address. Account addresses must belong to the node's network. The Blocks, Transactions, and Decisions tabs provide paginated history. The Network tab shows the current network state, parameters, phase timing, and node details. The main Governance page remains the place to propose and support decisions.

## Reading history

A confirmed transaction belongs to the node's current canonical chain. Its confirmation count is the number of blocks from its inclusion through the current tip. A reorganization can change that status. Pending transactions have not yet been included. Their fee is the exact signed amount; the required minimum and its split are a quote for the current state until inclusion.

An orphaned block or transaction was previously indexed on the canonical chain and has since been detached. The Explorer retains those known records for direct lookup. It does not claim to have observed every block produced by every miner.

Hashstash uses block height for transaction expiry, history ordering and decision length. Each completed block counts once in a decision. Auction lead and rest use a scheduled-seconds clock advanced by the parent’s target interval. Mining timestamps drive difficulty; they do not set governance deadlines. Explorer orders records by height and exposes header time in technical details.

Monetary values use hash, the same fixed unit as the wallet: one displayed hash is 10¹⁸ raw hash atoms. Exact hash values remain available on hover, including fees and fractional price ratios. Stash quantities use stash (one displayed stash is 10³⁶ share atoms), with their marked hash value shown separately on account pages. Mining work uses EH, including small decimal values, with exact EH amounts on hover. Conditional transactions identify their PASS or FAIL context; on-chain inclusion and the eventual selection of an outcome are distinct facts.

Transaction data is presented as hexadecimal bytes. Valid UTF-8 can be inspected as escaped plain text and appears in the public Chat feed. Encrypted mail stays in its dedicated view. Proposal explanations are plain UTF-8 verified against the signed description commitment, with the verified text exposed as `description_text` on the proposal record. These views never execute data or give it additional consensus effects; a description hash alone cannot reveal its text.

## Read-only API

The public RPC exposes these bounded methods:

| Method | Lookup |
| --- | --- |
| `explorer_blocks` | Canonical blocks, newest first |
| `explorer_block` | One block height or hash |
| `explorer_transactions` | Canonical transactions and current pending transactions |
| `explorer_transaction` | One transaction ID |
| `explorer_account` | Account balances and indexed activity |
| `explorer_governance` | Proposals, backing transactions, and decision records |
| `explorer_chat` | Public transaction text, with canonical and pending messages separate |
| `explorer_mail` | Common confirmed encrypted-mail stream; recipient discovery stays local |

Each response includes the network identity and the tip, height, and state commitment used for the read. Monetary strings in RPC responses and raw transaction details remain integer hash atoms; the UI converts them to displayed hash. Decision records expose exact leading-block counts. Page sizes default to 20 and are limited to 50. Follow the returned cursor rather than calculating offsets across new blocks or reorganizations. These methods do not expose server wallet management, private keys, block submission, or software-mining controls.

For example:

```json
{"jsonrpc":"2.0","id":1,"method":"explorer_blocks","params":{"limit":20}}
```

```json
{"jsonrpc":"2.0","id":2,"method":"explorer_block","params":{"height":6}}
```

The result envelope always contains `chain_id`, `tip`, `height`, and `state_root`. Amounts and rational numerators/denominators are decimal strings. Heights, offsets, and confirmation counts are JSON integers. Unknown parameters, malformed identifiers, wrong-network addresses, and limits outside 1–50 are rejected.

| Method | Parameters | Result fields and pagination |
| --- | --- | --- |
| `explorer_blocks` | `limit`, `before_height` | `blocks`, `next_before_height`; canonical heights descending |
| `explorer_block` | Exactly one of `height` or `hash`; `limit`, `tx_offset` | `block`, `transactions`, `next_tx_offset`; transactions in block order |
| `explorer_transactions` | `limit`, `before` | `transactions`, `pending`, `next_cursor`; canonical transactions descending by height and position |
| `explorer_transaction` | `txid` | `transaction`; canonical inclusion takes precedence, then the current mempool, then a previously indexed detached inclusion |
| `explorer_account` | `address`, `limit`, `before` | `account`, `pass_account`, `payment_available_hash`, `stash_value_hash`, `stash_withdrawal_hash`, corresponding optional `pass_…` valuations, `history`, `pending`, `next_cursor` |
| `explorer_governance` | `limit`, optional `proposal`, and the three independent cursors below | `phase`, `current`, `proposals`, `decisions`, `contributions` |
| `explorer_chat` | `limit`, optional `cursor` | `items`, `pending`, `next_cursor`, `available`, `ready`, `indexed_height`, `message_bytes` |
| `explorer_mail` | `limit`, optional paired `after`, `anchor` | Ascending confirmed `messages`, `next_cursor`, `scan_cursor`; global stream, no recipient fields or address filter |

`before_height` is exclusive. Transaction and account cursors are opaque `height:position` strings returned in `next_cursor`; send them as `before`. Governance uses `proposal_next_cursor` → `proposal_before` for proposals, `next_before_height` → `before_height` for decisions, and `next_cursor` → `before` for backing transactions. A live decision appears on the first decision page only. A cursor may lead to an empty final page. New pages use the latest node tip; callers that require an unchanged history should restart pagination if the tip reorganizes.

Block records contain their header, miner address and public key, expected hashes, Bitcoin-relative difficulty, body size, transaction count, subsidy, actual fee allocation and resulting state root. Genesis has no miner. Rewards report transaction_fees, minimum_fees and extra_fees separately from miner_fees and revenue_fees (allocation). The entire exact fee follows the governed split; extra_fees is the paid amount above the inclusion-time minimum, not a separate signed field. Detached blocks retain recorded accounting rather than claiming a current payment.

Transaction records include `txid`, `status`, `height`, `block_hash`, `confirmations`, sender/recipient addresses, `nonce`, `expiry_height`, `kind`, decoded `operation`, `amount` and `asset` where applicable, the exact signed `fee`, optional `minimum_fee` and `extra_fee` quote breakdown, and data fields. List data is limited to a 256-byte preview; transaction detail returns all bounded transaction bytes as `data_hex`, with `data_bytes` and `data_truncated` describing the preview. Arbitrary data remains uninterpreted.

Confirmed trade records and account events report actual filled input in `amount`. They also expose `input_requested`, `input_filled`, `input_unfilled`, `output`, `output_asset` and `fill_status` (`full`, `partial` or `unfilled`). The signed operation retains the requested input. Pending trades have no fill result. A trade can pay its fee while receiving no fill, and an unresolved outcome fill can later be discarded.

Conditional operations include `decision`, `outcome`, and `settlement`. Its `effect` is `conditional` while unresolved, `survived` or `discarded` after a canonical decision, `pending` for a mempool transaction, or `orphaned` for a detached inclusion. `resolved_outcome` identifies the canonical winner when known. `common` denotes an operation shared between both outcomes. Discarding a branch’s operation does not refund its transaction fee. Decision records expose `started_height`, `ended_height`, `blocks`, `observed_blocks`, `leading_blocks`, `blocks_remaining`, the frozen `pass_margin_bps`, a `funded` flag and final outcome. PASS needs a strict majority of all decision blocks; equal counts resolve FAIL. A block counts for PASS only when its parent closing quote exceeds FAIL by the frozen margin. The grant must also be fully escrowed; parameter proposals report funded.

An unused valid account returns `account: null`. Account history contains indexed sender/recipient activity and separate `mining_reward` and `governance_grant` protocol events. Each payment of a passing grant creates a credit event for its recipient, linked to the same proposal and decision without inventing a transaction ID. A grant proposal displays the full recipient list and combined amount; recipients are not credited by proposal submission. Balances are the current canonical state, not a sum of history rows.

During governance, `account` is the FAIL account and `pass_account` is PASS; each has its own full `ordinary` cash and shares. For a private account, `payment_available_hash` is the smaller outcome cash balance before fees, a payment limit rather than a third balance. Outside governance it is ordinary cash. PASS and FAIL balances and marked valuations are alternative futures and must not be added together.

Network and governance views expose each world’s reserve, curve mass, dynamic reserve ratio, waiting revenue and grant escrow. See [Reserve and revenue](RESERVE.md).

## Node storage

The Explorer maintains a separate derived SQLite index next to the chain database. For `chain.sqlite`, the index is `chain.explorer.sqlite`. It uses the existing validated chain history and does not change consensus rules, state commitments, transaction encodings, rewards, or mining templates.

The index records its network and schema version, catches up from stored history at startup, and follows canonical reorganizations. It can be reconstructed from the chain database. Index failure makes Explorer queries unavailable rather than accepting different blocks or modifying balances. Keep the chain database and its configuration when backing up a node; the Explorer database is a rebuildable convenience.

The derived index includes the public-text feed from transactions of any kind. It also retains encrypted-mail discovery, verified proposal rationale, and explicit actual miner/revenue transaction-fee allocations. A mismatched schema or chain identity causes a rebuild from validated chain history, including message author and canonical status; it does not migrate or alter consensus balances.

While the node is running, one background worker follows the canonical chain through a single coalesced wake notification. Canonical publication and mining-job updates do not wait for derived SQL or transaction replay. The worker captures one validated block at a time, keeps at most 128 immutable state checkpoints, and performs its replay and index writes outside the node's mutation lock. A deeper reorganization falls back to background replay from genesis. Dropping the last node handle closes and joins the worker. An initial index backfill takes place before network listeners start; it can extend the first startup after enabling or rebuilding Explorer.

Public queries use separate read-only SQLite snapshots. Each snapshot must match the node state used for the response; a request during a tip transition or background catch-up may report that the index is updating. No earlier index is silently presented as the current chain.

The isolated browser fixture can be generated with:

```text
cargo run --example explorer_fixture -- <new-output-directory>
```

It mines only its own local test chain and creates a transfer with uninterpreted data, a completed governance decision, and a prepared pending transaction. It does not contact public peers.
