# Hashstash consensus format

The complete genesis configuration fixes the chain identity and must match the database. [The specification](SPECIFICATION.md) describes economic transitions.

## Canonical encoding

`codec::encode` uses bincode 1 variable-width little-endian encoding. Struct fields appear in declaration order without names; tuples concatenate their elements. Unsigned integer types wider than u8 use the shortest representation below. Enum discriminants are zero-based u32 values encoded by the same rule. Vector, sequence and string lengths use the u64 form. A u8 remains one literal byte, booleans and Option discriminants occupy one byte, and fixed arrays/tuples carry no length prefix.

| Unsigned value | Encoding |
| --- | --- |
| 0 through 250 | One byte containing the value |
| 251 through 65,535 | 251 followed by two little-endian bytes |
| 65,536 through 2^32 − 1 | 252 followed by four little-endian bytes |
| 2^32 through 2^64 − 1 | 253 followed by eight little-endian bytes |
| 2^64 through 2^128 − 1, for a u128 field only | 254 followed by sixteen little-endian bytes |

Marker 255, a marker wider than the destination type, truncated values and nonminimal encodings are invalid. Decoding enforces record limits and rejects trailing bytes or any encoding that differs from its canonical re-encoding. Collection lengths remain bounded by their record and field limits; compact encoding does not relax those bounds.

Public amounts use `types::amount`: decimal strings in JSON and a compact byte-count followed by minimal unsigned little-endian magnitude bytes in binary records. Zero is encoded as an empty byte vector (`00`); a nonempty magnitude ending in a zero byte is invalid. Decoding is bounded by the containing record or request bytes, and subsequent validation applies the configured monetary and share ranges. Decimal strings contain digits only, with no leading zero except `"0"`. Hashes and public keys are fixed 32-byte arrays. State commitment tuples use num-bigint 0.4's sequence of little-endian u32 limbs for unwrapped BigUint values: the limb count and each limb use compact unsigned encoding. This differs from the annotated public-record amount adapter and is part of the specified commitment schema.

One displayed hash is 1,000 raw hash atoms; one displayed stash is 1,000 share atoms. CLI/RPC amounts remain raw integers. Monetary display names do not alter issuance or integer curve arithmetic. Physical mining work uses EH and EH/s. Marked Stash value uses marginal price; a full-redemption quote follows the curve and can be smaller.

## Genesis configuration

The chain ID is `tagged_hash("Hashstash/chain", codec::encode(&config))`. Every Config field participates in declaration order, including the explicit test_work fixture flag. Config and Settings reject unknown JSON fields. The encoded configuration fixes the chain identity. Transactions sign an anchor block from that chain; their bodies do not repeat the chain ID. All participants must use the same configuration, transaction/state formats and validation rules. The chain ID binds configuration bytes; it does not attest which software is running. Amount-only clearing, exact leading-price comparison and anchored transaction signatures require matching implementations. Start a fresh network with a distinct network name and empty database when changing these rules; existing databases and signed transactions cannot be reinterpreted under a new format.

Config fields are: network, test_work, genesis_time, initial_bits, limit_bits, daa_half_life, timestamp_window, future_seconds, max_signatures, max_height, money_bits, share_bits, max_integer_bits, quote_scale, share_scale, auction_timeout, initial. The source types define each width and amount annotation. The test_work flag must be false in production. An explicit test-fixtures build can accept true for disposable tests; it changes issuance to one expected hash per atom and therefore changes the chain identity. Production builds reject true.

Settings fields are block_bytes, minimum_fee_rate, interval, lead, rest, decision_blocks, max_price_change_bps, miner_fee_percent, pass_margin_bps, in that order. The first seven are u64; interval, lead and rest use seconds, decision_blocks counts blocks, and max_price_change_bps uses basis points. Config's auction_timeout also uses seconds. Both percentages are Option<u64> and must be present. MinerFeePercent is a whole percentage from 0 through 100; PassMarginBps is an unsigned basis-point margin. Config.share_scale is a positive, fixed genesis amount defining the initial raw stash per raw hash. It is not governable.

The three maintained presets use a 15-second target, 900-second ASERT half-life, 11-header median window and 120-second future allowance. Those are preset choices. Genesis validation requires a positive half-life and timestamp-window size; future allowance uses its u32 representation. The operator must choose genesis-only values sensibly, because the chain cannot change them. Validating each block loads up to timestamp_window ancestors. A max_signatures of zero permits only empty blocks, and a very large value lets a full block exceed peer and Stratum work limits ([network controls](NETWORK-HARDENING.md)). The governed half-life also bounds the target interval governance can choose. Timestamp rules and target encoding still apply. The target limit is immutable genesis configuration. The economic clock advances by parent_settings.interval for each block. Auction and rest deadlines preserve their nominal duration when the interval changes; decisions retain a frozen number of blocks. These are scheduled seconds, not header timestamps or wall-clock deadlines; the chain must advance for economic time to pass.

## Transactions and parameters

A signed transaction contains its body followed by exactly 64 BIP340 signature bytes, with no signature-length prefix. Body order is sender[32], nonce:u64, fee:Amount, anchor[32], expiry_blocks:u64, operation, data:Vec<u8>. The nonce and lifetime use compact unsigned encoding. The body fee is the exact total charged when included. The BIP340 signing message is tagged_hash("Hashstash/anchor-only-transaction", codec::encode(body)), binding every body field, including the anchor. The anchor commits to chain history and the receiving node verifies its ancestry. Chain ID remains in configuration, state commitments, addresses and peer messages, but not in transaction bodies or signatures as a separate field. Transaction IDs are SHA256d of the complete signed record. The anchor must be an ancestor of the including block’s parent, including that parent or genesis. With anchor height A and positive lifetime N, inclusion is valid exactly when A < height <= A + N. The sum uses checked u64 addition; the including block must independently satisfy the network’s height bound. Unknown anchors, references from another branch, zero lifetimes and overflow are invalid. Retries retain the original anchor and lifetime. Removing the anchor in a reorganization invalidates the transaction; a reorganization that preserves it does not. Two forks retaining the same anchor can both accept the transaction while its lifetime and account state permit. The anchor does not select between descendants of a shared block. Conditional Deposit and Redeem orders also sign a decision ID. That ID depends on the opening block's parent and the winning proposal, not on the opening block's contents (see Accounts, reserve and governance). A same-parent sibling of the opening block therefore opens the same decision, and such an order survives that replacement whenever its anchor does.

The anchor-only body layout and signature domain are incompatible with earlier transaction bytes; old signed records must not be reinterpreted. A transfer of 1 hash (1,000 atoms), a one-atom fee, a one-byte nonce, a two-block lifetime and empty data is 169 bytes including its signature. Unsigned wallet exports carry separate network context for address formatting and accidental-network checks; that context is not signed and cannot prove ancestry to an offline signer.

The operation is a direct six-variant enum followed by a length-prefixed data byte vector, including a zero length for empty data. Transaction data has no consensus text format; all bytes count toward the block-byte and fee-weight limits. Chat interprets readable UTF-8, and [Mail](MAIL.md) defines an encrypted application envelope.

| Tag | Operation | Payload order |
| --- | --- | --- |
| 0 | TransferExact | recipient, exact amount |
| 1 | Deposit | amount, optional decision, optional outcome |
| 2 | Redeem | shares, optional decision, optional outcome |
| 3 | Propose | round, description hash, proposal, support |
| 4 | Support | round, proposal ID, amount |
| 5 | Refund | round, proposal ID |

Unknown operation tags are rejected. Round numbers use compact u64 encoding. Outcome tags are Pass=0 and Fail=1. Proposal tags are Grant=0 (payments), Parameter=1 (parameter, old:u64, new:u64). Grant payments are a compact nonzero count followed by pairs of recipient[32] and amount:Amount, sorted by public-key bytes with no duplicate keys. Each key must be valid and each amount positive. The combined amount must fit the configured monetary range; there is no separately encoded total. Decoding is bounded by the actual transaction/record bytes; a hostile count cannot preallocate an oversized list. In JSON the grant is `{"Grant":{"payments":[{"recipient":[...],"amount":"..."}]}}`. Decision hashes and outcome options must either both be present or both absent. Human-readable records reject unknown fields.

Parameter tags are BlockBytes=0, Interval=1, Lead=2, Rest=3, DecisionBlocks=4, MinerFeePercent=5, PassMarginBps=6, MinimumFeeRate=7, MaxPriceChangeBps=8. A proposal's old value must equal the frozen value and its new value must differ. Genesis settings use the representability rules in the first column. Governance changes also need the second column:

| Parameter | Allowed genesis value | Additional rule for a governed `new` |
| --- | --- | --- |
| BlockBytes | At least 1,024 weight, enough for a new mining account; must fit the implementation's allocation representation | None |
| MinimumFeeRate | Any u64 raw hash atoms per 1,024 weight, including zero | `new <= max(2 * old, 1)` |
| Lead | Any u64 scheduled seconds, including zero | `new <= (auction_timeout - interval) / 2`, saturating at zero |
| Rest | Any u64 scheduled seconds, including zero | `new <= 2^22` |
| Interval | Positive u64 scheduled seconds | `new <= daa_half_life` |
| DecisionBlocks | Positive u64 block count | `new >= 3` and `new * interval <= 2^22` |
| MaxPriceChangeBps | Any u64 basis-point value; default 1,000 (10%) | `new > 0` |
| MinerFeePercent | A whole percentage from 0 through 100 | None |
| PassMarginBps | Any u64 basis-point value, including zero | None beyond the reachability rule |

Every governed change, whatever its parameter, must also leave `pass_margin_bps < (ceil(decision_blocks / 2) - 1) * max_price_change_bps` (saturating multiplication) in the changed settings. That keeps a later PASS majority arithmetically reachable: its earliest required observation follows `ceil(N/2) - 1` traded blocks, each bounded by the price-change limit. The governed rules exist because a passed value can only be reverted by another decision. Without them, one decision could end governance (fewer than three decision blocks, zero price movement, an unreachable margin), stall a phase indefinitely (a huge lead, rest or decision), let a late outbid force a refunded timeout (a lead too long for a replacement leader to mature), starve the difficulty schedule (an interval far above the ASERT half-life) or price every transaction out (a huge fee rate).

Every change supplies an exact `new` integer within these rules. All values fit u64. The node requires a 64-bit target; block capacity also fits `isize::MAX` (2^63 − 1), its allocation representation. Genesis values are representability checks, not suggested operating values. A one-block genesis decision resolves on the first subsequent block, before a conditional trade can affect its result.

The effective auction timeout is `max(auction_timeout, lead + interval)`, with checked addition. The scheduled clock and every deadline use checked u64 arithmetic. A Propose transaction is checked at the including block's clock. The projected decision/rest activation boundary is checked whenever the proposal would lead or open its decision, and failure cancels it rather than invalidating the Propose. Activation checks the value again. Rounding a phase duration up to a block boundary must also fit. A value that fits u64 can therefore still be invalid at a particular clock. The product of the decision block count and frozen interval, the end height and projected deadlines must fit. A governed change must also stay representable through every remaining height: at each check, `clock + interval * max_height + effective_timeout + decision_blocks * interval + rest + 2 * interval` must fit u64 under the changed settings. Later phase deadlines therefore cannot overflow before the height limit. As defence in depth, a rest deadline that would overflow saturates at 2^64 − 1: governance waits rather than every candidate block failing. Changes activate after the rest period under the frozen settings of their decision; the activating block still uses its parent's interval, and its child uses the new one. Existing signed anchors and lifetimes are never rewritten.

Auction leadership is evaluated once per block after its transactions. The incumbent keeps a tie with the highest bid; otherwise the ranking's last key leads, which is the highest bid and, among equal bids, the smallest proposal ID. A proposal that could not open its decision in that block is cancelled with `refund_height = height + 1` and skipped. Examples are an unfundable grant, an unrepresentable schedule or end height, and a parameter value invalid at its projected activation. It therefore never becomes leader or restarts another proposal's lead. A change of leader sets `lead_since` to the block's clock. The leader opens its decision when `clock - lead_since >= lead`, checked before the timeout test `clock - opened >= effective_timeout`. If a mature leader is cancelled, `replacement_height = height + 1` and no leader is chosen until the next block. Rest completion is processed after auctions in the same block.

Transfers credit the signed exact amount. Recipient creation increases the required minimum fee, which the exact signed fee must cover. Proposal explanations are transaction data; the UI verifies their SHA256 against the signed description hash.

## Fees, capacity and issuance

Transaction weight is its signed byte length plus 1,024 for a new TransferExact recipient, or 1,024 per payout in a grant proposal. Grant payout weight is fixed, whether or not those accounts already exist. The minimum fee is ceil(weight * minimum_fee_rate / 1024). The exact signed body.fee must meet this minimum and is charged in full. A transfer recipient created by a preceding transaction can reduce the required minimum and weight but does not reduce the signed payment. The presets start the minimum rate at one atom per 1,024 weight. A successful MinimumFeeRate proposal can set any representable rate, including zero; a zero rate requires no minimum fee. Empty or full blocks do not change it. An optional extra is only an input to the quote builder; the signed record contains one exact fee, not a separate extra or cap.

The grant proposal prepays bounded settlement work. This transaction fee is not refunded if the proposal loses, expires or becomes ineligible, or if recipients obtain accounts before settlement. It is distinct from refundable auction support. Its miner share goes to the miner that includes the proposal, under the ordinary fee split; settlement does not deduct another fee from any grant amount.

For each transaction, miner_fee = floor(actual_fee * active_miner_fee_percent / 100); waiting revenue receives the remainder. The initial split is 50/50. The whole paid fee is split, including any extra. This transfers existing hashes; it does not create issuance.

BlockBytes bounds both measured body bytes and transaction weight, including prepaid grant payout weight. A new mining recipient contributes 1,024 weight without any deduction from its protocol payment. Mandatory grant settlement is exempt from this closing block's weight limit because its work was charged with the proposal. Its recipient count was bounded by the proposal’s byte and weight capacity when included. Ordinary payment-account creation and miner-account creation retain their capacity checks. During governance, one logical payment-account creation counts once. Presets start with 16 KiB of body/weight capacity. There is no separate recipient-count or transaction-size setting: a transaction may use the block’s remaining byte and weight capacity, including its signature, data and execution weight. Block framing and any mining-account creation also need capacity. Governance can directly increase or decrease BlockBytes within its representation and mandatory-account bounds; independent signature-count limits still apply. Transport and API admission limits are separate service constraints.

For each block, physical expected work is W = floor(2^256 / (target + 1)). Production issuance uses Q = 10^15 expected hashes per atom. The block issues floor(W / Q) atoms; any smaller fraction is discarded. Total issued atoms are the sum of these independently rounded block rewards. A block below one petahash issues zero atoms. Losing blocks receive no reward. Fork choice still compares exact accumulated physical expected work, without monetary rounding.

## Accounts, reserve and governance

State uses persistent authenticated maps. The deterministic treap has priorities derived from keys, canonical roots independent of insertion order, and shared immutable subtrees. Account updates copy changed paths rather than cloning all accounts. Account field order is ordinary:Amount, shares:Amount, nonce:u64, epoch:u64. Each outcome's cash is its ordinary field; there is no extra conditional balance field. Public-key bytes are the map key, not an extra account field.

The account `epoch` is internal bookkeeping for governance context. Each decision increments `last_epoch`; account reads normalize the returned tag to that decision's number, or zero outside a decision. Stored records retain the context used when written. Changing this tag does not change a balance, mint funds or perform the PASS/FAIL split: the two account-tree roots hold those alternatives. The field participates in the account commitment and its stored value cannot exceed `last_epoch`. It is not a Unix timestamp.

A deposit d into an empty reserve sets reserve = curve_mass = d and creates d * Config.share_scale stash for its sender. Ordinary trades then use the current dynamic ratio. Revenue adds min(revenue, curve_mass - reserve) to reserve without changing curve mass or stash; excess waits. All stash belongs to accounts. Config.quote_scale must be at least Config.share_scale so the initial nonempty curve has a nonzero integer price quote. An empty world quotes zero, and a block in which either governance world is empty adds no PASS lead; its next deposit opens at the configured exchange rate.

A governance decision starts with two roots referencing the same account state. PASS and FAIL each expose full balances automatically. Selected Stash trades affect that world's cash and shares; ordinary payments and fees debit both worlds. Therefore shared payment availability is the minimum of the two cash balances. Nonces and account keys remain coordinated. Alternative balances must not be summed.

Grant eligibility requires positive, representable payments fully backed by available funds. A live Stash reserve must retain one raw hash atom so its curve remains valid. At activation, PASS escrows that total from waiting revenue first and reserve second, keeping mass and stash unchanged. FAIL moves the same reserve amount into its own waiting revenue without escrow, so both worlds open with equal reserve, mass and supply. Only then does the winning support become waiting revenue in both worlds, so it never funds its own grant. Neither world replenishes its reserve from revenue while the decision is active; the selected world replenishes in its resolution block. Each subsequent block compares exact completed-parent marginal prices P = M_pass/S_pass and F = M_fail/S_fail. When both worlds hold Stash it adds one leading block when M_pass*S_fail*10000 > M_fail*S_pass*(10000+m), using the frozen margin m. If either world holds no Stash, the block adds no lead. Display quote rounding and quote_scale do not affect this comparison. Equality adds none. After decision_blocks observations, PASS requires leading_blocks > decision_blocks/2; a tie fails. Resolution selects the winning root and atomically pays every listed amount once if PASS wins. No recipient is paid before resolution or partially paid by a failed transition. No account-wide settlement rewrite occurs. Losing tree nodes remain reachable while retained checkpoints need them.

Amount-only Deposit and Redeem operations are reserved from opening balances and cleared together once per world. The signed fee is paid even on a zero fill. Unfilled inputs are returned. Exact rounded closing marginal prices respect MaxPriceChangeBps. No order identifier or transaction position selects a rounding beneficiary. [Batch clearing](SPECIFICATION.md#amount-only-block-clearing) defines price determination, proportional allocation, dust handling and the remaining miner inclusion power.

Decision fields are id, epoch, round, proposal_id, proposal, started (scheduled clock), started_height, blocks, leading_blocks. The last three are u64. The opening height plus blocks is the resolution height; the observation occurs before that block’s transactions. The decision ID is tagged_hash("Hashstash/decision", encode((chain_id, round, proposal_id, started_height, parent_hash))). Here parent_hash is the block hash of the opening block's parent. Anyone who knows that parent and the maturing leader can compute the ID before the opening block exists, and same-parent siblings share it.

## State commitments

World root is tagged_hash("Hashstash/world", encode((accounts.root(), reserve, shares, revenue, grant_escrow, curve_mass, account_cash, account_shares))). Each dynamic curve field is committed.

The state root is tagged_hash("Hashstash/state", encode((A,B))). A contains chain_id, height, clock, issued, settings, frozen, world.root(), optional alternative.root(), phase. Clock is cumulative scheduled seconds. B contains proposal/support/round/ranking roots, auction_escrow, last_round, last_epoch. Field and tuple ordering is consensus-critical.

Tree domains are Hashstash/TreeEmpty, Hashstash/TreeValue, Hashstash/TreePriority and Hashstash/TreeNode. Protocol roots commit to authenticated map roots rather than their in-memory representation. All changes, including fees and protocol payments, must reproduce the declared state root.

Each map is a treap ordered by key bytes. A key's priority is tagged_hash("Hashstash/TreePriority", key). The node with the smallest (priority, key) is the root of each subtree, so the shape is independent of insertion order. The empty tree's root is tagged_hash("Hashstash/TreeEmpty", ""). A node's value hash is tagged_hash("Hashstash/TreeValue", encode(value)). Its root is tagged_hash("Hashstash/TreeNode", encode((key, value_hash, left_root, right_root))), where key is a length-prefixed byte vector.

| Map | Key | Value |
| --- | --- | --- |
| accounts (each world) | 32-byte public key | Account |
| proposals | 32-byte proposal ID | ProposalRecord |
| supports | tagged_hash("Hashstash/support", encode((round, proposal_id, sender))) | SupportRecord |
| rounds | round number as 8 big-endian bytes | RoundRecord |
| ranking | support amount as a 64-byte big-endian magnitude, then the bitwise NOT of the proposal ID (96 bytes) | proposal ID |

A proposal ID is tagged_hash("Hashstash/proposal", encode((chain_id, round, description, proposal))). Records encode their fields in this order, with Amount fields in the public amount form:

| Record | Fields and tags |
| --- | --- |
| ProposalRecord | round:u64, description[32], action:Proposal, support:Amount, refund_height:Option<u64> |
| SupportRecord | round:u64, proposal[32], sender[32], amount:Amount |
| RoundRecord | status:RoundStatus, refund_height:u64; RoundStatus tags Open=0, Won(proposal ID)=1, Timeout=2 |
| Phase | Auction=0, Governance=1 (Decision, above), Rest=2 |
| Auction | round:u64, opened:u64, leader:Option<[32]>, lead_since:u64, replacement_height:u64 |
| Rest | until:u64, pending:Option<(Parameter, u64)> |

## Mining wire format

The Bitcoin-style header is 80 bytes: version:u32 at offset 0, previous digest[32] at 4, Merkle root[32] at 36, timestamp:u32 at 68, bits:u32 at 72, nonce:u32 at 76. Integers are little endian; digest bytes are raw. Fixed version bits are 0x20000005, with rolling mask 0x1fffe000. Outside that mask the version must match exactly.

The sole Merkle leaf is a Bitcoin-serialized system coinbase. It has transaction version 1, one zero-prevout input (index and sequence 0xffffffff), a minimally encoded height plus PUSH8 and eight extranonce bytes, one zero-value output, and locktime 0. Its output script is OP_RETURN, PUSH68, ASCII HST!, miner key[32], commitment[32]. The commitment is tagged_hash("Hashstash/block-commitment", encode((transactions,state_root))). There is no optional proof field or padding. Coinbase transaction counts and script lengths use canonical CompactSize.

The header Merkle root is SHA256d of this coinbase, so Stratum supplies an empty Merkle branch. The complete ordered signed transaction vector is bound inside the commitment. Verifying that commitment needs the full vector; it does not provide short transaction-inclusion proofs.

The governed body measurement is state_root[32], CompactSize record count, and each record's CompactSize length plus complete bytes. Records are the coinbase followed by user transactions. The 80-byte header is excluded. Binary block record field order is header, height:u64, miner[32], state_root[32], extranonce[8], transactions. The extranonce is exactly eight bytes without a length prefix. The binary record's Header integers use the compact serializer; proof of work always hashes the separately constructed fixed 80-byte header specified above. Validators reconstruct all redundant commitments. Bitcoin CompactSize framing remains distinct from the compact integer encoding of consensus records.

## Timestamps, difficulty and forks

Proof of work compares the little-endian SHA256d header digest with a canonical positive target no easier than genesis limit_bits. Each branch derives cumulative scheduled seconds S_h = S_(h-1) + parent_settings.interval. Its first mined block supplies the ASERT anchor timestamp T_1 and scheduled seconds S_1. For a child of a non-genesis parent, error = (parent.timestamp - T_1) - (parent.expected_seconds - S_1). Ideal target is initial_target * 2^(error/daa_half_life), using the fixed-point integer ASERT approximation, compact rounding and target limit. The first two blocks use initial_bits: time before mining began is excluded. An interval change modifies future schedule increments without resetting the anchor. Competing branches retain their own first-block anchors; reopening reconstructs these from validated history.

Timestamp must exceed median past time and must not exceed local now + future_seconds. Median uses available ancestors including the parent, capped by timestamp_window, sorted at index length/2. Future blocks remain retryable. Time checks reduce but do not eliminate timestamp manipulation. Header time affects ASERT, while governance phases advance by the target interval, independently of the candidate timestamp. Transaction expiry is measured in blocks after its signed anchor; timestamp samples and confirmations retain their count units.

The greatest-work valid branch becomes active; equal-work arrivals retain the current tip. Reorganization replaces all affected state, issuance, fees, funding and decisions together. Accepted block bodies and checkpoints allow reconstruction; governance resolution gives no finality. SQLite commits block/tip changes atomically, and the node publishes tip and state together. Mempool recovery revalidates anchors, lifetimes, nonces, funds and decision bindings. Chain validation checks ancestry during admission, block validation, template construction and historical replay. The pure economic execution helper checks transaction structure and state transitions; callers must supply chain validation for ancestry and proof of work.

## Bounds and genesis

Genesis is a deterministic unmined height-zero anchor with zero cumulative work and issuance, empty accounts, reserve and revenue, eight zero extranonce bytes and no transactions. It commits the full configuration and an initial Rest state ending at initial.rest scheduled seconds, or opens auction round zero immediately when initial.rest is zero. Proposal rounds begin through normal transitions. Its zero miner is not a payable account. Mining validation starts at height 1.

Maximum configured height is positive and at most i64::MAX, matching the database height representation. Nonces, phase clocks and deadlines use checked u64 values. Config validates amount ranges, share ranges, bounded curve arithmetic, lifetime issuance and price-comparison capacity. Canonical records are bounded by their actual encoded bytes, configured field ranges and the including block’s byte/weight capacity. BlockBytes must fit the platform’s allocation representation. Peer frames and API responses have separate representation or service limits, so an otherwise valid enormous block is not guaranteed to pass every interface. These bounds constrain representability and work; they do not guarantee economic outcomes or constant validation latency.

Fields, enum tags, hash domains, rounding and coinbase construction are consensus rules. See [validation](VALIDATION.md) for tested scope, and [network controls](NETWORK-HARDENING.md) for limits that are node policy rather than consensus.

Peer transport framing is separate from consensus records. Binary peer messages carry canonical transaction and block bytes. Their chain identity and record domains must match this protocol.
