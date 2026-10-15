# Hashstash consensus format · protocol 26 · implementation 0.36.0

This implementation accepts protocol 26 configurations and records. The complete genesis configuration fixes the chain identity and must match the database. [The specification](SPECIFICATION.md) describes economic transitions.

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

Public amounts use `types::amount`: decimal strings in JSON and a compact byte-count followed by minimal unsigned little-endian magnitude bytes in binary records. Zero is encoded as an empty byte vector (`00`); a nonempty magnitude ending in a zero byte is invalid. The adapter rejects magnitudes longer than 8,192 bytes before allocating them, and configuration imposes narrower monetary/share limits. Decimal strings contain digits only, with no leading zero except `"0"`. Hashes and public keys are fixed 32-byte arrays. State commitment tuples use num-bigint 0.4's sequence of little-endian u32 limbs for unwrapped BigUint values: the limb count and each limb use compact unsigned encoding. This differs from the annotated public-record amount adapter and is part of the specified commitment schema.

One displayed hash is 10^18 raw hash atoms; one displayed stash is 10^36 share atoms. CLI/RPC amounts remain raw integers. Monetary display names do not alter issuance or integer curve arithmetic. Physical mining work uses EH and EH/s. Marked Stash value uses marginal price; a full-redemption quote follows the curve and can be smaller.

## Genesis configuration

The chain ID is `tagged_hash("Hashstash/chain/v26", codec::encode(&config))`. Every Config field participates in declaration order; there are no appended compatibility sections. Config and Settings reject unknown JSON fields.

Config fields are: protocol_version, network, genesis_time, initial_bits, limit_bits, daa_half_life, timestamp_window, future_seconds, max_signatures, max_height, money_bits, share_bits, max_integer_bits, quote_scale, share_scale, auction_timeout, reserve_min, grant_numerator, grant_denominator, budget_numerator, budget_denominator, budget_period, initial. The source types define each width and amount annotation.

Each grant-cap fraction accepts either `0 < numerator < denominator` or exactly `0/0`. The latter disables only that cap: `grant_numerator=grant_denominator=0` removes the per-grant reserve fraction, and `budget_numerator=budget_denominator=0` removes the per-epoch allowance. Mixed zero/nonzero pairs remain invalid. Both pairs are immutable genesis fields. The maintained presets retain their existing fractions and chain IDs. The sentinel uses previously invalid values without changing protocol 26 field encoding or hash domains; older implementations reject sentinel configurations. Enabling it therefore requires a new chain configuration, not a settings proposal or an in-place change to an existing chain.

Settings fields are block_bytes, minimum_fee_rate, interval, lead, rest, duration, miner_fee_percent, pass_margin_bps, in that order. The first six are u64; interval, lead, rest and duration use seconds. Config's auction_timeout and budget_period also use seconds. Both percentages are Option<u64> and must be present. MinerFeePercent is a whole percentage from 0 through 100; PassMarginBps is an unsigned basis-point margin. Config.share_scale is a positive, fixed genesis amount defining the initial raw stash per raw hash. It is not governable.

The three maintained presets use a 15-second target, 900-second ASERT half-life, 11-header median window and 120-second future allowance. Validation requires a half-life at least 900, median window at least 11 and future allowance at most 120. The target limit is immutable genesis configuration. The economic clock advances by parent_settings.interval for each block. Phase deadlines therefore preserve their nominal duration when the interval changes. These are scheduled seconds, not header timestamps or wall-clock deadlines; the chain must advance for economic time to pass.

## Transactions and parameters

A signed transaction contains its body followed by exactly 64 BIP340 signature bytes, with no signature-length prefix. Body order is chain_id[32], sender[32], nonce:u64, fee:Amount, expiry_height:u64, operation, data:Vec<u8>. The nonce and expiry use compact unsigned encoding. The body fee is the exact total charged when included. The BIP340 signing message is tagged_hash("Hashstash/Transaction/v26", codec::encode(body)), binding every body field and the full chain identity. Transaction IDs are SHA256d of the complete signed record. Expiry is inclusive.

The operation is a direct six-variant enum followed by a length-prefixed data byte vector, including a zero length for empty data. Transaction data has no consensus text format; all bytes count toward the block-byte and fee-weight limits. Chat interprets readable UTF-8, and [Mail](MAIL.md) defines an encrypted application envelope.

| Tag | Operation | Payload order |
| --- | --- | --- |
| 0 | TransferExact | recipient, exact amount |
| 1 | Deposit | amount, min_shares, optional decision, optional outcome |
| 2 | Redeem | shares, min_received, optional decision, optional outcome |
| 3 | Propose | round, description hash, proposal, support |
| 4 | Support | round, proposal ID, amount |
| 5 | Refund | round, proposal ID |

Unknown operation tags are rejected. Round numbers use compact u64 encoding. Outcome tags are Pass=0 and Fail=1. Proposal tags are Grant=0 (payments), Parameter=1 (parameter, old:u64, new:u64). Grant payments are a compact nonzero count followed by pairs of recipient[32] and amount:Amount, sorted by public-key bytes with no duplicate keys. Each key must be valid and each amount positive. The combined amount must fit the configured monetary range; there is no separately encoded total. Decoding is bounded by the actual transaction/record bytes; a hostile count cannot preallocate an oversized list. In JSON the grant is `{"Grant":{"payments":[{"recipient":[...],"amount":"..."}]}}`. Decision hashes and outcome options must either both be present or both absent. Human-readable records reject unknown fields.

Parameter tags are BlockBytes=0, Interval=1, Lead=2, Rest=3, Duration=4, MinerFeePercent=5, PassMarginBps=6, MinimumFeeRate=7. MinimumFeeRate is positive u64 raw hash atoms per 1,024 weight and changes by exact half/double. Capacity and phase durations use positive exact half/double changes in their stored units. Interval accepts a changed whole second from 1 through 60. MinerFeePercent accepts a changed whole percentage from 0 through 100; PassMarginBps accepts a changed unsigned margin. Decision duration must strictly exceed the target interval, leaving at least one block for conditional trading before resolution. Capacity must permit mandatory account creation. The effective auction timeout is max(auction_timeout, lead + interval). Deadlines and arithmetic must remain representable. Changes activate only after the rest period, judged under the frozen settings of their decision. The activating block still uses its parent's interval; only its child uses the new one. Existing signed expiry_height values are never rewritten.

Transfers credit the signed exact amount. Recipient creation increases the required minimum fee, which the exact signed fee must cover. Proposal explanations are transaction data; the UI verifies their SHA256 against the signed description hash.

## Fees, capacity and issuance

Transaction weight is its signed byte length plus 1,024 for a new TransferExact recipient, or 1,024 per payout in a grant proposal. Grant payout weight is fixed, whether or not those accounts already exist. The minimum fee is ceil(weight * minimum_fee_rate / 1024). The exact signed body.fee must meet this minimum and is charged in full. A transfer recipient created by a preceding transaction can reduce the required minimum and weight but does not reduce the signed payment. The minimum rate starts at one atom per 1,024 weight and changes only through a successful MinimumFeeRate half/double proposal. Empty or full blocks do not change it. An optional extra is only an input to the quote builder; the signed record contains one exact fee, not a separate extra or cap.

The grant proposal prepays bounded settlement work. This transaction fee is not refunded if the proposal loses, expires or becomes ineligible, or if recipients obtain accounts before settlement. It is distinct from refundable auction support. Its miner share goes to the miner that includes the proposal, under the ordinary fee split; settlement does not deduct another fee from any grant amount.

For each transaction, miner_fee = floor(actual_fee * active_miner_fee_percent / 100); waiting revenue receives the remainder. The initial split is 50/50. The whole paid fee is split, including any extra. This transfers existing hashes; it does not create issuance.

BlockBytes bounds both measured body bytes and transaction weight, including prepaid grant payout weight. A new mining recipient contributes 1,024 weight without any deduction from its protocol payment. Mandatory grant settlement is exempt from this closing block's weight limit because its work was charged with the proposal. Its recipient count was bounded by the proposal’s byte and weight capacity when included. Ordinary payment-account creation and miner-account creation retain their capacity checks. During governance, one logical payment-account creation counts once. Presets start with 16 KiB of body/weight capacity. There is no separate recipient-count or transaction-size setting: a transaction may use the block’s remaining byte and weight capacity, including its signature, data and execution weight. Block framing and any mining-account creation also need capacity. Governance can increase or decrease BlockBytes up to the implementation’s 32 MiB binary record ceiling; independent signature-count limits still apply.

Each canonical block creates exactly floor(2^256 / (target + 1)) raw hash atoms. Losing blocks receive no reward. Fork choice compares the accumulated expected work of valid branches.

## Accounts, reserve and governance

State uses persistent authenticated maps. The deterministic treap has priorities derived from keys, canonical roots independent of insertion order, and shared immutable subtrees. Account updates copy changed paths rather than cloning all accounts. Account field order is ordinary:Amount, shares:Amount, nonce:u64, epoch:u64. Each outcome's cash is its ordinary field; there is no extra conditional balance field. Epoch records account materialization's governance context. Public-key bytes are the map key, not an extra account field.

An empty reserve accepts deposits immediately. A deposit d sets reserve = curve_mass = d and creates d * Config.share_scale stash for its sender. Account hashes never convert automatically. Ordinary trades then use the current dynamic ratio. Revenue adds min(revenue, curve_mass - reserve) to reserve without changing curve mass or stash; excess waits. All stash belongs to accounts. Config.quote_scale must be at least Config.share_scale so the initial nonempty curve has a nonzero integer price quote. An empty world contributes zero to governance price integrals; its next deposit still opens at the configured exchange rate.

A governance decision starts with two roots referencing the same account state. PASS and FAIL each expose full balances automatically. Selected Stash trades affect that world's cash and shares; ordinary payments and fees debit both worlds. Therefore shared payment availability is the minimum of the two cash balances. Nonces and account keys remain coordinated. Alternative balances must not be summed.

Grant eligibility applies the reserve minimum, grant fraction, available backing and period budget to the combined payout amount. At activation, PASS escrows that total from waiting revenue first and reserve second, keeping mass and stash unchanged. Completed parent quotes floor(quote_scale * curve_mass / shares) contribute their covered scheduled seconds to the price integral. For full-window integral increases P and F and frozen margin m, PASS requires P*10000 > F*(10000+m). Equality selects FAIL. Resolution selects the winning root and atomically pays every listed amount once if PASS wins. No recipient is paid before resolution or partially paid by a failed transition. No account-wide settlement rewrite occurs. Losing tree nodes remain reachable while retained checkpoints need them.

An explicitly disabled fraction or period budget omits only its corresponding eligibility check. Grants still require positive, representable payments and full backing from waiting revenue plus reserve above `reserve_min`. Disabling the period cap leaves `budget_period`, epoch rollover and exact reserved/spent accounting intact. Each disabled epoch records allowance zero as metadata; it is never divided, subtracted from or treated as a spending ceiling. Audit still bounds all three amounts, requires allowance zero, and matches reservations exactly to the active decision's originating epoch. Settlement releases that reservation once and records successful spending in that epoch even after later epochs have opened.

## State commitments

World root is tagged_hash("Hashstash/world/v26", encode((accounts.root(), reserve, shares, revenue, grant_escrow, price_integral, curve_mass, account_cash, account_shares))). Each dynamic curve field is committed.

The state root is tagged_hash("Hashstash/state/v26", encode((A,B))). A contains chain_id, height, clock, issued, settings, frozen, world.root(), optional alternative.root(), phase. Clock is cumulative scheduled seconds. B contains proposal/support/round/ranking roots, auction_escrow, budgets.root(), budget_start, budget_epoch, last_round, last_epoch. Field and tuple ordering is consensus-critical.

Tree domains are Hashstash/TreeEmpty, Hashstash/TreeValue, Hashstash/TreePriority and Hashstash/TreeNode. Protocol roots commit to authenticated map roots rather than their in-memory representation. All changes, including fees and protocol payments, must reproduce the declared state root.

## Mining wire format

The Bitcoin-style header is 80 bytes: version:u32 at offset 0, previous digest[32] at 4, Merkle root[32] at 36, timestamp:u32 at 68, bits:u32 at 72, nonce:u32 at 76. Integers are little endian; digest bytes are raw. Fixed version bits are 0x20000005, with rolling mask 0x1fffe000. Outside that mask the version must match exactly.

The sole Merkle leaf is a Bitcoin-serialized system coinbase. It has transaction version 1, one zero-prevout input (index and sequence 0xffffffff), a minimally encoded height plus PUSH8 and eight extranonce bytes, one zero-value output, and locktime 0. Its output script is OP_RETURN, PUSH68, ASCII HST6, miner key[32], commitment[32]. The commitment is tagged_hash("Hashstash/block-commitment/v26", encode((transactions,state_root))). There is no optional proof field or padding. Coinbase transaction counts and script lengths use canonical CompactSize.

The header Merkle root is SHA256d of this coinbase, so Stratum supplies an empty Merkle branch. The complete ordered signed transaction vector is bound inside the commitment. Verifying that commitment needs the full vector; it does not provide short transaction-inclusion proofs.

The governed body measurement is state_root[32], CompactSize record count, and each record's CompactSize length plus complete bytes. Records are the coinbase followed by user transactions. The 80-byte header is excluded. Binary block record field order is header, height:u64, miner[32], state_root[32], extranonce[8], transactions. The extranonce is exactly eight bytes without a length prefix. The binary record's Header integers use the compact serializer; proof of work always hashes the separately constructed fixed 80-byte header specified above. Validators reconstruct all redundant commitments. Bitcoin CompactSize framing remains distinct from the compact integer encoding of consensus records.

## Timestamps, difficulty and forks

Proof of work compares the little-endian SHA256d header digest with a canonical positive target no easier than genesis limit_bits. Each branch derives cumulative scheduled seconds S_h = S_(h-1) + parent_settings.interval. Its first mined block supplies the ASERT anchor timestamp T_1 and scheduled seconds S_1. For a child of a non-genesis parent, error = (parent.timestamp - T_1) - (parent.expected_seconds - S_1). Ideal target is initial_target * 2^(error/daa_half_life), using the fixed-point integer ASERT approximation, compact rounding and target limit. The first two blocks use initial_bits: time before mining began is excluded. An interval change modifies future schedule increments without resetting the anchor. Competing branches retain their own first-block anchors; reopening reconstructs these from validated history.

Timestamp must exceed median past time and must not exceed local now + future_seconds. Median uses available ancestors including the parent, capped by timestamp_window, sorted at index length/2. Future blocks remain retryable. Time checks reduce but do not eliminate timestamp manipulation. Header time affects ASERT, while governance and grant-budget periods advance by the target interval, independently of the candidate timestamp. Transaction expiry remains an inclusive height limit; timestamp samples and confirmations retain their count units.

The greatest-work valid branch becomes active; equal-work arrivals retain the current tip. Reorganization replaces all affected state, issuance, fees, funding and decisions together. Accepted block bodies and checkpoints allow reconstruction; governance resolution gives no finality. SQLite commits block/tip changes atomically, and the node publishes tip and state together. Mempool recovery revalidates nonces, funds, expiry and decision bindings.

## Bounds and genesis

Genesis is a deterministic unmined height-zero anchor with zero cumulative work and issuance, empty accounts, reserve and revenue, eight zero extranonce bytes and no transactions. It commits an initial Rest state ending at initial.rest scheduled seconds and the full configuration. Stash deposits and withdrawals are already permitted. Proposal rounds and budgets begin through normal transitions. Its zero miner is not a payable account. Mining validation starts at height 1.

Maximum supported height is u32::MAX. Nonces, phase clocks and deadlines use checked u64 values. Config validates amount ranges, share ranges, bounded curve arithmetic, lifetime issuance and price-integral capacity. Binary block and transaction records have a 32 MiB implementation ceiling. Governed BlockBytes cannot exceed that ceiling. These bounds constrain representability and work; they do not guarantee economic outcomes or constant validation latency.

Fields, enum tags, hash domains, rounding and coinbase construction are consensus rules. See [validation](VALIDATION.md) for tested scope, and [network controls](NETWORK-HARDENING.md) for limits that are node policy rather than consensus.

Peer transport framing is separate from consensus records. Binary peer messages carry canonical transaction and block bytes. Their chain identity and record domains must match this protocol.
