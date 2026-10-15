# Hashstash consensus format · protocol 27 · implementation 0.37.1

This implementation accepts protocol 27 configurations and records. The complete genesis configuration fixes the chain identity and must match the database. [The specification](SPECIFICATION.md) describes economic transitions.

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

The chain ID is `tagged_hash("Hashstash/chain/v26", codec::encode(&config))`. Every Config field participates in declaration order; there are no appended compatibility sections. Config and Settings reject unknown JSON fields. Protocol 27 retains the `v26` hash-domain strings and record schema: the changed validation rules do not change the binary field layout. The encoded `protocol_version=27` configuration gives the chain a distinct identity, and transaction signatures bind that identity.

Config fields are: protocol_version, network, genesis_time, initial_bits, limit_bits, daa_half_life, timestamp_window, future_seconds, max_signatures, max_height, money_bits, share_bits, max_integer_bits, quote_scale, share_scale, auction_timeout, reserve_min, grant_numerator, grant_denominator, budget_numerator, budget_denominator, budget_period, initial. The source types define each width and amount annotation.

Each grant-cap ratio with a positive denominator is valid: a zero numerator means a zero cap, and positive ratios may equal or exceed one. Available backing still bounds actual grants. Exactly `0/0` disables only that cap: `grant_numerator=grant_denominator=0` removes the per-grant reserve fraction, and `budget_numerator=budget_denominator=0` removes the per-period allowance. A positive numerator with a zero denominator is invalid. Both pairs are immutable genesis fields. The supplied presets set both pairs to `0/0`, disabling these optional caps. Changing these values, including disabling either limit, creates a different chain configuration and identity; it is not a settings proposal or an in-place change to an existing chain.

Settings fields are block_bytes, minimum_fee_rate, interval, lead, rest, duration, miner_fee_percent, pass_margin_bps, in that order. The first six are u64; interval, lead, rest and duration use seconds. Config's auction_timeout and budget_period also use seconds. Both percentages are Option<u64> and must be present. MinerFeePercent is a whole percentage from 0 through 100; PassMarginBps is an unsigned basis-point margin. Config.share_scale is a positive, fixed genesis amount defining the initial raw stash per raw hash. It is not governable.

The three maintained presets use a 15-second target, 900-second ASERT half-life, 11-header median window and 120-second future allowance. Those are preset choices. Genesis validation requires a positive half-life and timestamp-window size; future allowance uses its u32 representation. Timestamp rules and target encoding still apply. The target limit is immutable genesis configuration. The economic clock advances by parent_settings.interval for each block. Phase deadlines therefore preserve their nominal duration when the interval changes. These are scheduled seconds, not header timestamps or wall-clock deadlines; the chain must advance for economic time to pass.

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

Parameter tags are BlockBytes=0, Interval=1, Lead=2, Rest=3, Duration=4, MinerFeePercent=5, PassMarginBps=6, MinimumFeeRate=7. A proposal's old value must equal the frozen value and its new value must differ. Nodes enforce the following rules:

| Parameter | Allowed direct value |
| --- | --- |
| BlockBytes | At least 1,024 weight, enough for a new mining account; must fit the implementation's allocation representation |
| MinimumFeeRate | Any u64 raw hash atoms per 1,024 weight, including zero |
| Lead, Rest | Any u64 scheduled seconds, including zero |
| Duration, Interval | Positive u64 scheduled seconds |
| MinerFeePercent | A whole percentage from 0 through 100 |
| PassMarginBps | Any u64 basis-point value, including zero |

Every change supplies an exact `new` integer within these rules. All values fit u64. The node requires a 64-bit target; block capacity also fits `isize::MAX` (2^63 − 1), its allocation representation. These are representability checks, not suggested operating values. A decision duration may be shorter than or equal to the target interval; in that case it can resolve in the first subsequent block, before a conditional trade can be included.

The effective auction timeout is `max(auction_timeout, lead + interval)`, with checked addition. The scheduled clock and every deadline use checked u64 arithmetic. Proposals are checked at submission, again for the projected decision/rest activation boundary, and at activation. Rounding a phase duration up to a block boundary must also fit. A value that fits u64 can therefore still be invalid at a particular clock. Config budgets price-integral arithmetic for the full u64 clock range, rather than assuming a fixed maximum governed interval. Changes activate after the rest period under the frozen settings of their decision; the activating block still uses its parent's interval, and its child uses the new one. Existing signed expiry_height values are never rewritten.

Transfers credit the signed exact amount. Recipient creation increases the required minimum fee, which the exact signed fee must cover. Proposal explanations are transaction data; the UI verifies their SHA256 against the signed description hash.

## Fees, capacity and issuance

Transaction weight is its signed byte length plus 1,024 for a new TransferExact recipient, or 1,024 per payout in a grant proposal. Grant payout weight is fixed, whether or not those accounts already exist. The minimum fee is ceil(weight * minimum_fee_rate / 1024). The exact signed body.fee must meet this minimum and is charged in full. A transfer recipient created by a preceding transaction can reduce the required minimum and weight but does not reduce the signed payment. The presets start the minimum rate at one atom per 1,024 weight. A successful MinimumFeeRate proposal can set any representable rate, including zero; a zero rate requires no minimum fee. Empty or full blocks do not change it. An optional extra is only an input to the quote builder; the signed record contains one exact fee, not a separate extra or cap.

The grant proposal prepays bounded settlement work. This transaction fee is not refunded if the proposal loses, expires or becomes ineligible, or if recipients obtain accounts before settlement. It is distinct from refundable auction support. Its miner share goes to the miner that includes the proposal, under the ordinary fee split; settlement does not deduct another fee from any grant amount.

For each transaction, miner_fee = floor(actual_fee * active_miner_fee_percent / 100); waiting revenue receives the remainder. The initial split is 50/50. The whole paid fee is split, including any extra. This transfers existing hashes; it does not create issuance.

BlockBytes bounds both measured body bytes and transaction weight, including prepaid grant payout weight. A new mining recipient contributes 1,024 weight without any deduction from its protocol payment. Mandatory grant settlement is exempt from this closing block's weight limit because its work was charged with the proposal. Its recipient count was bounded by the proposal’s byte and weight capacity when included. Ordinary payment-account creation and miner-account creation retain their capacity checks. During governance, one logical payment-account creation counts once. Presets start with 16 KiB of body/weight capacity. There is no separate recipient-count or transaction-size setting: a transaction may use the block’s remaining byte and weight capacity, including its signature, data and execution weight. Block framing and any mining-account creation also need capacity. Governance can directly increase or decrease BlockBytes within its representation and mandatory-account bounds; independent signature-count limits still apply. Transport and API admission limits are separate service constraints.

Each canonical block creates exactly floor(2^256 / (target + 1)) raw hash atoms. Losing blocks receive no reward. Fork choice compares the accumulated expected work of valid branches.

## Accounts, reserve and governance

State uses persistent authenticated maps. The deterministic treap has priorities derived from keys, canonical roots independent of insertion order, and shared immutable subtrees. Account updates copy changed paths rather than cloning all accounts. Account field order is ordinary:Amount, shares:Amount, nonce:u64, epoch:u64. Each outcome's cash is its ordinary field; there is no extra conditional balance field. Public-key bytes are the map key, not an extra account field.

The account `epoch` is internal bookkeeping for governance context. Each decision increments `last_epoch`; account reads normalize the returned tag to that decision's number, or zero outside a decision. Stored records retain the context used when written. Changing this tag does not change a balance, mint funds or perform the PASS/FAIL split: the two account-tree roots hold those alternatives. The field participates in the account commitment and its stored value cannot exceed `last_epoch`. It is distinct from `budget_epoch`, which numbers grant-budget periods, and neither field is a Unix timestamp.

A deposit d into an empty reserve sets reserve = curve_mass = d and creates d * Config.share_scale stash for its sender. Ordinary trades then use the current dynamic ratio. Revenue adds min(revenue, curve_mass - reserve) to reserve without changing curve mass or stash; excess waits. All stash belongs to accounts. Config.quote_scale must be at least Config.share_scale so the initial nonempty curve has a nonzero integer price quote. An empty world contributes zero to governance price integrals; its next deposit opens at the configured exchange rate.

A governance decision starts with two roots referencing the same account state. PASS and FAIL each expose full balances automatically. Selected Stash trades affect that world's cash and shares; ordinary payments and fees debit both worlds. Therefore shared payment availability is the minimum of the two cash balances. Nonces and account keys remain coordinated. Alternative balances must not be summed.

Grant eligibility applies the reserve minimum, available backing and any enabled grant-fraction and period-budget limits to the combined payout amount. At activation, PASS escrows that total from waiting revenue first and reserve second, keeping mass and stash unchanged. Completed parent quotes floor(quote_scale * curve_mass / shares) contribute their covered scheduled seconds to the price integral. For full-window integral increases P and F and frozen margin m, PASS requires P*10000 > F*(10000+m). Equality selects FAIL. Resolution selects the winning root and atomically pays every listed amount once if PASS wins. No recipient is paid before resolution or partially paid by a failed transition. No account-wide settlement rewrite occurs. Losing tree nodes remain reachable while retained checkpoints need them.

An explicitly disabled fraction or period budget omits only its corresponding eligibility check. Grants still require positive, representable payments and full backing from waiting revenue plus reserve above `max(reserve_min, 1)` for a live curve. Disabling the period cap leaves `budget_period`, epoch rollover and exact reserved/spent accounting intact. If one block crosses several windows, only the newly visited window is materialized; skipped windows had no opportunity to spend. Earlier records remain available for an outstanding grant's settlement. Each disabled epoch records allowance zero as metadata; it is never divided, subtracted from or treated as a spending ceiling. Audit bounds the allowance and cumulative spending counters at `money_bits + 64` bits; a reservation remains within the monetary range. Spending can count the same hashes more than once if they return and are granted again. Disabled budgets require allowance zero, and reservations match the active decision's originating epoch exactly. Settlement releases that reservation once and records successful spending in that epoch even after later epochs have opened.

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

Genesis is a deterministic unmined height-zero anchor with zero cumulative work and issuance, empty accounts, reserve and revenue, eight zero extranonce bytes and no transactions. It commits the full configuration and an initial Rest state ending at initial.rest scheduled seconds, or opens auction round zero immediately when initial.rest is zero. Proposal rounds and budgets begin through normal transitions. Its zero miner is not a payable account. Mining validation starts at height 1.

Maximum configured height is positive and at most i64::MAX, matching the database height representation. Nonces, phase clocks and deadlines use checked u64 values. Config validates amount ranges, share ranges, bounded curve arithmetic, lifetime issuance and price-integral capacity. Canonical records are bounded by their actual encoded bytes, configured field ranges and the including block’s byte/weight capacity. BlockBytes must fit the platform’s allocation representation. Peer frames and API responses have separate representation or service limits, so an otherwise valid enormous block is not guaranteed to pass every interface. These bounds constrain representability and work; they do not guarantee economic outcomes or constant validation latency.

Fields, enum tags, hash domains, rounding and coinbase construction are consensus rules. See [validation](VALIDATION.md) for tested scope, and [network controls](NETWORK-HARDENING.md) for limits that are node policy rather than consensus.

Peer transport framing is separate from consensus records. Binary peer messages carry canonical transaction and block bytes. Their chain identity and record domains must match this protocol.
