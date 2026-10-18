# Hashstash protocol specification

Hashstash is an account-based proof-of-work chain with transferable hashes, a reserve-backed stash conversion curve and market-based governance. Mining creates hashes in proportion to expected work. Accounts can exchange hashes for stash and back again. Governance compares two possible states, PASS and FAIL, to decide grants and permitted setting changes.

This document describes the current rules. The [consensus format](CONSENSUS.md) specifies their binary representation. Mathematical curve formulas below use ideal arithmetic; executable quotes follow the bounded integer algorithm and rounding described below.

## 1 Accounts, payments and issuance

An account is identified by a 32-byte BIP340 public key and holds spendable hashes and stash shares. Its nonce counts outgoing transactions and prevents a signed transaction from being spent twice. A transaction requires the sender's signature, exact next nonce, an ancestor block reference and a positive lifetime measured from that block. If the reference is block 100 and the lifetime is 2, inclusion is valid in blocks 101–102. A reference removed by a reorganization is invalid on that branch. The reference and lifetime are signed and cannot slide forward during retries. Payments credit the exact signed recipient amount; the signed fee is charged separately. Stash cannot be transferred between accounts.

Each canonical non-genesis block contributes `W = floor(2^256 / (target + 1))` expected hashing attempts. It creates `floor(W / 10^15)` atoms: one atom per whole petahash of expected work, discarding any smaller fraction for that block. A block below one petahash issues zero atoms. Total issuance adds the independently rounded rewards of canonical blocks. Actual attempts are not measurable from a proof. Losing blocks receive no reward. Nodes select the valid branch with greatest accumulated physical expected work and retain their current tip on equality; monetary rounding never changes fork choice. Local admission policy may first presync a far-behind branch's proof-of-work headers before validating its blocks, within the bounds described in [network controls](NETWORK-HARDENING.md); it changes when a heavier branch is adopted, not which branch wins.

One displayed hash equals 1,000 raw hash atoms; one displayed stash equals 1,000 raw share atoms. RPC and CLI use integer atoms. Mining work and hashrate use EH and EH/s. Display units do not change consensus arithmetic.

## 2 Starting the reserve

Genesis starts with empty accounts and reserve, zero stash and zero issued hashes. Its initial Rest phase ends when the scheduled clock reaches the configured rest duration, opening the first proposal auction. Mining creates the hashes that accounts can spend or deposit.

A signed deposit of `d` raw hashes into an empty reserve establishes:

```text
reserve R = d
total stash S = q * d
curve mass M = d
depositor's stash increases by q * d
```

The fixed genesis parameter `q = Config.share_scale` defaults to one raw share per raw hash. The opening ratio is 1 and the opening marginal price is `1/q`. Under the standard display units, one displayed hash initially obtains one displayed stash, excluding fees. Subsequent deposits and withdrawals use the current curve and require their owner's signature.

Fee revenue waits outside an empty or flat reserve. A decision requires an eligible auction winner; a grant must be fully backed at activation.

## 3 The reserve curve

Each outcome state, called a world in the implementation, stores:

| Field | Meaning |
| --- | --- |
| R | Actual hash reserve available for stash withdrawals |
| S | Total stash supply, all held by accounts |
| M | Curve mass: the price and curve-shape state, not a hash balance |
| U | Waiting revenue, held outside the reserve |
| E | Grant escrow, held outside the reserve until resolution |

For a nonempty curve, `0 < R <= M` and `S > 0`. Its reserve ratio and marginal price are:

```text
r = R / M
p = M / S = R / (r * S)
```

At `r = 1`, the curve is flat: ordinary buying and selling preserve the price in ideal arithmetic. Below 1, buying raises the price and selling lowers it. A smaller ratio makes the response steeper. Neither M nor a marked stash value is an additional reserve balance.

### Amount-only block clearing

A buy order commits a hash amount; a sell order commits a Stash amount. Neither specifies a limit price or minimum output. All included orders in the same world clear together from that block’s opening reserve. PASS and FAIL clear independently. Signed nonces and ordinary transaction dependencies still apply, but the order of valid Stash transactions cannot choose their clearing price or allocation.

In ideal arithmetic let D be total buy cash, B total Stash offered for sale, and x the net new Stash. The curve’s net cash change and common execution price satisfy:

```text
C(x) = R * ((1 + x/S)^(1/r) - 1)
P(x) = C(x)/x, with P(0) = M/S
D = P(x) * (B + x)
```

Each buyer receives its filled cash divided by P; each seller receives its filled Stash multiplied by P. Afterward `R' = R + P*x`, `S' = S + x`, and mass scales with reserve. This execution price is the average along the net curve movement; it differs from the closing marginal price `M'/S'`.

`MaxPriceChangeBps` bounds the actual closing marginal price relative to the opening one. Its default is 1,000 basis points (10%). If the full batch would move too far upward, buy inputs are reduced proportionally. If it would move too far downward, sell inputs are reduced proportionally. The opposite side remains eligible for its full input, subject to integer rounding and zero-output refunds. On a flat curve an inexact sale raises the price as well ([integer execution](#integer-execution)). There, if removing every buy input still leaves the batch too high, sell inputs are reduced instead while buys keep their full input, and if that also fails, both sides are reduced by the same fraction. A side whose fills are all exact leaves the price unchanged, so within the numeric range the other side's rounding never reduces it. On a curved world a sale raises the price only through rounding, and only the usual side is reduced. Unused input stays with its owner; it does not become an order for a future block. Accepted orders still pay their signed fees, even if their filled input is zero.

The bound applies separately to each block and compounds across blocks. Zero allows no price movement. Values at or above 10,000 allow a zero lower bound, including full redemption; the upper bound continues to use the configured value. An emptied curve reopens at the fixed genesis exchange rate, whatever its price was before it emptied, and a block in which either world is empty is no governance observation: it adds no PASS lead (section 7). A setting at or above 10,000 therefore lets a holder of all of one world's Stash empty that world, suppressing PASS leads while it stays empty, and reset its price to the genesis rate within two blocks. Only genesis can choose such a bound; governance is limited to 9,999 (section 7). Revenue replenishment and grant reservation change backing without changing the marginal price.

### Integer execution

The implementation uses integer ratios and directed logarithm bounds, never floating point. Small rational curves use exact power comparisons. A common price bracket determines conservative outputs: buys round Stash down and sells round hash payouts down. No transaction ID, array position or miner-selected rounding winner receives the leftover atoms. A flat curve's price M/S is exact and independent of volume: each order receives its rounded-down output and pays only the least input that buys that output, and the unusable principal is refunded. At a price whose reduced numerator or denominator is one, including the genesis exchange rate, every such trade is exact and leaves the price unchanged. At any other flat price each filled order, buy or sale, can raise it and none lowers it: a buy leaves under one hash atom of extra input in the reserve, and a sale burns under one extra Stash atom. No order needs a minimum lot, so a flat curve reached through revenue replenishment, whose supply is unrelated to its reserve, stays tradeable. Zero-output orders have their principal refunded together before the remaining batch is recalculated.

Directed logarithms use 4b+128 fractional bits, rounded up to a multiple of 64 and at most 2,048, where b is the widest input bit length; one-sided batches evaluate their probe-independent logarithm once. The price search brackets the root between the opening marginal price M/S and M(R+D)/(RS+MB), a bound on the closing marginal price (for a net sale also at least R/S). Within one clearing each price search starts where the previous one ended: every search, including one settled without curve work, records the floor of the mean of its final bounds with its scale, and the next search first probes that value times its own scale divided by the recorded scale, if it lies strictly inside the bracket. That probe and the following Newton proposals number at most 64; otherwise the search bisects, geometrically while the bracket spans more than a factor of two. A probe whose comparison stays undecided ends the search: its two neighbours become the bracket if each is a bracket end or is proven on its side, and otherwise the proven lower and upper bounds are each refined by arithmetic bisection towards that probe. Unless the work below is exhausted, a search on an exact small-ratio curve, or for an exact full redemption, finally tests the simplest fraction inside its bracket for equality.

Clearing one world performs at most 1,024 curve evaluations. A comparison decided by the integer checks that precede the curve costs nothing: a zero probe, a probe at or past D/B, where buy cash and sale proceeds would balance, sale proceeds reaching the funded reserve R + D, or an empty resulting supply. Any other comparison spends one evaluation, which covers its logarithms; a one-sided batch's probe-independent logarithm is computed during its first evaluation and never charged again. On an exact small-ratio curve an undecided logarithm comparison spends one more evaluation for its exact power comparison. Once the evaluations are exhausted every further comparison is undecided, so price brackets keep their proven bounds and the budget search below keeps its best proven candidate, and the result remains valid and conservative. When the limit binds, the result depends on this exact sequence of probes, so matching implementations must reproduce the reference search step for step. Block validation, template construction and mempool selection apply the same limit.

When a bound is reached, deterministic integer search reduces the affected side’s aggregate budget and apportions it by input amount. When both sides of a flat batch are reduced, it searches the buy budget and the sell budget is that budget times B/D, rounded down. It interpolates on the relative gap to the active bound with Illinois weighting. After an interpolation that fails to halve that gap it bisects, geometrically from one atom, for a run that doubles with each consecutive failure. It stops when the budget is resolved to one atom or to 2^-64 of the retained budget. Rounding can make the result conservative: this rule does not promise the greatest possible filled volume at dust boundaries. The same search reduces fills if their combined reserve, mass or supply would exceed the configured numeric range. Final exact cross-products enforce both price bounds against the actual rounded mass and supply. Reserve, Stash and mass must become empty together. Mass rounds down when reserve grows and up when it shrinks. All actual fills and refunds conserve cash and Stash.

Inputs and fees must be covered by the account’s opening balances, including all its other commitments in that block. A transfer, refund, mining reward or trade output received within the block cannot fund another operation in that same block. This removes funding-order dependencies from clearing. Account credits are aggregated; execution updates affected account-tree paths rather than rewriting all accounts whenever an order changes.

Miners still choose which transactions to include and can censor or delay orders. Batching removes within-block price priority for the included set; the price bound and leading-block rule do not eliminate manipulation across blocks. Without a limit price, any order sharing a block, which a miner can guarantee for its own, raises other buyers' common price on a curved world, and an order reaching the bound reduces the other fills on its side proportionally while their fees are still paid. The price bound limits this per block; flat curves are unaffected. Wallets use a short default trade expiry to limit how long an amount-only order remains eligible.

## 4 Revenue and grants

Revenue is a committed hash buffer collectively governed through the proposal process. It receives the non-miner share of each complete transaction fee and all support for an auction-winning proposal. The winning support joins revenue when its decision opens, after any grant has been reserved, so it never funds the proposal that paid it.

### Revenue replenishment

Outside a decision, revenue moves into a nonflat reserve as soon as the block's revenue processing runs:

```text
release = min(U, M - R)
R = R + release
U = U - release
M and S remain unchanged
```

This raises `r = R/M` toward 1 while leaving the current price `M/S` unchanged. At 1, further revenue waits. While a decision is active neither outcome replenishes: fees and the winning support wait as revenue in each outcome, so only trades change either curve's shape during the decision. Otherwise revenue could flatten an outcome right after a small trade and freeze that price for every remaining observation. The selected outcome replenishes from its resolution block. The same logical revenue is never counted twice in the selected outcome.

### Grant funding

A grant specifies one or more payments, each with a distinct valid recipient key and a positive amount. Payments are sorted by public-key bytes and the total G is their sum; no second total is stored. At decision activation, PASS sets aside that entire amount:

```text
from_revenue = min(U, G)
from_reserve = G - from_revenue
U = U - from_revenue
R = R - from_reserve
E = G
M and S remain unchanged
```

The reserve shortfall lowers the ratio without changing the marginal price or any account's stash quantity. Waiting revenue is spent first. FAIL makes no grant debit, but sets the same shortfall aside as its own waiting revenue:

```text
R_FAIL = R - from_reserve
U_FAIL = U + from_reserve
```

Both outcomes therefore open with the same reserve, mass and supply. Equal trades move their prices alike, and neither curve is structurally easier to move than the other. Recipients cannot spend escrow before resolution. If PASS wins, every listed amount is paid once in the same atomic transition; if FAIL wins, the PASS state is discarded.

FAIL is therefore not an untouched status quo while a reserve-drawing grant is decided. Its trades execute on the drawn curve, and its mass scales with its reserve as usual. A FAIL sale pays less than it would at the original ratio, and a FAIL buy creates less Stash. When FAIL is selected, ordinary replenishment adds `min(U, M - R)` to its reserve, which equals the shortfall only if FAIL saw no trades. After net FAIL sales part of the shortfall stays as waiting revenue, so the remaining holders' price is lower than the same sales would have left it on the original curve. Net FAIL buys do the opposite and draw extra waiting revenue into the reserve. Holders who sell FAIL during such a decision accept this difference.

Eligibility requires enough available funds for the combined amount G: waiting revenue plus at most half of the reserve, rounded down:

```text
G <= U + floor(R / 2)
```

One grant can therefore at most halve the reserve ratio of either outcome. Both outcomes open on that curve, so a draw of the whole reserve would otherwise leave each with a curve too steep for any buy to fill within the price-change bound, and with nothing for a sale to pay, until resolution. A live Stash reserve keeps at least one raw hash atom, so its curve remains valid. Registering a proposal does not reserve funding or guarantee eligibility; a proposal that could not open its decision is cancelled when it would lead (section 5). Revenue already inside the reserve is not counted again as waiting revenue.

Grants reduce withdrawal backing while preserving the price at that moment. Revenue and grants change the curve's shape rather than trading along it. Ordinary trades, revenue transfers and grants conserve existing hashes.

## 5 Proposals and auctions

Anyone with a funded account can propose a grant or one permitted setting change and contribute a positive auction bid. Further Support transactions add bids to a proposal. The highest total bid wins once it has remained leader for the frozen lead period, or when it leads at the auction timeout. A proposal ID binds the account that registered it, so a copied pending proposal becomes a separate proposal.

Leadership is evaluated once per block, after the block's transactions:

- The incumbent keeps a tie with the highest bid. Otherwise the highest bid leads, and equal bids go to the smallest proposal ID. Proposers can grind their IDs, so this rule gives no fairness guarantee: anyone can break a tie with a one-atom Support. A strictly higher bid restarts the lead period at the block's clock.
- A proposal that could not open its decision in that block never leads. Examples are an unfundable grant, an invalid projected schedule and an unrepresentable end height. It is cancelled, refundable from the next block, and the evaluation continues with the next bid. A grant can become unfundable after it took the lead, because sales lower the grant capacity. The auction therefore records, in order, each leader that a strictly higher bid displaced, with the lead start it held. When the leader is cancelled, the most recently displaced proposal that is still active is the incumbent again; if it leads, it resumes its recorded lead start, which may already be mature. A cancelled proposal therefore never costs the proposal it displaced any lead time, unless a live higher bid takes over instead. Cancelled proposals are dropped from the record.
- The lead test is inclusive (`clock - lead_since >= lead`). If a mature leader is nevertheless cancelled, the next leader is chosen in the following block.
- At the auction timeout (`clock - opened >=` the effective timeout), a leader that can open its decision opens it, even before its lead matures. Outbidding the leader late therefore wins the round, and the winning bid becomes revenue, instead of ending the round with every bid refunded. Without such a leader the round enters rest without a decision. Rest completion is processed after auctions, so a zero rest can open the next auction in the block that timed out or resolved the previous one.

The winning proposal's full bid becomes revenue even if the later decision rejects it. Losing contributions become refundable through signed Refund transactions; they are not automatically pushed to every contributor. Refund eligibility is recorded by round and proposal. Proposals with invalid activation conditions are cancelled under the auction rules.

Governance may change one of:

| Setting | Genesis value | Governed new value |
| --- | --- | --- |
| Block size and weight limit | From 4,096 through 64 MiB | Same, and at most half or twice the old limit |
| Minimum fee rate | Any unsigned 64-bit number of raw hash atoms per 1,024 weight, including zero | Any decrease to a positive rate; an increase to at most twice the old rate, or to 1 from 0, and to at most 2^16 times the genesis rate (2^16 from a zero genesis rate) |
| Target block interval | Positive whole scheduled seconds | At most the ASERT half-life, at most half or twice the old interval, and at least a quarter of the genesis interval (at least one second); an increase must also keep the current lead and decision length within their limits |
| Auction lead | Whole scheduled seconds, including zero | At most `(auction_timeout - interval) / 2` |
| Rest duration | Whole scheduled seconds, including zero | At most 2^22 seconds (about 48.5 days) |
| Decision length | Positive whole block count | At least 3 blocks, lasting at most 2^22 seconds at the frozen interval |
| Maximum Stash price change per block | Any u64 basis-point value, including zero; default 1,000 (10%) | From 1 through 9,999 |
| Miner fee percentage | Whole percent from 0 to 100 | Same |
| Required PASS margin | From 0 through 2^64 − 1 basis points; one basis point is 0.01% | Reachable, as below |

A proposal signs the exact old and new values, and the new value must differ. Every setting fits unsigned 64-bit representation. Raising block capacity itself needs a Propose, so the 4,096 minimum holds the heaviest Parameter Propose without data (339 bytes, with every variable-width field at its maximum), its 1,024 record weight and the 1,024 weight of a new mining account; a block at the minimum also fits a new-record Support beside them. The 64 MiB maximum keeps every valid block within peer framing, API responses, the Explorer index and an SQLite row. Genesis choices for timestamp-window size and ASERT half-life also retain only their required positive/representation rules; the preset values are not mandatory bounds. `init` and `run` warn, without changing validity, about a timestamp window outside 1 to 1,024, a signature limit of 0 or above 65,535, a half-life shorter than the block interval or longer than 2^22 seconds, and a future-time allowance of zero or longer than the half-life (one future-dated block could then more than halve the next block's difficulty).

A passed setting has no way back except another decision, so a governed change may not make the next one impossible. A decision's first observation is always a tie, so fewer than three blocks can never give PASS its strict majority. Zero price movement can never produce a lead. PASS must lead the last `floor(N/2) + 1` observations; the earliest of them reflects `ceil(N/2) - 1` traded blocks, so the settings after every governed change satisfy `m < (ceil(N/2) - 1) * MaxPriceChangeBps`. The duration limits keep every phase short enough to revisit. The lead limit keeps the effective auction timeout at its configured value and lets a proposal that leads in the first half of an auction mature before it. The lead and decision limits depend on the interval, so a longer interval is checked against both: two separately valid decisions cannot combine into a lead beyond the limit or a decision far longer than 2^22 seconds. A shorter interval only loosens them. The interval limit keeps the difficulty schedule stable (section 9); halving or doubling per decision, above a quarter of the genesis interval, also bounds chain growth, orphan risk and per-block state churn. Capacity likewise moves by at most a factor of two per decision. The fee-rate limits mean one decision cannot price every account out of the transaction that would revert it, repeated doublings stop at 2^16 times the genesis rate, so reverting them costs at most that multiple of a genesis-rate decision, and a passed rate is never zero, which would make permanent account and record state free. A price bound of 10,000 basis points or more permits full redemption, so a holder of all of one world's Stash could empty it and suppress PASS leads, including against the decision that would restore a lower bound; governance therefore cannot select one. Genesis may still start outside these limits, except for block capacity; such a chain may be unable to pass later changes.

Scheduled time and deadlines must remain representable. The effective auction timeout is the greater of the configured timeout and `lead + interval`; all additions and rounding to future block boundaries are checked. A governed change must also stay representable for the whole remaining height range, not only at one clock: `clock + interval * (max_height - height) + effective_timeout + decision_blocks * interval + rest + 2 * interval` must fit u64, using the changed settings at the checking block's clock and height. Each block advances the clock by one interval and uses one remaining height, so this bound does not change along an unchanged schedule. A genesis whose clock range ends before its height limit already exceeds it; such a chain may still make a change for which the same sum is no larger than under its current settings. A Propose transaction is checked at the current clock. The projected decision and rest activation boundary is checked whenever the proposal would lead or open its decision; a failure cancels it under the auction rules instead of invalidating the Propose. Activation checks the value again. A one-block genesis decision resolves on the first subsequent block, before an outcome trade can affect an observation. Decision block counts and projected scheduled-time arithmetic must fit their integer representations.

The reserve ratio is state derived from R and M, not a governed fixed parameter. Issuance, proof of work, authentication, timestamp-validation policy, ASERT half-life and opening share scale remain fixed by the protocol or genesis configuration. Approved settings activate after rest, with the activating block still using its parent's settings.

## 6 PASS and FAIL

A decision creates two worlds sharing the same initial account-tree root. PASS represents enactment; FAIL represents rejection. A grant changes both immediately as specified above: PASS escrows it, and FAIL holds the same reserve shortfall as waiting revenue. Parameter proposals retain the current settings during their own decision and rest.

Every stash deposit or redemption during a decision signs both the decision ID and chosen outcome. Outside a decision, both fields are absent. A PASS trade affects only PASS balances, stash and curve; it cannot be replayed as FAIL. Ordinary payments, fees, mining rewards, account existence and nonce advancement apply consistently to both alternatives. A payment must be affordable in both, so its available cash is the smaller balance. Do not add the two alternatives together.

At settlement, account balances continue directly from the chosen root. The losing root is no longer active but may remain reachable through retained checkpoints needed for reorganization.

## 7 Price comparison and resolution

A decision freezes a positive block count N and PASS margin m when it opens. Each subsequent block observes the completed parent’s exact marginal prices. For two nonempty curves, it adds one PASS leading block exactly when:

```text
M_PASS * S_FAIL * 10000 > M_FAIL * S_PASS * (10000 + m)
```

The size of the lead and the block timestamp add no extra weight. Equality contributes no PASS lead. After exactly N observations, PASS wins only if `leading_blocks > N/2` and the proposal is still fully funded. This is a strict majority of all observed blocks, including ties. A change to the PASS margin is judged under the old frozen margin.

Prices are compared as exact mass/supply ratios using integer cross-products. Display rounding and quote scale do not affect whether a block leads. A block in which either curve is empty adds no PASS lead, whatever the margin: an empty world has no market price, and its next deposit opens at the genesis rate. A one-atom bootstrap deposit therefore cannot lead an empty FAIL world.

A trade affects the closing quote of its inclusion block and is first counted by the following block. Resolution happens before the final block’s user transactions, so a last-moment trade cannot alter an observation that has already settled. Both outcomes open with equal quotes and identical curves, because FAIL sets aside the same reserve shortfall as PASS. A reserve-drawing grant thus steepens both curves alike, at most halving their reserve ratio, so both stay tradeable until resolution; FAIL trades in that period move value against waiting revenue as section 4 describes. The first observation is therefore a tie unless another prior state difference exists. There is no price integral or magnitude-weighted average.

The two curves share integer rounding. On a nearly flat curve, rounding lets buys raise the price slightly, while small sales may fail to lower it or even raise it. An equal trade in the other outcome is then the matching defence. A flat outcome at the genesis exchange rate, or at any flat price whose reduced numerator or denominator is one, cannot move at all, so a revenue-funded grant or a setting change on such a baseline resolves FAIL. At other flat prices any filled order, buy or sale, can raise that outcome's price and none lowers it: a buy leaves under one hash atom of extra input in the reserve, and a sale burns under one extra Stash atom ([integer execution](#integer-execution)). Selling an outcome's Stash there pushes that outcome toward a lead just as buying does; this is the same shared-rounding case as a nearly flat curve.

Resolution keeps the selected world’s accounts, reserve, supply, mass and revenue. A passing grant pays its escrow in full to the listed recipients once. Its account-update work was charged when the proposal was included. A passing setting change activates after rest. Reorganizations reverse a resolution together with dependent state changes. The rule measures market prices; it does not guarantee a proposal’s benefit.

## 8 Fees and block construction

The transaction signs one exact fee. Its minimum is:

```text
weight = signed transaction bytes + execution_weight
execution_weight = 1024 for a transfer to a new account
                 = 1024 for a parameter proposal
                 = 1024 * (payment_count + 1) for a grant proposal
                 = 1024 for a Support that creates the sender's support record
                 = 0 otherwise
minimum_fee = ceil(weight * governed_minimum_fee_rate / 1024)
require signed_fee >= minimum_fee
miner_fee = floor(signed_fee * miner_fee_percent / 100)
revenue_fee = signed_fee - miner_fee
```

The entire signed fee is charged. If an earlier transaction has already created a transfer recipient, its creation weight and required minimum can fall but the signed payment stays unchanged. Grant proposal execution weight is fixed per recipient, whether or not that account exists. Proposal and support records stay in consensus state permanently, so every proposal also pays 1,024 weight for its proposal record and first support record, and a Support pays it when the sender has no support record for that proposal yet; adding to an existing record does not. Like account creation, the Support charge depends on the state before the transaction. The proposal fee is not refunded when a grant loses or never activates, or when recipients receive accounts before settlement. This fee is separate from refundable auction support. Its miner share goes to the proposal's inclusion miner; no further fee is deducted from payouts. An optional extra is a quote-builder input, not a separately signed amount. The minimum rate can be zero. Empty or full blocks do not change it. Allocation conserves each fee exactly, including rounding.

Node policy selects executable transactions by miner fee per weight, respecting nonce dependencies. At a zero miner share, fee-ranking ties use transaction IDs. Other valid transaction selections remain consensus-valid. The governed body limit also bounds transaction weight, including prepaid grant execution, and new mining-account weight. Only mandatory grant settlement writes are exempt from this weight limit; their number was bounded by the proposal’s admitted bytes and prepaid execution weight. There is no separate recipient-count limit. A complete signed proposal may use the including block’s available byte and weight capacity. There is no separate transaction-size setting. Maintained presets start with 16 KiB of capacity; governance can set a different representable capacity. Transport and API admission apply separate resource limits. Block framing and any mining-account creation also consume capacity. During governance, one logical payment-account creation counts once.

## 9 Scheduled time, timestamps and difficulty

Each block advances the economic clock by its parent's target interval. Auction lead and rest periods use these scheduled seconds; decisions use their frozen block counts. Changing target interval preserves auction/rest nominal durations; actual elapsed time still varies with mining. Transaction expiry, confirmation depths and timestamp samples remain counts of blocks.

Mining uses a fixed 80-byte Bitcoin-style SHA256d header. The timestamp must exceed median past time and remain within the future allowance relative to the validating node's clock. Too-far-future blocks remain retryable. Presets use an 11-header median, 120-second future allowance, 900-second ASERT half-life and 15-second initial target interval.

Each branch records accumulated target seconds from genesis. For a non-genesis parent, ideal next target is:

```text
anchor_timestamp = max(block_1.timestamp, block_2.timestamp - block_1_interval)
error = (parent_timestamp - anchor_timestamp)
      - (parent_expected_seconds - first_block_expected_seconds)
ideal_target = initial_target * 2^(error / half_life)
```

`block_1_interval` is the target interval in block 1's post-state, the one block 2 is scheduled by; before block 2 exists, the anchor timestamp is block 1's own timestamp.

Each branch anchors ASERT at its first mined blocks, excluding the wait between creating the genesis configuration and starting mining. The anchor timestamp is the later of the first block's timestamp and the second block's timestamp less one target interval, so backdating the first block alone cannot turn that wait into timestamp error; a miner producing both of the first two blocks still can. A network calibrated with `init --hashrate` sets its target limit 256 times easier than the initial target, so neither such a backdated start nor a stall can make its blocks more than 256 times cheaper than calibrated. The first two blocks use the initial target, and the third never starts easier than it. Later targets use the fixed integer ASERT approximation, canonical compact rounding and the fixed genesis target limit. An interval change affects future schedule increments without resetting that branch's anchor. The half-life stays fixed, so a governed interval is at most the half-life. A block mined at the old spacing then lowers the next target by at most one halving, rather than demanding work that no miner can supply. Timestamp controls constrain but do not eliminate manipulation.

Header timestamps are u32 seconds. Once median past time reaches u32::MAX (2106-02-07 06:28:15 UTC) no timestamp can exceed it and the chain cannot be extended; this is a protocol lifetime limit that only a new header format could lift.

## 10 Authenticated state and execution

Accounts and protocol indexes use persistent authenticated maps: a Patricia trie over hashed keys commits each map, and an uncommitted index keeps the same entries in key order for lookups, ordered iteration and the auction ranking. Map roots are independent of insertion order. Updates copy changed paths and share untouched immutable subtrees. Starting a decision shares a root; settlement selects one. These operations avoid scanning or rewriting every account at phase boundaries. Path copies stay short whatever keys users choose: no entry lies under more than 256 trie branches, and pushing a key L levels below its natural depth of about log2(n) costs about 2^L hash evaluations ([state commitments](CONSENSUS.md#state-commitments)). Proposal actions are stored once at registration, apart from their mutable records, so supporting or cancelling a proposal never re-encodes its grant.

Block execution validates its parent, encoding, target and resource limits; advances scheduled time and counts the parent’s leading-block observation; settles a due decision; reserves transaction inputs and fees; clears the included amount-only orders in each world together; pays the mining subsidy and collected miner fees; replenishes the reserve from revenue outside a decision; processes auctions and complete grant escrow; applies due rest activation; and verifies the resulting committed state. Activation and revenue processing are deterministic and operate independently on active outcomes. The exact ordering is defined by the maintained consensus implementation and corresponding integration tests.

The world commitment includes the account root, reserve, stash supply, curve mass, waiting revenue, grant escrow, account aggregates. The top-level commitment includes worlds, chain identity, height, clock, issuance, settings, phase, proposal/action/support/refund indexes. A decision's action is committed through the action index alone. Every accepted block must reproduce its declared state root.

## 11 Conservation and bounds

Each possible outcome separately satisfies:

```text
account hashes + reserve + waiting revenue + grant escrow
  + live auction escrow and refundable support
  = cumulative issued hashes
total stash = sum of account stash
```

Curve mass, marginal marked values, withdrawal quotes are not additional money pools. Count alternative worlds separately, never together: only the selected outcome survives settlement. Reserve, stash and mass are empty together; a nonempty world has M >= R > 0.

Balances, shares, curve state, intermediate arithmetic, clocks, deadlines and collection sizes have explicit bounds. Intermediate integer widths are functions of the configured money and share widths. `max_integer_bits` validates the monetary and price-comparison products at genesis; it does not cap every intermediate. The direct reserve quotes stay below 8,192 bits. Batch clearing scales operands to about 3b+36 bits for b-bit inputs on exact power curves, whose comparisons then reach about 15(3b+36) bits, and its logarithms use at most 2,048 fractional bits. Nonces and heights never wrap. Genesis validation ensures the maximum expected-work issuance and opening stash allocation fit configured amounts. Voluntary operations exceeding bounds are rejected. Compact encoding does not remove execution or storage limits.

## 12 Records, storage and networking

Transactions contain sender, nonce, exact fee, anchor block hash, lifetime in blocks, one of six direct operations, arbitrary data bytes and a fixed 64-byte BIP340 signature. The signature covers the network's chain ID followed by the body (see [CONSENSUS.md](CONSENSUS.md)); the chain ID is not transmitted, and every node verifies against its own, so a transaction signed for one network is invalid on every other. Binary amounts use a compact length followed by their minimal unsigned little-endian magnitude; zero has no magnitude bytes. Other integers and lengths use canonical variable-width encoding. Unknown fields, invalid tags, nonminimal encodings, excess lengths and trailing bytes are rejected.

A block contains the header, height, miner key, state root, eight-byte mining extranonce and ordered transactions. Its Bitcoin-shaped system coinbase commits to the miner, transaction list and state root. It is the sole Merkle leaf, allowing SHA256 ASIC Stratum jobs with an empty Merkle branch. Validation of the transaction commitment needs the whole ordered list rather than a short per-transaction proof.

SQLite stores accepted blocks and active-chain metadata transactionally. The node publishes tip and state together. Restart validates history and rebuilds state and derived indexes, above the newest locally saved state checkpoint that passes its checks or else from genesis; history is not pruned. Reorganizations restore every accounting and governance field together and revalidate pending transactions. Neither checkpoint retention nor governance settlement creates finality.

Peers exchange bounded compact binary frames carrying canonical records. Block locators find a common ancestor. Peer transport version 2 opens each synchronization with header requests: a node learns other branches from their 80-byte headers whatever their blocks' size or length, holds a branch's headers only after counting that they claim more work than its tip, and then fetches that branch's blocks from where it leaves validated history, within a capacity allowance raised to that history's validated capacity. Fork choice is unchanged: the valid branch with the most work becomes the tip. Version 1 peers, which have no header messages, keep block synchronization. Nodes can use explicit peers, a closed set of pinned transport identities, or authenticated peer discovery. Authenticated sessions bind messages to their direction and sequence; authenticated modes cannot silently fall back to unauthenticated transport. A discovered public key proves control of that key, not a trusted operator or independent participant. Authentication does not encrypt traffic or prevent an eclipse by compromised peers or routing. Connection limits, per-IP work budgets, timeouts and bounded decoders constrain local resource use. State, disk history and replay time still grow. RPC and Stratum remain JSON services. See [node operation](RUNNING.md) and [network limits](NETWORK-HARDENING.md).

## 13 Applications and security scope

Signed transaction data is raw bytes. Chat interprets readable UTF-8 and Mail defines recipient-hidden encrypted envelopes. They are applications over the chain's data, not new account fields or consensus operation types.

Browser wallets sign locally and trust their serving origin. Keys stored in browser storage are unencrypted. Peer authentication and consensus validation do not establish application privacy, independent participation, economic stability or a guarantee against manipulation. HASH represents expected-work issuance rather than stable external purchasing power. Governance compares an internal stash/hash price, not an independently measured public benefit.

A database must use its exact genesis configuration. Chain, state, transaction, world and block commitments use the domains and field layouts in [CONSENSUS.md](CONSENSUS.md). Signed transactions bind the chain ID and an anchor block, and nodes require that anchor to belong to the branch accepting them. A shared anchor permits inclusion on either descendant fork until expiry, subject to the other transaction checks.
