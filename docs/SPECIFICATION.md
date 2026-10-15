# Hashstash protocol specification

Hashstash is an account-based proof-of-work chain with transferable hashes, a reserve-backed stash conversion curve and market-based governance. Mining creates hashes in proportion to expected work. Accounts can exchange hashes for stash and back again. Governance compares two possible states, PASS and FAIL, to decide grants and permitted setting changes.

This document describes the current rules. The [consensus format](CONSENSUS.md) specifies their binary representation. Mathematical curve formulas below use ideal arithmetic; executable quotes follow the bounded integer algorithm and rounding described below.

## 1 Accounts, payments and issuance

An account is identified by a 32-byte BIP340 public key and holds spendable hashes and stash shares. Its nonce counts outgoing transactions and prevents a signed transaction from being spent twice. A transaction requires the sender's signature, exact next nonce, full chain identity, an ancestor block reference and a positive lifetime measured from that block. If the reference is block 100 and the lifetime is 2, inclusion is valid in blocks 101–102. A reference removed by a reorganization is invalid on that branch. The reference and lifetime are signed and cannot slide forward during retries. Payments credit the exact signed recipient amount; the signed fee is charged separately. Stash cannot be transferred between accounts.

Each canonical non-genesis block contributes `W = floor(2^256 / (target + 1))` expected hashing attempts. It creates `floor(W / 10^15)` atoms: one atom per whole petahash of expected work, discarding any smaller fraction for that block. A block below one petahash issues zero atoms. Total issuance adds the independently rounded rewards of canonical blocks. Actual attempts are not measurable from a proof. Losing blocks receive no reward. Nodes select the valid branch with greatest accumulated physical expected work and retain their current tip on equality; monetary rounding never changes fork choice.

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

`MaxPriceChangeBps` bounds the actual closing marginal price relative to the opening one. Its default is 1,000 basis points (10%). If the full batch would move too far upward, buy inputs are reduced proportionally. If it would move too far downward, sell inputs are reduced proportionally. The opposite side remains eligible for its full input, subject to integer rounding and zero-output refunds. Unused input stays with its owner; it does not become an order for a future block. Accepted orders still pay their signed fees, even if their filled input is zero.

The bound applies separately to each block and compounds across blocks. Zero allows no price movement. Values at or above 10,000 allow a zero lower bound, including full redemption; the upper bound continues to use the configured value. An empty curve opens at the fixed genesis exchange rate. Revenue replenishment and grant reservation change backing without changing the marginal price.

### Integer execution

The implementation uses integer ratios and directed logarithm bounds, never floating point. Small rational curves use exact power comparisons. A common price bracket determines conservative outputs: buys round Stash down and sells round hash payouts down. No transaction ID, array position or miner-selected rounding winner receives the leftover atoms. Flat curves use exact reduced-price lots and refund unusable principal. Zero-output orders have their principal refunded together before the remaining batch is recalculated.

When a bound is reached, deterministic integer search reduces the affected side’s aggregate budget and apportions it by input amount. Rounding can make the result conservative: this rule does not promise the greatest possible filled volume at dust boundaries. The same search reduces fills if their combined reserve, mass or supply would exceed the configured numeric range. Final exact cross-products enforce both price bounds against the actual rounded mass and supply. Reserve, Stash and mass must become empty together. Mass rounds down when reserve grows and up when it shrinks. All actual fills and refunds conserve cash and Stash.

Inputs and fees must be covered by the account’s opening balances, including all its other commitments in that block. A transfer, refund, mining reward or trade output received within the block cannot fund another operation in that same block. This removes funding-order dependencies from clearing. Account credits are aggregated; execution updates affected account-tree paths rather than rewriting all accounts whenever an order changes.

Miners still choose which transactions to include and can censor or delay orders. Batching removes within-block price priority for the included set; the price bound and leading-block rule do not eliminate manipulation across blocks. Wallets use a short default trade expiry to limit how long an amount-only order remains eligible.

## 4 Revenue and grants

Revenue is a committed hash buffer collectively governed through the proposal process. It receives the non-miner share of each complete transaction fee and all support for an auction-winning proposal.

### Revenue replenishment

Revenue moves into a nonflat reserve as soon as the block's revenue processing runs:

```text
release = min(U, M - R)
R = R + release
U = U - release
M and S remain unchanged
```

This raises `r = R/M` toward 1 while leaving the current price `M/S` unchanged. At 1, further revenue waits. Each governance outcome processes its own state independently; the same logical revenue is never counted twice in the selected outcome.

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

The reserve shortfall lowers the ratio without changing the marginal price or any account's stash quantity. Waiting revenue is spent first. FAIL has no corresponding grant debit. Recipients cannot spend escrow before resolution. If PASS wins, every listed amount is paid once in the same atomic transition; if FAIL wins, the PASS state is discarded.

Eligibility requires enough available funds for the combined amount G: waiting revenue plus reserve, keeping one raw hash atom in a live Stash reserve so its curve remains valid. Registering a proposal does not reserve funding or guarantee eligibility. Revenue already inside the reserve is not counted again as waiting revenue.

Grants reduce withdrawal backing while preserving the price at that moment. Revenue and grants change the curve's shape rather than trading along it. Ordinary trades, revenue transfers and grants conserve existing hashes.

## 5 Proposals and auctions

Anyone with a funded account can propose a grant or one permitted setting change and contribute a positive auction bid. Further Support transactions add bids to a proposal. The highest total bid must remain leader for the frozen lead period; ties and bounded cancellation rules are deterministic. An auction timeout enters rest without a decision.

The winning proposal's full bid becomes revenue even if the later decision rejects it. Losing contributions become refundable through signed Refund transactions; they are not automatically pushed to every contributor. Refund eligibility is recorded by round and proposal. Proposals with invalid activation conditions are cancelled under the auction rules.

Governance may change one of:

| Setting | Permitted direct value |
| --- | --- |
| Block size and weight limit | At least 1,024, subject to allocation representation |
| Minimum fee rate | Any unsigned 64-bit number of raw hash atoms per 1,024 weight, including zero |
| Target block interval | Positive whole scheduled seconds |
| Auction lead and rest duration | Whole scheduled seconds, including zero |
| Decision length | Positive whole block count |
| Maximum Stash price change per block | Any u64 basis-point value, including zero; default 1,000 (10%) |
| Miner fee percentage | Whole percent from 0 to 100 |
| Required PASS margin | From 0 through 2^64 − 1 basis points; one basis point is 0.01% |

A proposal signs the exact old and new values, and the new value must differ. Every setting fits unsigned 64-bit representation; block capacity must also fit the host's allocation representation. The 1,024 minimum lets an otherwise empty block create its mining account. Genesis choices for timestamp-window size and ASERT half-life also retain only their required positive/representation rules; the preset values are not mandatory bounds.

Scheduled time and deadlines must remain representable. The effective auction timeout is the greater of the configured timeout and `lead + interval`; all additions and rounding to future block boundaries are checked. The node checks proposed settings at submission and their projected activation, then checks again when applying them. A one-block decision resolves on the first subsequent block, before an outcome trade can affect an observation. Decision block counts and projected scheduled-time arithmetic must fit their integer representations.

The reserve ratio is state derived from R and M, not a governed fixed parameter. Issuance, proof of work, authentication, timestamp-validation policy, ASERT half-life and opening share scale remain fixed by the protocol or genesis configuration. Approved settings activate after rest, with the activating block still using its parent's settings.

## 6 PASS and FAIL

A decision creates two worlds sharing the same initial account-tree root. PASS represents enactment; FAIL represents rejection. A grant changes PASS immediately as specified above. Parameter proposals retain the current settings during their own decision and rest.

Every stash deposit or redemption during a decision signs both the decision ID and chosen outcome. Outside a decision, both fields are absent. A PASS trade affects only PASS balances, stash and curve; it cannot be replayed as FAIL. Ordinary payments, fees, mining rewards, account existence and nonce advancement apply consistently to both alternatives. A payment must be affordable in both, so its available cash is the smaller balance. Do not add the two alternatives together.

At settlement, account balances continue directly from the chosen root. The losing root is no longer active but may remain reachable through retained checkpoints needed for reorganization.

## 7 Price comparison and resolution

A decision freezes a positive block count N and PASS margin m when it opens. Each subsequent block observes the completed parent’s exact marginal prices. For two nonempty curves, it adds one PASS leading block exactly when:

```text
M_PASS * S_FAIL * 10000 > M_FAIL * S_PASS * (10000 + m)
```

The size of the lead and the block timestamp add no extra weight. Equality contributes no PASS lead. After exactly N observations, PASS wins only if `leading_blocks > N/2` and the proposal is still fully funded. This is a strict majority of all observed blocks, including ties. A change to the PASS margin is judged under the old frozen margin.

Prices are compared as exact mass/supply ratios using integer cross-products. Display rounding and quote scale do not affect whether a block leads. An empty curve has zero price.

A trade affects the closing quote of its inclusion block and is first counted by the following block. Resolution happens before the final block’s user transactions, so a last-moment trade cannot alter an observation that has already settled. The opening quotes are equal when the decision merely reserves a grant, so its first observation is a tie unless another prior state difference exists. There is no price integral or magnitude-weighted average.

Resolution keeps the selected world’s accounts, reserve, supply, mass and revenue. A passing grant pays its escrow in full to the listed recipients once. Its account-update work was charged when the proposal was included. A passing setting change activates after rest. Reorganizations reverse a resolution together with dependent state changes. The rule measures market prices; it does not guarantee a proposal’s benefit.

## 8 Fees and block construction

The transaction signs one exact fee. Its minimum is:

```text
weight = signed transaction bytes + execution_weight
execution_weight = 1024 for a transfer to a new account
                 = 1024 * payment_count for a grant proposal
                 = 0 otherwise
minimum_fee = ceil(weight * governed_minimum_fee_rate / 1024)
require signed_fee >= minimum_fee
miner_fee = floor(signed_fee * miner_fee_percent / 100)
revenue_fee = signed_fee - miner_fee
```

The entire signed fee is charged. If an earlier transaction has already created a transfer recipient, its creation weight and required minimum can fall but the signed payment stays unchanged. Grant proposal execution weight is fixed per recipient, whether or not that account exists. The proposal fee is not refunded when a grant loses or never activates, or when recipients receive accounts before settlement. This fee is separate from refundable auction support. Its miner share goes to the proposal's inclusion miner; no further fee is deducted from payouts. An optional extra is a quote-builder input, not a separately signed amount. The minimum rate can be zero. Empty or full blocks do not change it. Allocation conserves each fee exactly, including rounding.

Node policy selects executable transactions by miner fee per weight, respecting nonce dependencies. At a zero miner share, fee-ranking ties use transaction IDs. Other valid transaction selections remain consensus-valid. The governed body limit also bounds transaction weight, including prepaid grant execution, and new mining-account weight. Only mandatory grant settlement writes are exempt from this weight limit; their number was bounded by the proposal’s admitted bytes and prepaid execution weight. There is no separate recipient-count limit. A complete signed proposal may use the including block’s available byte and weight capacity. There is no separate transaction-size setting. Maintained presets start with 16 KiB of capacity; governance can set a different representable capacity. Transport and API admission apply separate resource limits. Block framing and any mining-account creation also consume capacity. During governance, one logical payment-account creation counts once.

## 9 Scheduled time, timestamps and difficulty

Each block advances the economic clock by its parent's target interval. Auction lead and rest periods use these scheduled seconds; decisions use their frozen block counts. Changing target interval preserves auction/rest nominal durations; actual elapsed time still varies with mining. Transaction expiry, confirmation depths and timestamp samples remain counts of blocks.

Mining uses a fixed 80-byte Bitcoin-style SHA256d header. The timestamp must exceed median past time and remain within the future allowance relative to the validating node's clock. Too-far-future blocks remain retryable. Presets use an 11-header median, 120-second future allowance, 900-second ASERT half-life and 15-second initial target interval.

Each branch records accumulated target seconds from genesis. For a non-genesis parent, ideal next target is:

```text
error = (parent_timestamp - first_block_timestamp)
      - (parent_expected_seconds - first_block_expected_seconds)
ideal_target = initial_target * 2^(error / half_life)
```

Each branch anchors ASERT at its first mined block, excluding the wait between creating the genesis configuration and starting mining. The first two blocks use the initial target. Later targets use the fixed integer ASERT approximation, canonical compact rounding and the fixed genesis target limit. An interval change affects future schedule increments without resetting that branch's anchor. Timestamp controls constrain but do not eliminate manipulation.

## 10 Authenticated state and execution

Accounts and protocol indexes use persistent authenticated treaps. Keys determine deterministic priorities; map roots are independent of insertion order. Updates copy changed paths and share untouched immutable subtrees. Starting a decision shares a root; settlement selects one. These operations avoid scanning or rewriting every account at phase boundaries.

Block execution validates its parent, encoding, target and resource limits; advances scheduled time and counts the parent’s leading-block observation; settles a due decision; reserves transaction inputs and fees; clears the included amount-only orders in each world together; pays the mining subsidy and collected miner fees; replenishes reserves from revenue; processes auctions and complete grant escrow; applies due rest activation; and verifies the resulting committed state. Activation and revenue processing are deterministic and operate independently on active outcomes. The exact ordering is defined by the maintained consensus implementation and corresponding integration tests.

The world commitment includes the account root, reserve, stash supply, curve mass, waiting revenue, grant escrow, account aggregates. The top-level commitment includes worlds, chain identity, height, clock, issuance, settings, phase, proposal/support/refund indexes. Every accepted block must reproduce its declared state root.

## 11 Conservation and bounds

Each possible outcome separately satisfies:

```text
account hashes + reserve + waiting revenue + grant escrow
  + live auction escrow and refundable support
  = cumulative issued hashes
total stash = sum of account stash
```

Curve mass, marginal marked values, withdrawal quotes are not additional money pools. Count alternative worlds separately, never together: only the selected outcome survives settlement. Reserve, stash and mass are empty together; a nonempty world has M >= R > 0.

Balances, shares, curve state, intermediate arithmetic, clocks, deadlines and collection sizes have explicit bounds. Nonces and heights never wrap. Genesis validation ensures the maximum expected-work issuance and opening stash allocation fit configured amounts. Voluntary operations exceeding bounds are rejected. Compact encoding does not remove execution or storage limits.

## 12 Records, storage and networking

Transactions contain chain ID, sender, nonce, exact fee, anchor block hash, lifetime in blocks, one of six direct operations, arbitrary data bytes and a fixed 64-byte BIP340 signature. Binary amounts use a compact length followed by their minimal unsigned little-endian magnitude; zero has no magnitude bytes. Other integers and lengths use canonical variable-width encoding. Unknown fields, invalid tags, nonminimal encodings, excess lengths and trailing bytes are rejected.

A block contains the header, height, miner key, state root, eight-byte mining extranonce and ordered transactions. Its Bitcoin-shaped system coinbase commits to the miner, transaction list and state root. It is the sole Merkle leaf, allowing SHA256 ASIC Stratum jobs with an empty Merkle branch. Validation of the transaction commitment needs the whole ordered list rather than a short per-transaction proof.

SQLite stores accepted blocks and active-chain metadata transactionally. The node publishes tip and state together. Restart validates history and rebuilds state and derived indexes; history is not pruned. Reorganizations restore every accounting and governance field together and revalidate pending transactions. Neither checkpoint retention nor governance settlement creates finality.

Peers exchange bounded compact binary frames carrying canonical records. Block locators find a common ancestor. Nodes can use explicit peers, a closed set of pinned transport identities, or authenticated peer discovery. Authenticated sessions bind messages to their direction and sequence; authenticated modes cannot silently fall back to unauthenticated transport. A discovered public key proves control of that key, not a trusted operator or independent participant. Authentication does not encrypt traffic or prevent an eclipse by compromised peers or routing. Connection limits, per-IP work budgets, timeouts and bounded decoders constrain local resource use. State, disk history and replay time still grow. RPC and Stratum remain JSON services. See [node operation](RUNNING.md) and [network limits](NETWORK-HARDENING.md).

## 13 Applications and security scope

Signed transaction data is raw bytes. Chat interprets readable UTF-8 and Mail defines recipient-hidden encrypted envelopes. They are applications over the chain's data, not new account fields or consensus operation types.

Browser wallets sign locally and trust their serving origin. Keys stored in browser storage are unencrypted. Peer authentication and consensus validation do not establish application privacy, independent participation, economic stability or a guarantee against manipulation. HASH represents expected-work issuance rather than stable external purchasing power. Governance compares an internal stash/hash price, not an independently measured public benefit.

A database must use its exact genesis configuration. Chain, state, transaction, world and block commitments use the domains and field layouts in [CONSENSUS.md](CONSENSUS.md). Signed transactions bind the complete chain identity.
