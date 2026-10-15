# Hashstash protocol specification

Hashstash is an account-based proof-of-work chain with transferable hashes, a reserve-backed stash conversion curve and market-based governance. Mining creates hashes in proportion to expected work. Accounts can exchange hashes for stash and back again. Governance compares two possible states, PASS and FAIL, to decide grants and permitted setting changes.

This document describes the current rules. The [consensus format](CONSENSUS.md) specifies their binary representation. Mathematical curve formulas below use ideal arithmetic; executable quotes follow the bounded integer algorithm and rounding described below.

## 1 Accounts, payments and issuance

An account is keyed by a 32-byte BIP340 public key. Its record contains ordinary hash balance, stash share balance, nonce and epoch. The epoch identifies its materialization context. A transaction requires the sender's signature, exact next nonce, full chain identity and an unexpired inclusive block height. Payments credit the exact signed recipient amount; the signed fee is charged separately. Stash cannot be transferred between accounts.

Each accepted non-genesis block creates `floor(2^256 / (target + 1))` raw hash atoms. This is the expected number of hashing attempts represented by its required target, rounded down. Actual attempts are not measurable from the resulting proof. Only canonical work earns issuance; losing blocks receive no reward. Nodes select the valid branch with greatest accumulated expected work and retain their current tip on equality.

One displayed hash equals 10^18 raw hash atoms; one displayed stash equals 10^36 raw share atoms. RPC and CLI use integer atoms. Mining work and hashrate use EH and EH/s. Display units do not change consensus arithmetic.

## 2 Starting the reserve

Genesis has no account balances, reserve, stash or issued hashes. It begins with an ordinary Rest phase that delays the first proposal auction. Mining, payments and Stash trading are available immediately; an account must first obtain hashes to spend or deposit them.

Account hashes never convert automatically. A signed deposit of `d` raw hashes into an empty reserve establishes:

```text
reserve R = d
total stash S = q * d
curve mass M = d
depositor's stash increases by q * d
```

The fixed genesis parameter `q = Config.share_scale` defaults to 10^18 raw shares per raw hash. The opening ratio is 1 and the opening marginal price is `1/q`. Under the standard display units, one displayed hash initially obtains one displayed stash, excluding fees. Subsequent deposits use the current curve; while it stays flat, buying earlier does not obtain a cheaper rate. Every deposit and withdrawal requires its owner's signature.

Fee revenue remains outside an empty or flat reserve. Hashes mined at any time are ordinary spendable balances. The first proposal auction opens after the initial rest period, subject to the normal reserve and eligibility requirements for a decision.

## 3 The reserve curve

Each world stores:

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

### Ordinary trades

A deposit of `d` hashes creates:

```text
new_S = S * (1 + d/R)^r
stash_received = new_S - S
new_R = R + d
```

Redeeming `b` stash returns:

```text
new_S = S - b
new_R = R * (1 - b/S)^(1/r)
hashes_received = R - new_R
```

Ordinary trades preserve the current ratio in ideal arithmetic by scaling M with reserve: `new_M = M * new_R / R`. The executable rule rounds mass down on deposits and up on withdrawals, so reversing a trade cannot benefit from a more favorable curve shape created by that rounding. A signed deposit or redemption sets its minimum acceptable output. Zero-output and out-of-range trades are rejected. Fees are additional ordinary balance debits; they do not come out of the displayed trade output.

### Integer execution

Amounts and curve inputs are bounded integers, at most 512 bits. Flat curves use exact rational arithmetic. Small rational ratios whose reduced denominator is at most eight use integer powers and root comparisons. General ratios use deterministic directed bounds with 2,048 fractional bits: a bounded atanh series for logarithms, a bounded exponential series after division by 1,024, and ten squarings. Deposits use a lower bound on minted supply; withdrawals round retained reserve upward using a lower bound on the reciprocal exponential. These operations do not depend on floating-point or machine math libraries.

Rounding favors retained reserve. Deposits never create more stash than the ideal formula; withdrawals never pay more hashes than the ideal formula. A full supply redemption empties reserve, stash and mass. Restarting an empty curve uses the fixed genesis share scale and a flat curve; waiting revenue remains separate until it can replenish a nonflat curve.

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

Eligibility applies the configured reserve minimum, maximum grant fraction, available backing and remaining period budget to the combined amount G. The budget period begins with the first decision; each period fixes an allowance from the reserve and tracks reserved and spent grants. A proposal's registration does not reserve funding or guarantee eligibility. A grant cannot empty a live curve's reserve. Revenue already inside the reserve is not also available as waiting revenue.

Grants reduce withdrawal backing while preserving the price at that moment. Revenue and grants change the curve's shape rather than trading along it. Ordinary trades, revenue transfers and grants conserve existing hashes.

## 5 Proposals and auctions

Anyone with a funded account can propose a grant or one permitted setting change and contribute a positive auction bid. Further Support transactions add bids to a proposal. The highest total bid must remain leader for the frozen lead period; ties and bounded cancellation rules are deterministic. An auction timeout enters rest without a decision.

The winning proposal's full bid becomes revenue even if the later decision rejects it. Losing contributions become refundable through signed Refund transactions; they are not automatically pushed to every contributor. Refund eligibility is recorded by round and proposal. Proposals with invalid activation conditions are cancelled under the auction rules.

Governance may change one of:

| Setting | Permitted change |
| --- | --- |
| Block size and weight limit | Exact half or double |
| Minimum fee rate | Positive exact half or double |
| Target block interval | A changed whole second from 1 to 60 |
| Auction lead, decision duration, rest duration | Positive exact half or double in scheduled seconds |
| Miner fee percentage | A changed whole percent from 0 to 100 |
| Required PASS margin | A changed unsigned basis-point value |

The reserve ratio is state derived from R and M, not a governed fixed parameter. Issuance, proof of work, authentication, timestamp-validation policy, ASERT half-life and opening share scale remain fixed by the protocol or genesis configuration. Changes must satisfy capacity, arithmetic and deadline bounds. Approved settings activate after rest, with the activating block still using its parent's settings.

## 6 PASS and FAIL

A decision creates two worlds sharing the same initial account-tree root. PASS represents enactment; FAIL represents rejection. A grant changes PASS immediately as specified above. Parameter proposals retain the current settings during their own decision and rest.

Every stash deposit or redemption during a decision signs both the decision ID and chosen outcome. Outside a decision, both fields are absent. A PASS trade affects only PASS balances, stash and curve; it cannot be replayed as FAIL. Ordinary payments, fees, mining rewards, account existence and nonce advancement apply consistently to both alternatives. A payment must be affordable in both, so its available cash is the smaller balance. Do not add the two alternatives together.

At settlement, account balances continue directly from the chosen root. The losing root is no longer active but may remain reachable through retained checkpoints needed for reorganization.

## 7 Price comparison and resolution

The decision compares the marginal stash price over its full scheduled duration. Each completed parent world contributes `q = floor(Q * M / S)` multiplied by the target seconds covered by the next block. Empty curves quote zero. Q is the fixed positive quote scale. The two ratios may differ, so validators compare the full normalized price M/S, not reserve per share.

Let A be the cumulative quote integral, A_start its value at activation, D the frozen decision duration, t_start its start clock and C the closing block clock. Scores clip the last interval to the exact deadline:

```text
overshoot = C - (t_start + D)
score = A - A_start - closing_parent_quote * overshoot
average = score / D
PASS iff score_PASS * 10000 > score_FAIL * (10000 + margin_bps)
```

Equality selects FAIL. A change to the PASS margin is judged under the old frozen margin. A trade first affects the price observation in a following block. The full duration counts; there is no special final-price window.

If both outcomes stay flat at the same price, trades cannot separate their scores. A grant fully covered by waiting revenue leaves the curves unchanged, so that case resolves FAIL when no other state difference changes the scores. A grant that uses reserve can change PASS price sensitivity without changing its starting price. The mechanism does not guarantee that the price signal measures a grant's benefit or is immune to manipulation.

Resolution occurs before the closing block's user transactions. It keeps the selected world's account root, reserve, supply, mass, waiting revenue and price integral. A passing grant pays its existing escrow in full to the listed recipients, without payment deductions. Its bounded account updates were charged when the proposal was included, so they do not consume the closing block's transaction capacity. A passing setting change is recorded for activation after rest. Reorganizations can reverse a resolution along with every dependent state transition.

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

The entire signed fee is charged. If an earlier transaction has already created a transfer recipient, its creation weight and required minimum can fall but the signed payment stays unchanged. Grant proposal execution weight is fixed per recipient, whether or not that account exists. The proposal fee is not refunded when a grant loses or never activates, or when recipients receive accounts before settlement. This fee is separate from refundable auction support. Its miner share goes to the proposal's inclusion miner; no further fee is deducted from payouts. An optional extra is a quote-builder input, not a separately signed amount. Empty or full blocks do not change the governed minimum rate. Allocation conserves each fee exactly, including rounding.

Node policy selects executable transactions by miner fee per weight, respecting nonce dependencies. At a zero miner share, fee-ranking ties use transaction IDs. Other valid transaction selections remain consensus-valid. The governed body limit also bounds transaction weight, including prepaid grant execution, and new mining-account weight. Only mandatory grant settlement writes are exempt from this weight limit; their number was bounded by the proposal’s admitted bytes and prepaid execution weight. There is no separate recipient-count limit. A complete signed proposal may use the including block’s available byte and weight capacity. There is no separate transaction-size setting. Maintained presets start with 16 KiB of capacity; governance may change it within the implementation’s 32 MiB record ceiling. Block framing and any mining-account creation also consume capacity. During governance, one logical payment-account creation counts once.

## 9 Scheduled time, timestamps and difficulty

Each block advances the economic clock by its parent's target interval. Auction lead, decision, rest and grant-budget periods use these scheduled seconds. Changing target interval preserves their nominal duration; actual elapsed time still varies with mining. Transaction expiry, confirmation depths and timestamp samples remain counts of blocks.

Mining uses a fixed 80-byte Bitcoin-style SHA256d header. The timestamp must exceed median past time and remain within the future allowance relative to the validating node's clock. Too-far-future blocks remain retryable. Presets use an 11-header median, 120-second future allowance, 900-second ASERT half-life and 15-second initial target interval.

Each branch records accumulated target seconds from genesis. For a non-genesis parent, ideal next target is:

```text
error = (parent_timestamp - first_block_timestamp)
      - (parent_expected_seconds - first_block_expected_seconds)
ideal_target = initial_target * 2^(error / half_life)
```

Each branch anchors ASERT at its first mined block, excluding the wait between creating the genesis configuration and starting mining. The first two blocks use the initial target. Later targets use the fixed integer ASERT approximation, canonical compact rounding and the fixed genesis target limit. An interval change affects future schedule increments without resetting that branch's anchor. Timestamp controls constrain but do not eliminate manipulation.

## 10 Authenticated state and execution

Accounts and protocol indexes use persistent authenticated treaps. Keys determine deterministic priorities; map roots are independent of insertion order. Updates copy changed paths and share untouched immutable subtrees. Starting a decision shares a root; settlement selects one. Governance context avoids full account scans at phase boundaries.

Block execution validates its parent, encoding, target and resource limits; advances scheduled time and parent-price integrals; settles a due decision; applies ordered user transactions and fees; pays the mining subsidy and collected miner fees; replenishes reserves from revenue; processes auctions and complete grant escrow; applies due rest activation; and verifies the resulting committed state. Activation and revenue processing are deterministic and operate independently on active outcomes. The exact ordering is defined by the maintained consensus implementation and corresponding integration tests.

The world commitment includes the account root, reserve, stash supply, curve mass, waiting revenue, grant escrow, price integral, account aggregates. The top-level commitment includes worlds, chain identity, height, clock, issuance, settings, phase, proposal/support/refund indexes, budgets. Every accepted block must reproduce its declared state root.

## 11 Conservation and bounds

Each possible outcome separately satisfies:

```text
account hashes + reserve + waiting revenue + grant escrow
  + live auction escrow and refundable support
  = cumulative issued hashes
total stash = sum of account stash
```

Curve mass, marginal marked values, price integrals and withdrawal quotes are not additional money pools. Count alternative worlds separately, never together. Materializing an account in its current governance context cannot credit aggregate supply a second time. Reserve, stash and mass are empty together; a nonempty world has M >= R > 0.

Balances, shares, curve state, intermediate arithmetic, price integrals, clocks, deadlines and collection sizes have explicit bounds. Nonces and heights never wrap. Genesis validation ensures the maximum expected-work issuance and opening stash allocation fit configured amounts. Voluntary operations exceeding bounds are rejected. Compact encoding does not remove execution or storage limits.

## 12 Records, storage and networking

Transactions contain chain ID, sender, nonce, exact fee, expiry, one of six direct operations, arbitrary data bytes and a fixed 64-byte BIP340 signature. Binary amounts use a compact length followed by their minimal unsigned little-endian magnitude; zero has no magnitude bytes. Other integers and lengths use canonical variable-width encoding. Unknown fields, invalid tags, nonminimal encodings, excess lengths and trailing bytes are rejected.

A block contains the header, height, miner key, state root, eight-byte mining extranonce and ordered transactions. Its Bitcoin-shaped system coinbase commits to the miner, transaction list and state root. It is the sole Merkle leaf, allowing SHA256 ASIC Stratum jobs with an empty Merkle branch. Validation of the transaction commitment needs the whole ordered list rather than a short per-transaction proof.

SQLite stores accepted blocks and active-chain metadata transactionally. The node publishes tip and state together. Restart validates history and rebuilds state and derived indexes; history is not pruned. Reorganizations restore every accounting and governance field together and revalidate pending transactions. Neither checkpoint retention nor governance settlement creates finality.

Configured peers exchange bounded compact binary frames carrying canonical records. Block locators find a common ancestor. Optional pinned transport keys authenticate sessions, direction and sequence; pinned mode cannot silently fall back to unauthenticated transport. Authentication does not encrypt traffic or prevent an eclipse by compromised peers or routing. Connection limits, per-IP work budgets, timeouts and bounded decoders constrain local resource use. State, disk history and replay time still grow. RPC and Stratum remain JSON services. See [node operation](RUNNING.md) and [network limits](NETWORK-HARDENING.md).

## 13 Applications and security scope

Signed transaction data is raw bytes. Chat interprets readable UTF-8 and Mail defines recipient-hidden encrypted envelopes. They are applications over the chain's data, not new account fields or consensus operation types. The optional mixer is a separately operated trusted custodian; its operator knows the deposit-to-payout mapping and controls deposited funds.

Browser wallets sign locally and trust their serving origin. Keys stored in browser storage are unencrypted. Peer authentication and consensus validation do not establish application privacy, independent participation, economic stability or a guarantee against manipulation. HASH represents expected-work issuance rather than stable external purchasing power. Governance compares an internal stash/hash price, not an independently measured public benefit.

Implementation 0.36.0 accepts protocol 26 configurations and records. A database must use its exact genesis configuration. The specified chain and transaction domains bind compact records and signed application data to that protocol and network.
