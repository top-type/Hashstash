# Reserve and revenue

The shared reserve backs stash withdrawals. Every stash unit belongs to an account. Waiting revenue is a separate hash buffer governed through proposals.

## Curve state

For reserve R, stash supply S and curve mass M, the reserve ratio is r = R/M and marginal price is M/S. A deposit into an empty reserve starts with M = R and S = deposit × Config.share_scale, giving a flat curve. Ordinary buys and sells follow the current ratio; grants reduce reserve without reducing mass, and revenue replenishes reserve without increasing mass. Accounts keep their stash quantities through those protocol movements.

A grant drawn from reserve reduces withdrawal backing while preserving the marginal price at that moment. Marginal price is the price of a small trade at the current position; it is not a promise that all stash can be redeemed at that price. A grant covered entirely by waiting revenue leaves the curve unchanged. The [specification](SPECIFICATION.md) gives the trade formulas and deterministic rounding rules.

## Waiting revenue

Each transaction signs its exact fee. The governed miner percentage splits the entire fee, including any extra: the miner receives the rounded-down percentage and revenue receives the remainder. The initial split is 50/50. Winning auction bids also become revenue. These are transfers of existing hashes, not issuance.

Outside a decision, each block's revenue-processing step replenishes the reserve by min(waiting revenue, M - R). This moves the ratio toward 100% without changing the marginal price. Excess revenue stays in the waiting buffer; a flat curve consumes none. During a decision both outcomes keep revenue waiting, so only trades change either curve; the selected outcome replenishes from its resolution block, as far as its waiting revenue and curve gap allow.

## Grants and governance

A grant lists distinct recipients and a positive hash amount for each. The proposal’s block-byte and block-weight limits bound the list; there is no separate recipient-count setting. At activation, the combined amount must be backed by waiting revenue plus at most half of the reserve, rounded down. One grant can therefore at most halve the reserve ratio, and a live Stash reserve always keeps at least one raw hash atom. PASS immediately escrows that total, using waiting revenue first and reserve for any shortfall. Mass and stash supply do not change. FAIL retains its own funds but moves the same reserve shortfall into its waiting revenue, so both outcomes open on the same curve and equal trades move them alike. The half-reserve limit keeps that curve tradeable in both outcomes; a draw of nearly the whole reserve would leave each with a curve on which no buy fills and no sale pays until resolution. The winning bid becomes waiting revenue in both outcomes only after this reservation, so it never funds its own grant.

Only a passing decision pays the recipients, together and once, from escrow. Each receives the exact listed amount. The proposal transaction pays a fixed execution charge per recipient in advance; no settlement fee is deducted from their payouts. FAIL discards the alternate debit and escrow together. When FAIL is selected, replenishment moves `min(waiting revenue, M - R)` into its reserve. That restores the whole set-aside shortfall only if nobody traded FAIL during the decision. FAIL trades used the drawn curve: a FAIL sale paid less than at the original ratio, and after net FAIL sales part of the shortfall stays as waiting revenue, lowering the remaining holders' price compared with the same sales on the original curve. Net FAIL buys draw extra waiting revenue into the reserve instead. Fees received during a decision wait separately in each world, and settlement keeps only the selected world's reserve, curve mass, waiting revenue and account balances.

A decision lasts a fixed number of blocks. For each block, compare the previous block’s closing marginal prices M/S. PASS earns that block only if it exceeds FAIL by more than the frozen margin. A block in which either world has no Stash earns nothing. PASS must earn strictly more than half of all decision blocks; a tie resolves FAIL. If both curves remain flat at the same price, larger balances create no PASS lead. Nor does trading volume at the genesis exchange rate, or at any flat price whose reduced numerator or denominator is one. At other flat prices, which revenue replenishment can produce, each filled order's rounding remainder stays in the reserve and can raise that world's price by less than one atom of the order's input.

## RPC and conservation

Status and governance expose `reserve`, `shares`, `curve_mass`, `revenue` and `grant_capacity`; each governance world also exposes `grant_escrow`. Grant capacity is waiting revenue plus half of the reserve, rounded down; `grant_quote` uses the same rule. Revenue is the waiting amount outside reserve; it has no account view. Curve mass is price state, not an additional hash balance. Each outcome separately conserves account hashes + reserve + revenue + grant escrow + live auction escrow/refunds = issued hashes. Never add PASS and FAIL balances together.

Stash orders clear once per block as a batch. Each world uses one execution price, and excess input on a constrained side fills proportionally. Clearing a world has a fixed limit of curve evaluations; see the [specification](SPECIFICATION.md#integer-execution). The governed price-change limit bounds the actual closing curve price relative to the parent, initially by 10% per block. Unfilled input returns to the account. No order carries over after inclusion. Quotes preview one order against current state and can differ when other orders join the batch.

The order’s input and fee must be available at the block’s opening. Incoming transfers, refunds and trade proceeds in that block cannot finance it. Integer rounding preserves accounting; see [CONSENSUS.md](CONSENSUS.md) and [the specification](SPECIFICATION.md).
