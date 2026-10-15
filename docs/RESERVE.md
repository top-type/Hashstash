# Reserve and revenue

The shared reserve backs stash withdrawals. Every stash unit belongs to an account. Waiting revenue is a separate hash buffer governed through proposals.

## Curve state

For reserve R, stash supply S and curve mass M, the reserve ratio is r = R/M and marginal price is M/S. A deposit into an empty reserve starts with M = R and S = deposit × Config.share_scale, giving a flat curve. Ordinary buys and sells follow the current ratio; grants reduce reserve without reducing mass, and revenue replenishes reserve without increasing mass. Accounts keep their stash quantities through those protocol movements.

A grant drawn from reserve reduces withdrawal backing while preserving the marginal price at that moment. Marginal price is the price of a small trade at the current position; it is not a promise that all stash can be redeemed at that price. A grant covered entirely by waiting revenue leaves the curve unchanged. The [specification](SPECIFICATION.md) gives the trade formulas and deterministic rounding rules.

## Waiting revenue

Each transaction signs its exact fee. The governed miner percentage splits the entire fee, including any extra: the miner receives the rounded-down percentage and revenue receives the remainder. The initial split is 50/50. Winning auction bids also become revenue. These are transfers of existing hashes, not issuance.

Each block's revenue-processing step replenishes the reserve by min(waiting revenue, M - R). This moves the ratio toward 100% without changing the marginal price. Excess revenue stays in the waiting buffer; a flat curve consumes none.

## Grants and governance

A grant lists distinct recipients and a positive hash amount for each. The proposal’s block-byte and block-weight limits bound the list; there is no separate recipient-count setting. At activation, the combined amount must be fully backed by waiting revenue plus reserve above the configured retained minimum, with at least one raw hash kept in any live reserve even when that minimum is zero. PASS immediately escrows that total, using waiting revenue first and reserve for any shortfall. Mass and stash supply do not change. FAIL retains its own funds.

Genesis configuration can add two limits: a maximum grant amount as a fraction of the current reserve, and a spending allowance for each budget period. The supplied presets set both ratios to `0/0`, disabling these optional caps. A chain can instead enable either cap with a positive denominator: a zero numerator gives a zero cap, and positive ratios can equal or exceed one. A positive numerator with a zero denominator is invalid. Available backing still limits every grant. Disabling a cap does not create money or remove the retained reserve minimum, full-backing requirement, fees or grant accounting. The settings are fixed for that chain and cannot be changed by a governance proposal. A budget period is simply a scheduled-time spending window, numbered internally by `budget_epoch`. It begins with the first decision. Disabling its allowance cap keeps the same windows and exact reserved/spent records, without imposing a spending ceiling. A grant that settles later is accounted to the window in which its funding was reserved.

Only a passing decision pays the recipients, together and once, from escrow. Each receives the exact listed amount. The proposal transaction pays a fixed execution charge per recipient in advance; no settlement fee is deducted from their payouts. FAIL discards the alternate debit and escrow together. Fees received during a decision act separately in each world, and settlement keeps only the selected world's reserve, curve mass, waiting revenue and account balances.

Governance compares the average marginal price M/S across the full decision window. PASS must beat FAIL by more than the frozen PASS margin; even with a zero margin, equality resolves FAIL. If both curves stay flat at the same price, trades cannot separate those averages. This mechanism does not guarantee grant approval or economically sound decisions.

## RPC and conservation

Status and governance expose `reserve`, `shares`, `curve_mass`, `revenue` and `grant_capacity`; each governance world also exposes `grant_escrow`. Grant capacity is waiting revenue plus reserve above the retained minimum; enabled grant-fraction and period-budget limits apply separately. Revenue is the waiting amount outside reserve; it has no account view. Curve mass is price state, not an additional hash balance. Each outcome separately conserves account hashes + reserve + revenue + grant escrow + live auction escrow/refunds = issued hashes. Never add PASS and FAIL balances together.

The RPC quote and browser display use the current world's curve, including its ratio. Integer consensus execution conservatively rounds deposit issuance, retained reserve and mass; see [CONSENSUS.md](CONSENSUS.md) and [the specification](SPECIFICATION.md).
