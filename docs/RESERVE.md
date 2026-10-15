# Reserve and revenue

The shared reserve backs stash withdrawals. Every stash unit belongs to an account. Waiting revenue is a separate hash buffer governed through proposals.

## Curve state

For reserve R, stash supply S and curve mass M, the reserve ratio is r = R/M and marginal price is M/S. A deposit into an empty reserve starts with M = R and S = deposit × Config.share_scale, giving a flat curve. Ordinary buys and sells follow the current ratio; grants reduce reserve without reducing mass, and revenue replenishes reserve without increasing mass. Accounts keep their stash quantities through those protocol movements.

A grant drawn from reserve reduces withdrawal backing while preserving the marginal price at that moment. Marginal price is the price of a small trade at the current position; it is not a promise that all stash can be redeemed at that price. A grant covered entirely by waiting revenue leaves the curve unchanged. The [specification](SPECIFICATION.md) gives the trade formulas and deterministic rounding rules.

## Waiting revenue

Each transaction signs its exact fee. The governed miner percentage splits the entire fee, including any extra: the miner receives the rounded-down percentage and revenue receives the remainder. The initial split is 50/50. Winning auction bids also become revenue. These are transfers of existing hashes, not issuance.

Each block's revenue-processing step replenishes the reserve by min(waiting revenue, M - R). This moves the ratio toward 100% without changing the marginal price. Excess revenue stays in the waiting buffer; a flat curve consumes none.

## Grants and governance

A grant lists distinct recipients and a positive hash amount for each. The proposal’s block-byte and block-weight limits bound the list; there is no separate recipient-count setting. At activation, the combined amount must be fully backed by waiting revenue plus reserve, keeping one raw hash atom in a live Stash reserve so its curve remains valid. PASS immediately escrows that total, using waiting revenue first and reserve for any shortfall. Mass and stash supply do not change. FAIL retains its own funds.

Only a passing decision pays the recipients, together and once, from escrow. Each receives the exact listed amount. The proposal transaction pays a fixed execution charge per recipient in advance; no settlement fee is deducted from their payouts. FAIL discards the alternate debit and escrow together. Fees received during a decision act separately in each world, and settlement keeps only the selected world's reserve, curve mass, waiting revenue and account balances.

A decision lasts a fixed number of blocks. For each block, compare the previous block’s closing marginal prices M/S. PASS earns that block only if it exceeds FAIL by more than the frozen margin. PASS must earn strictly more than half of all decision blocks; a tie resolves FAIL. If both curves remain flat at the same price, neither trading volume nor larger balances create a PASS lead.

## RPC and conservation

Status and governance expose `reserve`, `shares`, `curve_mass`, `revenue` and `grant_capacity`; each governance world also exposes `grant_escrow`. Grant capacity is waiting revenue plus reserve, less the one raw hash atom retained by a live Stash curve. Revenue is the waiting amount outside reserve; it has no account view. Curve mass is price state, not an additional hash balance. Each outcome separately conserves account hashes + reserve + revenue + grant escrow + live auction escrow/refunds = issued hashes. Never add PASS and FAIL balances together.

Stash orders clear once per block as a batch. Each world uses one execution price, and excess input on a constrained side fills proportionally. The governed price-change limit bounds the actual closing curve price relative to the parent, initially by 10% per block. Unfilled input returns to the account. No order carries over after inclusion. Quotes preview one order against current state and can differ when other orders join the batch.

The order’s input and fee must be available at the block’s opening. Incoming transfers, refunds and trade proceeds in that block cannot finance it. Integer rounding preserves accounting; see [CONSENSUS.md](CONSENSUS.md) and [the specification](SPECIFICATION.md).
