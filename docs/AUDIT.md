# Hashstash 0.36.0 review scope

The reviewed model opens voluntary Stash trading at genesis, with an initially flat dynamic reserve curve, waiting hash revenue and full grant escrow at decision activation. The review uses protocol 26 configurations and records.

Review covers conservation in each world, immediate deposits into an empty flat reserve, price preservation for protocol reserve movements, directed integer curve bounds, grant eligibility and escrow, PASS/FAIL price normalization, settlement, reorganization and overflow limits. Multi-recipient review includes bounded decoding, canonical recipient ordering, aggregate funding limits, prepaid execution weight, atomic credits and miner-account overlap. Executable results are recorded in [VALIDATION.md](VALIDATION.md).

The protocol has six direct operations, exact signed fees, whole-fee miner/revenue allocation, compact binary records and bounded binary peer transport. Browser and cold signing bind the current transaction domain. Application data, recipient-hidden Mail and the optional custodial mixer are separate from the reserve mechanics.

The flat baseline deliberately permits equal-price outcomes that resolve FAIL. Different curve shapes can affect the cost of influencing a decision. Correct accounting does not prove economic stability, representative participation, manipulation resistance or project value.

Pinned peers authenticate identity and message integrity but cannot prevent all partitions, compromised peers, eclipse attacks or distributed resource attacks. Peer discovery and diversity are operator responsibilities. Account state, retained history and restart replay still grow.

Pre-mining deployment checks found that a genesis-time ASERT anchor counted time spent waiting before any miner joined. The corrected rule anchors each branch at its first mined block. Derived entry metadata carries that anchor through forks and is reconstructed on reopening; economic time and issuance rules are unchanged. This changes difficulty validation, so all three nodes of the existing height-zero test chain must receive the correction before mining begins. It is not a compatible rolling update for an already-mined chain using the former rule. Pauses after mining has begun remain part of ASERT's elapsed time.

Browser wallets trust the serving origin; stored keys are unencrypted. Public transaction actions and senders remain visible. Mail verifies the publishing transaction signature locally before decrypting contents; inclusion and confirmation counts still depend on the connected node. It does not hide the ledger, and static-key compromise can expose historical mail. A mixer custodian learns its deposit-to-payout mapping and can steal deposited funds.

Tests and source review are not independent security certification. Dependency-advisory matching and its limitations are recorded in [VALIDATION.md](VALIDATION.md); no long-duration adversarial-network certification is claimed. Deployment identity and chain receipts are distinct from local test results.
