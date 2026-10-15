# Local testnet

A fresh launch creates a distinct configuration and database.

```powershell
.\Start-Testnet.ps1 -Fresh -NoBrowser
```

The launcher records its executable, PID, UTC start ticks, listeners, config and keys in a manifest under the chosen data directory. Choose a different `-BasePort` or `-DataRoot` for an isolated test. Normal launch does not preload server wallets; visitor wallets live in the browser. `-SeedWallets` is an explicit option for automated local tests. It has no effect on browser storage.

```powershell
.\Stop-Testnet.ps1
.\Start-Testnet.ps1 -NoBrowser
```

Stopping verifies the owned process identities and preserves files. Resuming reuses the saved chain. `-Fresh` creates a distinct network identity. Keep backups of wallet keys independently of chain data. Never point disposable test directories or cleanup scripts at a live chain.

## Presets and phases

`config/devnet.json`, `config/testnet.json` and `config/slow-testnet.json` are development presets. They start with a 15-second mining target, 16 KiB block-byte and block-weight limit; transactions use the available block capacity. Decisions last 32, 16 and 240 blocks respectively. Each preset starts with a 10% per-block price-change limit. Auction lead and rest use scheduled seconds; expiry and confirmation depths use blocks. These are development choices, not production guarantees.

Each preset starts with an empty reserve and a Rest phase before the first proposal auction. A first deposit starts a flat curve at the configured share scale. Mining and Stash trading continue through rest, auction and governance. Bounded CLI mining can check local block propagation. External ASIC connections use node-level Stratum settings.

Production rules issue one atom per whole petahash of expected work in each block, discarding smaller fractions. Easy local blocks can issue zero atoms and cannot quickly fund wallet tests. Losing work is unpaid. Timestamp ASERT uses a 900-second half-life, 11-header median and 120-second future allowance. Its anchor is the first mined block of each branch; waiting before mining begins does not lower difficulty. Governance can set a positive whole-second target interval, subject to representable clocks and deadlines. The economic clock advances by the parent's target interval per block for auction lead and rest. Decision length remains a count of blocks when the interval changes. Actual wall time remains dependent on mining; signed transaction expiry and confirmation counts remain height-based.

## Wallet and governance

Create/import a wallet or add a watch-only account on the Wallet page. Back up keys privately. Payments displays an exact recipient amount, automatic minimum quote and exact signed fee. The complete fee is split by the governed miner share, initially 50%; revenue receives the remainder.

During a decision, holdings are alternatives. Trade Stash on PASS or FAIL directly. Shared payments and fees must fit both cash balances. The wallet shows the smaller available payment balance and separate outcome holdings; never add the alternatives. Each block counts for PASS only when its parent closing quote beats FAIL by the frozen margin. A strict majority of the full decision block count is required. PASS sets aside the full grant at decision opening, using waiting revenue first and then reserve. It pays every listed recipient once if PASS wins. Parameter changes activate after rest.

Stash orders in each block clear together at one execution price per world. The price-change bound can cause partial or zero fills; unused input stays in the account. Fees require existing cash. Every transaction signs a recent block hash and defaults to a two-block lifetime after that block. The anchor must remain on the chain used for inclusion. Signing provides no minimum-output guarantee.

Chat is a feed of public transaction data. Mail encrypts a message in any transaction's attached data; its standalone composer uses a self-payment. Explorer and Network are read-only views available without a wallet.

## Repeat isolated checks

Funded integration tests require an explicitly separate build and configuration. Build with `cargo build --release --locked --features test-fixtures --target-dir target/fixtures`. Copy a development configuration into a disposable test directory and set `test_work` to `true`. That flag is part of the chain identity. It enables one atom per expected hash for fast tests; it does not represent production issuance. A normal build rejects that configuration. Never deploy the fixture build or mix its chain data with a normal network.

```powershell
.\Start-Testnet.ps1 -Fresh -SeedWallets -NoBrowser -BasePort 28480 -DataRoot .\data\audit -Executable .\target\fixtures\release\hashstash.exe -Config <explicit-fixture-config>
python .\scripts\test_network.py <manifest-path> --report <report-path>
```

The committed presets and the ordinary launcher use `test_work: false`. `-SeedWallets` imports fixture wallets; it neither creates funds nor changes issuance. Process reports label accelerated tests separately, and normal-build checks verify zero issuance below one petahash. A report from accelerated testing is not evidence of real mining delivery or production reward amounts.

The network check deliberately transacts and mines on that selected local fixture. It tests supply, fees, Stash, revenue, grants, auctions, partial fills, block-majority decisions, external Stratum headers, relay and reorganization. Its temporary fork process stops afterward; stop the three fixture nodes using their saved manifest when done. The [validation guide](VALIDATION.md) describes the other checks. Use these scripts only with the disposable fixture created for them.

The load check defaults to 64 transactions per wave, which fits the standard 16 KiB preset. Its setup funds all fees and every input in a complete wave before submitting them. Even a self-payment cannot reuse its returned input within the same block. Larger waves require enough configured capacity; `--transactions-per-wave` selects the test workload.
