# Local testnet

The maintained presets and launcher use Hashstash 0.36.0 protocol 26. A fresh launch creates a distinct configuration and database.

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

`config/devnet.json`, `config/testnet.json` and `config/slow-testnet.json` are current-only validated development presets. They start with a 15-second mining target, 16 KiB block-byte and block-weight limit; transactions use the available block capacity. Phase durations are scheduled seconds; transaction expiry and confirmation depths remain block counts. The slow preset makes governance phases longer; none of the presets promises production safety.

Each preset starts with an empty reserve and an ordinary Rest phase. Account hashes stay spendable until their owner deposits or spends them. A first deposit starts a flat curve at the configured share scale. Mining and Stash trading continue through rest, auction and governance. The browser never starts CPU mining. For isolated easy-target tests, operators can use explicitly bounded CLI mining; external ASIC connections use node-level Stratum settings.

Each canonical block earns its target's expected-work subsidy. Losing work is unpaid. Timestamp ASERT uses a 900-second half-life, 11-header median and 120-second future allowance. Its anchor is the first mined block of each branch; waiting before mining begins does not lower difficulty. Governance can change the target interval from 1 through 60 seconds. The economic clock advances by the parent's target interval per block, preserving nominal phase durations and grant-budget periods as the interval changes. Actual wall time remains dependent on mining; signed transaction expiry and confirmation counts remain height-based.

## Wallet and governance

Create/import a wallet or add a watch-only account on the Wallet page. Back up keys privately. Send displays an exact recipient amount, automatic minimum quote and exact signed fee. The complete fee is split by the governed miner share, initially 50%; revenue receives the remainder.

During a decision, holdings are alternatives. Trade Stash on PASS or FAIL directly. Shared payments and fees must fit both cash balances. The wallet shows the smaller available payment balance and separate outcome holdings; never add the alternatives. Full-window price averages determine the result. PASS sets aside the full grant at decision opening, using waiting revenue first and then reserve. It pays the recipient once if PASS wins. Parameter changes activate after rest.

Chat is a feed of public transaction data. Mail encrypts a message in any transaction's attached data; its standalone composer uses a self-payment. Explorer and Network are read-only views available without a wallet.

## Repeat isolated checks

```powershell
.\Start-Testnet.ps1 -Fresh -SeedWallets -NoBrowser -BasePort 28480 -DataRoot .\data\audit
python .\scripts\test_network.py <manifest-path> --report <report-path>
```

The network check deliberately transacts and mines on that selected local fixture. It tests supply, fees, Stash, revenue, grants, auctions, outcome trading, parameter activation, external Stratum headers, relay and reorganization. Its temporary fork process stops afterward; stop the three fixture nodes using their saved manifest when done. [Validation](VALIDATION.md) describes completed checks. These checks do not authorize mining or claims against a cloud experiment.
