# Wallets

## Wallet setup in the app

The network phase is visible beside the Hashstash name on every page. Click Rest, Auction or Governance to open its details. **Explorer → Network → Phase timing** shows the current schedule. Decisions last a fixed number of blocks, and each block counts once. Auction lead and rest use scheduled seconds, advanced by each block’s target interval. Wall-clock estimates depend on mining; a stopped chain does not advance.

A new browser profile, site, or network starts with no saved wallets or selected account. You can browse the network without creating a wallet. Open **Wallet** in the main navigation. The three actions are:

- **Create wallet** generates a random private key in the browser and selects the new hot wallet.
- **Import private key** accepts a 64-character hexadecimal key or a backup file, saves it in the browser, then selects that hot wallet.
- **Watch account** accepts a checksummed address or exported watch-only file. Its forms prepare unsigned transactions for signing elsewhere.

The menu at the top identifies each wallet by its address and shows its hash and stash balances. Hot and watch-only labels distinguish the signing mode. Governance begins with full holdings in each possible outcome. If PASS and If FAIL show those separate positions; only the winner survives. For payments shows the smaller cash balance before fees, already included in both outcome rows. These values are never added together. Selecting an entry switches accounts immediately. Importing a private key for an existing watch entry upgrades it to a hot wallet; adding a watched address never removes a saved key. Adding a wallet does not create an on-chain account. Its first funded payment or mining reward does that. Mining configuration belongs to node operators; normal wallet pages do not initiate mining or change its payout account.

Hash amounts in the browser wallet and cold signer use **hash**: one displayed hash is 10¹⁸ raw hash atoms. Amount fields accept a decimal hash amount, optionally followed by `hash`, with up to 18 decimal places. One raw atom is `0.000000000000000001 hash`. Stash quantities use **stash**: one displayed stash is 10³⁶ protocol share atoms. Stash fields accept a decimal, optionally followed by `stash`, with up to 36 decimal places. Prices show hash per stash. Both display denominations preserve the underlying balances and signed amounts. Mining work uses EH and hash rate uses EH/s, including small decimal values.

Use **Stash** to buy or sell during Rest and Auction. During an active decision, that page links to **Governance**, where the same controls trade the selected PASS or FAIL outcome. The curve graph stays on Stash with its own PASS/FAIL selector, independent of the trade form. It plots marginal price against stash supply, shows the current point on a funded curve, and shows the flat opening rate for an empty reserve. After the decision, the trade controls return to Stash. Wallet management, sending, and Explorer remain available throughout.

The Wallet page displays the selected address. **Copy address** is sufficient to add it through **Watch account** on another node: the address already encodes the public key and a network fingerprint. Send, grant proposals, and typed watch-account entry require a valid address for the current network. **Back up private key** opens the selected hot wallet's private key, with separate copy and download buttons. Import accepts that backup format as well as `{"secret":"…","public":"…"}` key files. Watch-only entries contain no private key and do not offer a private-key backup. Watch-only descriptor files can be imported explicitly.

Wallets and selection are stored in the browser profile's local storage, separately for each origin (scheme, host, and port) and chain ID. Other visitors and browser profiles have independent wallets. Tabs at the same origin share wallets and selection; switching accounts cancels a pending transaction for the previous selection. Node restarts do not affect these saved browser wallets. Changing sites or ports does not transfer them: import a backup or watch the address there.

Keys are stored unencrypted in the browser and never sent to the node. Back up each private key before clearing site data or changing browsers. Browser wallets require HTTPS or localhost, secure randomness, and Web Locks support. The browser verifies every prepared transaction byte against the intended chain, sender, nonce, block reference, lifetime, operation, fees, and data before signing. Only signed transaction bytes are broadcast. As with any web wallet, use a trusted site: code served by that origin can access its saved wallets. Watch-only mode keeps spending keys on the separate signer.

Optional node wallets use a separate local database. They are not exposed by the public listener or automatically copied into browser storage. See the node-wallet tools below.

## Sending HASH

**Amount** is exactly what the recipient receives. The wallet quotes the required minimum automatically, including account creation when needed, and signs the exact total fee. Optional extra defaults to zero and is added when constructing that quote. Sending 1 hash with a total fee of 0.000001 hash costs exactly 1.000001 hash. If the signed fee is below the required minimum when included, the whole transaction is rejected; a higher signed fee is paid in full.

The entire actual fee—mandatory minimum plus optional extra—follows the governed miner/revenue split, initially 50% each. The miner receives the whole-atom floor of its percentage and the revenue receives the remainder. Governance can select any whole percentage from 0% to 100%; an approved change becomes active after rest and both outcomes use the same active split.

The cold signer shows the exact recipient amount, exact fee and total debit. It cannot verify the current minimum rate or fee allocation without a node; the signed fee itself is fixed and paid in full.

Revenue is a hash buffer governed through proposals. The non-miner part of fees and winning proposal bids supply it. Grants use waiting revenue first and then reserve; revenue replenishes a nonflat reserve while preserving stash supply and marginal price. See [Reserve and revenue](RESERVE.md).

**Chat** reads public text attached to transactions, including ordinary payments, Stash trades and proposal support. Add text to the transaction's Message field and use its normal signing flow. Pending messages can expire or be displaced by a reorganization; mute settings affect only this browser. See [message format and feed](CHAT.md).

## Transaction data

Transaction forms offer an optional **Message** field. Enter public text, encoded as UTF-8, or choose advanced hexadecimal input for exact bytes such as `00ff80`. Leaving it empty attaches no data. The bytes are public, signed, and stored with the transaction. Proposal description is its single text attachment, with a matching signed SHA256 commitment. Mail has its own encrypted payload and never places its subject or body in this public field.

Data contributes to the transaction size and mandatory fee. The complete signed transaction, including operation, signature and data, must fit the block’s byte and weight capacity. Editing data refreshes the fee quote. Hot signing and watch-only preparation carry the same bytes; the cold signer displays the exact hex and byte count for review.

## Grant proposals

A grant can pay multiple recipients in one decision. Enter a positive amount for each distinct recipient and review both the individual payments and their combined total. The wallet puts the list in canonical key order; the signed list fixes who receives each amount.

The proposal fee includes 1,024 execution weight per payout, even for an existing account. This fee is paid when the proposal is included and is not refunded if it loses. It is separate from the auction bid, whose refund rules still apply. The complete signed proposal must fit the block’s remaining byte and weight capacity. There is no separate recipient-count or transaction-size setting. Maintained presets start with 16 KiB of block capacity; prepaid payout weight also uses it. Governance sets the capacity directly. Actual transactions still need room for their bytes and execution weight, and each interface has its own resource limits.

If the proposal reaches a decision, PASS escrows the combined amount. If PASS wins, all recipients receive their exact listed amounts together, without a settlement fee or a manual claim. If FAIL wins, nobody receives the grant. The full list is also shown by the offline signer.

## Governance settings

Choose a setting and enter its exact new value. **Target block interval** uses positive whole seconds. **Decision length** uses a positive whole number of blocks. **Auction lead** and **Rest** use whole seconds and allow zero. **Block capacity** uses weight and must be at least 1,024 to cover a new mining account. **Minimum fee rate** uses whole raw hash atoms per 1,024 weight and allows zero. **Miner fee share** is a whole percentage from 0 through 100. **PASS margin** and **Price change per block** accept percentages in exact 0.01% steps, including zero and values above 100%. The initial price-change limit is 10% per block.

Values must fit unsigned 64-bit integers; block capacity must also fit the implementation’s allocation representation. Clocks, heights and future phase boundaries must remain representable. A one-block decision resolves before any trade included in its closing block can influence the result. See the [parameter rules](CONSENSUS.md#transactions-and-parameters).

The active decision and rest period keep their frozen settings; approved changes affect the following cycle. Changing the target interval changes approximate wall time, not the number of blocks in an active decision. Minimum fee rate starts at one in the presets; block usage does not adjust it.

The browser preserves every digit of the entered integer or margin percentage when quoting, exporting and signing. Offline review shows the exact old and proposed values. Signing verifies the canonical bytes; the node checks the proposal against the current settings, phase and schedule before accepting it.

## Buying and selling Stash

Choose **Buy** and enter the hashes to spend, or **Sell** and enter the stash to sell. The form shows the estimated receipt and fee. **More options** contains the optional extra fee, order expiry and message. Buying deposits hashes into the reserve and creates stash; selling removes stash and returns hashes from the reserve. During Rest and Auction, orders use the shared reserve. During Governance, each order selects PASS or FAIL. A deposit into an empty reserve opens a flat curve at the configured share scale.

Orders included in the same block clear together at one execution price per world. The batch respects the governed price-change limit, initially 10% from the previous closing price. Excess input on a constrained side fills proportionally. An order can fill fully, partly, or not at all; unused input stays in your balance. Included orders do not remain open for another block. The preview is an estimate, and other orders in the same batch can change it. If the preview predicts a partial fill, the form shows the estimated unused amount. A zero fill still pays the fee if included.

Fees require hashes already available before the block begins, in both outcomes during a decision. Withdrawal proceeds and incoming transfers in that block cannot fund an order or its fee. Signing fixes the input, fee, block reference and lifetime; it does not guarantee an output. Explorer shows the actual fill and returned input.

## Cold signing

An address encodes the same public key with a network fingerprint and a Bech32m checksum. Changing address presentation does not create a different account or alter balances. See [address format](ADDRESSES.md) for the encoding and command-line tools. A public-key-only watch descriptor can be imported explicitly; the app derives its address for the selected network.

On the signing computer, run:

```powershell
.\Start-ColdWallet.ps1
```

This opens the separate `bin/hashstash-cold.exe` tool at `http://127.0.0.1:19580/`. It serves its own embedded interface and makes no node or peer connections. For offline signing, run it on a disconnected computer. No browser extensions or downloaded assets are needed.

The launcher uses the latest local network configuration when available; `-Config PATH` or `-ChainId HEX` selects it explicitly. On a disconnected computer, set the network by importing the small file exported from **Explorer → Network → Identity → Export network**, or paste its full chain ID into the signer's Network field. A known network is required to copy an address or export its watch-only file. Changing networks clears a pending transaction review. A transaction for a different configured chain is rejected.

For a different network, export its identity and a new watch-only descriptor. A private key can represent an account on either network, but its address and balances are specific to the selected chain. Creating a fresh testnet does not move funds from a saved network.

Private key is the default import mode: paste the original 64-character hexadecimal key or choose its backup file. It restores the same public key; the address additionally depends on the selected network. Choose Passphrase explicitly only for an account originally derived from that passphrase. Entering a private key as a passphrase derives a different account. Spaces, capitalization, and Unicode characters are significant. No password stretching or strength requirement is applied to passphrase derivation.

Choose **Export watch-only account** to save the watch-only descriptor. Copy only that file to the online computer. The passphrase and private key stay in the running signer; they are not saved by the tool. **Lock** clears the loaded key and pending review. Closing the browser does not stop the signer process. The launcher prints its process ID; ending that process closes the tool.

## Prepare, sign, broadcast

1. In the watch-only interface, use Payments, Stash, or Governance forms. **Prepare transaction** opens an unsigned export. Copy it or download its file.
2. Bring the export to the cold computer. Import or paste it, then choose **Review**. The tool decodes the transaction itself and displays every signed field. Hash amounts and fees use exact hash decimals with every signed raw hash atom preserved; Stash quantities use exact stash decimals with every share atom preserved. Raw share atoms remain in the collapsed technical details.
3. Choose **Sign transaction**, then copy or export the signed result.
4. On the online computer, open **Payments → Advanced → Broadcast signed transaction**, paste or import the signed result, and choose **Broadcast**.

The signer checks the transaction format and matching sender. It cannot check live balances, governance state, or whether its block reference, nonce or lifetime is still usable; the online node validates those when broadcasting and including the transaction. Editing or replacing the unsigned input clears its previous review. Signing consumes that review.

Both hot and watch-only wallets offer this broadcast control. Every transaction defaults to a two-block lifetime. Trades expose this under **More options → Order expiry**; other transactions use **Payments → Advanced → Transaction expiry**. Preparation signs the current block hash. For example, an anchor at block 100 with a lifetime of 2 permits inclusion in blocks 101 or 102. An expired transaction must be prepared and signed again. If a reorganization removes its anchor, the transaction is invalid on that branch. Expiry governs how long an order can wait for inclusion; the price limit applies separately to each block, so it can compound while an order waits.

## Advanced startup options

The testnet launcher's separate `miner.key` files back up the configured mining recipients and can be imported explicitly through the Wallet page. `Start-Testnet.ps1 -Fresh -SeedWallets` preloads the optional server wallet database for automated functional tests, not browser storage. The manifest records that choice. `Start-Devnet.ps1` uses the same opt-in seeding.

For direct startup, optional `run --wallet-key miner.key` or `run --watch-key <address>` seeds the optional server wallet database. The watch option also accepts a raw public key for command-line use. These flags cannot be combined. Without either flag, a fresh server wallet database has no entries. These options do not change a visitor's browser wallets or selection.

`Start-WatchOnly.ps1 -WatchFile .\hashstash-watch.json` remains available when a separate node is wanted. It creates its own database, seeds a watch entry, and joins the latest testnet on ports 20080–20082. Use `-Address '<address>'` instead of `-WatchFile` to enter an address directly. Use `-ManifestPath PATH` to select a saved testnet or `-Config PATH -Peer HOST:PORT` for another configured network; `-BasePort` selects unused listener ports. Its browser Wallet page has its own create/import/watch controls; add the watch address there explicitly. Normal wallet switching does not require this launcher. `Stop-WatchOnly.ps1` stops that separate node and preserves its files.

## Preparing and broadcasting from PowerShell

Use the online interface's ordinary action forms to prepare transactions in watch-only mode. The CLI supports the same operations through JSON files. CLI amount and fee arguments, RPC amount strings, configuration values, and transaction bytes retain integer hash atoms; the displayed hash conversion is a UI presentation rule. This example sends one raw atom (`0.000000000000000001 hash`). Replace `RECIPIENT_ADDRESS` with the intended recipient’s address on the same chain:

```powershell
'{"TransferExact":{"recipient":"RECIPIENT_ADDRESS","amount":"1"}}' | Set-Content -Encoding ascii .\operation.json
.\bin\hashstash.exe prepare --url http://127.0.0.1:19480/rpc --sender '<address>' --operation-file .\operation.json --extra-fee 0 --expiry-blocks 2 --out .\unsigned.json
```

For a manual offline round trip, choose an explicit longer `--expiry-blocks` value if two blocks will not leave enough time. Move `unsigned.json` to the cold tool, review and sign it, then bring its signed transaction hex back to the online machine. Paste that hex into Broadcast in the online interface, or save it as `signed.txt` and run:

```powershell
.\bin\hashstash.exe broadcast --url http://127.0.0.1:19480/rpc --raw-file .\signed.txt
```

Preparation fills the chain identity, next available nonce, exact total fee, operation, data, current block reference and lifetime. Add `--data-hex 00ff80` to `prepare`, `send`, or `transfer` to attach exact bytes; omit it for empty data. Use `--extra-fee` to add an amount to the quoted minimum, or `--fee` to choose the exact total instead; these options are mutually exclusive. The entire signed fee follows the governed split. The optional extra is not independently encoded in the signed record. Preparation includes transactions already pending at that node when choosing the nonce. Preparing does not reserve a nonce or send a transaction. Two unbroadcast preparations may therefore use the same nonce; only one can be executed. Prepare again if the account changes or the signed transaction expires.

`preparetransaction` accepts `{sender, operation, fee?, extra_fee?, anchor?, expiry_blocks?, nonce?, data_hex?}` with a direct operation. Specify either the exact `fee` or quote-builder `extra_fee`, never both. Omitted extra is zero, so an omitted fee quotes the required minimum. `expiry_blocks` defaults to 2 for every operation. If supplied, `anchor` must match the preparation snapshot’s tip hash; omission selects that tip. Browser forms supply the exact reviewed tip, nonce and lifetime, then verify them before signing. Absolute `expiry_height` input is rejected. Fee quotes expose `anchor`, `anchor_height`, `expiry_blocks` and the derived inclusive `expiry_height` for display; only the anchor and lifetime are signed. The response contains the unsigned export plus `fee_quote`; save only `format` and `body` for the strict offline export, as the CLI and browser do. The quote reports `fee`, `minimum_fee`, `account_creation_fee`, `extra_fee`, `weight`, `minimum_fee_rate`, `miner_fee`, `revenue_fee` and `miner_fee_percent`, plus operation identity and exact lowercase `data_hex`/`data_bytes`. `extra_fee` describes the difference between the exact fee and the quoted minimum. `broadcasttransaction` accepts `{raw}` and returns `transaction_id`. Normal consensus validation applies before acceptance.

The browser manager does not call server-wallet endpoints. It serializes local storage updates with Web Locks and checks a wallet revision before importing, selecting, exporting, signing or decrypting mail. Only public account details, quote/preparation requests, encrypted mail and signed transaction bytes go to the node. Normal wallet pages do not submit mining work or configure a mining recipient.

## Optional node-wallet tools

Opt-in node wallets store keys and selection beside the chain database: `chain.sqlite` uses `chain.wallets.sqlite`. These keys are separate from browser wallets. Import a key file or an explicitly exported private-key backup through Wallet to use that account in the browser.

The private loopback listener exposes session-authorized wallet tools: `GET /api/session` lists wallet IDs and the current revision; `POST /api/wallet/manage` with `action:"export"`, its `id`, and that `revision` returns a backup when authorized with the local session token in `X-Hashstash-Token`. Export only the intended key and keep the private listener private. These routes and the `/api/wallet` signer are unavailable on the public-web listener. Normal browser use never calls them.

## Recovery and transaction formats

`hashstash-passphrase-v1` derives a secp256k1 signing key as follows. Take the exact UTF-8 passphrase bytes with no trimming or Unicode normalization. Append a four-byte little-endian counter, initially zero. Let `tag` be SHA-256 of the UTF-8 text `Hashstash/Passphrase/v1`. The candidate key is SHA-256 of `tag || tag || passphrase || counter`. If the result is not a valid secp256k1 secret scalar, increment the counter and retry. Public keys use the existing BIP340 x-only representation. The scheme is independent of network identity; transactions themselves are bound to their chain ID. Empty input is rejected and the input resource limit is 4,096 UTF-8 bytes.

Watch-only exports with a selected network use `{"format":"hashstash-watch-v2","address":"<address>","public_key":"<64 hex>","chain_id":"<64 hex>"}`. The full chain ID, decoded address, and public key must agree. A `hashstash-watch-v1` descriptor contains only `public_key` and can be imported for the selected network. Neither format contains a signing key. Independent recovery vectors, including significant whitespace and composed/decomposed Unicode, are in `tests/data/passphrase-v1.json`. Their secrets are public test fixtures.

These names identify wallet file formats, not consensus versions. Transaction signatures bind the exact chain configuration.

An unsigned export is `{"format":"hashstash-unsigned-v1","body":"<hex>"}`. Its body is the canonical binary `TransactionBody`; no separate human-readable summary is trusted. The signer rejects unknown export fields, unsupported formats, invalid keys, mismatched outcome context, and noncanonical or trailing bytes. The body directly contains one operation, its exact `fee`, and a raw `data` vector, including an empty vector when no bytes are attached. No fee cap, separate extra or fee envelope is serialized. The chain ID binds the transaction to its network; the node checks live proposal eligibility, balances, nonce, anchor ancestry, lifetime and the required minimum fee. Reviewed values remain strings so large integers are displayed exactly.

Signed exports are canonical `Transaction` bytes in hexadecimal, with surrounding whitespace permitted. Compact integer/length encoding and the fixed 64-byte signature follow [CONSENSUS.md](CONSENSUS.md). A transaction ID is SHA256d of those signed bytes. The format helper bounds lengths by the actual supplied record and checks canonical encoding. Each node enforces the current block-byte and block-weight capacity and amount limits. Browser memory, HTTP response limits and peer frame representation remain practical interface constraints. The wallet container is `hashstash-unsigned-v1`; its body must match the selected network and binds its chain ID. A signature from another chain is invalid.

## Mail and outcome balances

Mail encrypts subject and message locally for the sender and recipient using their existing account keys. See [encrypted mail](MAIL.md) for the format, visibility and recovery limits. Chat remains public. Never paste a private key into a recipient field.

Every account takes part in both governance outcomes automatically. Each outcome has its own cash and stash. Deposit or withdraw directly in PASS or FAIL. Only the winning outcome survives. Ordinary payments debit both cash balances, so the payment ceiling is their minimum, before fees. Every fee needs hashes already available in both outcomes before the block begins. Withdrawal proceeds cannot pay that fee. Use max reserves the exact quoted fee and checks both cash balances. Outcome totals are alternatives, never a sum. Governance keeps personal holdings separate from public prices and reserves.

Outcome trading binds the transaction to the active decision and selected PASS or FAIL state.

Mining configuration and CPU testing are operator functions, outside the normal wallet interface; Explorer retains read-only node-work statistics.

Offline review accepts only the six current direct operations and their signed data. Unknown operation tags and malformed byte encodings are rejected before approval; the unsigned-size limit reserves space for the full signature so a reviewed transaction remains broadcastable.
