# Recipient-hidden encrypted mail

Mail is a browser application over signed transaction data. Any valid transaction carrying a mail envelope in its signed `data` bytes can carry an encrypted message, independently of its public action. A payment may carry private instructions to its payee, and a Stash trade, proposal or other action may carry mail for any chosen key. The standalone Mail composer uses a positive `TransferExact` **to itself**, returning one raw atom to the sender and paying the ordinary network fee. That convenience sends no coins to the message recipient. There is no new consensus operation or account field.

## Discovery

Every Mail client reads the same bounded, chronological `explorer_mail` stream. Mail discovery requests contain no account address or recipient filter. This does not make all wallet traffic anonymous: ordinary account and snapshot queries still identify selected wallet keys to the connected node. Before decryption, the browser verifies the canonical signed transaction and its BIP340 signature, checks the transaction ID and chain, and binds the feed’s sender, nonce, ciphertext and public operation to those signed bytes. Missing or invalid signatures stop the page without advancing the saved cursor. It then attempts authenticated decryption locally and displays only successful messages. Wrong-key decryption failures are ordinary and silent. Watch-only accounts cannot discover incoming messages; they can prepare outgoing ciphertext for offline signing. The cold signer verifies the public transaction action, fee and ciphertext but cannot inspect the hidden message or intended recipient.

Scanning runs only while Mail is open with a local signing wallet. It uses bounded pages, pauses after 100 candidate envelopes, and offers Continue scan. Clear saved mail scan removes the current account’s checkpoint and cached ciphertext. Each browser stores an atomic checkpoint and the signed public transaction bytes of successfully opened messages for each chain and account; plaintext and keys are never written to the Mail cache. Restoring the cache rechecks each transaction signature and derives sender, nonce and ciphertext from the signed record before decryption. Unsigned cache checkpoints are not reused. The saved canonical anchor is checked with the connected node before restoration. The cache is limited to 256 messages and 2 MiB. If capacity or browser storage is exhausted, the last complete checkpoint is retained and the UI explains that later progress exists only for this visit. Local cache metadata reveals which ciphertext the local account opened to anyone with access to browser storage. A canonical anchor check protects continuation across chain changes. Detached anchors restart discovery and remove messages from the replaced history. Wallet, node-session and network changes cancel work and clear visible plaintext and drafts. No creation height is guessed for imported or existing wallets; absent reliable birthday metadata the first scan starts at genesis. No discovered-message fetch, automatic read receipt, remote image or plaintext RPC is used.

## Privacy boundary

Recipient, subject and body are encrypted. There is no public message-recipient identifier or recipient-derived filter tag. Every supported envelope has the same byte length, hiding text length within this format. The publishing account, public transaction action (including any payment recipient and amount), fees, inclusion timing, network activity and fact that this is mail remain observable. The encrypted recipient is independent of the public payment recipient; choosing the same person for both can reveal that relationship. Replies, other payments or behavior can reveal relationships. Fees charge for chain use but do not guarantee spam prevention.

Ciphertext is permanent. Static account-key compromise exposes historical sent and received mail: this format **does not provide forward secrecy**. A compromised browser or wallet-serving site can expose keys/plaintext. Global scanning does not conceal a visitor's IP address or remove trust in RPC completeness. Local signature verification proves that the publishing key signed the transaction; it does not independently prove block inclusion, confirmation counts or the node’s reported canonical history. This application protocol uses established primitives but has not received an independent security audit. It makes no sender-anonymity claim.

## Envelope and encryption

The current format is `hashstash.mail/2\n` followed by compact canonical JSON with fields in this exact order:

```json
{"ephemeral_key":"<32-byte hex>","iv":"<12-byte hex>","ciphertext":"<1168-byte hex>","recipient_iv":"<12-byte hex>","recipient_key":"<48-byte hex>","sender_iv":"<12-byte hex>","sender_key":"<48-byte hex>"}
```

The recipient_key and sender_key fields are encrypted content-key wraps, not account public keys. All hex is lowercase. Duplicate/unknown/reordered fields, noncanonical JSON, invalid curve points and wrong lengths are rejected. Every supported envelope is exactly 2,793 bytes, within the 3,072-byte parser limit and ordinary transaction limit. Chat excludes mail envelopes.

The pinned Noble secp256k1 implementation handles curve operations; Web Crypto supplies HKDF-SHA256 and AES-256-GCM. ECDH normalizes private scalars to the even-Y representative of their BIP340 x-only key and lifts peer keys to even-Y points. The shared secret is the resulting point's 32-byte x coordinate.

Each message generates a fresh ephemeral scalar, random 32-byte content key and three random 12-byte GCM nonces. Canonical encrypted JSON is ordered recipient, subject, body. A two-byte big-endian JSON byte length precedes the JSON, with zero padding to exactly 1,152 bytes. AES-GCM adds a 128-bit authentication tag, producing 1,168 ciphertext bytes.

Subject is 1-96 UTF-8 bytes and body 1-768. Both need non-whitespace content. Newline/tab are accepted; malformed Unicode and other controls are rejected. JSON escaping must also fit the padded bound.

Common authenticated data concatenates UTF-8 `Hashstash/Mail/v2\0`, chain ID, sender public key, eight-byte little-endian transaction nonce and ephemeral public key. All public keys and the chain ID occupy 32 bytes. The intended recipient is absent. Browser nonces use canonical unsigned-64-bit decimal strings; nonce changes invalidate prepared ciphertext and fee quotes.

Each role (recipient or sender) derives ECDH with its public key and the ephemeral scalar. HKDF uses the chain ID as salt and `Hashstash/Mail/v2/<role>\0`, common authenticated data and the role's candidate public key as info. A decrypting client derives its candidate from its own key without a lookup. The resulting AES key wraps the content key using authenticated data equal to common data followed by `/<role>`. The sender wrap enables sent-mail recovery, including the encrypted recipient.

Decryption authenticates both wrap and content before validating canonical JSON, length, zero padding and the encrypted recipient. Readable UTF-8 never establishes delivery. The outer transaction signature authenticates the publisher and binds operation, fees, nonce, expiry and ciphertext. Different chain/sender/nonce invalidates decryption; ordinary account nonces prevent transaction replay.

## Discovery API

`explorer_mail` accepts limit (at most 50) and optional paired after/anchor. The after value is an ascending height:position cursor; anchor is the canonical block hash from the prior scan. Results contain confirmed messages, next_cursor, scan_cursor and chain/tip/readiness/indexed-height context. At the end scan_cursor advances through the indexed height, including empty blocks. Pending mail is not indexed for discovery. Address filters are rejected.

The derived index rebuilds from every canonical transaction whose data decodes as a supported envelope. Reorganizations remove detached entries. Records contain `raw` (the complete canonical signed transaction in hexadecimal), sender, signed ciphertext context, `kind` and the unwrapped public `operation`, with no mail-recipient field. A derived-index schema change rebuilds older rows from canonical history so every result includes the signed record; it does not change consensus or the mail envelope. A custodian can read a payment's amount and destination from `operation.TransferExact` and reconcile it with `explorer_transaction {"txid":"..."}`, which includes full ciphertext and confirmed/orphaned/pending status. Indexing is derived metadata: consensus still validates the transaction action and signature, and mail clients authenticate the encrypted contents locally.

## Verification

Browser crypto tests and an independent Node/OpenSSL implementation cover sender/recipient/self delivery, x-only scalar representatives, wrong keys, authenticated malformed padding, tampering, context binding and fixed lengths. UI tests cover global pagination, cancellation, account/reorg isolation, local directory resolution, ciphertext-only standalone mail and encrypted attachments on other transaction forms. Sender-verification tests use real signed records and reject unsigned rows, altered signatures, forged sender metadata, changed ciphertext and nonce, wrong transaction IDs and chains, and mismatched operations before decryption or checkpoint advancement. Cache tests cover account isolation, atomic checkpoints, storage bounds, obsolete unsigned checkpoints and restoration failures. Large-grant mail tests preserve complete signed records across bounded pages. A disposable localhost wire scenario uses published fixture keys to sign, confirm, globally discover and decrypt a real transaction. No production keys, faucet claims or rentals are used by these tests.

## Transaction attachments

Payment, Stash, proposal, support and refund forms offer public text or an encrypted message. Encrypted attachments use a full recipient address and never look that recipient up on RPC. Payment recipient and mail recipient are independent. During proposals, an encrypted message replaces the public description and its ciphertext is committed by the proposal description hash; the proposed action stays public. The transaction signature binds its public action and the complete ciphertext.

See [MIXER.md](MIXER.md) for encrypted instructions carried on a deposit to a custodian.
