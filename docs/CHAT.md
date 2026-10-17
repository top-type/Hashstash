# Chat

Chat is a read-only feed of public text attached to ordinary transactions. Add a message in the **Message** field while sending hashes, trading stash, supporting a proposal, or performing another transaction. The transaction keeps its normal purpose, recipient, amount and fee; displaying its text requires no extra payment and introduces no message transaction type.

Open **Chat** to read without a wallet. Each entry links to its signed transaction and author and identifies the action that carried it. Confirmed entries appear in chain order, with pending messages shown separately. Muting an address affects only this browser and network. Chat has no separate composer or signing flow.

## Public text

The Message input encodes text as UTF-8 bytes in the signed transaction `data` vector. Leaving it empty attaches no data. Advanced hexadecimal input remains available for exact binary bytes; the CLI and RPC continue to use `--data-hex` and `data_hex` respectively. The complete signature covers those bytes together with the operation, amounts, fees, nonce, anchor block and lifetime.

The feed accepts nonblank valid UTF-8 without control characters other than line breaks, carriage returns and tabs. Text is blank when every character is Unicode White_Space or Default_Ignorable_Code_Point (for example a byte-order mark, zero-width space, joiner, variation selector, bidi control, Hangul filler or tag character). The node (`src/chat.rs`) and the browser feed (`ui/chat.js`) use the same literal range table, so such text is never indexed. The complete signed transaction, including its operation and signature, must fit the current block’s byte and weight capacity. Data contributes to the normal transaction weight and fee. Arbitrary binary data remains valid transaction data but is not displayed as a public text message.

Messages are permanent public chain data. The website renders them using plain text, never HTML or executable content. Explicit bidi embeddings, overrides and isolates (U+202A–U+202E, U+2066–U+2069) are shown as visible `‮`-style escapes, so a message cannot display in a different order from its signed text. The browser validates every returned record. A malformed record, for example from an older index or another node, is skipped and counted in the status line instead of hiding the rest of its page.

The displayed author comes from the validated transaction sender and is the only sender identity; there is no name registry. The label omits the network prefix that every address shares and shows the first 10 key-data characters and the 6 checksum characters (`hsh…` + 10 + `…` + 6), as the wallet does, so a lookalike costs about 2⁸⁰ work rather than matching a checksum. The full address is in the label's tooltip and opens in the Explorer. A name or persona supplied in message text grants no identity, and the **Automated** badge is a self-description, not a verified sender.

Versioned encrypted-mail envelopes are excluded from the text feed, including malformed or unknown versions under their reserved prefix. Mail stays in its dedicated encrypted view. Proposal explanations use plain UTF-8 and appear in the feed; the proposal view additionally checks that the text matches its signed description commitment. The feed's attribution proves who attached text, not that every claim in it is true or that arbitrary proposal text matches that commitment. Public messages and proposal explanations need no tagged format or JSON wrapper.

## Read-only feed API

```json
{"jsonrpc":"2.0","id":1,"method":"explorer_chat","params":{"limit":20}}
```

The method accepts only `limit` (1–50, default 20) and optional `cursor`. Pass a returned `next_cursor` unchanged to fetch older canonical messages. API pages are newest first; the website displays loaded confirmed messages in chain order. Responses include the Explorer context (`chain_id`, `tip`, `height`, `state_root`), `available`, `ready`, `indexed_height`, `message_bytes`, canonical `items`, separate `pending`, and `next_cursor`. `message_bytes` reports the current governed transaction capacity for composing new records. Historical messages remain readable when they exceed that current capacity, including after a governance reduction; the current limit is not retroactive. New transactions must fit the current block capacity, including operation and signature overhead.

Entries contain `txid`, `sender`, `kind`, `text`, `status`, `height`, `block_hash`, `position`, and `confirmations`. `recipient`, `amount`, and `asset` describe the underlying action when applicable; an absent amount is not a zero-value payment. Amounts remain raw integer atom strings, with their asset identifying hash or stash units. Pending entries have null inclusion fields and zero confirmations. Each canonical and pending list is bounded by the requested limit.

The rebuildable Explorer index follows the canonical chain. If it has not reached the current tip, the response reports that it is updating. A reorganization can remove confirmed messages; pending transactions can expire or disappear without inclusion. Mining is required for confirmation. The feed orders by canonical block height and transaction position. Mining timestamps do not change that ordering.

## Automated demo activity

Optional automated-demo runners attach plain UTF-8 text to their explicitly budgeted ordinary transactions. Their messages remain visibly labelled automated and limited to 512 bytes. The public feed does not expand their funding, cadence, account or signing permissions.

## Private messages

Use [Mail](MAIL.md) for an encrypted subject and body addressed to another account. Mail encrypts in the browser and attaches ciphertext to transaction data. Its standalone composer uses a self-payment. Choose an encrypted attachment to include mail with another transaction; plain text in a Message field is public.
