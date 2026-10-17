"use strict";

(() => {
    const $ = id => document.getElementById(id);
    const {parseAmount: parseAmount, formatHash: formatHash, formatExactHash: formatExactHash, formatHashrate: formatHashrate, formatExactWork: formatExactWork, exactInput: exactInput} = HashstashAmounts;
    const state = {
        session: null,
        managing: false,
        config: null,
        status: null,
        gov: null,
        account: null,
        pass: null,
        fail: null,
        balances: null,
        proposals: [],
        mempool: [],
        senderMempool: null,
        pendingNonce: null,
        ready: false,
        contextEpoch: 0,
        refreshing: false,
        miningInfo: null,
        submitting: false,
        broadcasting: false,
        trade: "deposit",
        tradeAll: false,
        quoteVersion: 0,
        quoteOutput: null,
        quoteFailed: false,
        sendQuote: null,
        sendFailed: false
    };
    const settings = {
        BlockBytes: [ "block_bytes", "Block capacity", "weight" ],
        Interval: [ "interval", "Target block interval", "seconds" ],
        Lead: [ "lead", "Auction lead period", "seconds" ],
        Rest: [ "rest", "Rest period", "seconds" ],
        DecisionBlocks: [ "decision_blocks", "Decision length", "blocks" ],
        MinerFeePercent: [ "miner_fee_percent", "Miner fee share", "%" ],
        PassMarginBps: [ "pass_margin_bps", "PASS margin", "bps" ],
        MinimumFeeRate: [ "minimum_fee_rate", "Minimum fee rate", "hash / 1,024 weight" ],
        MaxPriceChangeBps: [ "max_price_change_bps", "Price change per block", "bps" ]
    };
    const parameterAvailable = parameter => Object.hasOwn(settings, parameter);
    const titles = {
        overview: "Overview",
        wallet: "Wallet",
        stash: "Stash",
        send: "Payments",
        governance: "Governance",
        chat: "Chat",
        mail: "Mail",
        network: "Network",
        explorer: "Explorer",
        guide: "Guide"
    };
    let quoteTimer, toastTimer, sendTimer, rpcId = 0, sendVersion = 0, sessionVersion = 0;
    let privateBackup = null, importedPublic = null, browserWallet = null, walletChain = null, unsubscribeWallet = null, walletStorageError = "";
    const walletBalanceNodes = new Map;
    const proposalExplanations = new Map, explanationRequests = new Set;
    const feeForms = [ "trade", "send", "propose", "support", "refund", "mail" ];
    const feeQuotes = new Map, feeBuilders = new Map, feeTimers = new Map, feeVersions = new Map;
    const pendingFeeRefresh = new Set;
    class QuoteRefreshPending extends Error {}
    const faucet = {
        config: null,
        configChain: null,
        configAt: null,
        checking: false,
        lastKey: "",
        lastAt: 0,
        data: null,
        error: "",
        sequence: 0,
        busy: new Set,
        claims: new Map
    };
    function recipientKey(form) { return addressKey(form.elements.recipient.value); }
    const grantRows = [];
    function transactionByteLimit() {
        return BigInt(state.status?.settings?.block_bytes || 0);
    }
    let grantRowNumber = 0;
    function grantDraft() { return grantRows.map(row => [row.elements.recipient.value, row.elements.amount.value]); }
    function grantTotal(payments) { return payments.reduce((total,payment)=>total + BigInt(payment.amount),0n).toString(); }
    function updateGrantRows() {
        for (const row of grantRows) row.remove.disabled = grantRows.length === 1;
        try { const total = grantRows.reduce((sum,row)=>sum + BigInt(integer(row.elements.amount.value,"Grant amount")),0n); if(total >= 1n << 512n) throw new Error("Grant total is too large."); text("grant-total",formatExactHash(total)); }
        catch { text("grant-total","—"); }
    }
    function addGrantRow() {
        const number = ++grantRowNumber, container = append($("grant-payments"),"div","grant-payment"), ownerForm = $("propose-form");
        const recipientLabel = append(container,"label","","Recipient address"), recipient = append(recipientLabel,"input","");
        Object.assign(recipient,{name:`grant_recipient_${number}`,placeholder:"hsh…",autocomplete:"off",spellcheck:false,maxLength:256});
        const amountLabel = append(container,"label","","Amount · hash"), amount = append(amountLabel,"input","");
        Object.assign(amount,{name:`grant_amount_${number}`,placeholder:"0",inputMode:"decimal"});amount.dataset.exa="true";
        const remove = append(container,"button","small-link","Remove");remove.type="button";remove.setAttribute("aria-label",`Remove recipient ${number}`);
        const row = {id:`grant-row-${number}-form`,elements:{recipient,amount},ownerForm,remove,container};
        grantRows.push(row);
        for(const input of [recipient,amount])input.addEventListener("input",()=>{updateGrantRows();feeSoon(ownerForm);});
        remove.addEventListener("click",()=>{if(grantRows.length===1)return;grantRows.splice(grantRows.indexOf(row),1);container.remove();updateGrantRows();feeSoon(ownerForm);});
        updateGrantRows();return row;
    }
    async function grantPayments() {
        if(!grantRows.length)throw new Error("Add at least one recipient.");
        const merged = new Map();
        for(const row of grantRows){const recipient=recipientKey(row), amount=BigInt(integer(row.elements.amount.value,"Grant amount"));merged.set(recipient,(merged.get(recipient)||0n)+amount);}
        const payments=[...merged].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([recipient,amount])=>({recipient:hexBytes(recipient),amount:amount.toString()}));
        if(BigInt(grantTotal(payments)) >= 1n << 512n)throw new Error("Grant total is too large.");
        return payments;
    }
    const chat = typeof HashstashChat === "object" ? HashstashChat.create({
        rpc: rpc,
        amountText: amountText
    }) : null;
    const explorer = typeof HashstashExplorer === "object" ? HashstashExplorer.create({
        rpc: rpc,
        amountText: amountText
    }) : null;
    const mail = typeof HashstashMail === "object" ? HashstashMail.create({
        rpc: rpc,
        amountText: amountText,
        encodeAddress: address,
        recipientKey: () => recipientKey($("mail-form")),
        getIdentity: () => ({
            chain_id: state.status?.chain_id,
            sender: key(),
            nonce: nextNonce().toString(),
            wallet_id: state.session?.wallet_id,
            wallet_revision: state.session?.wallet_revision
        }),
        decrypt: (data, identity, expected) => browserWallet.decryptMail(data, identity, expected),
        verifySigned: (raw, expected) => HashstashBrowserWallet.verifySigned(raw, expected),
        onDraftChange: () => {
            feeSoon($("mail-form"));
            feedback($("mail-form"), "");
        }
    }) : null;
    const transactionMail = typeof HashstashTransactionMail === "object" ? HashstashTransactionMail.create({
        decodeAddress: addressKey,
        getIdentity: () => ({chain_id: state.status?.chain_id, sender: key(), nonce: nextNonce().toString(), wallet_id: state.session?.wallet_id, wallet_revision: state.session?.wallet_revision})
    }) : null;
    async function prepareTransactionData(form) {
        if (form.elements.data_format?.value === "private") {
            if (!transactionMail) throw new Error("Encrypted attachments are unavailable. Reload the page.");
            await transactionMail.prepare(form);
        }
    }
    function attachmentIdentity(form) { return JSON.stringify([form.elements.mail_recipient?.value,form.elements.mail_subject?.value,form.elements.mail_body?.value,nextNonce().toString()]); }
    const amountRenders = new WeakMap, listRenders = new WeakMap;
    function text(id, value) {
        const node = $(id), content = String(value);
        if (node && node.textContent !== content) {
            node.textContent = content;
            amountRenders.delete(node);
        }
    }
    function renderChanged(node, value) {
        const signature = JSON.stringify(value);
        if (listRenders.get(node) === signature) return false;
        listRenders.set(node, signature);
        return true;
    }
    function amountText(target, value) {
        const node = typeof target === "string" ? $(target) : target;
        if (!node) return;
        const content = String(value), units = /(^|[\s/])(hash|EH|stash)(?=$|[\s/])/g;
        if (amountRenders.get(node) === content && node.textContent === content) return;
        amountRenders.set(node, content);
        node.replaceChildren();
        let offset = 0;
        for (const match of content.matchAll(units)) {
            const start = match.index + match[1].length;
            start > offset && node.appendChild(document.createTextNode(content.slice(offset, start)));
            const unit = document.createElement("span");
            unit.className = "amount-unit " + (match[2] === "stash" ? "unit-stash" : "unit-hash");
            unit.textContent = match[2];
            node.appendChild(unit);
            offset = start + match[2].length;
        }
        offset < content.length && node.appendChild(document.createTextNode(content.slice(offset)));
    }
    function compactAmount(node, formatted) {
        node.textContent = formatted.replace(/ (?:hash|stash)$/, "");
        node.setAttribute("aria-label", formatted);
        amountRenders.delete(node);
    }
    function integer(value, label = "Amount", allowZero = false) {
        let raw;
        try {
            raw = parseAmount(value);
        } catch (error) {
            throw new Error(`${label}: ${error.message}`);
        }
        const n = BigInt(raw);
        if (!allowZero && n === 0n) throw new Error(`${label} must be greater than zero.`);
        return n.toString();
    }
    function stashInteger(value) {
        const raw = HashstashShares.parseAmount(value);
        if (BigInt(raw) === 0n) throw new Error("stash amount must be greater than zero.");
        return raw;
    }
    function stashNumber(id, value) {
        amountText(id, `${HashstashShares.formatAmount(value || "0")} stash`);
        $(id) && ($(id).title = `${HashstashShares.exactInput(value || "0")} stash`);
    }
    function safeInteger(value, label) {
        const raw = String(value ?? "").trim();
        if (!/^\d+$/.test(raw) || raw.length > 160) throw new Error(`${label} must be a whole number without a unit suffix.`);
        const n = BigInt(raw);
        if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} is too large for this form.`);
        return Number(n);
    }
    function jsonInteger(value) {
        const n = BigInt(value);
        if (n < 0n || n > 18446744073709551615n) throw new Error("Setting exceeds the supported integer range.");
        if (n <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(n);
        if (JSON.rawJSON) return JSON.rawJSON(n.toString());
        throw new Error("This browser cannot submit this large setting exactly.");
    }
    function hexBytes(value, label = "Public key") {
        const h = String(value ?? "").trim();
        if (!/^[0-9a-fA-F]{64}$/.test(h)) throw new Error(`${label} must have exactly 64 hexadecimal characters.`);
        return Array.from(h.match(/../g), x => parseInt(x, 16));
    }
    function hex(bytes) {
        if (!Array.isArray(bytes) && !ArrayBuffer.isView(bytes)) return String(bytes || "");
        const parts = [];
        for (let start = 0; start < bytes.length; start += 32768) parts.push(Array.from(bytes.slice(start, start + 32768), x => x.toString(16).padStart(2, "0")).join(""));
        return parts.join("");
    }
    function address(value = key()) {
        const publicKey = hex(value);
        return publicKey ? HashstashAddress.encode(publicKey, state.session?.address_hrp) : "";
    }
    function addressKey(value) {
        return HashstashAddress.decode(String(value ?? "").trim(), state.session?.address_hrp);
    }
    function short(value) {
        const s = hex(value);
        return s ? `${s.slice(0, 7)}…${s.slice(-5)}` : "—";
    }
    function shortAddress(value) {
        const full = address(value), start = full.lastIndexOf("1") + 1;
        return full ? `hsh…${full.slice(start, start + 10)}…${full.slice(-6)}` : "—";
    }
    function proposalShort(value) {
        // Proposers choose a free description commitment, so a 48-bit label
        // could be ground to match another proposal. Show 64 bits.
        const s = hex(value);
        return s ? `${s.slice(0, 10)}…${s.slice(-6)}` : "—";
    }
    function visibleControls(value) {
        // Explicit bidi embeddings, overrides and isolates in user-authored
        // text are shown as escapes so it cannot display out of signed order.
        return String(value).replace(/[\u202a-\u202e\u2066-\u2069]/g, c => `\\u${c.charCodeAt(0).toString(16)}`);
    }
    function commas(value) {
        return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
    function hashAmount(value) {
        return formatHash(String(value || "0"));
    }
    function settingValue(field, value, unit, exact = false) {
        if (field === "minimum_fee_rate") return `${formatExactHash(String(value))} / 1,024 weight`;
        if (unit === "bps") return `${fraction(value, 100, 2)}%`;
        if (unit === "%") return `${value}%`;
        if (unit === "seconds") return exact ? `${commas(value)} seconds` : duration(value);
        if (unit === "hashes") return exact ? formatExactHash(String(value)) : hashAmount(value);
        return `${commas(value)} ${unit}`;
    }
    function fraction(numerator, denominator, places = 6) {
        const n = BigInt(numerator || "0"), d = BigInt(denominator || "1");
        if (n === 0n || d === 0n) return "0";
        const whole = n / d, scale = 10n ** BigInt(places), tail = n % d * scale / d;
        if (whole === 0n && tail === 0n) return `<0.${"0".repeat(places - 1)}1`;
        return commas(whole) + (tail ? "." + tail.toString().padStart(places, "0").replace(/0+$/, "") : "");
    }
    function ratioValue(object) {
        return object ? formatHash(object.numerator, object.denominator) : "0 hash";
    }
    function markedAccountValue(data) {
        const cash = BigInt(data?.account?.ordinary || "0");
        const mark = data?.stash_value_hash || {
            numerator: "0",
            denominator: "1"
        };
        return {
            numerator: (cash * BigInt(mark.denominator) + BigInt(mark.numerator)).toString(),
            denominator: mark.denominator
        };
    }
    function number(id, value) {
        const node = $(id);
        if (!node) return;
        amountText(node, hashAmount(value));
        node.title = formatExactHash(String(value || "0"));
    }
    function rational(id, value) {
        amountText(id, ratioValue(value));
        $(id) && ($(id).title = "");
        if ($(id) && value) {
            const n = BigInt(value.numerator), d = BigInt(value.denominator);
            $(id).title = formatExactHash(n, d);
        }
    }
    function sharePrice(id, value) {
        const scaled = value ? {
            numerator: (BigInt(value.numerator) * chartShareUnit).toString(),
            denominator: value.denominator
        } : null;
        text(id, ratioValue(scaled).replace(/ hash$/, ""));
        $(id) && ($(id).title = `${scaled ? formatExactHash(scaled.numerator, scaled.denominator) : "0 hash"}/stash`);
    }
    function blockCount(value) {
        const count = BigInt(value) > 0n ? BigInt(value) : 0n;
        return `${commas(count)} block${count === 1n ? "" : "s"}`;
    }
    function protocolDuration(value) {
        return duration(value);
    }
    function duration(seconds) {
        const value = typeof seconds === "bigint" || typeof seconds === "string" ? BigInt(seconds) : BigInt(Math.ceil(seconds));
        const s = value > 0n ? value : 0n;
        if (s >= 86400n) return `${s / 86400n}d ${s % 86400n / 3600n}h`;
        if (s >= 3600n) return `${s / 3600n}h ${s % 3600n / 60n}m`;
        if (s >= 60n) return `${s / 60n}m ${s % 60n}s`;
        return `${s}s`;
    }
    function toast(message) {
        text("toast", message);
        $("toast").hidden = false;
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => {
            $("toast").hidden = true;
        }, 4500);
    }
    function alert(message) {
        text("global-alert", message || "");
        $("global-alert").hidden = !message;
    }
    function feedback(form, message, failed = false) {
        const node = form.querySelector(".form-feedback");
        if (!node) return;
        node.textContent = message;
        node.classList.toggle("error", failed);
    }
    // A submitted transaction can expire, or lose its anchor or decision in a
    // reorganization; the node then drops it without notice. Follow each
    // form's last submission by sender nonce until it leaves the pool.
    const submissions = new Map;
    function trackSubmission(form, id, sender, nonce) {
        submissions.set(form.id, {id: id, sender: sender, nonce: BigInt(nonce), misses: 0});
    }
    function followSubmissions(cleared) {
        for (const [formId, tracked] of submissions) {
            const form = $(formId);
            if (!form || tracked.sender !== key()) {
                submissions.delete(formId);
                continue;
            }
            const message = `Pending · ${short(tracked.id)}`;
            const shown = form.querySelector(".form-feedback")?.textContent;
            if (shown !== message && !(cleared && shown === "")) {
                // A newer action on this form replaced the indicator.
                submissions.delete(formId);
                continue;
            }
            if (BigInt(state.account?.account?.nonce || "0") > tracked.nonce) {
                submissions.delete(formId);
                feedback(form, `Mined or replaced · ${short(tracked.id)}`);
                continue;
            }
            if (ownPending().some(tx => hex(tx.body?.sender) === tracked.sender && BigInt(tx.body.nonce) === tracked.nonce)) {
                tracked.misses = 0;
                shown === message || feedback(form, message);
                continue;
            }
            // The snapshot lists bounded prefixes of the pool and of this
            // sender's rows, and a tip change briefly publishes an empty pool
            // before recovery: confirm twice.
            const truncated = Array.isArray(state.senderMempool) ? state.senderMempool.length >= 128 : Number(state.status?.mempool || 0) > state.mempool.length;
            if (truncated || ++tracked.misses < 2) {
                shown === message || feedback(form, message);
                continue;
            }
            submissions.delete(formId);
            feedback(form, `No longer pending · ${short(tracked.id)} expired or was invalidated by a reorganization. Prepare it again.`, true);
        }
    }
    // Node JSON carries u64 values (settings, proposal parameters, lifetimes)
    // that can exceed 2^53. Engines without JSON.parse source-text access get
    // those integer literals quoted first, so each arrives as the same exact
    // decimal string the source-text path returns instead of failing the
    // whole response.
    const jsonSourceText = (() => {
        try {
            let source = null;
            JSON.parse("1", (_key, value, context) => (source = context?.source, value));
            return source === "1";
        } catch {
            return false;
        }
    })();
    function quoteUnsafeIntegers(source) {
        return source.replace(/"(?:[^"\\]|\\.)*"|(?<![\d.eE+-])-?\d{16,}(?![\d.eE])/g, token => token[0] === '"' || Number.isSafeInteger(Number(token)) ? token : `"${token}"`);
    }
    async function exactJSON(response) {
        const source = await response.text();
        return JSON.parse(jsonSourceText ? source : quoteUnsafeIntegers(source), (_key, value, context) => {
            if (typeof value === "number" && Number.isInteger(value) && !Number.isSafeInteger(value)) {
                if (!context?.source || !/^-?\d+$/.test(context.source)) throw new Error("This browser cannot safely read a large numeric field from the node.");
                return context.source;
            }
            return value;
        });
    }
    async function rpc(method, params = {}) {
        const response = await fetch("/rpc", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...state.session?.token ? {
                    "X-Hashstash-Token": state.session.token
                } : {}
            },
            body: JSON.stringify({
                jsonrpc: "2.0",
                id: ++rpcId,
                method: method,
                params: params
            }),
            cache: "no-store"
        });
        if (!response.ok) throw new Error(`Node request failed (${response.status}).`);
        const data = await exactJSON(response);
        if (data.error) throw new Error(data.error.message || "The node rejected this request.");
        return data.result;
    }
    function activeDecision() {
        return state.gov?.phase?.Governance || null;
    }
    // The block after the decision's last tip resolves it in prepare_block,
    // before any of its transactions, so a conditional trade prepared now can
    // never be included. This is the same height test consensus applies.
    const tradingClosedMessage = "Trading is closed: the decision resolves at the start of the next block, before its transactions.";
    function decisionClosing() {
        const decision = activeDecision();
        return !!decision && !!state.status && BigInt(state.status.height) - BigInt(decision.started_height) + 1n >= BigInt(decision.blocks);
    }
    // consensus::pass_beats_fail: one block's exact PASS/FAIL comparison.
    // Mirrors consensus::pass_beats_fail: a world without Stash has no
    // market price, so a block with either world empty adds no PASS lead.
    function passBeatsFail(pass, fail, marginBps) {
        const passShares = BigInt(pass.shares), failShares = BigInt(fail.shares);
        if (passShares === 0n || failShares === 0n) return false;
        return BigInt(pass.curve_mass) * failShares * 10000n > BigInt(fail.curve_mass) * passShares * (10000n + BigInt(marginBps));
    }
    function phaseName() {
        return state.gov ? Object.keys(state.gov.phase)[0] : "Auction";
    }
    function auctionTimeout() {
        const fixed = BigInt(state.config.auction_timeout), lead = BigInt(state.gov.frozen.lead) + BigInt(state.gov.frozen.interval);
        return lead > fixed ? lead : fixed;
    }
    function phaseTiming() {
        if (!state.ready || !state.gov) return null;
        const name = phaseName(), phase = state.gov.phase[name], clock = BigInt(state.gov.clock);
        const interval = BigInt(state.status.settings.interval);
        const remaining = deadline => deadline > clock ? deadline - clock : 0n;
        const blocks = value => (value + interval - 1n) / interval;
        let seconds, total, end, summaryEnd = "remaining";
        if (name === "Auction") {
            const timeout = remaining(BigInt(phase.opened) + auctionTimeout());
            const lead = phase.leader ? remaining(BigInt(phase.lead_since) + BigInt(state.gov.frozen.lead)) : null;
            // A leader opens its decision when its lead completes or, at the
            // latest, at the timeout; only an auction without one times out.
            const wins = lead !== null && blocks(lead) <= blocks(timeout);
            seconds = wins ? lead : timeout;
            total = wins ? BigInt(state.gov.frozen.lead) : auctionTimeout();
            end = lead !== null ? "decision" : "auction timeout";
            summaryEnd = lead !== null ? "to decision" : "to timeout";
        } else if (name === "Governance") {
            const totalBlocks = BigInt(phase.blocks), elapsed = BigInt(state.status.height) - BigInt(phase.started_height);
            const completedBlocks = elapsed < 0n ? 0n : elapsed > totalBlocks ? totalBlocks : elapsed;
            const count = totalBlocks - completedBlocks;
            return {seconds: count * interval, blocks: count, total: totalBlocks * interval, totalBlocks, completedBlocks,
                estimate: `~${duration(count * interval)}`, end: "resolution", summary: `${blockCount(count)} remaining`,
                detail: `${blockCount(count)} at the ${interval}s target.`};
        } else {
            if (name !== "Rest") return null;
            seconds = remaining(BigInt(phase.until));
            total = BigInt(state.gov.frozen.rest);
            end = "next auction";
        }
        const count = blocks(seconds), totalBlocks = blocks(total), estimate = `~${duration(count * interval)}`;
        const completedBlocks = totalBlocks > count ? totalBlocks - count : 0n;
        return {
            seconds: seconds,
            blocks: count,
            total: total,
            totalBlocks: totalBlocks,
            completedBlocks: completedBlocks,
            estimate: estimate,
            end: end,
            summary: `${blockCount(count)} ${summaryEnd}`,
            detail: `${blockCount(count)} at the ${interval}s target.`
        };
    }
    function networkPhaseView() {
        const height = state.ready ? state.status?.height : null, heightLink = $("sidebar-height");
        const hasHeight = height !== null && height !== void 0;
        $("network-status").dataset.ready = String(state.ready && hasHeight);
        text("sidebar-height-value", hasHeight ? commas(height) : "—");
        heightLink.setAttribute("aria-label", hasHeight ? `Block height ${commas(height)}. Open block in Explorer.` : "Block height unavailable");
        heightLink.title = hasHeight ? "Open current block in Explorer" : "Waiting for a node snapshot.";
        if (hasHeight) {
            heightLink.href = `#explorer?block=${encodeURIComponent(height)}`;
            heightLink.removeAttribute("aria-disabled");
            heightLink.removeAttribute("tabindex");
        } else {
            heightLink.removeAttribute("href");
            heightLink.setAttribute("aria-disabled", "true");
            heightLink.setAttribute("tabindex", "-1");
        }
        const name = state.ready && state.gov ? phaseName() : null;
        const label = {
            Auction: "Auction",
            Governance: "Governance",
            Rest: "Rest"
        }[name] || "Unavailable";
        text("network-phase-label", label);
        const timing = phaseTiming();
        text("network-phase-time", timing?.summary || "");
        $("network-phase-time").hidden = !timing;
        const detail = timing ? `${timing.detail} ${blockCount(timing.blocks)} to ${timing.end}.${hasHeight ? ` Block ${commas(height)}.` : ""}` : "Phase unavailable";
        const progress = $("network-phase-progress"), showProgress = !!timing && timing.totalBlocks > 0n;
        progress.hidden = !showProgress;
        if (showProgress) {
            // Only the canonical logical clock advances this bar, in block steps.
            progress.value = Number(timing.completedBlocks * 10000n / timing.totalBlocks) / 100;
            progress.setAttribute("aria-label", `${label} progress`);
            progress.setAttribute("aria-valuetext", `${blockCount(timing.completedBlocks)} completed of ${commas(timing.totalBlocks)}. ${blockCount(timing.blocks)} to ${timing.end}.${hasHeight ? ` Block ${commas(height)}.` : ""}`);
            progress.title = detail;
        } else {
            progress.removeAttribute("value");
            progress.removeAttribute("aria-valuetext");
            progress.title = "";
        }
        $("network-phase").title = detail;
        $("network-phase").href = name ? "#governance" : "#network";
        $("network-phase").setAttribute("aria-label", `Network phase: ${label}${timing ? `. ${timing.summary}` : ""}`);
        overviewPriceView();
        miningView();
    }
    function key() {
        return state.session?.public_key || "";
    }
    function outcomeCash(data) {
        return data?.account?.["ordinary"] ?? "0";
    }
    function snapshotAccount(data) {
        // An explicit null is a successfully queried address with no balance.
        // A missing response is still unknown.
        return data === null ? null : data?.account;
    }
    function paymentCash(pass, fail, ordinary) {
        const cash = account => account === null ? "0" : account?.ordinary ?? null;
        if (!activeDecision()) return cash(ordinary);
        const passCash = cash(pass), failCash = cash(fail);
        if (passCash === null || failCash === null) return null;
        const a = BigInt(passCash), b = BigInt(failCash);
        return (a < b ? a : b).toString();
    }
    function checkOutcomeFunds(operation, exactFee) {
        if (!activeDecision()) return;
        if (!state.pass?.account || !state.fail?.account) throw new Error("Outcome balances are unavailable. Refresh before spending.");
        const fee = BigInt(exactFee), [kind, value] = Object.entries(operation)[0];
        if (![ "TransferExact", "Deposit", "Redeem" ].includes(kind)) return;
        for (const [name, data] of [ [ "Pass", state.pass ], [ "Fail", state.fail ] ]) {
            let available = BigInt(data.account.ordinary), debit = fee;
            kind === "TransferExact" && (debit += BigInt(value.amount));
            kind === "Deposit" && value.outcome === name && (debit += BigInt(value.amount));
            if (available < debit) throw new Error(`${name.toUpperCase()} balance cannot cover this transaction and its fee. Payments and fees need hashes in both outcomes.`);
        }
    }
    function walletIdentity() {
        return JSON.stringify([ state.contextEpoch, state.session?.token, state.session?.address_hrp, state.session?.wallet_id, state.session?.wallet_revision, key() ]);
    }
    function context(outcome) {
        const decision = activeDecision();
        if (outcome && !decision) throw new Error("This conditional outcome is no longer active. Refresh and try again.");
        return {
            decision: outcome ? decision.id : null,
            outcome: outcome || null
        };
    }
    function formValues(form) {
        return Object.fromEntries(new FormData(form));
    }
    function transactionData(form) {
        if (form.id === "mail-form") {
            if (!mail) throw new Error("Mail is unavailable on this network.");
            return {
                data_hex: mail.data()
            };
        }
        if (form.elements.data_format?.value === "private") {
            if (!transactionMail) throw new Error("Encrypted attachments are unavailable.");
            return {data_hex: transactionMail.data(form)};
        }
        if (form.id === "propose-form" && typeof HashstashProposalData === "object") return {
            data_hex: HashstashProposalData.encode(form.elements.description.value)
        };
        if (form.id === "propose-form") throw new Error("Proposal message encoder is unavailable. Reload the page.");
        const format = form.elements.data_format.value;
        if (format === "text") {
            const message = form.elements.data_text.value;
            if (!message.trim()) return {};
            if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(message)) throw new Error("Message contains invalid Unicode.");
            if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/u.test(message)) throw new Error("Message contains unsupported control characters.");
            const bytes = (new TextEncoder).encode(message);
            if (bytes.length > transactionByteLimit()) throw new Error("Message exceeds the block capacity.");
            return {
                data_hex: hex(bytes)
            };
        }
        if (format !== "hex") throw new Error("Choose text or hexadecimal data.");
        const data = form.elements.data_hex.value.trim();
        if (!data) return {};
        if (!/^(?:[0-9a-fA-F]{2})+$/.test(data)) throw new Error("Data must contain pairs of hexadecimal digits, without a prefix or spaces.");
        if (data.length / 2 > transactionByteLimit()) throw new Error("Data exceeds the block capacity.");
        return {
            data_hex: data.toLowerCase()
        };
    }
    function transactionDataView(form) {
        if (!form.elements.data_format) return;
        const enabled = true, raw = form.elements.data_format.value === "hex", encrypted = form.elements.data_format.value === "private";
        const prefix = form.id.replace("-form", "");
        const privateFields = $(prefix + "-private-fields");
        if (privateFields) privateFields.hidden = !encrypted;
        for (const field of ["mail_recipient","mail_subject","mail_body"]) if (form.elements[field]) { form.elements[field].disabled = !encrypted; form.elements[field].required = encrypted; }
        if (form.id === "propose-form") { form.elements.description.disabled = encrypted; $("proposal-description-field").hidden = encrypted; $("proposal-description-help").hidden = encrypted; return; }
        form.elements.data_format.disabled = !enabled;
        form.elements.data_text.disabled = !enabled || raw || encrypted;
        form.elements.data_hex.disabled = !enabled || !raw;
        $(form.id.replace("-form", "-message-field")).hidden = raw || encrypted;
        $(form.id.replace("-form", "-hex-field")).hidden = !raw;
        if (enabled) {
            for (const [field, multiplier] of [["data_text", 1n], ["data_hex", 2n]]) {
                const limit = transactionByteLimit() * multiplier;
                if (limit <= 2147483647n) form.elements[field].maxLength = Number(limit);
                else form.elements[field].removeAttribute("maxlength");
            }
        }
    }
    function append(parent, tag, className, content) {
        const node = document.createElement(tag);
        className && (node.className = className);
        content !== void 0 && (node.textContent = content);
        parent.appendChild(node);
        return node;
    }
    function appendAmount(parent, tag, className, content) {
        const node = append(parent, tag, className);
        amountText(node, content);
        return node;
    }
    function modeButtons() {
        const enabled = state.ready && !!state.session && !!state.account && !state.submitting && !state.managing;
        document.querySelectorAll(".wallet-action").forEach(button => {
            button.disabled = !enabled || button.classList.contains("auction-action") && phaseName() !== "Auction";
            button.dataset.hotLabel ||= button.textContent;
            const label = button.id === "trade-submit" ? state.trade === "deposit" ? "Buy stash" : "Sell stash" : button.dataset.hotLabel;
            button.textContent = state.session?.wallet_enabled ? label : "Prepare transaction";
        });
        $("broadcast-submit").disabled = !state.ready || !state.session || state.broadcasting;
        const managerEnabled = !!state.session && !!browserWallet && !walletStorageError && !state.managing && !state.submitting;
        document.querySelectorAll(".wallet-manage-action,[data-wallet-form]").forEach(button => {
            button.disabled = !managerEnabled;
        });
        $("account-select").disabled = !managerEnabled || !state.session?.wallets?.length;
        $("export-private").disabled = !managerEnabled || !state.session?.wallet_enabled;
        for (const id of [ "copy-key", "copy-receive-key" ]) $(id).disabled = !key();
        $("export-network").disabled = !state.ready;
        $("trade-submit").disabled = !enabled || decisionClosing() || !state.quoteOutput || state.quoteOutput.identity !== tradeIdentity();
        $("send-submit").disabled = !enabled || !state.sendQuote || state.sendQuote.identity !== sendIdentity();
        document.querySelectorAll(".wallet-action").forEach(button => {
            const form = button.closest("form");
            form && feeBuilders.has(form.id) && feeQuotes.get(form.id)?.identity !== feeIdentity(form) && (button.disabled = true);
        });
        tradeBalanceView();
        faucetView();
    }
    function faucetKey() {
        return key() && state.session?.chain_id ? `${state.session.chain_id}:${address()}` : "";
    }
    function faucetRetry(value) {
        return Number.isSafeInteger(value) && value >= 0 ? Math.min(value, 31536e3) : 0;
    }
    function faucetClaimResult(data, chain) {
        if (!data || data.chain_id && data.chain_id !== chain || ![ "pending", "confirmed", "expired" ].includes(data.status) || !/^[a-f0-9]{64}$/.test(data.txid || "") || !/^[1-9][0-9]{0,159}$/.test(data.amount_hashes || "")) throw new Error("Faucet response is unavailable.");
        return {
            ...data,
            retryAt: Date.now() + faucetRetry(data.retry_after_seconds) * 1e3
        };
    }
    function faucetView() {
        const claimKey = faucetKey(), matching = faucet.config?.chain_id === state.session?.chain_id;
        $("wallet-faucet").hidden = !matching || !claimKey;
        if (!matching || !claimKey) return;
        const current = faucet.lastKey === claimKey ? faucet.data : null, claim = faucet.claims.get(claimKey);
        const retryAt = current ? current.retryAt : claim?.retryAt;
        const cooldown = Math.max(0, Math.ceil(((retryAt || 0) - Date.now()) / 1e3));
        const busy = faucet.busy.has(claimKey), pending = claim?.status === "pending";
        $("faucet-claim").disabled = !state.ready || state.managing || busy || pending || cooldown > 0 || !current?.enabled || !current.available;
        text("faucet-claim", busy ? "Requesting…" : "Get test hashes");
        amountText("faucet-amount", current?.amount_hashes ? formatHash(current.amount_hashes) : "");
        const wait = cooldown ? current?.cooldown_scope === "network" ? `Retry in ${duration(cooldown)}` : `Available in ${duration(cooldown)}` : "";
        let message = "";
        busy ? message = "Requesting…" : pending ? message = "Pending" : claim?.status === "confirmed" ? message = `${formatHash(claim.amount_hashes)} received.${wait ? ` ${wait}` : ""}` : cooldown ? message = wait : state.ready ? faucet.lastKey === claimKey && faucet.error ? message = faucet.error : current?.state === "waiting_for_mining" ? message = "Waiting for mining" : current?.state === "unfunded" ? message = "Unfunded" : current?.state === "quota_reached" ? message = "Limit reached" : current?.state === "pending" ? message = "Payment pending" : current && !current.available ? message = "Unavailable" : current || (message = "Checking…") : message = "Connecting…";
        pending && current?.mining_active === false && (message = "Pending · waiting for mining");
        text("faucet-status", message);
        $("faucet-status").hidden = !message;
        if (claim?.txid && claim.status) {
            const transaction = append($("faucet-status"), "a", "text-link faucet-transaction", "Transaction ↗");
            transaction.href = `#explorer?tx=${encodeURIComponent(claim.txid)}`;
        }
        $("faucet-status").title = claim?.txid ? `Transaction ${claim.txid}` : "";
    }
    async function faucetRequest(url, options = {}) {
        let timer;
        try {
            return await Promise.race([ fetch(url, {
                cache: "no-store",
                credentials: "omit",
                redirect: "error",
                referrerPolicy: "no-referrer",
                ...options
            }).then(async response => ({
                response: response,
                data: response.ok || response.status !== 404 ? await exactJSON(response) : null
            })), new Promise((_resolve, reject) => {
                timer = setTimeout(() => reject(new Error("Faucet unavailable. Try again shortly.")), 1e4);
            }) ]);
        } finally {
            clearTimeout(timer);
        }
    }
    async function refreshFaucet(force = false) {
        // The faucet may be a separately operated origin, and its status query
        // names the selected address. Ask only while Wallet, where the faucet
        // control lives, is open.
        if (!state.ready || faucet.checking || location.hash.split("?")[0] !== "#wallet") return;
        const chain = state.status.chain_id, claimKey = faucetKey(), sequence = faucet.sequence;
        const identity = walletIdentity();
        const current = () => state.ready && chain === state.status?.chain_id && identity === walletIdentity() && sequence === faucet.sequence;
        faucet.checking = true;
        try {
            if (faucet.configChain !== chain || faucet.configAt === null || Date.now() - faucet.configAt >= 6e4) {
                const {response: response, data: data} = await faucetRequest("/faucet-config.json");
                if (!current()) return;
                faucet.configChain = chain;
                faucet.configAt = Date.now();
                // A same-origin deployment descriptor opts in. No credentials or wallet
                // keys are sent to the separately operated faucet.
                                faucet.config = response.ok && data?.chain_id === chain && typeof data.url === "string" && /^https:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?\/?$/i.test(data.url) ? {
                    chain_id: chain,
                    url: data.url.replace(/\/$/, "")
                } : null;
                if (!faucet.config) {
                    faucet.data = null;
                    return;
                }
            }
            if (!faucet.config || !claimKey || faucet.busy.has(claimKey)) return;
            if (!force && faucet.lastKey === claimKey && Date.now() - faucet.lastAt < 1e4) return;
            const {response: response, data: data} = await faucetRequest(`${faucet.config.url}/faucet/status?address=${encodeURIComponent(address())}`);
            if (!current()) return;
            faucet.lastKey = claimKey;
            faucet.lastAt = Date.now();
            faucet.error = "";
            if (response.status === 404) {
                faucet.config = null;
                faucet.data = null;
                return;
            }
            if (!response.ok || data?.chain_id !== chain || typeof data.enabled !== "boolean" || typeof data.available !== "boolean" || !/^[1-9][0-9]{0,159}$/.test(data.amount_hashes || "")) throw new Error("Faucet unavailable. Try again shortly.");
            faucet.data = {
                ...data,
                retryAt: Date.now() + faucetRetry(data.retry_after_seconds) * 1e3
            };
            data.claim ? faucet.claims.set(claimKey, faucetClaimResult(data.claim, chain)) : faucet.busy.has(claimKey) || faucet.claims.delete(claimKey);
        } catch (error) {
            if (current()) {
                faucet.lastKey = claimKey;
                faucet.lastAt = Date.now();
                faucet.data = null;
                faucet.error = "Faucet unavailable. Try again shortly.";
            }
        } finally {
            faucet.checking = false;
            faucetView();
        }
    }
    async function claimFaucet() {
        faucetView();
        if ($("wallet-faucet").hidden || $("faucet-claim").disabled) return;
        const claimKey = faucetKey(), chain = state.status.chain_id, recipient = address(), config = faucet.config;
        const identity = walletIdentity();
        faucet.busy.add(claimKey);
        faucet.sequence++;
        faucetView();
        try {
            const {response: response, data: data} = await faucetRequest(`${config.url}/faucet/claim`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    address: recipient
                })
            });
            if (!response.ok) {
                const retry = faucetRetry(data?.retry_after_seconds);
                retry && faucet.claims.set(claimKey, {
                    retryAt: Date.now() + retry * 1e3
                });
                throw new Error(response.status === 429 ? "Limit reached" : "Faucet unavailable. Try again shortly.");
            }
            if (data?.chain_id !== chain) throw new Error("Faucet network changed. Refresh and try again.");
            faucet.claims.set(claimKey, faucetClaimResult(data, chain));
            if (identity === walletIdentity() && chain === state.status?.chain_id) {
                faucet.error = "";
                await refresh();
            }
        } catch (error) {
            if (identity === walletIdentity() && chain === state.status?.chain_id) {
                faucet.error = error.message;
                faucet.lastKey = claimKey;
                faucet.data = null;
            }
        } finally {
            faucet.busy.delete(claimKey);
            faucet.lastAt = 0;
            faucetView();
            // Only GET is retried. A timed-out POST may already have been accepted.
                        refreshFaucet(true);
        }
    }
    $("faucet-claim").addEventListener("click", claimFaucet);
    function transactionExpiry(form) {
        const raw = $(form.id === "trade-form" ? "trade-expiry" : "wallet-expiry").value.trim();
        if (!/^[0-9]+$/.test(raw) || raw.length > 20) throw new Error("Transaction expiry must be a positive whole number of blocks.");
        const lifetime = BigInt(raw);
        if (!lifetime || lifetime > 18446744073709551615n) throw new Error("Transaction expiry must fit a positive 64-bit block count.");
        return lifetime;
    }
    async function submit(form, operation) {
        if (!state.ready) throw new Error("Wait for the node connection to refresh.");
        if (!state.session) throw new Error("Wallet session is unavailable.");
        if (!key()) throw new Error("Select a wallet first.");
        if (!state.account) throw new Error("Your account needs its first hashes payment before it can send transactions.");
        if (state.submitting) throw new Error("Wait for the current submission to finish.");
        if (state.managing) throw new Error("Wait for the wallet change to finish.");
        if (form.id === "send-form" && operation.TransferExact && (!state.sendQuote || state.sendQuote.identity !== sendIdentity())) throw new Error("Wait for a current payment quote.");
        const feeQuote = feeQuotes.get(form.id);
        if (!feeQuote || feeQuote.identity !== feeIdentity(form)) throw new Error("Wait for the current fee quote.");
        const feeFields = {
            fee: feeQuote.fee
        };
        checkOutcomeFunds(operation, feeFields.fee);
        const expiry = transactionExpiry(form);
        if (!expiry) throw new Error("Transaction expiry must be greater than zero.");
        const identity = submissionIdentity(form), hot = state.session.wallet_enabled, dataFields = transactionData(form);
        const nonce = nextNonce();
        const expiryHeight = BigInt(state.status.height) + BigInt(expiry);
        if (expiryHeight > 18446744073709551615n) throw new Error("Transaction lifetime overflows the block height.");
        const request = {
            sender: key(),
            operation: operation,
            ...feeFields,
            ...dataFields,
            expiry_blocks: jsonInteger(expiry),
            nonce: jsonInteger(nonce),
            anchor: state.status.tip
        };
        const expected = {
            ...request,
            nonce: nonce.toString(),
            anchor_height: String(state.status.height),
            current_height: String(state.status.height),
            chain_id: state.status.chain_id,
            data_hex: dataFields.data_hex || "",
            wallet_id: state.session.wallet_id,
            wallet_revision: state.session.wallet_revision
        };
        state.submitting = true;
        modeButtons();
        feedback(form, hot ? "Signing and submitting…" : "Preparing transaction…");
        try {
            if (identity !== submissionIdentity(form)) throw new Error("Details or connection changed. Review again.");
            const prepared = await rpc("preparetransaction", request);
            // RPC adds a fee quote; only these three fields form the offline export.
            const envelope = {format: prepared?.format, chain_id: prepared?.chain_id, body: prepared?.body};
            if (identity !== submissionIdentity(form)) throw new Error("Details or connection changed. Prepare the transaction again.");
            if (typeof envelope?.body !== "string" || envelope.body.length / 2 + 64 > transactionByteLimit()) throw new Error("Transaction exceeds the block capacity.");
            HashstashBrowserWallet.verifyUnsigned(envelope, expected);
            checkPreparedWeight(envelope.body, feeQuote, operation);
            if (identity !== submissionIdentity(form)) throw new Error("Details or connection changed. Review again.");
            if (!hot) {
                $("unsigned-output").value = JSON.stringify({
                    format: envelope.format,
                    chain_id: envelope.chain_id,
                    body: envelope.body
                }, null, 2);
                $("unsigned-dialog").showModal();
                feedback(form, "Unsigned transaction prepared.");
                form.id === "propose-form" && rememberDescription(operation);
                return envelope;
            }
            const signed = await browserWallet.signUnsigned(envelope, expected);
            if (identity !== submissionIdentity(form)) throw new Error("Wallet or details changed. Submit again.");
            const data = await rpc("broadcasttransaction", {
                raw: signed.raw
            });
            const id = data.transaction_id;
            if (!id || id !== signed.transaction_id) throw new Error("The node returned an unexpected transaction ID.");
            form.id === "propose-form" && rememberDescription(operation);
            toast("Transaction submitted.");
            if (form.id !== "mail-form" || identity === submissionIdentity(form)) {
                form.id === "mail-form" && mail?.sent();
                feedback(form, `Pending · ${short(id)}`);
                trackSubmission(form, id, request.sender, nonce);
            }
            await refresh();
            return data;
        } finally {
            state.submitting = false;
            modeButtons();
            $("trade-amount").value && quoteSoon();
            form.id === "send-form" && sendSoon();
        }
    }
    // The snapshot's global mempool page is capped at 128 rows. The node also
    // reports the selected sender's own pending rows and its next nonce over
    // the whole pool, the value preparetransaction requires.
    function ownPending() {
        return Array.isArray(state.senderMempool) ? state.senderMempool : state.mempool.filter(tx => hex(tx.body?.sender) === key());
    }
    function nextNonce() {
        let nonce = BigInt(state.account?.account?.nonce || "0");
        /^\d{1,20}$/.test(String(state.pendingNonce ?? "")) && BigInt(state.pendingNonce) > nonce && (nonce = BigInt(state.pendingNonce));
        for (const transaction of ownPending()) hex(transaction.body?.sender) === key() && BigInt(transaction.body.nonce) >= nonce && (nonce = BigInt(transaction.body.nonce) + 1n);
        return nonce;
    }
    function submissionIdentity(form) {
        const values = formValues(form);
        if(form.id === "propose-form" && values.type === "grant")values.payments=grantDraft();
        form.id === "trade-form" && (values.all = state.tradeAll);
        form.id === "send-form" && (values.quoteIdentity = sendIdentity());
        values.nonce = nextNonce().toString();
        form.id === "propose-form" && values.type === "parameter" && (values.currentSetting = [ state.status?.settings?.[settings[values.parameter]?.[0]] ]);
        return JSON.stringify([ walletIdentity(), state.session?.wallet_enabled, $(form.id === "trade-form" ? "trade-expiry" : "wallet-expiry").value, state.status?.chain_id, state.status?.tip, state.status?.height, state.status?.state_root, phaseName(), activeDecision()?.id, state.gov?.phase?.Auction?.round, form.id === "trade-form" ? state.trade : null, values ]);
    }
    function bindForm(id, operationBuilder) {
        const form = $(id);
        const build = async values => { await prepareTransactionData(form); return operationBuilder(values); };
        feeBuilders.set(id, build);
        form.addEventListener("change", () => transactionDataView(form));
        form.addEventListener("input", () => feeSoon(form));
        form.addEventListener("change", () => feeSoon(form));
        form.addEventListener("submit", async event => {
            event.preventDefault();
            if (form.dataset.preparing === "true" || state.submitting) return;
            form.dataset.preparing = "true";
            try {
                const identity = submissionIdentity(form);
                const operation = await build(formValues(form));
                if (identity !== submissionIdentity(form)) throw new Error("Details or connection changed. Review and submit again.");
                await submit(form, operation);
            } catch (error) {
                feedback(form, error.message, true);
            } finally {
                form.dataset.preparing = "false";
            }
        });
    }
    function feeIdentity(form) {
        return JSON.stringify([ submissionIdentity(form), state.status?.tip, state.status?.state_root, state.status?.height, state.status?.fee_policy, state.status?.settings?.miner_fee_percent, state.status?.settings?.minimum_fee_rate ]);
    }
    function checkQuoteSnapshot(result) {
        if (!/^[0-9a-f]{64}$/.test(result.tip) || !/^[0-9a-f]{64}$/.test(result.state_root) || !Number.isSafeInteger(result.height) || result.height < 0) throw new Error("Invalid quote context.");
        if (result.tip !== state.status.tip || result.state_root !== state.status.state_root || result.height !== state.status.height) throw new QuoteRefreshPending("Updating quote for the latest block.");
    }
    function checkFeeQuote(result, extra, form, operation = null) {
        for (const field of [ "fee", "minimum_fee", "account_creation_fee", "grant_recipient_fee", "record_fee", "extra_fee", "weight", "minimum_fee_rate" ]) if (typeof result[field] !== "string" || !/^(0|[1-9]\d{0,159})$/.test(result[field])) throw new Error("Invalid fee quote.");
        if (result.chain_id !== state.status.chain_id) throw new Error("Fee quote belongs to a different network.");
        checkQuoteSnapshot(result);
        if (result.anchor !== state.status.tip || String(result.anchor_height) !== String(state.status.height) || String(result.expiry_blocks) !== String(transactionExpiry(form)) || BigInt(result.expiry_height) !== BigInt(state.status.height) + BigInt(transactionExpiry(form))) throw new Error("Fee quote does not match the transaction lifetime.");
        if (result.sender_public_key !== key() || result.sender !== address() || result.extra_fee !== extra) throw new Error("Fee quote does not match this account.");
        // The nonce's encoded length is part of the weight the fee pays for.
        if (result.nonce !== void 0 && String(result.nonce) !== nextNonce().toString()) throw new Error("Fee quote does not match the transaction number.");
        {
            const data = transactionData(form).data_hex || "";
            if (result.data_hex !== data || result.data_bytes !== data.length / 2) throw new Error("Fee quote does not match the transaction data.");
        }
        if (BigInt(result.fee) !== BigInt(result.minimum_fee) + BigInt(extra) || BigInt(result.account_creation_fee) > BigInt(result.minimum_fee) || BigInt(result.weight) === 0n) throw new Error("Invalid fee quote totals.");
        const price = BigInt(result.minimum_fee_rate), weight = BigInt(result.weight), creation = BigInt(result.account_creation_fee);
        if (weight > BigInt(transactionByteLimit())) throw new Error("Transaction exceeds the block capacity.");
        if (price !== BigInt(state.status.settings.minimum_fee_rate) || price > 18446744073709551615n) throw new Error("Minimum fee rate changed. Refresh for the current rate.");
        if (BigInt(result.minimum_fee) !== (price * weight + 1023n) / 1024n || creation !== 0n && (creation !== price || weight < 1024n)) throw new Error("Invalid fee quote weight.");
        // A new proposal or support record carries 1,024 weight at the same rate.
        const record = BigInt(result.record_fee);
        if (record !== 0n && (record !== price || weight < 1024n) || operation?.Propose && record !== price || operation && !operation.Propose && !operation.Support && record !== 0n) throw new Error("Invalid governance record fee.");
        const grantFee=BigInt(result.grant_recipient_fee);
        const grantCount=operation?.Propose?.proposal?.Grant?.payments?.length || 0;
        if(grantFee!==price*BigInt(grantCount) || grantFee>BigInt(result.minimum_fee) || weight < BigInt(grantCount)*1024n || grantCount && creation!==0n)throw new Error("Invalid grant recipient fee.");
        {
            for (const name of [ "miner_fee", "revenue_fee" ]) if (typeof result[name] !== "string" || !/^(0|[1-9]\d{0,159})$/.test(result[name])) throw new Error("Invalid fee allocation.");
            const percent = String(result.miner_fee_percent);
            if (!/^(0|[1-9]\d{0,2})$/.test(percent) || BigInt(percent) > 100n || percent !== String(state.status.settings.miner_fee_percent)) throw new Error("Fee allocation changed. Refresh for the current split.");
            const fee = BigInt(result.fee), miner = BigInt(result.miner_fee), revenue = BigInt(result.revenue_fee);
            if (miner !== fee * BigInt(percent) / 100n || miner + revenue !== fee) throw new Error("Invalid fee allocation totals.");
        }
        return result;
    }
    function checkPreparedWeight(body, quote, operation) {
        // The quoted weight, and so the minimum fee, came from the node.
        // Re-derive it from the exact prepared bytes: the body plus a 64-byte
        // signature, 1,024 per grant recipient, 1,024 for a proposal's records
        // and, only for a payment that creates its recipient's account or a
        // support that creates its sender's record, another 1,024.
        const base = BigInt(body.length / 2 + 64), recipients = BigInt(operation?.Propose?.proposal?.Grant?.payments?.length || 0), records = operation?.Propose ? 1024n : 0n;
        const extra = BigInt(quote?.weight ?? -1) - base - recipients * 1024n - records, free = BigInt(quote?.minimum_fee_rate ?? 1) === 0n;
        const creation = BigInt(quote?.account_creation_fee ?? 0) !== 0n, record = BigInt(quote?.record_fee ?? 0) !== 0n;
        const creates = !!operation?.TransferExact && extra === 1024n && (creation || free) && !record;
        const supports = !!operation?.Support && extra === 1024n && (record || free) && !creation;
        const plain = extra === 0n && !creation && (operation?.Propose ? record || free : !record);
        if (!(plain || creates || supports)) throw new Error("The quoted fee weight does not match the prepared transaction.");
    }
    function clearFeeAllocation(form) {
        const node = $(form.id.replace("-form", "-fee-allocation"));
        if (node) {
            node.hidden = true;
            node.textContent = "";
        }
    }
    function showFeeQuote(form, result, identity = feeIdentity(form)) {
        pendingFeeRefresh.delete(form.id);
        feeQuotes.set(form.id, {
            ...result,
            identity: identity
        });
        const node = $(form.id.replace("-form", "-fee-quote"));
        amountText(node, formatExactHash(result.fee));
        node.title = `Exact fee: ${formatExactHash(result.fee)}. Minimum: ${formatExactHash(result.minimum_fee)}. Optional extra: ${formatExactHash(result.extra_fee)}. This is the total fee signed and paid if the transaction is included.`;
        const allocation = $(form.id.replace("-form", "-fee-allocation"));
        {
            const percent = Number(result.miner_fee_percent);
            amountText(allocation, `Fee ${formatExactHash(result.fee)} · Miner ${formatExactHash(result.miner_fee)} (${percent}%) · Revenue ${formatExactHash(result.revenue_fee)} (${100 - percent}%).`);
            allocation.title = "The entire fee, including the optional extra, follows the miner/revenue split in effect when the transaction is included.";
            allocation.hidden = false;
        }
        feeError(form, scheduledChangeNote(result));
        modeButtons();
    }
    // A pending fee-rate increase or capacity decrease that takes effect within
    // the transaction's lifetime leaves it valid only for the blocks before.
    function scheduledChangeNote(result) {
        const change = result.scheduled_change;
        if (!change || change.valid_after !== false || !Number.isSafeInteger(change.effective_height) || !/^(0|[1-9]\d{0,159})$/.test(String(change.minimum_fee))) return "";
        if (change.parameter === "MinimumFeeRate") return `The minimum fee rises to ${formatExactHash(change.minimum_fee)} from block ${commas(change.effective_height)}, so this transaction is valid only before that block. Add the difference as an optional extra to keep its whole lifetime.`;
        if (change.parameter === "BlockBytes") return `Block capacity falls from block ${commas(change.effective_height)}, and this transaction will no longer fit after that block.`;
        return "";
    }
    function feeError(form, message) {
        const node = $(form.id.replace("-form", "-fee-error"));
        if (!node) return;
        node.textContent = message;
        node.hidden = !message;
    }
    function feeSoon(form, preserveDisplay = false) {
        if (form.id === "send-form") return;
        feeQuotes.delete(form.id);
        pendingFeeRefresh.delete(form.id);
        clearTimeout(feeTimers.get(form.id));
        feeVersions.set(form.id, (feeVersions.get(form.id) || 0) + 1);
        if (preserveDisplay !== true) {
            clearFeeAllocation(form);
            text(form.id.replace("-form", "-fee-quote"), "—");
            feeError(form, "");
        }
        modeButtons();
        feeTimers.set(form.id, setTimeout(() => quoteFee(form), 300));
    }
    async function quoteFee(form) {
        if (!state.ready || !key() || state.submitting || state.managing) return;
        const version = (feeVersions.get(form.id) || 0) + 1;
        feeVersions.set(form.id, version);
        const identity = feeIdentity(form), current = () => feeVersions.get(form.id) === version && identity === feeIdentity(form) && state.ready;
        try {
            const operation = await feeBuilders.get(form.id)(formValues(form));
            if (!current()) return;
            const extra = integer(form.elements.extra_fee.value, "Optional extra", true);
            const result = await rpc("fee_quote", {
                sender: key(),
                operation: operation,
                ...transactionData(form),
                extra_fee: extra,
                anchor: state.status.tip,
                expiry_blocks: jsonInteger(transactionExpiry(form)),
                nonce: jsonInteger(nextNonce())
            });
            if (!current()) return;
            checkFeeQuote(result, extra, form, operation);
            checkOutcomeFunds(operation, result.fee);
            showFeeQuote(form, result, identity);
        } catch (error) {
            if (current()) {
                feeQuotes.delete(form.id);
                if (error instanceof QuoteRefreshPending) {
                    pendingFeeRefresh.add(form.id);
                    modeButtons();
                    return;
                }
                pendingFeeRefresh.delete(form.id);
                clearFeeAllocation(form);
                const node = $(form.id.replace("-form", "-fee-quote"));
                node.textContent = "—";
                node.title = error.message;
                const values = formValues(form), hasInput = (form.id === "mail-form" ? [ "recipient", "subject", "message" ] : [ "amount", "support", "grant", "proposal" ]).some(name => String(values[name] || "").trim());
                !hasInput || form.id === "trade-form" && !state.quoteOutput || feeError(form, error.message);
                modeButtons();
            }
        }
    }
    function feeView() {
        $("guide-transaction-data").hidden = false;
        text("guide-transaction-data", "Any transaction can attach data, signed by its sender and charged by size. Applications interpret those bytes without changing the payment or trade underneath.");
        for (const name of feeForms) {
            const form = $(`${name}-form`);
            $(`${name}-fee`).hidden = false;
            form.elements.extra_fee.disabled = false;
            form.elements.extra_fee.required = true;
            form.elements.extra_fee.title = "Optional extra added to the minimum fee. The entire fee follows the miner/revenue ratio.";
            $(`${name}-data`) && ($(`${name}-data`).hidden = name === "mail" || false);
            transactionDataView(form);
        }
    }
    const guideTabs = [ "overview", "technical" ];
    function selectGuideTab(name, focus = false) {
        for (const tab of guideTabs) {
            const selected = tab === name, button = $(`guide-${tab}-tab`);
            button.setAttribute("aria-selected", String(selected));
            button.tabIndex = selected ? 0 : -1;
            button.classList.toggle("selected", selected);
            $(`guide-${tab}-panel`).hidden = !selected;
        }
        if (focus) $(`guide-${name}-tab`).focus();
    }
    for (const tab of guideTabs) {
        $(`guide-${tab}-tab`).addEventListener("click", () => selectGuideTab(tab));
        $(`guide-${tab}-tab`).addEventListener("keydown", event => {
            if (![ "ArrowLeft", "ArrowRight", "Home", "End" ].includes(event.key)) return;
            event.preventDefault();
            selectGuideTab(event.key === "Home" ? "overview" : event.key === "End" ? "technical" : tab === "overview" ? "technical" : "overview", true);
        });
    }
    function route() {
        const requested = location.hash.slice(1).split("?")[0] || "overview";
        const name = requested;
        const selected = titles[name] ? name : "overview";
        document.querySelectorAll(".view").forEach(view => {
            view.hidden = view.id !== `view-${selected}`;
        });
        document.querySelectorAll("[data-route]").forEach(link => {
            const current = link.dataset.route === (selected === "network" ? "explorer" : selected);
            link.classList.toggle("active", current);
            if (current) {
                for (let parent = link.parentElement; parent; parent = parent.parentElement) if (parent.tagName === "DETAILS") parent.open = true;
                link.setAttribute("aria-current", "page");
                link.parentElement.scrollWidth > link.parentElement.clientWidth && link.scrollIntoView({
                    block: "nearest",
                    inline: "nearest"
                });
            } else link.removeAttribute("aria-current");
        });
        text("page-crumb", titles[selected]);
        document.title = `${titles[selected]} · Hashstash`;
        state.ready && accountView();
        window.scrollTo({
            top: 0,
            left: 0,
            behavior: "instant"
        });
        renderCurves();
        explorer?.route();
        chat?.route();
        mail?.route();
        refreshExplanations();
        refreshFaucet();
    }
    function accountView() {
        const a = state.ready ? snapshotAccount(state.account) : void 0;
        const selectedWallet = !!key();
        $("overview-account").hidden = !selectedWallet;
        $("overview-empty").hidden = selectedWallet;
        $("receive-card").hidden = !selectedWallet;
        $("receive-empty").hidden = selectedWallet;
        const sendPanel = $("send-form").closest("article");
        if (sendPanel) sendPanel.hidden = !selectedWallet;
        const balance = paymentCash(state.ready ? snapshotAccount(state.pass) : void 0, state.ready ? snapshotAccount(state.fail) : void 0, a);
        for (const id of [ "overview-cash", "send-available" ]) if (balance === null) {
            text(id, "—");
            $(id).title = "Unavailable";
        } else number(id, balance);
        text("overview-cash-label", activeDecision() ? "Available" : "hash");
        const paymentHelp = activeDecision() ? "A payment spends hashes in both outcomes. This is the smaller of those balances, before fees." : "Hashes available to spend, before fees.";
        if (activeDecision()) for (const id of [ "overview-cash", "send-available" ]) $(id).title = `${balance === null ? "Unavailable" : formatExactHash(balance)}. ${paymentHelp}`;
        if ($("governance-common-cash")) {
            selectedWallet && balance !== null ? number("governance-common-cash", balance) : text("governance-common-cash", "—");
            activeDecision() && ($("governance-common-cash").title = `${balance === null ? "Unavailable" : formatExactHash(balance)}. ${paymentHelp}`);
        }
        const decisionActive = !!activeDecision();
        $("overview-stash-row").hidden = decisionActive;
        $("overview-total").hidden = decisionActive;
        $("overview-total-outcomes").hidden = !decisionActive;
        rational("overview-total", markedAccountValue(state.account));
        rational("overview-total-pass", markedAccountValue(state.pass, true));
        rational("overview-total-fail", markedAccountValue(state.fail, true));
        stashNumber("overview-stash", a?.shares || "0");
        text("overview-stash-label", decisionActive ? "stash (FAIL)" : "stash");
        for (const id of [ "overview-cash", "overview-total", "overview-total-pass", "overview-total-fail", "overview-stash" ]) compactAmount($(id), $(id).textContent);
        const outcome = $("trade-outcome").value;
        const selected = outcome === "Pass" ? state.pass : outcome === "Fail" ? state.fail : state.account;
        stashNumber("stash-total", selected?.account?.shares || "0");
        rational("stash-marked", selected?.stash_value_hash);
        $("governance-wallet-help").hidden = selectedWallet;
        $("governance-common").hidden = !selectedWallet;
        $("governance-actions").hidden = !selectedWallet;
        $("governance-trading").hidden = !decisionActive || !selectedWallet;
        for (const side of ["pass", "fail"]) $(`${side}-holdings`).hidden = !selectedWallet;
        for (const [name, data] of [ [ "pass", state.pass ], [ "fail", state.fail ] ])
        // Market prices belong to the decision, including for visitors without a wallet.
        // A missing wallet is not a zero-priced market or a zero-valued position.
        if (selectedWallet) {
            state.ready && snapshotAccount(data) !== void 0 ? number(`${name}-cash`, outcomeCash(data)) : text(`${name}-cash`, "—");
            stashNumber(`${name}-stash`, data?.account?.shares || "0");
            rational(`${name}-stash-marked`, data?.stash_value_hash);
        } else for (const suffix of [ "cash", "stash", "stash-marked" ]) {
            text(`${name}-${suffix}`, "—");
            $(`${name}-${suffix}`).title = "Select a wallet to see your holdings.";
        }
        if (!selectedWallet) {
            for (const id of [ "overview-cash", "overview-total", "overview-stash", "send-available", "stash-total", "stash-marked" ]) text(id, "—");
        }
        if (!state.ready) {
            for (const id of [ "overview-cash", "overview-total", "overview-total-pass", "overview-total-fail", "overview-stash", "send-available", "stash-total", "stash-marked", "governance-common-cash", "pass-cash", "pass-stash", "pass-stash-marked", "fail-cash", "fail-stash", "fail-stash-marked" ]) {
                text(id, "—");
                $(id).title = "Unavailable";
                $(id).removeAttribute("aria-label");
            }
        }
        tradeBalanceView();
    }
    function overviewPriceView() {
        const conditional = state.ready && !!activeDecision();
        $("overview-conversion-ordinary").hidden = conditional;
        $("overview-conversion-pass").hidden = $("overview-conversion-fail").hidden = !conditional;
        const note = "Estimated value uses the current price. Selling can receive a different amount, depending on the fill and fees.";
        $("overview-conversion").title = note;
        for (const [id, world] of [ [ "overview-price", state.gov?.world ], [ "overview-price-pass", state.gov?.pass ], [ "overview-price-fail", state.gov?.world ] ]) {
            const available = state.ready && world;
            if (available) {
                sharePrice(id, worldPrice(world));
                $(id).title += `. ${note}`;
            } else {
                text(id, "—");
                $(id).title = state.ready ? "No Stash price available." : "Price unavailable while disconnected.";
            }
        }
    }
    function tradeBalanceView() {
        const outcome = $("trade-outcome").value;
        const selected = outcome === "Pass" ? state.pass : outcome === "Fail" ? state.fail : state.account;
        const account = snapshotAccount(selected);
        const balance = $("trade-balance");
        if (!state.ready || !key() || account === void 0) {
            balance.textContent = "—";
            balance.title = "";
            return;
        }
        const redeem = state.trade === "redeem";
        const value = redeem ? account?.shares || "0" : account?.ordinary || "0";
        amountText(balance, redeem ? `${HashstashShares.formatAmount(value)} stash` : `${hashAmount(value)}`);
        balance.title = redeem ? `${HashstashShares.exactInput(value)} stash` : formatExactHash(String(value || "0"));
    }
    function renderActivity() {
        const list = $("activity-list");
        const rows = ownPending().filter(tx => hex(tx.body?.sender) === key());
        $("activity-panel").hidden = !key() || rows.length === 0;
        text("activity-count", `${state.mempool.length} pending`);
        if (!renderChanged(list, [ state.session?.address_hrp, rows.slice(0, 5) ])) return;
        list.replaceChildren();
        if (!rows.length) {
            const empty = append(list, "div", "empty-state");
            append(empty, "h3", "", "No pending transactions");
            return;
        }
        for (const tx of rows.slice(0, 5)) {
            const displayed = tx.display_operation || tx.body.operation;
            const kind = Object.keys(displayed)[0], operation = displayed[kind];
            const assetClass = [ "Deposit", "Redeem" ].includes(kind) ? "activity-stash" : [ "TransferExact", "Support", "Refund" ].includes(kind) ? "activity-hash" : "";
            const row = append(list, "div", `activity-row ${assetClass}`);
            append(row, "span", "activity-symbol", {
                Deposit: "+",
                Redeem: "↙",
                TransferExact: "↗",
                Propose: "⚑"
            }[kind] || "↔");
            const copy = append(row, "div", "activity-copy");
            append(copy, "strong", "", {
                Deposit: "Stash deposit",
                Redeem: "Stash withdrawal",
                TransferExact: "Send",
                Propose: "New proposal",
                Support: "Proposal support",
                Refund: "Auction refund"
            }[kind] || kind);
            append(copy, "small", "", `${shortAddress(tx.body.sender)} · nonce ${tx.body.nonce}${operation.outcome ? ` · ${operation.outcome.toUpperCase()}` : ""}`);
            const val = append(row, "div", "activity-value");
            appendAmount(val, "span", "", operation.shares ? `${HashstashShares.formatAmount(operation.shares)} stash` : hashAmount(operation.amount || operation.support || "0"));
            append(val, "small", "", "pending");
        }
    }
    function worldPrice(world) {
        if (!world || BigInt(world.shares) === 0n) return {
            numerator: "1",
            denominator: String(state.config.share_scale)
        };
        return {
            numerator: String(world.curve_mass),
            denominator: String(world.shares)
        };
    }
    function reserveRatio(world) {
        return world && BigInt(world.curve_mass || "0") > 0n ? `${fraction(BigInt(world.reserve) * 100n, world.curve_mass, 2)}%` : world ? "100%" : "—";
    }
    // Exact amounts stay as BigInt. Floating point is used only for SVG geometry.
    const chartScale = 1000000n, chartShareUnit = HashstashShares.DISPLAY_SCALE;
    function chartPrice(world, multiplier = 1) {
        const [digits, exponent = "0"] = String(Math.max(0, multiplier)).split("e");
        const decimals = (digits.split(".")[1] || "").length, shift = Number(exponent) - decimals;
        const m = BigInt(digits.replace(".", "")) * 10n ** BigInt(Math.max(0, shift));
        const scale = 10n ** BigInt(Math.max(0, -shift));
        const price = worldPrice(world);
        const numerator = BigInt(price.numerator) * chartShareUnit * m;
        const denominator = BigInt(price.denominator) * scale;
        return formatHash(numerator, denominator);
    }
    // A preview of p(s) = p(current) * (s / current_supply)^(M/R - 1).
    // Exact balances and executable quotes never use these SVG coordinates.
    function curveModel(world) {
        const supply = BigInt(world.shares), reserve = BigInt(world.reserve), mass = BigInt(world.curve_mass);
        const empty = supply === 0n;
        if (supply < 0n || reserve < 0n || mass < reserve || (empty ? reserve !== 0n || mass !== 0n : reserve === 0n)) return null;
        const power = empty ? 0 : Number(mass - reserve) / Number(reserve);
        if (!Number.isFinite(power)) return null;
        const xmax = empty ? 2 : 1.25;
        const ymax = Math.max(1.5, Math.min(4, 1.1 * Math.exp(Math.min(Math.log(4), power * Math.log(xmax)))));
        const clipped = power > 0 && power * Math.log(xmax) > Math.log(ymax);
        const end = clipped ? Math.exp(Math.log(ymax) / power) : xmax;
        const value = x => power === 0 ? 1 : x === 0 ? 0 : Math.exp(Math.min(Math.log(ymax), power * Math.log(x)));
        const points = Array.from({length: 101}, (_, i) => {
            const x = end * i / 100;
            return [x, value(x)];
        });
        // Sampling prices too preserves the sharp rise of very steep curves.
        // Work remains bounded independently of the reserve ratio.
        if (power > 0) for (let i = 1; i <= 100; i++) {
            const y = ymax * i / 100, x = Math.exp(Math.log(y) / power);
            if (x > 0 && x <= end) points.push([x, y]);
        }
        if (!empty) points.push([1, 1]);
        if (clipped) points.push([end, ymax]);
        points.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
        return {empty, power, xmax, ymax, clipped, points, supply: empty ? chartShareUnit : supply};
    }
    function curveTick(numerator, denominator) {
        if (numerator === 0n) return "0";
        let exponent = numerator.toString().length - denominator.toString().length;
        if (exponent >= 0 ? numerator < denominator * 10n ** BigInt(exponent) : numerator * 10n ** BigInt(-exponent) < denominator) exponent--;
        const shift = 2 - exponent;
        const n = shift >= 0 ? numerator * 10n ** BigInt(shift) : numerator;
        const d = shift < 0 ? denominator * 10n ** BigInt(-shift) : denominator;
        let digits = Number((n + d / 2n) / d);
        if (digits >= 1000) { digits /= 10; exponent++; }
        const trim = value => value.replace(/(\.\d*?)0+$/, "$1").replace(/\.$/, "");
        if (exponent < -3 || exponent > 4) return `${trim((digits / 100).toFixed(2))}e${exponent}`;
        return trim((digits * 10 ** (exponent - 2)).toFixed(Math.max(0, 2 - exponent)));
    }
    function curveWorld() {
        return state.gov?.world;
    }
    function svgElement(parent, name, attributes, content) {
        const el = document.createElementNS("http://www.w3.org/2000/svg", name);
        for (const [key, value] of Object.entries(attributes || {})) el.setAttribute(key, String(value));
        content !== void 0 && (el.textContent = content);
        parent.appendChild(el);
        return el;
    }
    function drawCurve(svg, world) {
        if (!svg || !svg.parentElement.clientWidth || !world) return;
        const width = Math.max(280, Math.min(1200, svg.parentElement.clientWidth)), height = 280;
        if (!renderChanged(svg, [width, world.reserve, world.shares, world.curve_mass, state.config.share_scale, "single"])) return;
        const model = curveModel(world);
        svg.replaceChildren();
        svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
        if (!model) {
            svgElement(svg, "title", {id: "curve-plot-title"}, "Curve data is unavailable");
            svgElement(svg, "desc", {id: "curve-plot-desc"}, "The reported reserve and supply do not describe a valid curve.");
            svgElement(svg, "text", {x: 12, y: 48, class: "curve-axis-label"}, "Curve data is unavailable.");
            text("curve-range", "");
            return;
        }
        const {empty, power, xmax, ymax, clipped, points, supply} = model;
        const price = worldPrice(world);
        const labelPrice = multiple => curveTick(BigInt(price.numerator) * chartShareUnit * BigInt(Math.round(multiple * Number(chartScale))), BigInt(price.denominator) * HashstashAmounts.DISPLAY_SCALE * chartScale);
        const labels = Array.from({length: 5}, (_, tick) => labelPrice(ymax * tick / 4));
        const left = Math.max(52, Math.min(90, Math.max(...labels.map(label => label.length)) * 6 + 16));
        const right = 18, top = 34, bottom = 49;
        const plotW = width - left - right, plotH = height - top - bottom;
        const px = x => left + x / xmax * plotW, py = y => top + plotH - y / ymax * plotH;
        svg.dataset.reserve = world.reserve;
        svg.dataset.shares = world.shares;
        svg.dataset.exponent = String(power);
        svg.dataset.preview = empty ? "opening" : "funded";
        svg.dataset.clipped = String(clipped);
        const context = "";
        svgElement(svg, "title", {id: "curve-plot-title"}, `${context}Stash conversion curve. ${empty ? "Starting" : "Current"} price ${chartPrice(world)}/stash.`);
        svgElement(svg, "desc", {id: "curve-plot-desc"}, `Horizontal axis: total stash supply. Vertical axis: hash per stash. ${power === 0 ? "The exchange rate is flat." : "The price rises as supply increases."} ${empty ? "The reserve is empty; this is the opening exchange rate." : "A dot marks the current supply and price."} ${clipped ? "The line ends at the top of the visible price range." : ""} This shows the current curve before fees and integer rounding; grants and revenue can change its shape.`);
        svgElement(svg, "text", {
            x: left,
            y: 15,
            class: "curve-axis-label"
        }, "hash / stash");
        for (let tick = 0; tick <= 4; tick++) {
            const y = ymax * tick / 4, x = xmax * tick / 4;
            svgElement(svg, "line", {
                x1: left,
                x2: width - right,
                y1: py(y),
                y2: py(y),
                class: "curve-grid"
            });
            svgElement(svg, "text", {
                x: left - 10,
                y: py(y) + 4,
                "text-anchor": "end",
                class: "curve-axis-label"
            }, labels[tick]);
            svgElement(svg, "line", {
                x1: px(x),
                x2: px(x),
                y1: top,
                y2: top + plotH,
                class: "curve-grid"
            });
            const rawSupply = supply * BigInt(empty ? tick : tick * 5), divisor = BigInt(empty ? 2 : 16);
            svgElement(svg, "text", {
                x: px(x),
                y: height - 26,
                "text-anchor": tick === 0 ? "start" : tick === 4 ? "end" : "middle",
                class: "curve-axis-label"
            }, curveTick(rawSupply, divisor * chartShareUnit));
        }
        svgElement(svg, "text", {
            x: width - right,
            y: height - 6,
            "text-anchor": "end",
            class: "curve-axis-label"
        }, "Total stash supply");
        const curve = points.map(([x, y], i) => `${i ? "L" : "M"}${px(x).toFixed(2)},${py(y).toFixed(2)}`).join(" ");
        const last = points[points.length - 1];
        svgElement(svg, "path", {
            d: `${curve} L${px(last[0]).toFixed(2)},${py(0).toFixed(2)} L${px(0).toFixed(2)},${py(0).toFixed(2)} Z`,
            class: "curve-fill"
        });
        svgElement(svg, "path", {
            d: curve,
            class: "curve-line",
            fill: "none"
        });
        if (empty) {
            svgElement(svg, "text", {x: px(xmax) - 7, y: py(1) - 12, "text-anchor": "end", class: "curve-point-label"}, "Starting price");
        } else {
            svgElement(svg, "line", {x1: px(1), x2: px(1), y1: py(0), y2: py(1), class: "curve-guide"});
            svgElement(svg, "circle", {cx: px(1), cy: py(1), r: 5, class: "curve-current"});
            svgElement(svg, "text", {x: px(1) - 10, y: py(1) - 13, "text-anchor": "end", class: "curve-point-label"}, "Current");
        }
        $("curve-range").hidden = false;
        text("curve-range", clipped ? `Shown up to ${labelPrice(ymax)} hash/stash; the curve continues above the chart.` : empty ? "The first deposit starts at this flat exchange rate." : "Withdrawals move left; deposits move right.");
    }
    // Both outcomes share absolute supply and price axes. Geometry is approximate;
    // the exact market amounts and decision comparison above remain BigInt-based.
    function chartRatio(numerator, denominator) {
        const n = numerator.toString(), d = denominator.toString();
        const digits = 15, ne = Math.max(0, n.length - digits), de = Math.max(0, d.length - digits);
        return Number(n.slice(0, digits)) / Number(d.slice(0, digits)) * 10 ** (ne - de);
    }
    function governanceCurveTick(numerator, denominator) {
        const value = curveTick(numerator, denominator), match = /^([0-9.]+)e(-[0-9]+)$/.exec(value);
        if (!match || Number(match[2]) < -6) return value;
        return Number(value).toFixed(2 - Number(match[2])).replace(/0+$/, "").replace(/\.$/, "");
    }
    function drawOutcomeCurves(svg, titleId, descriptionId) {
        if (!activeDecision() || !svg?.parentElement.clientWidth) return;
        const width = Math.max(280, Math.min(1200, svg.parentElement.clientWidth)), height = 250;
        const worlds = [["pass", state.gov.pass], ["fail", state.gov.world]];
        if (!renderChanged(svg, [width, "outcomes", worlds.map(([, w]) => [w?.reserve, w?.curve_mass, w?.shares])])) return;
        svg.replaceChildren();
        svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
        svgElement(svg, "title", {id: titleId}, "PASS and FAIL conversion curves");
        svgElement(svg, "desc", {id: descriptionId}, "Both curves use the same total stash supply and hash-per-stash axes. Dots mark current supply and price. These are current conversion curves, not price history or probabilities. The decision counts the blocks led by each outcome. Preview excludes fees and integer rounding.");
        const funded = worlds.filter(([, world]) => world && BigInt(world.shares) > 0n && curveModel(world));
        if (!funded.length) {
            svgElement(svg, "text", {x: 18, y: 58, class: "curve-axis-label"}, "The first deposit starts a curve.");
            return;
        }
        const supply = funded.reduce((max, [, world]) => BigInt(world.shares) > max ? BigInt(world.shares) : max, 1n);
        const reference = funded.reduce((best, entry) => BigInt(entry[1].curve_mass) * BigInt(best[1].shares) > BigInt(best[1].curve_mass) * BigInt(entry[1].shares) ? entry : best)[1];
        const models = funded.map(([side, world]) => ({
            side, world, power: Number(BigInt(world.curve_mass) - BigInt(world.reserve)) / Number(world.reserve),
            currentX: Number(world.shares) / Number(supply),
            price: chartRatio(BigInt(world.curve_mass) * BigInt(reference.shares), BigInt(world.shares) * BigInt(reference.curve_mass))
        }));
        const requestedSupply = (supply * 5n + 3n) / 4n, supplyStep = 10n ** BigInt(requestedSupply.toString().length - 1);
        const supplyMaximum = (requestedSupply + supplyStep - 1n) / supplyStep * supplyStep;
        const xmax = Number(supplyMaximum) / Number(supply), ymax = Math.max(1.5, Math.min(4, Math.max(...models.map(m => Math.exp(Math.min(Math.log(4), Math.log(m.price) + m.power * Math.log(xmax / m.currentX)))))));
        const labelPrice = value => curveTick(BigInt(reference.curve_mass) * chartShareUnit * BigInt(Math.round(value * Number(chartScale))), BigInt(reference.shares) * HashstashAmounts.DISPLAY_SCALE * chartScale);
        const labels = [0, 1, 2, 3].map(i => labelPrice(ymax * i / 3));
        const left = Math.max(48, Math.min(90, Math.max(...labels.map(label => label.length)) * 6 + 14)), right = 18, top = 30, bottom = 49;
        const plotW = width - left - right, plotH = height - top - bottom;
        const px = value => left + value / xmax * plotW, py = value => top + plotH - value / ymax * plotH;
        svgElement(svg, "text", {x: left, y: 13, class: "curve-axis-label"}, "hash / stash");
        for (let tick = 0; tick <= 3; tick++) {
            const value = ymax * tick / 3;
            svgElement(svg, "line", {x1: left, x2: width - right, y1: py(value), y2: py(value), class: "curve-grid"});
            svgElement(svg, "text", {x: left - 10, y: py(value) + 4, "text-anchor": "end", class: "curve-axis-label"}, labels[tick]);
        }
        for (let tick = 0; tick <= 4; tick++) svgElement(svg, "text", {x: px(xmax * tick / 4), y: height - 26, "text-anchor": tick === 0 ? "start" : tick === 4 ? "end" : "middle", class: "curve-axis-label"}, governanceCurveTick(supplyMaximum * BigInt(tick), 4n * chartShareUnit));
        svgElement(svg, "text", {x: width - right, y: height - 6, "text-anchor": "end", class: "curve-axis-label"}, "stash supply");
        for (const model of models) {
            const {side, world, currentX, price, power} = model;
            const end = power > 0 ? Math.min(xmax, currentX * Math.exp((Math.log(ymax) - Math.log(price)) / power)) : xmax;
            const points = Array.from({length: 101}, (_, i) => {
                const x = end * i / 100;
                const y = power === 0 ? price : x === 0 ? 0 : Math.exp(Math.min(Math.log(ymax), Math.log(price) + power * Math.log(x / currentX)));
                return [x, y];
            });
            if (power > 0) for (let i = 1; i <= 100; i++) {
                const y = ymax * i / 100, x = currentX * Math.exp((Math.log(y) - Math.log(price)) / power);
                if (x > 0 && x <= end) points.push([x, y]);
            }
            points.push([currentX, price]);
            points.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
            const path = svgElement(svg, "path", {d: points.map(([x, y], i) => `${i ? "L" : "M"}${px(x).toFixed(2)},${py(y).toFixed(2)}`).join(" "), class: `governance-curve-line ${side}`, fill: "none"});
            path.dataset.exponent = String(power);
            path.dataset.clipped = String(end < xmax);
            const dot = svgElement(svg, "circle", {cx: px(currentX), cy: py(price), r: 4.5, class: `governance-curve-dot ${side}`});
            svgElement(dot, "title", {}, `${side.toUpperCase()} current price: ${chartPrice(world)}/stash`);
        }
    }
    function renderCurves() {
        if (!state.gov || !state.config) return;
        const active = !!activeDecision(), world = curveWorld();
        $("curve-single-price").hidden = active;
        $("curve-world-details").hidden = active;
        $("curve-outcomes").hidden = !active;
        $("curve-outcome-details").hidden = !active;
        if (active) {
            for (const [side, outcome] of [["pass", state.gov.pass], ["fail", state.gov.world]]) {
                sharePrice(`curve-price-${side}`, worldPrice(outcome));
                text(`curve-ratio-${side}`, reserveRatio(outcome));
                amountText(`curve-reserve-${side}`, hashAmount(outcome?.reserve || "0"));
                stashNumber(`curve-supply-${side}`, outcome?.shares || "0");
            }
            text("curve-range", "Both outcomes use the same axes. Dots mark current supply and price.");
            $("curve-range").hidden = false;
            drawOutcomeCurves($("curve-svg"), "curve-plot-title", "curve-plot-desc");
            drawOutcomeCurves($("governance-curve-svg"), "governance-curve-title", "governance-curve-description");
        } else {
            text("curve-context", "Current curve");
            text("reserve-ratio", `${reserveRatio(world)} reserve ratio`);
            text("curve-price", world ? chartPrice(world).replace(/ hash$/, "") : "—");
            $("curve-price").title = world ? `${chartPrice(world)}/stash` : "";
            amountText("curve-reserve", hashAmount(world?.reserve || "0"));
            stashNumber("curve-supply", world?.shares || "0");
            drawCurve($("curve-svg"), world);
        }
    }
    function placeStashTrading() {
        const active = !!activeDecision(), mount = $(active ? "governance-trade-mount" : "stash-trade-mount");
        const trading = $("stash-trading");
        // Keep the same controls and listeners; unchanged polls must not remount them.
                trading.parentElement !== mount && mount.appendChild(trading);
        $("governance-trading").hidden = !active || !key();
        $("stash-decision-notice").hidden = !active;
    }
    function governanceView() {
        const gov = state.gov, name = phaseName(), phase = gov.phase[name], clock = gov.clock;
        text("gov-phase-label", name === "Governance" ? "Decision" : name);
        text("metric-phase", name === "Governance" ? "Decision" : name);
        document.querySelectorAll("[data-cycle]").forEach(el => el.classList.toggle("current", el.dataset.cycle === name.toLowerCase()));
        const decision = activeDecision(), active = !!decision;
        $("outcome-section").hidden = !active;
        $("governance-market-details").hidden = !active;
        $("governance-details").hidden = !active && !(name === "Auction" && phase.leader);
        $("stash-context-notice").hidden = !active;
        text("stash-context-notice", decisionClosing() ? tradingClosedMessage : "Fees require hashes in both outcomes.");
        $("gov-result").hidden = !active;
        if (!active) {
            text("gov-result-status", "");
            text("gov-result-detail", "");
        }
        const proposalId = hex(decision?.proposal_id || (name === "Auction" ? phase.leader : null));
        $("gov-proposal-link").hidden = !proposalId;
        proposalId ? $("gov-proposal-link").href = `#explorer?governance=${encodeURIComponent(proposalId)}` : $("gov-proposal-link").removeAttribute("href");
        const grant = decision?.proposal?.Grant;
        $("gov-title").classList.toggle("sr-only", !!grant);
        $("gov-grant-funding").hidden = !grant;
        $("gov-grant-payments").hidden = !grant;
        $("gov-grant-payments").replaceChildren();
        if (grant) {
            renderGrantPayments($("gov-grant-payments"), grant, {...gov.decision_grant, id: proposalId});
            const funded = gov.pass.grant_escrow, required = decisionGrantTotal(grant);
            let requiredText = hashAmount(required), fundedText = hashAmount(funded);
            // Rounded-equal amounts must not imply a fully funded grant.
                        if (BigInt(funded) < BigInt(required) && fundedText === requiredText) {
                fundedText = formatExactHash(funded);
                requiredText = formatExactHash(required);
            }
            amountText("gov-grant-progress", `${fundedText} / ${requiredText}`);
            $("gov-grant-progress").title = `Set aside on PASS: ${formatExactHash(funded)}. Required: ${formatExactHash(required)}. Paid at resolution only if PASS wins.`;
        } else {
            text("gov-grant-progress", "");
            $("gov-grant-progress").title = "";
        }
        placeStashTrading();
        const tradeSelect = $("trade-outcome");
        const oldOutcome = tradeSelect.value;
        tradeSelect.closest("label").hidden = !active;
        for (const option of tradeSelect.options) option.disabled = !active;
        active && !tradeSelect.value && (tradeSelect.value = "Pass");
        if (!active) {
            tradeSelect.value = "";
        }
        if (oldOutcome !== tradeSelect.value) {
            state.tradeAll = false;
            quoteSoon();
        }
        if (name === "Auction") {
            text("gov-round", `Round ${phase.round}`);
            text("gov-title", phase.leader ? `Leader ${proposalShort(phase.leader)}` : "Auction open");
            text("gov-subtitle", phase.leader ? "The leading proposal advances after its required lead or at the auction timeout." : "Choose the next proposal.");
            text("overview-governance-title", "Auction open");
            text("overview-governance-text", phase.leader ? `Leader ${proposalShort(phase.leader)}` : "No leader");
        } else if (active) {
            text("gov-round", `Round ${decision.round}`);
            text("gov-title", grant ? "Recipients" : proposalTitle(decision.proposal));
            const total = BigInt(decision.blocks), elapsed = BigInt(state.status.height) - BigInt(decision.started_height);
            const observed = elapsed < 0n ? 0n : elapsed > total ? total : elapsed;
            const leading = BigInt(decision.leading_blocks), other = observed - leading;
            if (leading < 0n || other < 0n) throw new Error("Invalid decision block counts.");
            const margin = BigInt(gov.frozen.pass_margin_bps || 0);
            const criterion = `PASS must lead in more than half of ${blockCount(total)}.${margin ? ` A block counts only when its price is more than ${fraction(margin, 100, 2)}% above FAIL.` : " Equal prices add no PASS lead."}`;
            text("gov-subtitle", criterion);
            text("overview-governance-title", "Decision active");
            text("overview-governance-text", proposalTitle(decision.proposal, gov.decision_grant?.payment_count));
            for (const [id, world, count] of [["pass", gov.pass, leading], ["fail", gov.world, other]]) {
                text(`${id}-leading-blocks`, commas(count));
                const hasStash = BigInt(world.shares) > 0n;
                sharePrice(`${id}-price`, hasStash ? worldPrice(world) : {numerator: "0", denominator: "1"});
                if (!hasStash) $(`${id}-price`).title = "No outstanding stash. Its price is zero until a deposit starts the reserve.";
            }
            const funded = !grant || BigInt(gov.pass.grant_escrow) === BigInt(decisionGrantTotal(grant));
            // At the last tip the next block adds one observation from this
            // tip's closing prices and then resolves before its transactions,
            // so the outcome is already fixed. Show it as consensus will decide it.
            const final = decisionClosing();
            const finalLeading = leading + (passBeatsFail(gov.pass, gov.world, margin) ? 1n : 0n);
            const passLeads = final ? funded && finalLeading > total / 2n : leading * 2n > observed && funded;
            text("gov-result-status", final ? passLeads ? "PASS decided" : "FAIL decided" : observed ? passLeads ? "PASS leads" : "FAIL leads" : "Pending");
            text("gov-result-detail", final ? `${commas(finalLeading)} of ${blockCount(total)} count for PASS, including this block's closing prices. The decision resolves at the start of the next block, before its transactions.${funded ? "" : " Funding is incomplete."}` : `${commas(leading)} of ${blockCount(observed)} counted for PASS. ${blockCount(total - observed)} remain.${funded ? "" : " Funding is incomplete."}`);
            $("gov-result").dataset.outcome = final || observed ? passLeads ? "pass" : "fail" : "";
            $("gov-result").title = final ? `The result is fixed: no transaction can change it before resolution. ${criterion}` : `${blockCount(observed)} observed. ${criterion} The result is not final until resolution.`;
            for (const side of ["pass", "fail"]) {
                const isLeading = (final || !!observed) && (side === "pass" ? passLeads : !passLeads);
                $(`${side}-outcome-leader`).hidden = true;
                $(`${side}-outcome-card`).title = isLeading ? final ? `${side.toUpperCase()} is decided. Resolution follows in the next block.` : `${side.toUpperCase()} leads. Decision pending.` : "";
                $(`${side}-outcome-card`).classList.toggle("is-leading", isLeading);
            }
            number("pass-reserve", gov.pass.reserve);
            number("fail-reserve", gov.world.reserve);
        } else {
            text("gov-round", "");
            text("gov-title", "Rest period");
            text("gov-subtitle", phase.pending ? `${settings[phase.pending[0]][1]} → ${settingValue(settings[phase.pending[0]][0], phase.pending[1], settings[phase.pending[0]][2])} after rest` : "Next auction pending");
            text("overview-governance-title", "Rest period");
            text("overview-governance-text", `${protocolDuration(BigInt(phase.until) - BigInt(clock))} until next auction`);
        }
        const timing = phaseTiming();
        text("gov-countdown", blockCount(timing.blocks));
        text("gov-countdown-label", "left");
        $("gov-countdown").setAttribute("aria-label", `${blockCount(timing.blocks)} to ${timing.end}`);
        $("gov-countdown").title = `${timing.estimate} at the target interval. Actual time depends on mining.`;
        text("gov-mining-status", "Timing advances with mined blocks.");
        $("gov-progress").value = Math.max(0, Math.min(100, Number(timing.total - timing.seconds) * 100 / Number(timing.total)));
        parameterPreview();
        renderProposals();
        renderDecisionMessage();
        supportPreview();
    }
    // The snapshot keeps the first payments of a large grant with its count
    // (`truncated`); a page draws at most that many rows of any grant.
    const shownGrantPayments = 256;
    function grantPaymentCount(grant, paymentCount) {
        const count = Number(paymentCount);
        return Number.isSafeInteger(count) && count > grant.payments.length ? count : grant.payments.length;
    }
    function proposalTitle(action, paymentCount) {
        if (action.Grant) {
            const shown = action.Grant.payments.slice(0, shownGrantPayments), count = grantPaymentCount(action.Grant, paymentCount);
            return shown.map(payment => `${shortAddress(payment.recipient)} · ${hashAmount(payment.amount)}`).join(" / ") + (count > shown.length ? ` / … ${commas(count)} payments` : "");
        }
        const p = action.Parameter;
        return `Set ${settings[p.parameter][1].toLowerCase()} to ${settingValue(settings[p.parameter][0], p.new, settings[p.parameter][2])}`;
    }
    function renderGrantPayments(parent, grant, summary = {}) {
        const shown = grant.payments.slice(0, shownGrantPayments), count = grantPaymentCount(grant, summary.payment_count);
        for(const payment of shown){const row=append(parent,"div","grant-payout"),recipient=address(payment.recipient),link=append(row,"a","explorer-link",recipient);link.href=`#explorer?account=${encodeURIComponent(recipient)}`;link.title=recipient;appendAmount(row,"span","",formatExactHash(payment.amount));}
        if (count <= shown.length) return;
        // Never present part of a grant as the whole of it.
        const more = append(parent, "p", "field-help grant-more", `First ${commas(shown.length)} of ${commas(count)} payments. `);
        if (summary.id) {
            const link = append(more, "a", "explorer-link", "Full list in Explorer ↗");
            link.href = `#explorer?governance=${encodeURIComponent(hex(summary.id))}`;
        }
    }
    // A decision grant's total; a summarized one carries it beside its payments.
    function decisionGrantTotal(grant) {
        const total = state.gov?.decision_grant?.payment_total;
        return typeof total === "string" && /^(0|[1-9]\d{0,159})$/.test(total) ? total : grantTotal(grant.payments);
    }
    function renderDecisionMessage() {
        const id = hex(activeDecision()?.proposal_id), node = $("gov-decision-message");
        const message = state.ready && id ? proposalExplanations.get(`${state.status.chain_id}:${id}`) || "" : "";
        text("gov-decision-message", visibleControls(message));
        node.hidden = !message;
    }
    // Descriptions are published on chain. This session's own submissions are
    // remembered in memory until the explorer has them; drafts are never stored.
    const submittedDescriptions = new Map;
    function rememberDescription(operation) {
        const form = $("propose-form");
        if (!operation?.Propose || form.elements.data_format?.value === "private") return;
        submittedDescriptions.delete(hex(operation.Propose.description));
        submittedDescriptions.set(hex(operation.Propose.description), form.elements.description.value.trim());
        submittedDescriptions.size > 32 && submittedDescriptions.delete(submittedDescriptions.keys().next().value);
    }
    function savedDescription(hashValue, shared) {
        const local = submittedDescriptions.get(hex(hashValue)) || "";
        if (typeof HashstashProposalData === "object") return HashstashProposalData.verifiedText(shared, hex(hashValue)) || HashstashProposalData.verifiedText(local, hex(hashValue));
        return local;
    }
    // Earlier versions wrote every intermediate draft of a description to
    // localStorage under its own key. Remove that retired cache.
    try {
        for (let index = localStorage.length - 1; index >= 0; index--) {
            const name = localStorage.key(index);
            typeof name === "string" && name.startsWith("hashstash-description-") && localStorage.removeItem(name);
        }
    } catch {/* Cleanup of the retired draft cache is optional. */}
    function refreshExplanations() {
        if (typeof HashstashProposalData !== "object" || !state.ready || location.hash.split("?")[0] !== "#governance") return;
        const chain = state.status.chain_id;
        const activeId = hex(activeDecision()?.proposal_id);
        const known = proposalRecords();
        const activeRecord = activeId && (known.find(record => hex(record.id) === activeId) || { id: activeId, proposal: {} });
        const records = activeRecord ? [activeRecord, ...known.filter(record => hex(record.id) !== activeId)] : known;
        for (const record of records.slice(0, 40)) {
            const id = hex(record.id), cache = `${chain}:${id}`, request = `${cache}:${state.status.tip}`;
            if (proposalExplanations.has(cache) || explanationRequests.has(request)) continue;
            explanationRequests.add(request);
            rpc("explorer_governance", {
                proposal: id,
                limit: 1
            }).then(result => {
                if (result.chain_id !== chain) return;
                const p = result.proposals?.find(p => p.id === id);
                const verified = HashstashProposalData.verifiedText(p?.description_text, hex(record.proposal.description ?? p?.description));
                if (verified) {
                    proposalExplanations.set(cache, verified);
                    proposalExplanations.size > 200 && proposalExplanations.delete(proposalExplanations.keys().next().value);
                }
                if (state.ready && state.status.chain_id === chain) {
                    renderProposals();
                    renderDecisionMessage();
                }
            }).catch(() => {}).finally(() => {
                explanationRequests.size > 200 && explanationRequests.clear();
            });
        }
    }
    // The snapshot holds the first page of its round, best supported first.
    // Further pages of that order belong to the same tip and are dropped with it.
    function proposalRecords() {
        const extra = state.extraProposals;
        if (!extra || extra.tip !== state.status?.tip) return state.proposals;
        const listed = new Set(state.proposals.map(record => record.id));
        return [...state.proposals, ...extra.records.filter(record => !listed.has(record.id))];
    }
    function proposalTotal(records) {
        return Number.isSafeInteger(state.proposalsTotal) && state.proposalsTotal > records.length ? state.proposalsTotal : records.length;
    }
    async function loadMoreProposals(button) {
        const tip = state.status.tip, round = state.proposals[0]?.proposal.round;
        if (round === void 0) return;
        const loaded = state.extraProposals?.tip === tip ? state.extraProposals.records : [];
        button.disabled = true;
        try {
            const page = await rpc("proposals", {round, offset: state.proposals.length + loaded.length, tip});
            if (!Array.isArray(page)) throw new Error("Invalid proposals page.");
            if (state.status?.tip !== tip) return;
            state.extraProposals = {tip, records: [...loaded, ...page]};
            page.length || (state.proposalsTotal = state.proposals.length + loaded.length);
        } catch (error) {
            button.title = error.message;
        } finally {
            button.disabled = false;
        }
        renderProposals();
    }
    function renderProposals() {
        const list = $("proposal-list");
        const name = phaseName(), phase = state.gov.phase[name], round = phase.round;
        const records = proposalRecords().filter(p => round === void 0 || p.proposal.round === round);
        const total = proposalTotal(records);
        text("proposal-heading", name === "Rest" ? "Proposal history" : "Proposals");
        text("proposal-count", total > records.length ? `${commas(records.length)} of ${commas(total)} proposals` : `${records.length} proposal${records.length === 1 ? "" : "s"}`);
        if (!renderChanged(list, [ name, phase.leader, phase.proposal_id, key(), records, total, records.map(record => savedDescription(record.proposal.description, proposalExplanations.get(`${state.status.chain_id}:${hex(record.id)}`))), state.status?.settings ])) return;
        list.replaceChildren();
        if (!records.length) {
            const empty = append(list, "div", "panel empty-state");
            append(empty, "h3", "", "No proposals");
            return;
        }
        const leader = hex(phase.leader || phase.proposal_id);
        records.sort((a, b) => BigInt(a.proposal.support) === BigInt(b.proposal.support) ? a.id.localeCompare(b.id) : BigInt(a.proposal.support) > BigInt(b.proposal.support) ? -1 : 1);
        for (const record of records) {
            const p = record.proposal, row = append(list, "article", "proposal-card" + (record.id === leader ? " is-leader" : ""));
            const main = append(row, "div", "proposal-main");
            if (!p.action.Grant) append(main, "h3", "proposal-title", proposalTitle(p.action));
            if(p.action.Grant)renderGrantPayments(main,p.action.Grant,{payment_count:record.payment_count,id:record.id});
            const description = savedDescription(p.description, proposalExplanations.get(`${state.status.chain_id}:${hex(record.id)}`) ?? record.description_text ?? p.description_text);
            if (description) {
                const explanation = append(main, "details", "proposal-explanation");
                append(explanation, "summary", "", "Explanation");
                append(explanation, "p", "proposal-detail", visibleControls(description));
            }
            const winner = name === "Governance" && record.id === leader;
            const cancelled = p.refund_height !== null && p.refund_height !== void 0;
            const status = winner ? "In decision · bid becomes revenue" : name !== "Auction" || cancelled ? name === "Governance" ? "Not selected · backing may be refundable" : cancelled ? "Removed from auction" : "Past proposal" : record.id === leader ? "Current auction leader" : "In auction";
            append(main, "p", "proposal-detail", `Round ${p.round} · ${proposalShort(record.id)} · ${status}`);
            const side = append(row, "div", "proposal-side"), support = append(side, "div", "proposal-support");
            appendAmount(support, "strong", "", hashAmount(p.support));
            append(support, "small", "", "backing");
            const isSupport = name === "Auction" && p.round === round && !cancelled;
            // Rest lists the round that just ended. Its losing and timed-out
            // backers can reclaim support; the check tells a winner's backers
            // that theirs became revenue.
            if (!winner) {
                const button = append(side, "button", "button button-light", isSupport ? "Support ↗" : "Check refund ↙");
                button.type = "button";
                button.disabled = !key();
                key() || (button.title = isSupport ? "Select a wallet to support a proposal." : "Select a wallet to check your refundable support.");
                button.addEventListener("click", () => {
                    const form = $(isSupport ? "support-form" : "refund-form");
                    form.elements.proposal.value = record.id;
                    isSupport || (form.elements.round.value = p.round);
                    for (let parent = form.parentElement; parent; parent = parent.parentElement) parent.tagName === "DETAILS" && (parent.open = true);
                    form.scrollIntoView({
                        behavior: "smooth",
                        block: "center"
                    });
                    (isSupport ? form.elements.amount : form.elements.proposal).focus();
                    isSupport ? supportPreview() : checkSupport(form);
                    feeSoon(form);
                });
            }
            if (winner || name === "Rest") {
                const details = append(side, "a", "button button-light", "Details ↗");
                details.href = `#explorer?governance=${encodeURIComponent(record.id)}`;
            }
        }
        if (total > records.length) {
            const more = append(list, "button", "button button-light proposal-more", `Load more · ${commas(total - records.length)} not shown`);
            more.type = "button";
            more.addEventListener("click", () => loadMoreProposals(more));
        }
    }
    async function checkSupport(form) {
        try {
            const v = formValues(form);
            hexBytes(v.proposal, "Proposal ID");
            const round = safeInteger(v.round, "Round");
            const data = await rpc("support", {
                key: key(),
                round: round,
                proposal: v.proposal.trim()
            });
            feedback(form, `${formatExactHash(String(data.amount))} of your support. ${data.status === "converted_to_revenue" ? "This proposal won its round; its support became revenue and is never refundable." : data.refundable ? "Available for refund." : data.status === "none" ? "Nothing to refund." : "Not currently refundable."}`);
        } catch (error) {
            feedback(form, error.message, true);
        }
    }
    // Support is signed for a pasted 64-hex ID. Resolve it to the proposal it
    // backs before signing and show that action, so an ID passed around
    // elsewhere cannot silently back something else.
    const supportLookups = new Map;
    let supportPreviewVersion = 0;
    async function supportProposal(value) {
        const auction = state.gov?.phase?.Auction;
        if (!auction) throw new Error("There is no open auction.");
        const id = hex(hexBytes(value, "Proposal ID")).toLowerCase();
        const known = proposalRecords(), local = known.find(record => record.id === id);
        let proposal = local?.proposal;
        // The snapshot lists one page of the round; look up the rest.
        const unlisted = Number.isSafeInteger(state.proposalsTotal) ? state.proposalsTotal > known.length : known.length >= 128;
        if (!local && unlisted) {
            const chain = state.status.chain_id, cache = `${chain}:${state.status.tip}:${id}`;
            if (!supportLookups.has(cache)) {
                supportLookups.size > 50 && supportLookups.clear();
                supportLookups.set(cache, rpc("explorer_governance", {
                    proposal: id,
                    limit: 1
                }).then(result => result.chain_id === chain && result.proposals?.find(item => item.id === id) || null).catch(() => null));
            }
            const found = await supportLookups.get(cache);
            found && (proposal = {round: found.round, action: found.action});
        }
        if (!proposal?.action || String(proposal.round) !== String(auction.round) || proposal.refund_height !== null && proposal.refund_height !== void 0) throw new Error("This ID is not an active proposal in the current auction round.");
        return {id, action: proposal.action, payment_count: local?.payment_count};
    }
    async function supportPreview() {
        const version = ++supportPreviewVersion, node = $("support-proposal-preview"), raw = $("support-form").elements.proposal.value.trim();
        const shown = !!raw && state.ready;
        let target = null, message = "";
        if (shown) try {
            target = await supportProposal(raw);
        } catch (error) {
            message = error.message;
        }
        // Polling re-resolves the ID; leave an unchanged preview in place.
        if (version !== supportPreviewVersion || !renderChanged(node, [ shown, target, message, state.session?.address_hrp ])) return;
        node.replaceChildren();
        node.hidden = !shown;
        if (!shown) return;
        node.classList.toggle("error", !target);
        if (!target) {
            append(node, "p", "field-help", message);
            return;
        }
        append(node, "p", "field-help", `Backs proposal ${proposalShort(target.id)}:`);
        if (target.action.Grant) renderGrantPayments(node, target.action.Grant, target);
        else {
            const p = target.action.Parameter, setting = settings[p?.parameter];
            append(node, "p", "proposal-title", setting ? `${setting[1]}: ${settingValue(setting[0], p.old, setting[2], true)} → ${settingValue(setting[0], p.new, setting[2], true)}` : "Unknown action");
        }
    }
    function parameterPreview() {
        if (!state.status) return;
        const select = $("proposal-parameter");
        parameterAvailable(select.value) || (select.value = "BlockBytes");
        const parameter = select.value, setting = settings[parameter], old = state.status.settings[setting[0]], input = $("proposal-value");
        const margin = ["PassMarginBps", "MaxPriceChangeBps"].includes(parameter), positive = ["Interval", "DecisionBlocks", "BlockBytes"].includes(parameter);
        input.required = $("proposal-type").value === "parameter";
        text("proposal-value-label", parameter === "MinimumFeeRate" ? "Minimum fee rate · raw hashes / 1,024 weight" : `${setting[1]} · ${margin ? "%" : setting[2]}`);
        input.inputMode = margin ? "decimal" : "numeric";
        input.min = parameter === "BlockBytes" ? "1024" : positive ? "1" : "0";
        input.max = margin ? "184467440737095516.15" : parameter === "MinerFeePercent" ? "100" : "18446744073709551615";
        input.step = margin ? "0.01" : "1";
        let next;
        try {
            next = directParameterValue(parameter, input.value);
        } catch (error) {
            text("parameter-preview", `Current: ${settingValue(setting[0], old, setting[2])}`);
            $("parameter-preview").title = error.message;
            return;
        }
        text("parameter-preview", `${settingValue(setting[0], old, setting[2])} → ${settingValue(setting[0], next, setting[2])}`);
        $("parameter-preview").title = "Applies after rest if approved.";
    }
    function directParameterValue(parameter, value) {
        if (!parameterAvailable(parameter)) throw new Error("This network does not support this parameter.");
        const raw = String(value ?? "").trim();
        let next;
        if (["PassMarginBps", "MaxPriceChangeBps"].includes(parameter)) {
            if (raw.length > 24 || !/^\d+(?:\.\d{1,2})?$/.test(raw)) throw new Error("This percentage needs at most two decimal places.");
            const [whole, decimals = ""] = raw.split(".");
            next = BigInt(whole) * 100n + BigInt(decimals.padEnd(2, "0"));
        } else {
            if (raw.length > 20 || !/^\d+$/.test(raw)) throw new Error(`${settings[parameter][1]} must be a whole number without a unit suffix.`);
            next = BigInt(raw);
        }
        if (next > 18446744073709551615n) throw new Error("Setting exceeds the supported integer range.");
        if (["Interval", "DecisionBlocks", "BlockBytes"].includes(parameter) && next === 0n) throw new Error(`${settings[parameter][1]} must be positive.`);
        if (parameter === "BlockBytes" && next < 1024n) throw new Error("Block capacity must cover the miner account’s 1,024 weight.");
        if (parameter === "MinerFeePercent" && next > 100n) throw new Error("Miner fee share must be between 0 and 100%.");
        return next;
    }
    function networkView() {
        const s = state.status;
        feeView();
        sendView();
        $("guide-revenue").hidden = false;
        $("chat-nav").hidden = false;
        $("chat-enabled").hidden = false;
        $("guide-chat").hidden = false;
        text("network-revenue-label", "Waiting revenue");
        text("support-help", "Winning bid → revenue · losing bids → refunds.");
        text("grant-account-help", "Paid if PASS wins.");
        for (const [id, world] of [["pass", state.gov.pass], ["fail", state.gov.world]]) {
            text(`${id}-ratio`, reserveRatio(world));
            number(`${id}-revenue`, world?.revenue || "0");
        }
        text("guide-fees", `Transaction weight determines the minimum fee. Governance sets its rate and the miner's share. The entire fee, including any extra, currently goes ${s.settings.miner_fee_percent}% to the miner and ${100 - Number(s.settings.miner_fee_percent)}% to revenue.`);
        text("guide-proposals", "A proposal requests a grant or sets a new value for one network setting. Decision length uses blocks. Auction lead, rest and target interval use whole seconds. The miner’s fee share uses whole percentages from 0 to 100; PASS margin and the price-change limit use 0.01% steps. Block capacity uses weight; the minimum fee rate uses raw hashes per 1,024 weight.");
        text("guide-revenue-flow", "Revenue fills the gap between reserve and curve mass. This raises the reserve ratio toward 100%, making the curve flatter while keeping its current price and stash supply unchanged. Once the gap is filled, further revenue waits outside the reserve.");
        text("guide-grant-flow", "At the start of a grant decision, PASS sets aside the proposed payments from waiting revenue, then at most half of the reserve. FAIL moves the same reserve amount to its waiting revenue. Both curves become equally steeper, while the current price and stash supply stay unchanged. If PASS wins, the recipients receive those payments. If FAIL wins, revenue refills its reserve as far as the curve allows; FAIL sales during the decision paid the steeper curve's lower price and can leave part of that amount as revenue.");
        text("network-height", commas(s.height));
        number("network-issued", s.issued);
        text("network-clock", protocolDuration(s.clock));
        $("network-clock").title = `${commas(s.clock)} scheduled seconds`;
        text("timing-help", "Scheduled time");
        text("governance-common-label", "Available");
        $("governance-common-label").title = "Available for payments, before fees.";
        const outcomeHelp = "Two possible outcomes. Your balances continue from the winning side.";
        text("governance-outcome-help", outcomeHelp);
        text("guide-outcome-balances", "You can trade stash separately in PASS and FAIL. Payments and fees spend hashes in both, so the amount available for a payment is the smaller hash balance, less its fee.");
        document.querySelectorAll(".outcome-cash-label").forEach(node => {
            node.textContent = "Hashes";
        });
        text("guide-decision", "Each block compares the previous block’s exact closing stash prices before display rounding. PASS gets one leading block when its price beats FAIL by more than the required margin. PASS wins only with more than half of all decision blocks; a tie means FAIL. The margin and decision length are fixed when the decision begins.");
        text("guide-clock", "A decision lasts its configured number of blocks. Each block counts once toward PASS or FAIL. Auction lead and rest use a scheduled clock that advances by the target interval; mining determines the actual wait. Transaction expiry and confirmations also use block counts.");
        text("guide-difficulty", "ASERT, the difficulty-adjustment algorithm, uses block timestamps to aim for the governed average block interval. Only blocks on the accepted chain create new hashes; losing blocks receive no reward.");
        for (const field of [ "reserve", "revenue", "grant_capacity" ]) {
            const node = $(`network-${field}`);
            if (activeDecision()) {
                const pass = state.gov.pass[field] || "0", fail = state.gov.world[field] || "0";
                amountText(node, `PASS ${hashAmount(pass)}\nFAIL ${hashAmount(fail)}`);
                node.title = `PASS: ${formatExactHash(String(pass))}; FAIL: ${formatExactHash(String(fail))}`;
            } else number(`network-${field}`, s[field] || "0");
        }
        text("network-ratio", activeDecision() ? `PASS ${reserveRatio(state.gov.pass)} · FAIL ${reserveRatio(state.gov.world)}` : reserveRatio(state.gov.world));
        text("network-chain", s.chain_id);
        text("network-tip", s.tip);
        text("network-root", s.state_root);
        $("network-height").href = `#explorer?block=${encodeURIComponent(s.height)}`;
        const dl = $("network-settings");
        if (renderChanged(dl, [ s.settings ])) {
            dl.replaceChildren();
            for (const [parameter, [field, label, unit]] of Object.entries(settings)) {
                if (!parameterAvailable(parameter)) continue;
                const row = append(dl, "div");
                append(row, "dt", "", label);
                const amount = append(row, "dd", "", parameter === "MinerFeePercent" ? `${s.settings[field]}% · Revenue ${100 - Number(s.settings[field])}%` : settingValue(field, s.settings[field], unit));
                amount.title = settingValue(field, s.settings[field], unit, true);
            }
        }
        parameterPreview();
        const frozen = state.gov.frozen;
        text("timing-auction", `${protocolDuration(frozen.lead)} lead · ${protocolDuration(auctionTimeout())} limit`);
        text("timing-governance", blockCount(activeDecision()?.blocks ?? frozen.decision_blocks));
        text("timing-rest", protocolDuration(frozen.rest));
    }
    function miningView() {
        const data = state.ready ? state.miningInfo : null, stratum = data?.stratum;
        const available = !!stratum;
        available && stratum.enabled;
        text("mining-workers", available ? commas(data.workers_connected) : "—");
        amountText("mining-hashrate", data?.hashrate_hps == null ? "—" : formatHashrate(data.hashrate_hps));
        $("mining-hashrate").title = available ? data.hashrate_hps == null ? "Waiting for enough accepted shares to estimate hash rate." : `Estimated from accepted shares over ${duration(data.hashrate_window_seconds)}. ${formatExactWork(data.hashrate_hps)}/s.` : "";
        text("mining-shares", available ? `${commas(data.accepted_shares)} / ${commas(data.rejected_shares)}` : "—");
        $("mining-shares").title = available ? `${commas(data.accepted_shares)} accepted; ${commas(data.rejected_shares)} rejected since node start.` : "";
        text("mining-blocks", available ? commas(data.blocks_found) : "—");
        $("mining-blocks").title = available ? `${commas(data.blocks_found)} Stratum blocks found since node start.` : "";
        const workers = available && Array.isArray(data.workers) ? data.workers.slice(0, 64) : [];
        $("mining-worker-details").hidden = !workers.length;
        const list = $("mining-worker-list");
        if (!renderChanged(list, workers)) return;
        list.replaceChildren();
        for (const worker of workers) {
            const row = append(list, "div", "mining-worker-row");
            append(row, "span", "", worker.worker || "Unnamed");
            const shares = append(row, "span", "", `${commas(worker.accepted_shares)} / ${commas(worker.rejected_shares)}`);
            shares.title = `${commas(worker.accepted_shares)} accepted; ${commas(worker.rejected_shares)} rejected`;
            append(row, "span", "", worker.last_share_age_seconds == null ? "—" : `${duration(worker.last_share_age_seconds)} ago`);
        }
    }
    function resetContext() {
        transactionMail?.clear();
        state.ready = false;
        state.contextEpoch++;
        explorer?.update({
            ready: false,
            chain_id: state.session?.chain_id
        });
        chat?.update({
            ready: false,
            available: false,
            chain_id: state.session?.chain_id
        });
        mail?.update({
            node_id: state.contextEpoch,
            ready: false,
            available: false,
            chain_id: state.session?.chain_id
        });
        feeQuotes.clear();
        pendingFeeRefresh.clear();
        submissions.clear();
        feeForms.forEach(name => clearFeeAllocation($(`${name}-form`)));
        feeTimers.forEach(clearTimeout);
        feeTimers.clear();
        feeVersions.clear();
        networkPhaseView();
        state.account = state.pass = state.fail = state.balances = state.status = state.gov = state.miningInfo = null;
        state.proposals = [];
        state.proposalsTotal = state.extraProposals = null;
        renderDecisionMessage();
        state.mempool = [];
        state.senderMempool = state.pendingNonce = null;
        document.querySelectorAll("form").forEach(form => {
            // Public Explorer searches are independent of the selected wallet.
            if (!form.querySelector(".form-feedback")) return;
            form.reset();
            feedback(form, "");
        });
        $("unsigned-dialog").close();
        $("unsigned-output").value = "";
        $("wallet-switcher").close();
        clearBackup();
        importedPublic = null;
        tradeTab("deposit");
        sendVersion++;
        clearTimeout(sendTimer);
        state.sendQuote = null;
        state.sendFailed = false;
        text("send-net", "—");
        text("send-cost", "—");
        walletView();
        modeButtons();
    }
    async function loadSession() {
        const version = ++sessionVersion;
        const response = await fetch("/api/session", {
            cache: "no-store"
        });
        if (!response.ok) throw new Error(`Session unavailable (${response.status}).`);
        const remote = await exactJSON(response);
        if (version !== sessionVersion) return false;
        if (!/^[0-9a-f]{64}$/.test(remote.chain_id || "") || remote.address_hrp !== "hsh" + remote.chain_id.slice(0, 16)) throw new Error("Address network is unavailable.");
        if (walletChain !== remote.chain_id) {
            unsubscribeWallet?.();
            browserWallet?.destroy?.();
            browserWallet = null;
            walletStorageError = "";
            walletChain = remote.chain_id;
            try {
                browserWallet = HashstashBrowserWallet.createStore(walletChain);
                unsubscribeWallet = browserWallet.subscribe(() => {
                    resetContext();
                    state.managing || state.submitting || refresh();
                });
            } catch (error) {
                walletStorageError = error.message;
            }
        }
        let local = {
            wallets: [],
            wallet_id: null,
            wallet_revision: 0,
            public_key: null,
            wallet_enabled: false
        };
        try {
            if (browserWallet) {
                local = browserWallet.snapshot();
                walletStorageError = "";
            }
        } catch (error) {
            walletStorageError = error.message;
        }
        const session = {
            chain_id: remote.chain_id,
            address_hrp: remote.address_hrp,
            miner: remote.miner,
            token: remote.token,
            public_web: !!remote.public_web,
            ...local
        };
        !state.session || session.token === state.session.token && session.address_hrp === state.session.address_hrp && session.public_key === state.session.public_key && session.miner === state.session.miner && session.wallet_enabled === state.session.wallet_enabled && session.wallet_id === state.session.wallet_id && session.wallet_revision === state.session.wallet_revision || resetContext();
        state.session = session;
        text("wallet-storage-status", walletStorageError ? `Browser wallet unavailable: ${walletStorageError}` : "");
        $("wallet-storage-status").hidden = !walletStorageError;
        text("receive-key", address());
        walletView();
        return true;
    }
    async function refresh() {
        if (state.refreshing) return;
        state.refreshing = true;
        try {
            if (!await loadSession()) return;
            const identity = walletIdentity();
            // Do not disclose the association between every locally saved wallet.
            const keys = key() ? [key()] : [];
            const snapshot = await rpc("snapshot", {
                ...key() ? {
                    key: key()
                } : {},
                ...keys.length ? {
                    keys: keys
                } : {}
            });
            if (identity !== walletIdentity()) throw new Error("Wallet changed while refreshing. Retry refresh.");
            const {status: status, governance: gov, mempool: mempool, account: account, proposals: proposals, pass: pass, fail: fail, balances: balances, config: config, mining: miningInfo} = snapshot;
            if (!/^[0-9a-f]{64}$/.test(status.chain_id) || state.session.chain_id !== status.chain_id || state.session.address_hrp !== "hsh" + status.chain_id.slice(0, 16)) throw new Error("Address network changed. Refresh again.");
            state.status && status.chain_id !== state.status.chain_id && resetContext();
            const previousDecision = hex(activeDecision()?.id), previousNonce = nextNonce();
            const changedState = state.status?.tip !== status.tip || state.status?.state_root !== status.state_root || state.status?.height !== status.height || previousDecision !== hex(gov.phase?.Governance?.id);
            if (!config || typeof config.network !== "string" || !config.network.length || !/^[1-9][0-9]*$/.test(String(config.quote_scale)) || !/^[1-9][0-9]*$/.test(String(config.share_scale)) || !/^[0-9]+$/.test(String(config.auction_timeout))) throw new Error("Invalid network configuration.");
            state.config = config;
            $("test-work-notice").hidden = config.test_work !== true;
            settings.BlockBytes[1] = "Block capacity";
            settings.BlockBytes[2] = "weight";
            [ ...$("proposal-parameter").options ].find(option => option.value === "BlockBytes").textContent = settings.BlockBytes[1];
            state.status = status;
            state.gov = gov;
            state.mempool = mempool;
            state.senderMempool = key() && Array.isArray(snapshot.sender_mempool) ? snapshot.sender_mempool : null;
            state.pendingNonce = key() ? snapshot.pending_nonce ?? null : null;
            state.account = account;
            state.proposals = proposals;
            state.proposalsTotal = Number.isSafeInteger(snapshot.proposals_total) ? snapshot.proposals_total : null;
            state.extraProposals?.tip === status.tip || (state.extraProposals = null);
            state.pass = pass;
            state.fail = fail;
            state.balances = balances || null;
            state.miningInfo = miningInfo || null;
            state.ready = true;
            if (previousDecision !== hex(activeDecision()?.id)) {
                state.quoteVersion++;
                clearTimeout(quoteTimer);
                state.quoteOutput = null;
                state.quoteFailed = false;
                state.tradeAll = false;
                feeQuotes.delete("trade-form");
                clearFeeAllocation($("trade-form"));
                clearTimeout(feeTimers.get("trade-form"));
                feeVersions.set("trade-form", (feeVersions.get("trade-form") || 0) + 1);
                text("trade-fee-quote", "—");
                feeError($("trade-form"), "");
                text("trade-quote", "—");
                $("trade-quote").title = "";
                text("quote-height", "");
                $("quote-height").title = "";
                text("quote-remaining", "");
                $("quote-remaining").hidden = true;
                feedback($("trade-form"), "");
            }
            followSubmissions(previousDecision !== hex(activeDecision()?.id));
            networkPhaseView();
            text("reserve-ratio", `${reserveRatio(curveWorld())} reserve ratio`);
            text("header-height", commas(status.height));
            number("metric-reserve", status.reserve);
            number("metric-revenue", status.revenue);
            text("metric-pending", commas(status.mempool));
            governanceView();
            accountView();
            walletView();
            renderActivity();
            networkView();
            modeButtons();
            renderCurves();
            refreshExplanations();
            text("connection-label", "Connected");
            $("connection-dot").classList.remove("offline");
            alert("");
            explorer?.update({
                ready: true,
                chain_id: status.chain_id,
                tip: status.tip
            });
            refreshFaucet();
            chat?.update({
                ready: true,
                available: true,
                chain_id: status.chain_id,
                tip: status.tip,
                height: status.height,
                message_bytes: transactionByteLimit().toString()
            });
            $("mail-nav").hidden = false;
            mail?.update({
            node_id: state.contextEpoch,
                ready: true,
                available: true,
                chain_id: status.chain_id,
                tip: status.tip,
                height: status.height,
                key: key(),
                address: address(),
                wallet_id: state.session?.wallet_id,
                wallet_revision: state.session?.wallet_revision,
                can_decrypt: !!state.session?.wallet_enabled
            });
            !$("trade-amount").value || state.submitting || state.managing || !changedState && !state.quoteFailed || quoteSoon(true);
            $("send-form").elements.recipient.value && $("send-form").elements.amount.value && !state.submitting && !state.managing && (changedState || state.sendFailed) && sendSoon(true);
            if (!state.submitting && !state.managing) {
                feeForms.filter(name => !["trade","send"].includes(name) && (changedState || previousNonce !== nextNonce() || pendingFeeRefresh.has(`${name}-form`))).forEach(name => feeSoon($(`${name}-form`),true));
                if (pendingFeeRefresh.has("trade-form") && state.quoteOutput) feeSoon($("trade-form"), true);
                if (previousNonce !== nextNonce()) { sendSoon(true); if ($("trade-amount").value) quoteSoon(true); }
            }
        } catch (error) {
            state.ready = false;
            state.balances = null;
            state.quoteVersion++;
            state.quoteOutput = null;
            state.quoteFailed = true;
            clearTimeout(quoteTimer);
            sendVersion++;
            state.sendQuote = null;
            state.sendFailed = true;
            clearTimeout(sendTimer);
            text("send-net", "—");
            text("send-cost", "—");
            networkPhaseView();
            accountView();
            walletView();
            modeButtons();
            renderDecisionMessage();
            alert(`Could not refresh the node: ${error.message}`);
            text("connection-label", "Offline");
            $("connection-dot").classList.add("offline");
        } finally {
            state.refreshing = false;
            if (!state.ready) {
                explorer?.update({
                    ready: false,
                    chain_id: state.session?.chain_id
                });
            chat?.update({
                    ready: false,
                    available: false,
                    chain_id: state.session?.chain_id
                });
                mail?.update({
            node_id: state.contextEpoch,
                    ready: false,
                    available: false,
                    chain_id: state.session?.chain_id
                });
            }
        }
    }
    async function quote() {
        const version = ++state.quoteVersion, identity = tradeIdentity();
        const raw = $("trade-amount").value;
        state.quoteOutput = null;
        state.quoteFailed = false;
        modeButtons();
        if (!state.ready || !key()) return;
        if (!raw.trim()) {
            text("trade-quote", "—");
            text("quote-height", "");
            return;
        }
        try {
            const kind = state.trade, amount = kind === "deposit" ? integer(raw) : stashInteger(raw), outcome = $("trade-outcome").value;
            if (decisionClosing()) throw new Error(tradingClosedMessage);
            const result = await rpc("stash_quote", {
                key: key(),
                kind: kind,
                amount: amount,
                ...outcome ? {
                    outcome: outcome
                } : {},
                ...state.tradeAll && kind === "redeem" ? {
                    all: true
                } : {}
            });
            if (version !== state.quoteVersion || identity !== tradeIdentity() || !state.ready) return;
            if (hex(result.decision) !== hex(activeDecision()?.id)) throw new QuoteRefreshPending("Updating quote for the current decision.");
            for (const field of [ "input_requested", "input_filled", "input_unfilled", "output", "shares", "output_hash", "share_before", "share_after", "stash_before_hash", "stash_after_hash" ]) if (typeof result[field] !== "string" || !/^\d{1,160}$/.test(result[field])) throw new Error("Invalid Stash quote.");
            checkQuoteSnapshot(result);
            const requested = BigInt(result.input_requested), filled = BigInt(result.input_filled), unfilled = BigInt(result.input_unfilled);
            const owned = BigInt(snapshotAccount(outcome === "Pass" ? state.pass : outcome === "Fail" ? state.fail : state.account)?.shares || "0");
            if (result.kind !== kind || result.indicative !== true || result.partial_fill_possible !== true || result.execution !== "block_batch") throw new Error("Invalid Stash quote.");
            if (requested !== (state.tradeAll && kind === "redeem" ? owned : BigInt(amount)) || filled + unfilled !== requested) throw new Error("Quote does not match the requested amount.");
            const output = BigInt(result.output), before = BigInt(result.share_before), after = BigInt(result.share_after);
            if (before !== owned || (kind === "deposit" ? BigInt(result.shares) !== output || after !== before + output : filled > before || after !== before - filled || BigInt(result.shares) !== requested || BigInt(result.output_hash) !== output)) throw new Error("Invalid Stash quote.");
            state.tradeAll && kind === "redeem" && ($("trade-amount").value = HashstashShares.exactInput(result.input_requested));
            amountText("trade-quote", kind === "deposit" ? `${HashstashShares.formatAmount(result.shares)} stash` : formatExactHash(result.output_hash));
            $("trade-quote").title = kind === "deposit" ? `${HashstashShares.exactInput(result.shares)} stash` : formatExactHash(result.output_hash);
            const unused = kind === "deposit" ? formatExactHash(result.input_unfilled) : `${HashstashShares.formatAmount(result.input_unfilled)} stash`;
            amountText("quote-remaining", unfilled > 0n ? `Estimated unused: ${unused}` : `Stash balance: ${HashstashShares.formatAmount(result.share_after)} stash`);
            $("quote-remaining").title = unfilled > 0n ? "This amount would stay in your balance. The final fill depends on the other orders included." : `${HashstashShares.exactInput(result.share_after)} stash`;
            $("quote-remaining").hidden = false;
            text("quote-height", filled === 0n ? "No fill estimated. A fee still applies if included." : "Final amount may differ or fill partly. Fee shown below.");
            $("quote-height").title = `Estimated at block ${commas(result.height)}. Orders in the same block share an execution price. Unfilled input stays in your balance.`;
            state.quoteOutput = {
                ...result,
                identity: tradeIdentity()
            };
            feeSoon($("trade-form"), true);
        } catch (error) {
            if (version === state.quoteVersion && identity === tradeIdentity() && state.ready) {
                state.quoteFailed = true;
                if (error instanceof QuoteRefreshPending) return;
                clearFeeAllocation($("trade-form"));
                text("trade-quote", "Quote unavailable");
                text("quote-height", error.message);
                text("quote-remaining", "");
                $("quote-remaining").hidden = true;
                text("trade-fee-quote", "—");
            }
        } finally {
            modeButtons();
        }
    }
    function sendView() {

        text("send-amount-label", "Amount · hash");
        text("guide-transfer-fees", "The wallet signs one exact fee: the required minimum plus any extra you choose. Inclusion charges that full amount. If the minimum rises above it first, prepare a new transaction with a sufficient fee.");
    }
    function sendIdentity() {
        const v = formValues($("send-form"));
        return JSON.stringify([ walletIdentity(), state.status?.chain_id, state.status?.tip, state.status?.state_root, state.status?.height, state.status?.settings?.miner_fee_percent, state.status?.settings?.minimum_fee_rate, v.recipient, v.amount, v.extra_fee, v.data_format, v.data_text, v.data_hex, attachmentIdentity($("send-form")), $("wallet-expiry").value ]);
    }
    async function previewSend() {
        const version = ++sendVersion, identity = sendIdentity(), form = $("send-form"), v = formValues(form);
        state.sendQuote = null;
        state.sendFailed = false;
        modeButtons();
        if (!state.ready || !key()) return;
        if (!v.recipient.trim() || !v.amount.trim()) {
            text("send-net", "—");
            return;
        }
        try {
            const recipient = recipientKey(form), amount = integer(v.amount);
            await prepareTransactionData(form);
            if (version !== sendVersion || identity !== sendIdentity() || !state.ready) return;
            let fee = "0";
            let charge, net, total;
            {
                const extra = integer(v.extra_fee, "Optional extra", true);
                const result = await rpc("transfer_quote", {
                    sender: key(),
                    recipient: recipient,
                    amount: amount,
                    ...transactionData(form),
                    extra_fee: extra,
                    anchor: state.status.tip,
                    expiry_blocks: jsonInteger(transactionExpiry($("send-form"))),
                    nonce: jsonInteger(nextNonce())
                });
                if (version !== sendVersion || identity !== sendIdentity() || !state.ready) return;
                checkFeeQuote(result, extra, form);
                for (const field of [ "amount", "recipient_receives", "total_debit" ]) if (typeof result[field] !== "string" || !/^(0|[1-9]\d{0,159})$/.test(result[field])) throw new Error("Invalid payment quote.");
                if (result.public_key !== recipient || result.recipient !== address(recipient) || result.amount !== amount || result.recipient_receives !== amount || result.pending !== false) throw new Error("Payment quote does not match the requested transfer.");
                if (BigInt(result.total_debit) !== BigInt(amount) + BigInt(result.fee)) throw new Error("Invalid payment quote totals.");
                checkOutcomeFunds({
                    TransferExact: {
                        amount: amount
                    }
                }, result.fee);
                fee = result.fee;
                charge = BigInt(result.account_creation_fee);
                net = BigInt(amount);
                total = BigInt(result.total_debit);
                state.sendQuote = {
                    ...result,
                    identity: identity
                };
                showFeeQuote(form, result);
            }
            amountText("send-net", formatExactHash(net));
            $("send-net").title = formatExactHash(net);
            amountText("send-cost", `Total ${formatExactHash(total)}`);
            $("send-cost").title = `Exact total debit: ${formatExactHash(total)}. Any account creation charge is included in the fee.`;
        } catch (error) {
            if (version === sendVersion && identity === sendIdentity() && state.ready) {
                state.sendQuote = null;
                feeQuotes.delete(form.id);
                state.sendFailed = true;
                if (error instanceof QuoteRefreshPending) return;
                clearFeeAllocation(form);
                text("send-net", "Check payment details");
                text("send-cost", error.message);
            }
        } finally {
            modeButtons();
        }
    }
    function sendSoon(preserveDisplay = false) {
        // The last display is independent of whether it may authorize a spend.
        // Repeated background refreshes must not erase it while a request waits.
        const keepDisplay = preserveDisplay === true;
        sendVersion++;
        state.sendQuote = null;
        state.sendFailed = false;
        clearTimeout(sendTimer);
        feeQuotes.delete("send-form");
        if (!keepDisplay) {
            clearFeeAllocation($("send-form"));
            feeError($("send-form"), "");
            text("send-fee-quote", "—");
            text("send-net", "—");
            text("send-cost", "—");
            $("send-net").title = "";
            $("send-cost").title = "";
        }
        modeButtons();
        sendTimer = setTimeout(previewSend, 250);
    }
    function quoteSoon(preserveDisplay = false) {
        const keepDisplay = preserveDisplay === true;
        state.quoteVersion++;
        state.quoteOutput = null;
        state.quoteFailed = false;
        clearTimeout(quoteTimer);
        feeQuotes.delete("trade-form");
        if (!keepDisplay) {
            clearFeeAllocation($("trade-form"));
            feeError($("trade-form"), "");
            text("trade-fee-quote", "—");
            text("trade-quote", "—");
            $("trade-quote").title = "";
            text("quote-height", "");
            $("quote-height").title = "";
            text("quote-remaining", "");
            $("quote-remaining").hidden = true;
        }
        $("trade-max").setAttribute("aria-pressed", String(state.tradeAll));
        modeButtons();
        quoteTimer = setTimeout(quote, 350);
    }
    function tradeIdentity() {
        return JSON.stringify([ walletIdentity(), state.status?.chain_id, activeDecision()?.id, state.trade, state.tradeAll, $("trade-amount").value, $("trade-outcome").value, $("trade-form").elements.extra_fee.value, $("trade-expiry").value, $("trade-form").elements.data_format.value, $("trade-form").elements.data_text.value, $("trade-form").elements.data_hex.value, attachmentIdentity($("trade-form")) ]);
    }
    function tradeTab(kind) {
        $("trade-form").dataset.trade = kind;
        state.quoteVersion++;
        clearTimeout(quoteTimer);
        state.trade = kind;
        state.tradeAll = false;
        state.quoteOutput = null;
        state.quoteFailed = false;
        $("trade-amount").value = "";
        $("trade-max").setAttribute("aria-pressed", "false");
        document.querySelectorAll("[data-trade-tab]").forEach(button => button.classList.toggle("selected", button.dataset.tradeTab === kind));
        text("trade-amount-label", kind === "deposit" ? "Spend · hash" : "Sell · stash");
        text("trade-unit", kind === "deposit" ? "hash" : "stash");
        $("trade-amount").inputMode = "decimal";
        $("trade-amount").title = kind === "deposit" ? "Amount in hashes; up to 3 decimal places." : "Amount in stash; up to 3 decimal places.";
        text("quote-label", "Estimated receive");
        text("trade-submit", kind === "deposit" ? "Buy stash" : "Sell stash");
        text("trade-quote", "—");
        text("quote-height", "");
        $("quote-height").title = "";
        text("quote-remaining", "");
        $("quote-remaining").hidden = true;
        feedback($("trade-form"), "");
        renderCurves();
        modeButtons();
    }
    async function copyKey() {
        if (!key()) {
            location.hash = "#wallet";
            return;
        }
        try {
            await navigator.clipboard.writeText(address());
            toast("Address copied.");
        } catch {
            toast("Copy the address shown in Payments.");
            location.hash = "send";
        }
    }
    function downloadText(name, content) {
        const url = URL.createObjectURL(new Blob([ content ], {
            type: "text/plain;charset=utf-8"
        }));
        const link = document.createElement("a");
        link.href = url;
        link.download = name;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1e3);
    }
    function walletBalancesView(node, publicKey) {
        const balances = state.ready ? state.balances?.[hex(publicKey).toLowerCase()] : void 0;
        const conditional = state.ready && !!activeDecision();
        const outcomes = conditional ? [ [ "account", "Available" ], [ "pass", "PASS" ], [ "fail", "FAIL" ] ] : [ [ "account", "" ] ];
        if (!renderChanged(node, [ hex(publicKey), outcomes, balances, true ])) return;
        node.replaceChildren();
        node.dataset.conditional = String(conditional);
        const heading = append(node, "span", "wallet-balance-heading");
        append(heading, "span", "", "");
        append(heading, "span", "unit-hash", "hash");
        append(heading, "span", "unit-stash", "stash");
        for (const [field, label] of outcomes) {
            const balance = balances?.[field], row = append(node, "span", "wallet-balance-row");
            row.dataset.outcome = field;
            append(row, "small", "wallet-balance-outcome", label);
            const cash = conditional && field === "account" ? paymentCash(balances?.pass, balances?.fail, balances?.account) : balance === void 0 ? null : conditional && field !== "account" ? balance?.["ordinary"] || "0" : balance?.ordinary || "0";
            const shares = balance === void 0 ? null : balance?.shares || "0";
            const hash = append(row, "span", "wallet-balance-hash");
            const stash = append(row, "span", "wallet-balance-stash");
            compactAmount(hash, cash === null ? "— hash" : hashAmount(cash));
            compactAmount(stash, conditional && field === "account" ? "" : `${shares === null ? "—" : HashstashShares.formatAmount(shares)} stash`);
            hash.title = cash === null ? "" : formatExactHash(cash);
            stash.title = shares === null ? "" : `${HashstashShares.exactInput(shares)} stash`;
        }
        node.title = conditional ? "Available is the smaller outcome cash balance, before fees, already included in each outcome. Only the winner survives. Do not add these values together." : "";
    }
    function walletSelectorAmount(node, formatted, raw, decimals) {
        compactAmount(node, formatted);
        if (raw !== null && BigInt(raw) > 0n && BigInt(raw) * 1000000n < 10n ** BigInt(decimals)) node.textContent = "<0.000001";
    }
    function walletSelectorBalancesView() {
        const node = $("account-summary"), balances = state.ready ? state.balances?.[hex(key()).toLowerCase()] : void 0;
        const conditional = state.ready && !!activeDecision();
        if (!renderChanged(node, [ key(), balances, conditional ])) return;
        node.replaceChildren();
        const account = balances?.account;
        const cash = conditional ? paymentCash(balances?.pass, balances?.fail, account) : account === null ? "0" : account?.ordinary ?? null;
        const cashGroup = append(node, "span", "account-summary-asset");
        if (conditional) append(cashGroup, "span", "sr-only", "Available before fees ");
        const cashValue = append(cashGroup, "span", "account-summary-cash");
        walletSelectorAmount(cashValue, cash === null ? "— hash" : hashAmount(cash), cash, HashstashAmounts.DISPLAY_DECIMALS);
        cashValue.title = cash === null ? "Unavailable" : `${conditional ? "Available before fees · " : ""}${formatExactHash(cash)}`;
        append(cashGroup, "span", "unit-hash", "hash");
        const sharesGroup = append(node, "span", "account-summary-asset account-summary-shares");
        for (const [field, label] of conditional ? [ [ "pass", "PASS" ], [ "fail", "FAIL" ] ] : [ [ "account", "" ] ]) {
            const balance = balances?.[field], shares = balance === null ? "0" : balance?.shares ?? null;
            const holding = append(sharesGroup, "span", "account-summary-holding");
            holding.dataset.outcome = field;
            if (label) append(holding, "small", "account-summary-outcome", label);
            const value = append(holding, "span", "account-summary-stash");
            walletSelectorAmount(value, `${shares === null ? "—" : HashstashShares.formatAmount(shares)} stash`, shares, HashstashShares.DISPLAY_DECIMALS);
            value.title = shares === null ? "Unavailable" : `${label ? label + " · " : ""}${HashstashShares.exactInput(shares)} stash`;
        }
        append(sharesGroup, "span", "unit-stash", "stash");
    }
    function walletView() {
        const session = state.session;
        if (!session) return;
        const wallets = session.wallets || [], selector = $("account-select");
        selector.hidden = wallets.length === 0;
        $("wallet-current").hidden = !key();
        $("view-wallet").dataset.hasWallet = String(!!key());
        const fingerprint = JSON.stringify([ wallets, session.wallet_id, session.address_hrp ]);
        if (selector.dataset.wallets !== fingerprint) {
            const list = $("wallet-switcher-list");
            list.replaceChildren();
            walletBalanceNodes.clear();
            for (const wallet of wallets) {
                const entry = append(list, "button", "wallet-entry");
                entry.type = "button";
                entry.dataset.walletId = wallet.id;
                const selected = wallet.id === session.wallet_id;
                entry.setAttribute("aria-pressed", String(selected));
                entry.title = address(wallet.public_key);
                const copy = append(entry, "span", "wallet-entry-copy");
                const heading = append(copy, "span", "wallet-entry-heading");
                append(heading, "strong", "", shortAddress(wallet.public_key));
                append(heading, "small", "wallet-mode-badge", wallet.mode === "hot" ? "Hot wallet" : "Watch only");
                walletBalanceNodes.set(wallet.id, {
                    publicKey: wallet.public_key,
                    node: append(copy, "span", "wallet-balances")
                });
                const check = append(entry, "span", "wallet-entry-check", selected ? "✓" : "");
                check.setAttribute("aria-hidden", "true");
                entry.addEventListener("click", async () => {
                    if (state.managing || state.submitting) return;
                    if (state.session?.wallet_id === wallet.id) {
                        $("wallet-switcher").close();
                        return;
                    }
                    try {
                        await manageWallet("select", {
                            id: wallet.id
                        });
                        $("wallet-switcher").close();
                        walletMessage("");
                    } catch (error) {
                        walletView();
                        walletMessage(error.message, true);
                        toast(error.message);
                    }
                });
            }
            selector.dataset.wallets = fingerprint;
        }
        for (const {publicKey: publicKey, node: node} of walletBalanceNodes.values()) walletBalancesView(node, publicKey);
        selector.value = session.wallet_id || "";
        text("wallet-name", "Balances");
        text("account-label", shortAddress(key()));
        walletSelectorBalancesView();
        walletBalancesView($("account-balances"), key());
        selector.title = address();
        text("wallet-kind", key() ? session.wallet_enabled ? "Hot wallet" : "Watch only" : "");
        text("wallet-public", address());
        $("wallet-public").title = address();
        $("wallet-explore").href = `#explorer?account=${encodeURIComponent(address())}`;
        $("export-private").hidden = !session.wallet_enabled;
        modeButtons();
    }
    function walletMessage(message, failed = false) {
        text("wallet-feedback", message);
        $("wallet-feedback").classList.toggle("error", failed);
    }
    function clearBackup() {
        privateBackup = null;
        $("backup-private").value = "";
        $("backup-dialog").close();
    }
    function walletForm(selected) {
        for (const name of [ "import", "watch" ]) $("wallet-" + name + "-panel").hidden = name !== selected;
        document.querySelectorAll("[data-wallet-form]").forEach(button => button.setAttribute("aria-expanded", String(button.dataset.walletForm === selected)));
        $("import-private-key").value = "";
        importedPublic = null;
        walletMessage("");
    }
    async function manageWallet(action, values = {}) {
        if (!state.session) throw new Error("Wait for the node connection.");
        if (!browserWallet || walletStorageError) throw new Error(walletStorageError || "Browser wallet storage is unavailable.");
        if (state.managing || state.submitting) throw new Error("Wait for the current action to finish.");
        const identity = walletIdentity(), revision = state.session.wallet_revision, guard = {
            wallet_revision: revision
        };
        state.managing = true;
        modeButtons();
        try {
            let result;
            if (action === "create") result = await browserWallet.create(guard); else if (action === "import") {
                if (values.public_key && HashstashBrowserWallet.publicKey(values.private_key) !== values.public_key) throw new Error("Backup public key does not match.");
                result = await browserWallet.importPrivate(values.private_key, guard);
            } else if (action === "watch") result = await browserWallet.watch(values.public_key, guard); else if (action === "select") result = await browserWallet.select(values.id, guard); else {
                if (action !== "export") throw new Error("Unknown wallet action.");
                result = {
                    format: "hashstash-private-v1",
                    private_key: await browserWallet.exportPrivate(values.id, guard),
                    public_key: key()
                };
            }
            if (action === "export") {
                if (identity !== walletIdentity()) throw new Error("Wallet changed. Request the backup again.");
                return result;
            }
            // Tabs on this site share the browser's wallet selection.
                        await loadSession();
            await refresh();
            return result;
        } finally {
            state.managing = false;
            modeButtons();
        }
    }
    $("account-select").addEventListener("click", () => {
        state.managing || state.submitting || !state.session?.wallets?.length || $("wallet-switcher").showModal();
    });
    $("wallet-switcher-close").addEventListener("click", () => $("wallet-switcher").close());
    $("wallet-switcher-manage").addEventListener("click", () => $("wallet-switcher").close());
    document.querySelectorAll("[data-wallet-form]").forEach(button => button.addEventListener("click", () => walletForm(button.dataset.walletForm)));
    document.querySelectorAll("[data-wallet-cancel]").forEach(button => button.addEventListener("click", () => walletForm(null)));
    $("wallet-create").addEventListener("click", async () => {
        try {
            await manageWallet("create");
            walletForm(null);
            walletMessage("Wallet created in this browser. Back up its private key.");
        } catch (error) {
            walletMessage(error.message, true);
        }
    });
    $("wallet-import-form").addEventListener("submit", async event => {
        event.preventDefault();
        const form = $("wallet-import-form");
        try {
            const privateKey = hex(hexBytes(form.elements.private_key.value, "Private key"));
            const values = {
                private_key: privateKey,
                ...importedPublic ? {
                    public_key: importedPublic
                } : {}
            };
            form.elements.private_key.value = "";
            importedPublic = null;
            await manageWallet("import", values);
            walletForm(null);
            walletMessage("Wallet imported into this browser. Keep your backup.");
        } catch (error) {
            feedback(form, error.message, true);
        }
    });
    $("import-private-key").addEventListener("input", () => {
        importedPublic = null;
    });
    $("import-private-file").addEventListener("change", async () => {
        const form = $("wallet-import-form");
        try {
            const file = $("import-private-file").files[0];
            if (!file) return;
            if (file.size > 4096) throw new Error("Private key file is too large.");
            let value = (await file.text()).trim(), publicKey = null;
            if (value.startsWith("{")) {
                const data = JSON.parse(value), modern = data.format === "hashstash-private-v1";
                const allowed = modern ? [ "format", "private_key", "public_key" ] : [ "secret", "public" ];
                if (Object.keys(data).some(name => !allowed.includes(name))) throw new Error("Invalid private key file.");
                value = modern ? data.private_key : data.secret;
                publicKey = modern ? data.public_key : data.public;
                publicKey !== void 0 && (publicKey = hex(hexBytes(publicKey)));
            }
            form.elements.private_key.value = hex(hexBytes(value, "Private key"));
            importedPublic = publicKey;
            feedback(form, "Key file loaded.");
        } catch (error) {
            form.elements.private_key.value = "";
            importedPublic = null;
            feedback(form, error.message, true);
        } finally {
            $("import-private-file").value = "";
        }
    });
    $("watch-form").addEventListener("submit", async event => {
        event.preventDefault();
        const form = $("watch-form");
        try {
            await manageWallet("watch", {
                public_key: addressKey(form.elements.public_key.value)
            });
            walletForm(null);
            walletMessage("Watch-only account added.");
        } catch (error) {
            feedback(form, error.message, true);
        }
    });
    $("watch-file").addEventListener("change", async () => {
        const form = $("watch-form");
        const identity = walletIdentity();
        try {
            const file = $("watch-file").files[0];
            if (!file) return;
            if (file.size > 4096) throw new Error("Public key file is too large.");
            let value = (await file.text()).trim();
            if (identity !== walletIdentity()) throw new Error("Wallet or network changed. Load the file again.");
            if (value.startsWith("{")) {
                const data = JSON.parse(value);
                if (data.format === "hashstash-watch-v2") {
                    if (Object.keys(data).some(name => ![ "format", "address", "public_key", "chain_id" ].includes(name)) || data.chain_id !== state.status?.chain_id || typeof data.public_key !== "string" || addressKey(data.address) !== hex(hexBytes(data.public_key))) throw new Error("Invalid address file or different network.");
                    value = data.address;
                } else {
                    if (data.format !== "hashstash-watch-v1" || typeof data.public_key !== "string" || Object.keys(data).some(name => ![ "format", "public_key" ].includes(name))) throw new Error("Invalid address file.");
                    value = address(hex(hexBytes(data.public_key)));
                }
            } else /^[a-f0-9]{64}$/i.test(value) && (value = address(value));
            form.elements.public_key.value = address(addressKey(value));
            feedback(form, "Address loaded.");
        } catch (error) {
            form.elements.public_key.value = "";
            feedback(form, error.message, true);
        } finally {
            $("watch-file").value = "";
        }
    });
    $("export-network").addEventListener("click", () => {
        state.ready && downloadText("hashstash-network.json", JSON.stringify({
            format: "hashstash-network-v1",
            chain_id: state.status.chain_id
        }, null, 2) + "\n");
    });
    $("export-private").addEventListener("click", async () => {
        try {
            clearBackup();
            const expected = key(), result = await manageWallet("export", {
                id: state.session.wallet_id
            });
            if (result.format !== "hashstash-private-v1" || result.public_key !== expected || !/^[a-f0-9]{64}$/i.test(result.private_key || "")) throw new Error("Invalid private key backup.");
            privateBackup = result;
            $("backup-private").value = result.private_key;
            $("backup-dialog").showModal();
        } catch (error) {
            walletMessage(error.message, true);
        }
    });
    $("backup-close").addEventListener("click", clearBackup);
    $("backup-dialog").addEventListener("close", () => {
        privateBackup = null;
        $("backup-private").value = "";
    });
    $("backup-copy").addEventListener("click", async () => {
        try {
            if (!privateBackup) return;
            await navigator.clipboard.writeText(privateBackup.private_key);
            toast("Private key copied.");
        } catch {
            toast("Select and copy the private key.");
        }
    });
    $("backup-download").addEventListener("click", () => {
        privateBackup && downloadText("hashstash-private-key.json", JSON.stringify(privateBackup, null, 2) + "\n");
    });
    $("broadcast-form").addEventListener("submit", async event => {
        event.preventDefault();
        const form = $("broadcast-form");
        if (state.broadcasting) return;
        try {
            if (!state.ready) throw new Error("Wait for the node connection to refresh.");
            const raw = $("broadcast-raw").value.trim();
            if (!raw || raw.length % 2 || BigInt(raw.length) > transactionByteLimit() * 2n || !/^[a-f0-9]+$/i.test(raw)) throw new Error("Enter a signed transaction within the block capacity, in hexadecimal format.");
            state.broadcasting = true;
            modeButtons();
            feedback(form, "Broadcasting…");
            const result = await rpc("broadcasttransaction", {
                raw: raw
            });
            if (!result?.transaction_id) throw new Error("The node did not return a transaction ID.");
            // Follow the selected account's own broadcasts by sender nonce, as
            // the transaction forms do. Another account's is not refreshed here.
            let signed = null;
            try {
                signed = HashstashBrowserWallet.verifySigned(raw, {chain_id: state.status?.chain_id});
            } catch {
                // The node accepted bytes this page cannot decode or verify
                // for its network; it reports only the ID.
            }
            if (signed?.txid === result.transaction_id && signed.sender === key()) {
                feedback(form, `Pending · ${short(result.transaction_id)}`);
                trackSubmission(form, result.transaction_id, signed.sender, signed.nonce);
            } else {
                feedback(form, `Broadcast · ${short(result.transaction_id)}. This form follows only the selected account's transactions.`);
            }
            toast("Transaction broadcast.");
            await refresh();
        } catch (error) {
            feedback(form, error.message, true);
        } finally {
            state.broadcasting = false;
            modeButtons();
        }
    });
    $("broadcast-file").addEventListener("change", async () => {
        try {
            const file = $("broadcast-file").files[0];
            if (!file) return;
            if (BigInt(file.size) > transactionByteLimit() * 2n + 2n) throw new Error("Signed transaction file exceeds the block capacity.");
            $("broadcast-raw").value = (await file.text()).trim();
            feedback($("broadcast-form"), "");
        } catch (error) {
            feedback($("broadcast-form"), error.message, true);
        } finally {
            $("broadcast-file").value = "";
        }
    });
    $("unsigned-close").addEventListener("click", () => $("unsigned-dialog").close());
    $("unsigned-copy").addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText($("unsigned-output").value);
            toast("Unsigned transaction copied.");
        } catch {
            toast("Select and copy the transaction text.");
        }
    });
    $("unsigned-download").addEventListener("click", () => downloadText("hashstash-unsigned.json", $("unsigned-output").value));
    bindForm("trade-form", v => {
        const amount = state.trade === "deposit" ? integer(v.amount) : stashInteger(v.amount), ctx = context(v.outcome), quote = state.quoteOutput;
        if (decisionClosing()) throw new Error(tradingClosedMessage);
        if (activeDecision() && !v.outcome) throw new Error("Choose PASS or FAIL while governance is active.");
        if (!quote || quote.identity !== tradeIdentity()) throw new Error("Wait for a current quote.");
        if (hex(quote.decision) !== hex(ctx.decision)) throw new Error("Decision changed. Refresh and submit again.");
        return state.trade === "deposit" ? {
            Deposit: {
                amount: amount,

                ...ctx
            }
        } : {
            Redeem: {
                shares: quote.input_requested,

                ...ctx
            }
        };
    });
    bindForm("mail-form", async v => {
        if (!mail) throw new Error("Mail is unavailable on this network.");
        recipientKey($("mail-form"));
        const recipient = hexBytes(key()), amount = "1";
        await mail.prepare();
        return {
            TransferExact: {
                recipient: recipient,
                amount: amount
            }
        };
    });
    bindForm("send-form", v => {
        const recipient = hexBytes(recipientKey($("send-form"))), amount = integer(v.amount);
        const quote = state.sendQuote;
        if (!quote || quote.identity !== sendIdentity()) throw new Error("Wait for a current payment quote.");
        return {
            TransferExact: {
                recipient: recipient,
                amount: amount
            }
        };
    });
    bindForm("support-form", async v => {
        const auction = state.gov?.phase?.Auction;
        if (!auction) throw new Error("There is no open auction.");
        const target = await supportProposal(v.proposal);
        return {
            Support: {
                round: auction.round,
                proposal: hexBytes(target.id, "Proposal ID"),
                amount: integer(v.amount)
            }
        };
    });
    $("support-form").elements.proposal.addEventListener("input", supportPreview);
    bindForm("refund-form", v => ({
        Refund: {
            round: safeInteger(v.round, "Auction round"),
            proposal: hexBytes(v.proposal, "Proposal ID")
        }
    }));
    bindForm("propose-form", async v => {
        const auction = state.gov?.phase?.Auction;
        if (!auction) throw new Error("There is no open auction.");
        let proposal;
        if (v.type === "grant") {
            const payments = await grantPayments(), amount = grantTotal(payments);
            const quote = await rpc("grant_quote", {
                amount: amount
            });
            if (!quote.feasible) throw new Error("Grant exceeds the available revenue and half of the reserve.");
            proposal = {
                Grant: {
                    payments
                }
            };
        } else {
            if (!parameterAvailable(v.parameter)) throw new Error("This network does not support this parameter.");
            const current = BigInt(state.status.settings[settings[v.parameter][0]]), next = directParameterValue(v.parameter, v.parameter_value);
            if (next === current) throw new Error("Choose a different value.");
            proposal = {
                Parameter: {
                    parameter: v.parameter,
                    old: jsonInteger(current),
                    new: jsonInteger(next)
                }
            };
        }
        const encrypted = $("propose-form").elements.data_format?.value === "private";
        const descriptionBytes = encrypted ? new Uint8Array(transactionData($("propose-form")).data_hex.match(/../g).map(value => parseInt(value,16))) : (new TextEncoder).encode(v.description.trim());
        const description = new Uint8Array(await crypto.subtle.digest("SHA-256", descriptionBytes));
        return {
            Propose: {
                round: auction.round,
                description: Array.from(description),
                proposal: proposal,
                support: integer(v.support, "Initial support")
            }
        };
    });
    $("skip-link").addEventListener("click", event => {
        event.preventDefault();
        $("main-content").focus();
    });
    $("grant-add").addEventListener("click",()=>{addGrantRow();feeSoon($("propose-form"));});
    addGrantRow();
    window.addEventListener("hashchange", route);
    route();
    window.addEventListener("resize", renderCurves);
    document.querySelectorAll("[data-trade-tab]").forEach(button => button.addEventListener("click", () => tradeTab(button.dataset.tradeTab)));
    $("trade-amount").addEventListener("input", () => {
        state.tradeAll = false;
        quoteSoon();
    });
    $("trade-form").elements.extra_fee.addEventListener("input", () => {
        quoteSoon();
    });
    $("trade-form").elements.data_hex.addEventListener("input", quoteSoon);
    $("trade-form").elements.data_text.addEventListener("input", quoteSoon);
    for (const field of ["mail_recipient","mail_subject","mail_body"]) $("trade-form").elements[field].addEventListener("input", quoteSoon);
    $("trade-form").addEventListener("change", quoteSoon);
    $("send-form").addEventListener("input", sendSoon);
    $("send-form").addEventListener("change", sendSoon);
    $("trade-outcome").addEventListener("change", () => {
        state.tradeAll = false;
        accountView();
        renderCurves();
        quoteSoon();
    });
    $("trade-max").addEventListener("click", async () => {
        const outcome = $("trade-outcome").value, selected = outcome === "Pass" ? state.pass : outcome === "Fail" ? state.fail : state.account;
        if (!state.ready || !selected?.account) return;
        if (decisionClosing()) {
            feedback($("trade-form"), tradingClosedMessage, true);
            return;
        }
        state.tradeAll = state.trade === "redeem";
        let value = BigInt(state.tradeAll ? selected.account.shares : outcome ? outcomeCash(selected) : selected.account.ordinary);
        let warning = "";
        if (state.trade === "deposit") {
            const identity = tradeIdentity(), snapshot = state.status.state_root, balance = value;
            try {
                const extra = integer($("trade-form").elements.extra_fee.value, "Optional extra", true);
                for (let attempt = 0; attempt < 8; attempt++) {
                    if (value <= 0n) break;
                    const quote = await rpc("stash_quote", {
                        key: key(),
                        kind: "deposit",
                        amount: value.toString(),
                        ...outcome ? {
                            outcome: outcome
                        } : {}
                    });
                    const operation = {
                        Deposit: {
                            amount: value.toString(),

                            ...context(outcome)
                        }
                    };
                    const fee = await rpc("fee_quote", {
                        sender: key(),
                        operation: operation,
                        ...transactionData($("trade-form")),
                        extra_fee: extra,
                        anchor: state.status.tip,
                        expiry_blocks: jsonInteger(transactionExpiry($("trade-form"))),
                        nonce: jsonInteger(nextNonce())
                    });
                    if (identity !== tradeIdentity() || snapshot !== state.status?.state_root || !state.ready) return;
                    checkFeeQuote(fee, extra, $("trade-form"));
                    // Fees need cash already held in every outcome. Keep one
                    // more minimum fee in this one, so the account can still
                    // sell the Stash it buys or pay later.
                    const reserve = BigInt(fee.minimum_fee);
                    warning = "";
                    if (outcome && true) {
                        const opposite = outcome === "Pass" ? state.fail : state.pass;
                        if (!opposite?.account || BigInt(opposite.account.ordinary) < BigInt(fee.fee)) throw new Error("The other outcome needs enough hashes for the fee.");
                        if (BigInt(opposite.account.ordinary) - BigInt(fee.fee) < reserve) warning = "This leaves the other outcome too little for another fee, which blocks later transactions until the account receives hashes.";
                    }
                    const next = balance - BigInt(fee.fee) - reserve;
                    if (next >= value) break;
                    value = next;
                }
            } catch (error) {
                feedback($("trade-form"), error.message, true);
                return;
            }
        }
        $("trade-amount").value = state.tradeAll ? HashstashShares.exactInput(value > 0n ? value : 0n) : exactInput(value > 0n ? value : 0n);
        quoteSoon();
        feedback($("trade-form"), warning);
    });
    $("proposal-type").addEventListener("change", () => {
        const grant = $("proposal-type").value === "grant";
        $("proposal-grant-fields").hidden = !grant;
        $("proposal-parameter-fields").hidden = grant;
        parameterPreview();
    });
    $("proposal-parameter").addEventListener("change", parameterPreview);
    $("proposal-value").addEventListener("input", parameterPreview);
    $("trade-expiry").addEventListener("input", quoteSoon);
    $("wallet-expiry").addEventListener("input", () => {
        feeForms.forEach(name => feeSoon($(`${name}-form`)));
        sendSoon();
    });
    $("refund-form").elements.proposal.addEventListener("change", () => {
        $("refund-form").elements.round.value && checkSupport($("refund-form"));
    });
    $("copy-key").addEventListener("click", copyKey);
    $("copy-receive-key").addEventListener("click", copyKey);
    $("refresh-now").addEventListener("click", refresh);
    modeButtons();
    document.querySelectorAll("input[data-exa]").forEach(input => {
        input.inputMode = "decimal";
        input.title = "Amount in hashes; up to 3 decimal places.";
        input.name === "fee" && (input.title += " Minimum permitted fee: 0 hash.");
    });
    refresh();
    setInterval(refresh, 2e3);
})();
