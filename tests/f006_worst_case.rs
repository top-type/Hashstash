//! Audit F006 (node side), measurement only. How far one world's batch
//! clearing can be driven towards `batch::CLEARING_WORK`, what that costs in
//! wall time, and what one block execution and one pool reselection cost when
//! such trades are pending. Production code is unchanged; the only assertions
//! are the consensus work cap, conservation, and that the cap is reachable.
//!
//! The batches below came from a seeded random search and hill climb over
//! consensus-valid worlds and batches (reserve plus deposits within the money
//! range, redemptions within supply), reduced to families:
//!   * steep curves (curve mass far above reserve, near the top of the 512-bit
//!     range) with a large redemption reach the cap, even without a price
//!     bound, so a single candidate's price searches can use the whole budget;
//!   * adding a deposit side makes both logarithms vary with the probe (two
//!     directed 2048-bit series per evaluation), the most expensive evaluation;
//!   * nearly flat curves (mass = reserve + 1) take about 250 evaluations with
//!     expensive logarithms.
//! Any input of 480 bits or more selects the widest (2048-bit) precision.
//!
//! `worst_case_clearing_is_capped` runs in the suite (work counts only). The
//! timing benchmarks are ignored by default:
//!   cargo test --release --features test-fixtures --test f006_worst_case \
//!     -- --ignored --nocapture --test-threads 1
#[path = "support/curved.rs"]
mod curved;
mod support;

use hashstash::{
    batch::{self, Clearing, Order},
    chain::Chain,
    codec,
    config::Config,
    consensus, crypto,
    node::Node,
    state::{Phase, State, World},
    types::*,
};
use num_traits::{One, Zero};
use std::{collections::HashSet, time::Instant};

fn max_money() -> Amount {
    (Amount::one() << 512usize) - 1u32
}

fn pow2(bits: usize) -> Amount {
    Amount::one() << bits
}

fn n(digits: &str) -> Amount {
    digits.parse().unwrap()
}

fn order(id: u32, amount: Amount) -> Order {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&id.to_be_bytes());
    Order { id: key, amount }
}

/// Orders splitting `total` by fixed weights.
fn split(base: u32, total: &Amount, weights: &[u32]) -> Vec<Order> {
    let sum: u32 = weights.iter().sum();
    weights
        .iter()
        .enumerate()
        .map(|(i, w)| order(base + i as u32, (total * *w / sum).max(Amount::one())))
        .collect()
}

#[derive(Clone)]
struct Batch {
    label: &'static str,
    w: World,
    buys: Vec<Order>,
    sells: Vec<Order>,
    cap: u64,
}
impl Batch {
    /// Inputs an actual block could carry: reserve plus all deposits within
    /// the money range, redemptions within supply, mass at least reserve.
    fn reachable(&self) -> bool {
        let cash: Amount = self.buys.iter().map(|o| &o.amount).sum();
        let sold: Amount = self.sells.iter().map(|o| &o.amount).sum();
        &self.w.reserve + cash <= max_money()
            && sold <= self.w.shares
            && self.w.curve_mass >= self.w.reserve
            && self.w.curve_mass <= max_money()
            && self.w.shares <= max_money()
    }
    fn clear(&self, limit: u64) -> (Clearing, u64, f64) {
        let c = Config::devnet();
        let started = Instant::now();
        let (r, work) =
            batch::clear_with_work(&c, &self.w, &self.buys, &self.sells, self.cap, limit).unwrap();
        (r, work, started.elapsed().as_secs_f64() * 1000.0)
    }
    /// Best of `reps` timings, in milliseconds.
    fn time(&self, limit: u64, reps: usize) -> (u64, f64) {
        let mut best = f64::MAX;
        let mut work = 0;
        for _ in 0..reps {
            let (_, spent, ms) = self.clear(limit);
            work = spent;
            best = best.min(ms);
        }
        (work, best)
    }
}

fn world(reserve: Amount, shares: Amount, curve_mass: Amount) -> World {
    World {
        reserve,
        shares,
        curve_mass,
        ..World::default()
    }
}

/// The slowest consensus-reachable batch the seeded climb found: R ~ 2^489,
/// M ~ 2^511 (M/R ~ 2^22), S ~ 2^261, three deposits and six redemptions of
/// about half the supply, no price bound. It spends the whole budget in the
/// full candidate's price searches.
fn searched() -> Batch {
    let w = world(
        n(
            "1046910856945786926135766216973404930149887412359447427230483204038670955895759989292925655395454035721195533867190631022567686945113448499898587751",
        ),
        n("2427005118627969996894781934602136172342131597135460309739253780490190456825445"),
        n(
            "3351951982485649274893506249551461531869841455148098344430890360930441007518444853385108568344480391590541069758393851473835465640169980512381401083406622",
        ),
    );
    let buys = [
        "166420478717023",
        "66219402273999340604678136594611511663873619119707011700950738620234912995",
        "42433232606505723169789018172126612642611119592702809503775861510868875168143705184574794711332178948680800341804008",
    ];
    let sells = [
        "1139270276131891503103229164446424354205988474586713072833019682092642678465916",
        "149061986698280255793054108398984965315087961377476286007443",
        "66056313732550255080236227521453",
        "63154186460603324916258013179930720772287638015910101158776909670693480336970",
        "7552639243972355830900883937253965197269262611722351917249569220384631828321",
        "52884316685951531731422149931260212826",
    ];
    Batch {
        label: "searched: steep 2^489/2^511, 3 buys + 6 sells, no bound",
        w,
        buys: buys
            .iter()
            .enumerate()
            .map(|(i, a)| order(i as u32, n(a)))
            .collect(),
        sells: sells
            .iter()
            .enumerate()
            .map(|(i, a)| order(100 + i as u32, n(a)))
            .collect(),
        cap: u64::MAX,
    }
}

/// Steep curve: mass just below 2^512, reserve = mass >> k, a redemption of
/// `sell_pct` of supply and optionally deposits of reserve >> `buy_shift`.
fn steep(
    label: &'static str,
    k: usize,
    sbits: usize,
    sell_pct: u32,
    buy_shift: Option<usize>,
    cap: u64,
) -> Batch {
    let curve_mass = max_money() - (pow2(399) + 7u32);
    let w = world(
        &curve_mass >> k,
        pow2(sbits) + pow2(sbits - 1) / 3u32,
        curve_mass,
    );
    let sells = split(100, &(&w.shares * sell_pct / 100u32), &[5, 3, 2, 7, 1, 4]);
    let buys = buy_shift.map_or_else(Vec::new, |shift| {
        split(0, &(&w.reserve >> shift), &[3, 1, 2])
    });
    Batch {
        label,
        w,
        buys,
        sells,
        cap,
    }
}

/// Nearly flat curve (M = R + 1) at the top magnitude with large two-sided
/// volume: expensive logarithms, one long price search.
fn nearly_flat() -> Batch {
    let reserve = pow2(510) + 12345u32;
    let w = world(reserve.clone(), pow2(510) + 999u32, &reserve + 1u32);
    let buys = split(0, &(&reserve * 19u32 / 20u32), &[9, 1, 4, 7, 2, 8, 3, 6]);
    let sells = split(100, &(&w.shares * 9u32 / 20u32), &[2, 7, 1, 8, 2, 8, 1, 8]);
    Batch {
        label: "nearly flat M=R+1 ~2^510, 8 buys + 8 sells",
        w,
        buys,
        sells,
        cap: 1000,
    }
}

fn families() -> Vec<Batch> {
    vec![
        searched(),
        steep(
            "steep k=40 S~2^400, 90% redemption, bound 10%",
            40,
            400,
            90,
            None,
            1000,
        ),
        steep(
            "steep k=12 S~2^261, 50% redemption + buys, bound 10%",
            12,
            261,
            50,
            Some(104),
            1000,
        ),
        steep(
            "steep k=22 S~2^400, 50% redemption, bound 10%",
            22,
            400,
            50,
            None,
            1000,
        ),
        nearly_flat(),
    ]
}

fn conserved(w: &World, r: &Clearing) {
    let cash: Amount = r.buys.iter().map(|f| &f.input).sum();
    let paid: Amount = r.sells.iter().map(|f| &f.output).sum();
    let bought: Amount = r.buys.iter().map(|f| &f.output).sum();
    let sold: Amount = r.sells.iter().map(|f| &f.input).sum();
    assert_eq!(&w.reserve + cash, &r.reserve + paid);
    assert_eq!(&w.shares + bought, &r.shares + sold);
}

/// Deterministic: the work cap is reachable by consensus-valid inputs and is
/// never exceeded. No timing.
#[test]
fn worst_case_clearing_is_capped() {
    let mut most = 0;
    for b in families() {
        assert!(b.reachable(), "{}", b.label);
        let (r, work, _) = b.clear(batch::CLEARING_WORK);
        conserved(&b.w, &r);
        assert!(work <= batch::CLEARING_WORK);
        most = most.max(work);
    }
    assert_eq!(
        most,
        batch::CLEARING_WORK,
        "no family reaches the clearing work cap"
    );
}

#[test]
#[ignore = "benchmark: run with --ignored --nocapture --test-threads 1"]
fn bench_clearing_per_world() {
    println!("\nper-world clearing (best of 3, release)");
    println!(
        "{:<58} {:>5} {:>9} {:>8}",
        "batch", "evals", "ms", "ms/eval"
    );
    for b in families() {
        let (work, ms) = b.time(batch::CLEARING_WORK, 3);
        println!(
            "{:<58} {work:>5} {ms:>9.1} {:>8.3}",
            b.label,
            ms / work.max(1) as f64
        );
    }
    // Marginal cost per evaluation at 2048-bit precision: the same searched
    // batch stopped at increasing work limits.
    let b = searched();
    let mut points = Vec::new();
    for limit in [128u64, 256, 512, 768, 1024] {
        let (work, ms) = b.time(limit, 3);
        points.push((work, ms));
        println!("searched batch, limit {limit:>4}: {work:>4} evals {ms:>8.1} ms");
    }
    let (w0, t0) = points[1];
    let (w1, t1) = points[4];
    println!(
        "marginal cost per evaluation (256..1024): {:.3} ms",
        (t1 - t0) / (w1 - w0) as f64
    );
    // A decision block clears the FAIL and the PASS world separately; each
    // has its own CLEARING_WORK budget.
    let fail = searched();
    let mut pass = searched();
    pass.sells[0].amount += 1u32;
    let started = Instant::now();
    let (_, a, _) = fail.clear(batch::CLEARING_WORK);
    let (_, b, _) = pass.clear(batch::CLEARING_WORK);
    println!(
        "decision block, both worlds at the searched shape: {} evals, {:.1} ms",
        a + b,
        started.elapsed().as_secs_f64() * 1000.0
    );
}

// ---------------------------------------------------------------------------
// End to end: block execution on crafted maximum-magnitude states.

const HOLDER: [u8; 32] = [211; 32];
/// Spare cash for fees on every patched account.
const MARGIN: u32 = 1_000_000;

fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}

fn trader(world: u8, index: u32) -> [u8; 32] {
    let mut secret = [7u8; 32];
    secret[0] = 212 + world;
    secret[1..5].copy_from_slice(&index.to_be_bytes());
    secret
}

fn sign(s: &State, secret: &[u8; 32], nonce: u64, operation: Operation) -> Transaction {
    support::sign_minimum(
        s,
        TransactionBody {
            sender: key(secret),
            nonce,
            fee: 0u32.into(),
            anchor: codec::block_hash(&codec::genesis_block(&Config::devnet()).unwrap()),
            expiry_blocks: s.height + 10_000,
            operation,
            data: vec![],
        },
        secret,
        0,
    )
}

/// One world's traders: (secret, cash, shares, trade).
type Traders = Vec<([u8; 32], Amount, Amount, Operation)>;

fn traders(s: &State, world: u8, b: &Batch, outcome: Option<Outcome>) -> Traders {
    let decision = outcome.and(s.decision_id());
    let mut out = Vec::new();
    for (i, o) in b.buys.iter().enumerate() {
        let operation = Operation::Deposit {
            amount: o.amount.clone(),
            decision,
            outcome,
        };
        out.push((
            trader(world, i as u32),
            o.amount.clone(),
            Amount::zero(),
            operation,
        ));
    }
    for (i, o) in b.sells.iter().enumerate() {
        let operation = Operation::Redeem {
            shares: o.amount.clone(),
            decision,
            outcome,
        };
        out.push((
            trader(world, 100 + i as u32),
            Amount::zero(),
            o.amount.clone(),
            operation,
        ));
    }
    out
}

/// Rewrite one world to the batch's curve and give its traders their
/// balances; other worlds' traders get fee cash only. A holder account keeps
/// share and HASH conservation against `issued`.
#[allow(clippy::too_many_arguments)]
fn shape_world(
    c: &Config,
    w: &mut World,
    epoch: u64,
    b: &Batch,
    own: &Traders,
    others: &[&Traders],
    issued: &Amount,
    auction_escrow: &Amount,
) {
    for (secret, cash, shares, _) in own {
        let account = Account {
            ordinary: cash + MARGIN,
            shares: shares.clone(),
            nonce: 0,
            epoch,
        };
        w.put(key(secret), account, c).unwrap();
    }
    for (secret, ..) in others.iter().copied().flatten() {
        let account = Account {
            ordinary: MARGIN.into(),
            shares: Amount::zero(),
            nonce: 0,
            epoch,
        };
        w.put(key(secret), account, c).unwrap();
    }
    w.reserve = b.w.reserve.clone();
    w.curve_mass = b.w.curve_mass.clone();
    w.shares = b.w.shares.clone();
    let holder = key(&HOLDER);
    let old = w.account(&holder, Some(epoch)).unwrap_or(Account {
        epoch,
        ..Account::default()
    });
    let shares = &b.w.shares - (&w.account_shares - &old.shares);
    let cash = issued
        - (&w.account_cash - &old.ordinary)
        - &w.reserve
        - &w.revenue
        - &w.grant_escrow
        - auction_escrow;
    w.put(
        holder,
        Account {
            ordinary: cash,
            shares,
            ..old
        },
        c,
    )
    .unwrap();
    w.validate(c, issued, auction_escrow).unwrap();
}

fn execute(c: &Config, s: &State, txs: &[Transaction]) -> (State, f64) {
    let started = Instant::now();
    let next = consensus::execute(c, s, &s.root(), &key(&HOLDER), &Amount::zero(), txs).unwrap();
    (next, started.elapsed().as_secs_f64() * 1000.0)
}

fn step(c: &Config, s: &State, txs: &[Transaction], subsidy: u32) -> State {
    let work = Amount::from(subsidy) * c.work_per_atom().unwrap();
    let next = consensus::execute(c, s, &s.root(), &key(&HOLDER), &work, txs).unwrap();
    next.audit(c).unwrap();
    next
}

/// A real grant decision: genesis, a deposit, an auction and a winning grant.
fn governance_state(c: &Config) -> State {
    let mut s = step(c, &State::genesis(c), &[], 1_000_000);
    let deposit = Operation::Deposit {
        amount: 500_000u32.into(),
        decision: None,
        outcome: None,
    };
    let tx = sign(&s, &HOLDER, 0, deposit);
    s = step(c, &s, &[tx], 0);
    while !matches!(s.phase, Phase::Auction(_)) {
        s = step(c, &s, &[], 0);
    }
    let proposal = Proposal::Grant {
        payments: vec![GrantPayment {
            recipient: key(&[251; 32]),
            amount: &s.world.reserve / 20u32,
        }],
    };
    let propose = Operation::Propose {
        round: s.auction_round().unwrap(),
        description: [251; 32],
        proposal,
        support: 1u32.into(),
    };
    let nonce = s.account(&key(&HOLDER), None).unwrap().nonce;
    let tx = sign(&s, &HOLDER, nonce, propose);
    s = step(c, &s, &[tx], 0);
    for _ in 0..500 {
        if s.decision_id().is_some() {
            break;
        }
        s = step(c, &s, &[], 0);
    }
    assert!(
        matches!(s.phase, Phase::Governance(_)),
        "grant did not activate"
    );
    s
}

fn signed_trades(s: &State, traders: &Traders) -> Vec<Transaction> {
    traders
        .iter()
        .map(|(secret, _, _, op)| sign(s, secret, 0, op.clone()))
        .collect()
}

#[test]
#[ignore = "benchmark: run with --ignored --nocapture --test-threads 1"]
fn bench_block_execution_with_worst_trades() {
    let c = Config::devnet();
    let issued = pow2(511);
    println!(
        "\nblock execution: consensus::execute (finish_block -> settle_trades -> clear_memoized)"
    );

    // One world: a fresh state in its initial rest, curve and balances patched.
    let b = searched();
    assert!(b.reachable());
    let mut s = State::genesis(&c);
    let own = traders(&s, 0, &b, None);
    // A later newcomer that changes the included trade set.
    let late_deposit = Operation::Deposit {
        amount: pow2(300),
        decision: None,
        outcome: None,
    };
    let late: Traders = vec![(trader(9, 0), pow2(300), Amount::zero(), late_deposit)];
    let escrow = s.auction_escrow.clone();
    shape_world(&c, &mut s.world, 0, &b, &own, &[&late], &issued, &escrow);
    // The late trader needs its deposit cash too.
    let mut account = s.world.account(&key(&late[0].0), None).unwrap();
    account.ordinary += &late[0].1;
    s.world.put(key(&late[0].0), account, &c).unwrap();
    let mut holder = s.world.account(&key(&HOLDER), None).unwrap();
    holder.ordinary -= &late[0].1;
    s.world.put(key(&HOLDER), holder, &c).unwrap();
    s.issued = issued.clone();
    s.validate(&c).unwrap();
    let txs = signed_trades(&s, &own);
    let (first, miss) = execute(&c, &s, &txs);
    first.validate(&c).unwrap();
    let (_, hit) = execute(&c, &s, &txs);
    let mut more = txs.clone();
    more.push(sign(&s, &late[0].0, 0, late[0].3.clone()));
    let (_, changed) = execute(&c, &s, &more);
    println!(
        "one world, {} trades: memo miss {miss:.1} ms, memo hit {hit:.1} ms, +1 newcomer trade (miss) {changed:.1} ms",
        txs.len()
    );

    // A decision block: both worlds at the searched shape (PASS perturbed).
    let mut s = governance_state(&c);
    let epoch = s.epoch().unwrap();
    let mut pass_batch = searched();
    pass_batch.sells[0].amount += 1u32;
    let fail = traders(&s, 0, &b, Some(Outcome::Fail));
    let pass = traders(&s, 1, &pass_batch, Some(Outcome::Pass));
    let escrow = s.auction_escrow.clone();
    shape_world(
        &c,
        &mut s.world,
        epoch,
        &b,
        &fail,
        &[&pass],
        &issued,
        &escrow,
    );
    let alternative = s.alternative.as_mut().unwrap();
    shape_world(
        &c,
        alternative,
        epoch,
        &pass_batch,
        &pass,
        &[&fail],
        &issued,
        &escrow,
    );
    s.issued = issued;
    s.validate(&c).unwrap();
    let mut txs = signed_trades(&s, &fail);
    txs.extend(signed_trades(&s, &pass));
    let (next, miss) = execute(&c, &s, &txs);
    next.validate(&c).unwrap();
    let (_, hit) = execute(&c, &s, &txs);
    println!(
        "decision block, {} trades over two worlds: memo miss {miss:.1} ms, memo hit {hit:.1} ms",
        txs.len()
    );
}

// ---------------------------------------------------------------------------
// End to end on a mined chain: selection and node reselection with a full
// trade pool, at the magnitudes a fixture chain reaches.

const OWNER: [u8; 32] = [61; 32];

fn mined_config() -> Config {
    let mut c = Config::devnet();
    c.initial_bits = 0x1f1fffff;
    c.limit_bits = c.initial_bits;
    c
}

fn append(chain: &mut Chain, transactions: Vec<Transaction>) {
    let time = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let template = chain.template(key(&OWNER), transactions, time).unwrap();
    let block = Chain::mine(template, 1_000_000).unwrap();
    assert!(chain.submit(block, time as u64).unwrap());
}

fn chain_sign(
    chain: &Chain,
    secret: &[u8; 32],
    nonce: u64,
    operation: Operation,
    extra: u64,
) -> Transaction {
    support::sign_minimum(
        chain.tip_state(),
        TransactionBody {
            sender: key(secret),
            nonce,
            fee: 0u32.into(),
            anchor: codec::block_hash(&codec::genesis_block(&chain.config).unwrap()),
            expiry_blocks: chain.tip_height() + 10_000,
            operation,
            data: vec![],
        },
        secret,
        extra,
    )
}

#[test]
#[ignore = "benchmark: run with --ignored --nocapture --test-threads 1"]
fn bench_pool_reselection_on_a_mined_chain() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("f006.db");
    let c = mined_config();
    let mut chain = Chain::open(&path, c.clone()).unwrap();
    for _ in 0..8 {
        append(&mut chain, vec![]);
    }
    curved::chain(&mut chain, &OWNER);
    // Fund 32 traders; half of them buy shares to redeem later.
    let count = 32u32;
    let owner = chain.tip_state().account(&key(&OWNER), None).unwrap();
    let cash = &owner.ordinary / (2 * count);
    let funding: Vec<_> = (0..count)
        .map(|i| {
            let op = Operation::TransferExact {
                recipient: key(&trader(0, i)),
                amount: cash.clone(),
            };
            chain_sign(&chain, &OWNER, owner.nonce + u64::from(i), op, 0)
        })
        .collect();
    // Account creation weighs 1024 units: at most a few per 16 KiB block.
    for part in funding.chunks(8) {
        append(&mut chain, part.to_vec());
    }
    let shares: Vec<_> = (0..count / 2)
        .map(|i| {
            let op = Operation::Deposit {
                amount: &cash / 2u32,
                decision: None,
                outcome: None,
            };
            chain_sign(&chain, &trader(0, i), 0, op, 0)
        })
        .collect();
    append(&mut chain, shares);
    let s = chain.tip_state().clone();
    println!(
        "\nmined chain at height {}: reserve {} ({} bits), shares {}, mass {}, trader cash {}",
        chain.tip_height(),
        s.world.reserve,
        s.world.reserve.bits(),
        s.world.shares,
        s.world.curve_mass,
        cash
    );
    // Pool: four trades per trader, redemptions from the share holders and
    // deposits from the others, together far past the price bound.
    let mut pool = Vec::new();
    for i in 0..count {
        let secret = trader(0, i);
        let account = s.account(&key(&secret), None).unwrap();
        for k in 0..4u64 {
            let op = if i < count / 2 {
                Operation::Redeem {
                    shares: (&account.shares / 5u32).max(Amount::one()),
                    decision: None,
                    outcome: None,
                }
            } else {
                Operation::Deposit {
                    amount: &account.ordinary / 5u32,
                    decision: None,
                    outcome: None,
                }
            };
            pool.push(chain_sign(&chain, &secret, account.nonce + k, op, k));
        }
    }
    let select = |candidates: &[Transaction]| {
        let ids: HashSet<Hash> = candidates.iter().map(codec::transaction_id).collect();
        let started = Instant::now();
        let r = chain
            .select_authenticated(key(&OWNER), candidates, 4096, &ids)
            .unwrap();
        (r, started.elapsed().as_secs_f64() * 1000.0)
    };
    let (selected, miss) = select(&pool);
    let (_, hit) = select(&pool);
    let last = trader(0, count - 1);
    let last_nonce = s.account(&key(&last), None).unwrap().nonce + 4;
    let newcomer = Operation::Deposit {
        amount: 1u32.into(),
        decision: None,
        outcome: None,
    };
    let mut grown = pool.clone();
    grown.push(chain_sign(&chain, &last, last_nonce, newcomer, 0));
    let (_, changed) = select(&grown);
    println!(
        "Chain::select_authenticated, {} candidates -> {} selected: miss {miss:.2} ms, hit {hit:.2} ms, +1 trade {changed:.2} ms",
        pool.len(),
        selected.transactions.len()
    );
    drop(chain);

    // The node path: each submission reselects the whole pool under the lock.
    let node = Node::open(&path, c, key(&OWNER)).unwrap();
    let mut accepted = 0;
    let mut times = Vec::new();
    for tx in pool {
        let started = Instant::now();
        let ok = node.submit_transaction(tx).is_ok();
        times.push(started.elapsed().as_secs_f64() * 1000.0);
        accepted += usize::from(ok);
    }
    let tail = &times[times.len() - 16..];
    println!(
        "Node::submit_transaction: {accepted} of {} accepted, mempool {}; last 16 submissions mean {:.2} ms, max {:.2} ms",
        times.len(),
        node.status().unwrap()["mempool"],
        tail.iter().sum::<f64>() / tail.len() as f64,
        tail.iter().copied().fold(0.0, f64::max)
    );
}
