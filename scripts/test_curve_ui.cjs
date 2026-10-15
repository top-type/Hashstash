'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { harness } = require('./test_wallet_ui.cjs');
const source = fs.readFileSync(path.join(__dirname, '../ui/app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '../ui/index.html'), 'utf8');
const shareUnit = 10n ** 36n, hashUnit = 10n ** 18n;
// Exercise the shipped model rather than maintaining another implementation.
const context = vm.createContext({chartShareUnit: shareUnit});
vm.runInContext(source.slice(source.indexOf('    function curveModel('), source.indexOf('    function curveWorld(')), context);
let checks = 0;
const eq = (actual, expected, message) => { assert.deepEqual(actual, expected, message); checks++; };
const ok = (value, message) => { assert.ok(value, message); checks++; };
const near = (actual, expected, message) => { ok(Math.abs(actual - expected) < 1e-10, message); };
const world = (reserve, mass, supply = shareUnit) => ({reserve: String(reserve), curve_mass: String(mass), shares: String(supply), revenue: '0', grant_escrow: '0'});
const nodes = (svg, className) => svg.children.filter(child => child.class === className);
const coords = element => [...element.d.matchAll(/[ML](-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/g)].map(match => [Number(match[1]), Number(match[2])]);

function bounded(model) {
  ok(model.points.length <= 203, 'curve sampling has a fixed work bound');
  ok(model.points.every(([x,y]) => Number.isFinite(x) && Number.isFinite(y)), 'all coordinates are finite');
  ok(model.points.every(([x,y]) => x >= 0 && x <= model.xmax && y >= 0 && y <= model.ymax + 1e-12), 'the path stays inside the plotted range');
  ok(model.points.every(([x,y],i,p) => !i || (x >= p[i-1][0] && y + 1e-10 >= p[i-1][1])), 'price and supply advance monotonically');
}

async function run() {
  const empty = context.curveModel(world(0n, 0n, 0n));
  eq(empty.empty, true); eq(empty.power, 0); eq(empty.xmax, 2);
  ok(empty.points.every(([,y]) => y === 1), 'genesis has a horizontal opening-price line'); bounded(empty);
  for (const [reserve, mass, power, halfPrice] of [[1n,1n,0,1], [1n,2n,1,0.5], [1n,3n,2,0.25], [1n,5n,4,0.0625], [2n,3n,0.5,Math.SQRT1_2]]) {
    const model = context.curveModel(world(reserve, mass));
    near(model.power, power, 'marginal exponent is M/R minus one');
    const half = model.points.find(([x]) => Math.abs(x - 0.5) < 1e-12);
    ok(half, 'normal curves sample half the current supply'); near(half[1], halfPrice);
    ok(model.points.some(([x,y]) => x === 1 && y === 1), 'the current price lies on the curve'); bounded(model);
  }
  for (const [reserve, mass] of [[1n,1001n], [1n,10n**150n], [10n**150n-1n,10n**150n]]) {
    const model = context.curveModel(world(reserve, mass, 10n**150n)); bounded(model);
    if (mass > 2n * reserve) {
      eq(model.clipped, true); near(model.points.at(-1)[1], model.ymax);
      ok(model.points.at(-1)[0] < model.xmax, 'a steep line ends at the top boundary instead of becoming a false plateau');
    }
  }
  for (const bad of [world(0n,1n,0n),world(1n,1n,0n),world(0n,1n),world(2n,1n)]) eq(context.curveModel(bad), null);
  for (const [n,d,text] of [[0n,1n,'0'],[1n,1n,'1'],[125n,100n,'1.25'],[1n,1000n,'0.001'],[1n,10n**100n,'1e-100'],[10n**150n,1n,'1e150'],[99999n,1n,'1e5']]) eq(context.curveTick(n,d),text);

  const h = await harness({empty: true});
  const s = h.currentSnapshot;
  s.governance.phase = {Rest: {until: 480, pending: null}};
  s.governance.world = world(0n,0n,0n);
  Object.assign(s.status, s.governance.world, {height: 0, clock: 0});
  h.get('curve-stage').clientWidth = 620;
  await h.refresh(); await h.navigate('#stash');
  const svg = h.get('curve-svg');
  eq(h.get('curve-panel').parentElement.id, 'view-stash');
  eq(h.get('curve-panel').hidden, false); eq(svg.hidden, false);
  eq(svg.dataset.preview, 'opening'); eq(svg.dataset.exponent, '0');
  eq(h.get('curve-price').textContent, '1');
  eq(h.get('reserve-ratio').textContent, '100% reserve ratio');
  eq(h.get('curve-outcomes').hidden, true);
  ok(!html.includes('id="curve-outcome"'), 'the chart has no outcome selector');
  eq(nodes(svg,'curve-line').length, 1); eq(nodes(svg,'curve-current').length, 0);
  ok(coords(nodes(svg,'curve-line')[0]).every(([,y],i,p) => y === p[0][1]), 'the rendered genesis path is horizontal');
  ok(svg.children.some(child => child.id === 'curve-plot-title' && child.textContent.includes('Starting price 1 hash/stash')));
  ok(svg.children.some(child => child.id === 'curve-plot-desc' && child.textContent.includes('reserve is empty')));
  ok(nodes(svg,'curve-axis-label').some(child => child.textContent === 'Total stash supply'));
  ok(nodes(svg,'curve-axis-label').some(child => child.textContent === '2'), 'opening horizontal ticks use displayed stash units');
  ok(!/id="curve-details"/.test(html), 'graph is not hidden in a disclosure');
  ok(html.indexOf('id="curve-panel"') < html.indexOf('id="stash-live"'), 'graph is outside the moving trade region');
  const initialPath = nodes(svg,'curve-line')[0];
  await h.refresh(); eq(nodes(svg,'curve-line')[0], initialPath, 'unchanged polling retains the existing SVG');

  s.config.share_scale = '2000000000000000000'; await h.refresh();
  eq(h.get('curve-price').textContent,'0.5');
  ok(svg.children.some(child => child.id === 'curve-plot-title' && child.textContent.includes('0.5 hash/stash')), 'opening scale change invalidates the SVG cache');
  s.config.share_scale = String(hashUnit);
  s.governance.world = world(hashUnit,3n*hashUnit);
  Object.assign(s.status,s.governance.world,{height:1}); await h.refresh();
  eq(svg.dataset.preview,'funded');eq(svg.dataset.exponent,'2');eq(nodes(svg,'curve-current').length,1);
  eq(h.get('curve-price').textContent,'3');
  ok(h.get('curve-range').textContent.includes('Withdrawals move left'));
  s.governance.world.reserve = String(hashUnit/2n); await h.refresh();
  eq(svg.dataset.exponent,'5');eq(h.get('curve-price').textContent,'3','reserve-only change preserves current marginal price');

  s.governance.phase = {Governance: {id:'ef'.repeat(32),proposal_id:'ab'.repeat(32),round:0,started:0,blocks:16,started_height:16,leading_blocks:0,proposal:{Grant:{payments:[{recipient:'12'.repeat(32),amount:'10'}]}}}};
  s.governance.pass = world(hashUnit,5n*hashUnit);
  await h.refresh();await h.navigate('#stash');
  eq(h.get('stash-trading').parentElement.id,'governance-trade-mount');
  eq(h.get('curve-panel').parentElement.id,'view-stash');eq(h.get('curve-outcomes').hidden,false);
  eq(h.get('curve-single-price').hidden,true);eq(h.get('curve-world-details').hidden,true);eq(h.get('curve-outcome-details').hidden,false);
  const signedBefore = h.wallet.length, quoteBefore = h.get('trade-outcome').value;
  eq(h.get('curve-price-pass').textContent,'5');eq(h.get('curve-price-fail').textContent,'3');
  eq(h.get('curve-ratio-pass').textContent,'20%');eq(h.get('curve-ratio-fail').textContent,'16.66%');
  eq(nodes(svg,'governance-curve-line pass')[0].dataset.exponent,'4');
  eq(nodes(svg,'governance-curve-line fail')[0].dataset.exponent,'5');
  ok(svg.children.some(child => child.id === 'curve-plot-title' && child.textContent === 'PASS and FAIL conversion curves'));
  eq(h.wallet.length,signedBefore);eq(h.get('trade-outcome').value,quoteBefore,'the two-curve preview does not change a prepared trade');

  s.governance.world = world(1n,10n**150n,10n**150n);
  h.get('curve-stage').clientWidth = 280;await h.refresh();
  eq(nodes(svg,'governance-curve-line fail')[0].dataset.clipped,'true');
  for (const side of ['pass','fail']) {
    const line = nodes(svg,`governance-curve-line ${side}`)[0], pathPoints = coords(line);
    ok(pathPoints.length<=202);ok(pathPoints.every(([x,y])=>Number.isFinite(x)&&Number.isFinite(y)&&x>=0&&x<=280&&y>=0&&y<=250));
    ok(!/NaN|Infinity/.test(line.d));
  }
  ok(svg.children.length<35,'extreme ratios do not create unbounded DOM nodes');
  ok(nodes(svg,'curve-axis-label').every(child=>child.textContent.length<=18),'extreme numeric ticks stay compact');
  // The governance chart compares both actual curves on shared axes. A steeper
  // PASS curve may have a lower current price after trades; do not normalize it away.
  const comparison = h.get('governance-curve-svg');
  h.get('governance-curve-stage').appendChild(comparison);
  h.get('governance-curve-stage').clientWidth = 620;
  s.governance.world = world(hashUnit,hashUnit,shareUnit);
  s.governance.pass = world(hashUnit * 3n / 8n,hashUnit * 3n / 4n,shareUnit);
  await h.refresh(); await h.navigate('#governance');
  eq(nodes(comparison,'governance-curve-line pass')[0].dataset.exponent,'1');
  eq(nodes(comparison,'governance-curve-line fail')[0].dataset.exponent,'0');
  const passDot = nodes(comparison,'governance-curve-dot pass')[0], failDot = nodes(comparison,'governance-curve-dot fail')[0];
  near(Number(passDot.cx), Number(failDot.cx), 'equal supply uses the same horizontal position');
  ok(Number(passDot.cy) > Number(failDot.cy), 'lower PASS price sits below FAIL on a common vertical scale');
  ok(coords(nodes(comparison,'governance-curve-line fail')[0]).every(([,y],i,p) => y === p[0][1]), 'a 100% reserve ratio is visibly flat');
  ok(coords(nodes(comparison,'governance-curve-line pass')[0]).some(([,y],i,p) => i && y !== p[i-1][1]), 'a 50% reserve ratio visibly changes with supply');
  const comparisonPath = nodes(comparison,'governance-curve-line pass')[0];
  await h.refresh(); eq(nodes(comparison,'governance-curve-line pass')[0], comparisonPath, 'unchanged snapshots preserve the SVG');
  s.governance.pass.shares = String(shareUnit / 2n); await h.refresh();
  ok(Number(nodes(comparison,'governance-curve-dot pass')[0].cx) < Number(nodes(comparison,'governance-curve-dot fail')[0].cx), 'different current supplies are not misleadingly aligned');
  s.governance.pass = world(1n, (1n << 511n), (1n << 511n));
  s.governance.world = world(1n << 511n, 1n << 511n, 1n << 511n);
  h.get('governance-curve-stage').clientWidth = 280;
  await h.refresh();
  for (const side of ['pass','fail']) {
    const line = nodes(comparison,`governance-curve-line ${side}`)[0], points = coords(line);
    ok(!/NaN|Infinity/.test(line.d), 'large integer products cannot overflow geometry');
    ok(points.length <= 202, 'comparison sampling is bounded');
    ok(points.every(([x,y])=>Number.isFinite(x)&&Number.isFinite(y)&&x>=0&&x<=280&&y>=0&&y<=250), 'comparison geometry stays within its viewport');
  }
  eq(h.wallet.length,signedBefore,'the comparison never signs or changes a transaction');
  s.governance.phase={Rest:{until:480,pending:null}};s.governance.pass=null;await h.refresh();
  eq(h.get('curve-outcomes').hidden,true);eq(h.get('curve-single-price').hidden,false);eq(h.get('curve-context').textContent,'Current curve');
  eq(nodes(svg,'curve-line').length,1,'resolution restores the single surviving curve');
  console.log(`Stash curve UI: ${checks} math, rendering and interaction checks passed.`);
}
run().catch(error=>{console.error(error);process.exitCode=1;});
