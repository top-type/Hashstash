'use strict';
const {spawnSync}=require('node:child_process'),path=require('node:path'),fs=require('node:fs');
const suites=[
  'test_addresses.cjs','test_amounts.cjs','test_shares.cjs','test_browser_wallet.cjs',
  'test_browser_wallet_ui.cjs','test_cold_ui.cjs','test_wallet_ui.cjs','test_curve_ui.cjs','test_governance_view.cjs','test_grants_ui.cjs','test_timing_ui.cjs',
  'test_explorer_ui.cjs','test_chat_ui.cjs','test_faucet_ui.cjs','test_mail_crypto.cjs',
  'test_mail_crypto_interop.cjs','test_mail_ui.cjs','test_mail_cache.cjs','test_transaction_mail.cjs','test_mixer_ui.cjs','test_proposal_data.cjs','test_outcome_wallet.cjs','test_fee_split_ui.cjs','test_quote_refresh_ui.cjs',
];
const discovered=fs.readdirSync(__dirname).filter(name=>/^test_.*\.cjs$/.test(name)&&name!=='test_all_frontend.cjs').sort();
if(JSON.stringify(discovered)!==JSON.stringify([...suites].sort()))throw Error('Update the frontend runner when adding or removing a suite.');
for(const suite of suites){
  console.log(`Running ${suite}`);
  const run=spawnSync(process.execPath,[path.join(__dirname,suite)],{cwd:path.resolve(__dirname,'..'),stdio:'inherit',timeout:120000});
  if(run.error)throw run.error;
  if(run.status!==0){console.error(`${suite} failed (${run.status??run.signal})`);process.exit(run.status||1);}
}
console.log(`All ${suites.length} frontend suites passed. Individual assertion totals are reported above.`);
