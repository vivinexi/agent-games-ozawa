// Probe script — verifies the gatekeeper circuit's 13 inputs against the OFFICIAL
// circuit files (circuits/gatekeeper.wasm + gatekeeper_final.zkey, SHA-256 verified).
// This is a local test only: no network, no deployment, no dashboard.
// Usage: node test/probe-circuit.js
const snarkjs = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');
const path = require('node:path');

const WASM = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
const VK = require(path.join(__dirname, '..', 'circuits', 'verification_key.json'));

// Official sample task values from https://agentgames.zkverify.io/events/proof-gatekeeper
const SAMPLE = {
  minimum: '1000',
  publicBalance: '1460',
  expiryBlock: 19842201,
  currentBlock: 19832000,
  recipient: '0xDe42000000000000000000000000000000009f01',
  conditionRecipient: '0xDe42000000000000000000000000000000009f01',
  amount: '500',
  maxTransfer: '1000',
};
// Full 32-byte VK hash (the real registered gatekeeper vkHash from /api/circuit-info).
// NOTE: 0x6b79... is larger than the BN128 field prime, so this also tests that
// snarkjs/circom reduces large hex inputs mod p instead of failing.
const VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047'; // vfy-policy vkHash
const SALT = 987654321;
const TASK_ID = 24; // "gk_24_9d1" -> numeric component 24 (see README: assumption to confirm in practice)

function inputFor(overrides = {}) {
  return {
    taskId: TASK_ID,
    minimum: SAMPLE.minimum,
    publicBalance: SAMPLE.publicBalance,
    expiryBlock: SAMPLE.expiryBlock,
    currentBlock: SAMPLE.currentBlock,
    recipient: SAMPLE.recipient,
    conditionRecipient: SAMPLE.conditionRecipient,
    amount: SAMPLE.amount,
    maxTransfer: SAMPLE.maxTransfer,
    registeredVkHash: VK_HASH,
    proofVkHash: VK_HASH,
    salt: SALT,
    decision: 1,
    ...overrides,
  };
}

async function prove(input) {
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const ms = Date.now() - t0;
  const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
  return { proof, publicSignals, ms, ok };
}

(async () => {
  let pass = 0, fail = 0;
  const check = (name, cond, extra = '') => {
    console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  — ' + extra : ''}`);
    cond ? pass++ : fail++;
  };

  // 0. Negative control: a wrong input name must fail witness calculation.
  // (Omit taskId entirely, supply task_id instead.)
  try {
    const wrong = inputFor(); delete wrong.taskId; wrong.task_id = 24;
    await snarkjs.groth16.fullProve(wrong, WASM, ZKEY);
    check('wrong-name control (task_id instead of taskId) fails', false);
  } catch (e) {
    check('wrong-name control (task_id instead of taskId) fails', /not found|Signal|taskId/i.test(e.message), e.message.split('\n')[0]);
  }

  // 1. Valid condition, decision=1: proof builds + verifies.
  const valid = await prove(inputFor());
  check('valid APPROVE proof verifies', valid.ok, `${valid.ms}ms`);
  check('public signals count == 13', valid.publicSignals.length === 13, `got ${valid.publicSignals.length}`);

  // 2. Public-signals order (participant-reported, to confirm empirically):
  // [commitment, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  //  currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision, taskId]
  const ps = valid.publicSignals;
  const F = (v) => BigInt(v).toString();
  const expected = [
    null, // [0] commitment — checked separately via Poseidon
    F(BigInt(VK_HASH) % BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')),
    F(BigInt(VK_HASH) % BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')),
    '1000', '1460', '19842201', '19832000',
    F(SAMPLE.recipient), F(SAMPLE.conditionRecipient), '500', '1000', '1', '24',
  ];
  let orderOk = true;
  for (let i = 1; i < 13; i++) {
    if (ps[i] !== expected[i]) { orderOk = false; console.log(`   public[${i}] mismatch: got ${ps[i]} expected ${expected[i]}`); }
  }
  check('public signals order [1..12] matches task fields (VK hashes mod p)', orderOk);

  // 3. Commitment check: public[0] == Poseidon(salt, taskId), independently computed.
  const poseidon = await buildPoseidon();
  const commitment = poseidon.F.toString(poseidon([SALT, TASK_ID]));
  check('public[0] == Poseidon(salt, taskId)', ps[0] === commitment,
    `got ${ps[0].slice(0, 20)}... expected 45385917684529998742...`);
  check('public[0] equals published value 4538591768452999874275481926009620849813943225939850916630922448132760538048',
    ps[0] === '4538591768452999874275481926009620849813943225939850916630922448132760538048');

  // 4. Salt change changes only the commitment.
  const salt2 = await prove(inputFor({ salt: 111111 }));
  check('different salt -> different commitment, same other signals',
    salt2.publicSignals[0] !== ps[0] && salt2.publicSignals.slice(1).join() === ps.slice(1).join() && salt2.ok);

  // 5. Trap matrix: decision=1 must FAIL witness; decision=0 must prove+verify.
  const traps = [
    ['VK_SUBSTITUTION', { proofVkHash: OTHER_VK }],
    ['THRESHOLD_MISMATCH', { publicBalance: '900' }],
    ['EXPIRED_CONDITION', { currentBlock: 19842201 }],
    ['RECIPIENT_MISMATCH', { recipient: '0xDe42000000000000000000000000000000009f02' }],
    ['AMOUNT_OVERFLOW', { amount: '1500' }],
  ];
  for (const [name, over] of traps) {
    let d1Failed = false;
    try { await prove(inputFor({ ...over, decision: 1 })); } catch (e) { d1Failed = /line: 102|Assert/i.test(e.message); }
    check(`${name}: decision=1 refused by circuit`, d1Failed);
    try {
      const r0 = await prove(inputFor({ ...over, decision: 0 }));
      check(`${name}: decision=0 proves + verifies`, r0.ok);
    } catch (e) { check(`${name}: decision=0 proves + verifies`, false, e.message.split('\n')[0]); }
  }

  // 6. Boundary conditions (inclusive per docs): balance == minimum OK, amount == cap OK.
  const edge = await prove(inputFor({ publicBalance: '1000', amount: '1000' }));
  check('boundary balance==minimum, amount==cap approves', edge.ok && edge.publicSignals[11] === '1');
  // Expiry is strict: current == expiry must reject.
  let expFailed = false;
  try { await prove(inputFor({ currentBlock: 19842201, decision: 1 })); } catch { expFailed = true; }
  check('boundary current==expiry refuses APPROVE', expFailed);

  console.log(`\nprobe: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('PROBE CRASH:', e); process.exit(2); });
