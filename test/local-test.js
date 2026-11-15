// Local smoke tests for agent.js — spawns the real server as a child process
// with a TEST HMAC secret (never the dashboard secret) and checks the full
// HTTP behaviour. Usage: node test/local-test.js
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');
const snarkjs = require('snarkjs');

const PORT = 3456;
const SECRET = 'test-only-local-secret-0001';
const BASE = `http://127.0.0.1:${PORT}`;
const VK = require(path.join(__dirname, '..', 'circuits', 'verification_key.json'));
const VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';

const RECIPIENT = '0xDe42000000000000000000000000000000009f01';
const PROOF_TX = '0xa4c10000000000000000000000000000000000000000000000000000008ff1';

function sampleTask(overrides = {}, taskId = 'gk_24_9d1', proofTx = PROOF_TX) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'competition',
    issued_at: '2026-11-15T14:00:00Z',
    deadline_at: '2026-11-15T14:01:00Z',
    input: {
      registered_vk: VK_HASH,
      proof_vk: VK_HASH,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: '500',
      max_transfer: '1000',
      proof_tx: proofTx,
      ...overrides,
    },
  };
}

function sign(body) {
  const raw = JSON.stringify(body);
  return { raw, sig: crypto.createHmac('sha256', SECRET).update(raw).digest('hex') };
}
async function post(pathname, body, sigOverride) {
  const { raw, sig } = body === null ? { raw: '', sig: '' } : sign(body);
  const headers = { 'content-type': 'application/json' };
  if (sigOverride !== null) headers['x-agent-games-signature'] = sigOverride === undefined ? sig : sigOverride;
  const t0 = Date.now();
  const res = await fetch(BASE + pathname, { method: 'POST', headers, body: raw || undefined, signal: AbortSignal.timeout(20000) });
  const text = await res.text();
  return { status: res.status, ms: Date.now() - t0, text, headers: res.headers, json: safeJson(text) };
}
function safeJson(t) { try { return JSON.parse(t); } catch { return null; } }
function verifyResponseSig(text, sig) {
  return !!sig && crypto.timingSafeEqual(
    Buffer.from(sig), Buffer.from(crypto.createHmac('sha256', SECRET).update(text).digest('hex')));
}

(async () => {
  const child = spawn('node', ['agent.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, AGENT_NAME: 'ozawa' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '', err = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { err += d; });
  let pass = 0, fail = 0;
  const check = (name, cond, extra = '') => {
    console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  — ' + extra : ''}`);
    cond ? pass++ : fail++;
  };
  try {
    // wait for health
    let up = false;
    for (let i = 0; i < 50 && !up; i++) {
      try { const r = await fetch(BASE + '/health', { signal: AbortSignal.timeout(2000) }); up = r.ok; } catch { await new Promise((r) => setTimeout(r, 200)); }
    }
    check('server starts and answers /health', up);
    const health = await (await fetch(BASE + '/health', { signal: AbortSignal.timeout(5000) })).json();
    check('GET /health returns status ok + hmac_configured', health.status === 'ok' && health.hmac_configured === true, JSON.stringify(health));
    const root = await fetch(BASE + '/', { signal: AbortSignal.timeout(5000) });
    check('GET / returns 200 (no root 404)', root.ok);

    // 401s
    const noSig = await post('/agent', sampleTask(), null);
    check('POST /agent without HMAC -> 401', noSig.status === 401, `got ${noSig.status}`);
    const badSig = await post('/agent', sampleTask(), 'deadbeef');
    check('POST /agent with wrong HMAC -> 401', badSig.status === 401, `got ${badSig.status}`);

    // preflight
    const pre = await post('/agent', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: '2026-11-15T14:00:00Z', nonce: 'abc123' });
    check('signed preflight -> {ok:true, protocolVersion:v1}', pre.status === 200 && pre.json && pre.json.ok === true && pre.json.protocolVersion === 'v1', pre.text.slice(0, 120));
    check('preflight response is HMAC-signed', verifyResponseSig(pre.text, pre.headers.get('x-agent-games-signature')));

    // valid task -> APPROVE + verifiable proof
    const valid = await post('/agent', sampleTask());
    check('signed valid task -> 200 in <60s', valid.status === 200 && valid.ms < 60000, `${valid.ms}ms`);
    check('valid task -> APPROVE / VALID_CONDITION', valid.json && valid.json.decision === 'APPROVE' && valid.json.reason_code === 'VALID_CONDITION', valid.text.slice(0, 120));
    check('valid response carries proof + 13 public_signals',
      valid.json && valid.json.proof && Array.isArray(valid.json.public_signals) && valid.json.public_signals.length === 13,
      `public_signals=${valid.json && valid.json.public_signals && valid.json.public_signals.length}`);
    let proofOk = false;
    if (valid.json && valid.json.proof) {
      proofOk = await snarkjs.groth16.verify(VK, valid.json.public_signals, valid.json.proof);
    }
    check('valid APPROVE proof verifies against official vk', proofOk);
    check('valid response public[11] (decision) == 1 and public[12] (taskId) == 24',
      valid.json && valid.json.public_signals[11] === '1' && valid.json.public_signals[12] === '24');
    check('valid response is HMAC-signed', verifyResponseSig(valid.text, valid.headers.get('x-agent-games-signature')));
    check('valid response echoes proof_tx', valid.json && valid.json.proof_tx === PROOF_TX);

    // retry identical
    const retry = await post('/agent', sampleTask());
    check('retry of same task_id returns byte-identical response', retry.text === valid.text);

    // VK mismatch -> REJECT + proof verifies (decision=0)
    const vkBad = await post('/agent', sampleTask({ proof_vk: OTHER_VK }, 'gk_25_ab2', '0xb4c10000000000000000000000000000000000000000000000000000009ff2'));
    check('VK-mismatch task -> REJECT / VK_SUBSTITUTION', vkBad.json && vkBad.json.decision === 'REJECT' && vkBad.json.reason_code === 'VK_SUBSTITUTION', vkBad.text.slice(0, 120));
    let vkProofOk = false;
    if (vkBad.json && vkBad.json.proof) vkProofOk = await snarkjs.groth16.verify(VK, vkBad.json.public_signals, vkBad.json.proof);
    check('VK-mismatch REJECT proof verifies (decision=0)', vkProofOk);
    check('VK-mismatch response is HMAC-signed', verifyResponseSig(vkBad.text, vkBad.headers.get('x-agent-games-signature')));

    // proof reuse: same proof_tx, different task_id
    const reuse = await post('/agent', sampleTask({}, 'gk_26_cd3', PROOF_TX));
    check('reused proof_tx, new task -> REJECT / PROOF_REUSED', reuse.json && reuse.json.decision === 'REJECT' && reuse.json.reason_code === 'PROOF_REUSED', reuse.text.slice(0, 120));
    check('PROOF_REUSED response carries NO proof/public_signals', reuse.json && !('proof' in reuse.json) && !('public_signals' in reuse.json));

    // threshold trap via /gatekeeper alias
    const alias = await post('/gatekeeper', sampleTask({ public_balance: '900' }, 'gk_27_ef4', '0xc4c1000000000000000000000000000000000000000000000000000000aff3'));
    check('POST /gatekeeper alias: threshold trap -> REJECT / THRESHOLD_MISMATCH', alias.json && alias.json.decision === 'REJECT' && alias.json.reason_code === 'THRESHOLD_MISMATCH', alias.text.slice(0, 120));

    // malformed body (signed but not a task)
    const bad = await post('/agent', { hello: 'world' });
    check('signed non-task body -> REJECT / INVALID_TASK', bad.json && bad.json.decision === 'REJECT' && bad.json.reason_code === 'INVALID_TASK');

    console.log(`\nlocal-test: ${pass} passed, ${fail} failed`);
    if (err.trim()) console.log('--- server stderr (expected witness errors are normal for trap tests) ---\n' + err.trim().slice(0, 500));
    globalThis.__failures = fail;
  } finally {
    child.kill('SIGTERM');
  }
  // Force exit: undici keep-alive sockets otherwise keep the event loop alive.
  process.exit(globalThis.__failures ? 1 : 0);
})().catch((e) => { console.error('TEST CRASH:', e); process.exit(2); });
