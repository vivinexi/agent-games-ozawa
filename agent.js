// ozawa — Proof Gatekeeper agent for zkVerify Agent Games Season 01
// Participant: @sadesgos. Hosting: Railway. Target: Round 04, Mon 16 Nov 2026 17:30 WIB.
//
// Protocol source of truth (read 2026-11-15, text fetch + raw HTML):
//   https://agentgames.zkverify.io/build
//   https://agentgames.zkverify.io/events/proof-gatekeeper
//   https://agentgames.zkverify.io/api/circuit-info
//
// VERIFIED protocol facts (do not "improve" these from memory):
// - Endpoint: POST at the FULL handler path you register, e.g. /agent.
//   "The platform posts to the URL exactly as registered; a root path that
//   returns 404 will fail preflight and every task." Primary path here is
//   /agent; /gatekeeper is kept as an alias only.
// - Incoming task envelope: { type: "agent-games.proof-gatekeeper.v1",
//   task_id, mode, issued_at, deadline_at, input: { registered_vk, proof_vk,
//   minimum, public_balance, expiry_block, current_block, recipient,
//   condition_recipient, amount, max_transfer, proof_tx } }
// - Preflight request: { type: "agent-games.preflight.v1", agent_id,
//   issued_at, nonce } -> respond { ok: true, protocolVersion: "v1" }, signed.
// - Response (provable tasks): { decision, reason_code, proof_tx, proof,
//   public_signals } — proof is the snarkjs Groth16 proof object
//   { pi_a, pi_b, pi_c, protocol: "groth16", curve: "bn128" }, public_signals
//   is an array of decimal strings in output-then-public order.
//   For PROOF_REUSED tasks there is no proof to submit: omit proof +
//   public_signals (score model: those tasks are excluded from the proof bonus).
// - Every inbound request: verify HMAC x-agent-games-signature over the RAW
//   body BEFORE parsing. Every response: sign with the same header over the
//   raw response body. Secret comes ONLY from env AGENT_GAMES_HMAC_SECRET
//   (dashboard "Rotate Secret"). A placeholder/mismatched secret fails
//   preflight with a signature error.
// - Hard deadline: 60 seconds. Fail closed: on timeout/error/uncertainty,
//   REJECT — never approve by default.
//
// Circuit facts — verified locally against the OFFICIAL circuit files
// (circuits/gatekeeper.wasm + gatekeeper_final.zkey; SHA-256 matches the
// published values; vk: groth16/bn128, nPublic = 13; see test/probe-circuit.js,
// 19/19 checks pass):
// - 13 inputs: taskId, minimum, publicBalance, expiryBlock, currentBlock,
//   recipient, conditionRecipient, amount, maxTransfer, registeredVkHash,
//   proofVkHash, salt (private), decision (1 = approve, 0 = reject).
// - The circuit enforces decision == computed verdict: APPROVE (1) only when
//   every check passes; any trap with decision=1 refuses the witness
//   (GatekeeperEvaluation line 102). decision=0 always proves for trap tasks.
// - 13 public signals, output-then-public order:
//   [commitment, registeredVkHash, proofVkHash, minimum, publicBalance,
//   expiryBlock, currentBlock, recipient, conditionRecipient, amount,
//   maxTransfer, decision, taskId]
//   where commitment = Poseidon(salt, taskId) (verified independently with
//   circomlibjs; public[0] for salt=987654321, taskId=24 equals the published
//   value 4538591768452999874275481926009620849813943225939850916630922448132760538048).
// - Boundaries: balance == minimum OK, amount == max_transfer OK (inclusive);
//   expiry is strict: current_block must be < expiry_block.
// - VK hashes are full 32-byte hex; they exceed the BN128 field prime and are
//   reduced mod p by snarkjs (verified in the probe with the real vkHash).
//
// ASSUMPTIONS (not documented officially — confirm via preflight/practice):
// - taskId encoding: "gk_24_9d1" -> 24 (numeric component after "gk_").
//   Fallback for other formats: SHA-256(task_id) mod p. The proof verifies
//   cryptographically for any consistent encoding; only a platform-side check
//   of publicSignals[12] could depend on the encoding, and none is documented.
// - The platform re-verifies the local Groth16 proof from the response; no
//   Kurier/mainnet submission is done here (that needs a KURIER_API_KEY the
//   user does not have). If practice shows a proofReference is also required,
//   that is a separate integration step — see README "Still unverified".
// - Decision rule follows the 7 DOCUMENTED trap varieties only
//   (proof_vk == registered_vk passes the VK check). The circuit only checks
//   the two VK hashes are equal to each other, not that they equal the
//   circuit vkHash — see README for why no extra /api/circuit-info check is
//   applied as a decision rule.

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const snarkjs = require('snarkjs');

const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const AGENT_NAME = process.env.AGENT_NAME || 'ozawa';
const CIRCUIT_DIR = process.env.CIRCUIT_DIR || path.join(__dirname, 'circuits');
const WASM_PATH = path.join(CIRCUIT_DIR, 'gatekeeper.wasm');
const ZKEY_PATH = path.join(CIRCUIT_DIR, 'gatekeeper_final.zkey');
const VK_PATH = path.join(CIRCUIT_DIR, 'verification_key.json');

// BN128 scalar field prime (for the taskId fallback hash).
const FIELD_P = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

for (const f of [WASM_PATH, ZKEY_PATH, VK_PATH]) {
  if (!fs.existsSync(f)) {
    console.error(`FATAL: missing circuit file: ${f}`);
    console.error('Download from https://agentgames.zkverify.io/circuits/ into ./circuits/');
    process.exit(1);
  }
}
const VK = require(VK_PATH);
if (VK.nPublic !== 13) {
  console.error(`FATAL: unexpected verification key nPublic=${VK.nPublic} (expected 13)`);
  process.exit(1);
}
if (!HMAC_SECRET) {
  console.error('WARNING: AGENT_GAMES_HMAC_SECRET is not set — every request will be 401 and');
  console.error('preflight will fail. Set it from the dashboard (Rotate Secret) and restart.');
}

const seenProofTx = new Map(); // proof_tx -> first task_id that used it
const responseCache = new Map(); // task_id -> exact response object (retry = identical)

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}
function safeEqual(a, b) {
  const ba = Buffer.from(a || '', 'utf8');
  const bb = Buffer.from(b || '', 'utf8');
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
function signResponse(res, bodyObj) {
  const raw = JSON.stringify(bodyObj);
  if (HMAC_SECRET) res.setHeader('x-agent-games-signature', hmacHex(HMAC_SECRET, raw));
  res.setHeader('content-type', 'application/json');
  res.end(raw);
}

// task_id "gk_24_9d1" -> 24. Fallback: SHA-256(task_id) mod p (deterministic).
function encodeTaskId(taskId) {
  const m = /^gk_(\d+)_/.exec(String(taskId || ''));
  if (m) return m[1];
  if (/^\d+$/.test(String(taskId || ''))) return String(taskId);
  const h = crypto.createHash('sha256').update(String(taskId || '')).digest('hex');
  return (BigInt('0x' + h) % FIELD_P).toString();
}

function randomSalt() {
  let s = 0n;
  while (s === 0n) s = BigInt('0x' + crypto.randomBytes(16).toString('hex')) % FIELD_P;
  return s.toString();
}

// Deterministic decision — check order defines reason_code.
// APPROVE only when EVERY check passes. Inclusive bounds: balance == minimum
// OK, amount == max_transfer OK; expiry strict: current < expiry.
function decide(input, taskId) {
  const toBig = (v) => BigInt(v);
  if (String(input.proof_vk).toLowerCase() !== String(input.registered_vk).toLowerCase())
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  if (toBig(input.public_balance) < toBig(input.minimum))
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  if (Number(input.current_block) >= Number(input.expiry_block))
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  if (String(input.recipient).toLowerCase() !== String(input.condition_recipient).toLowerCase())
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  if (toBig(input.amount) > toBig(input.max_transfer))
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  if (input.proof_tx && seenProofTx.has(input.proof_tx) && seenProofTx.get(input.proof_tx) !== taskId)
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

function circuitInput(input, taskId, decisionNum, salt) {
  return {
    taskId: encodeTaskId(taskId),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: String(input.recipient),
    conditionRecipient: String(input.condition_recipient),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    registeredVkHash: String(input.registered_vk),
    proofVkHash: String(input.proof_vk),
    salt,
    decision: decisionNum,
  };
}

async function handleTask(task) {
  const taskId = task.task_id;
  const input = task.input || {};
  if (responseCache.has(taskId)) return responseCache.get(taskId);

  const required = ['registered_vk', 'proof_vk', 'minimum', 'public_balance',
    'expiry_block', 'current_block', 'recipient', 'condition_recipient',
    'amount', 'max_transfer'];
  const missing = required.filter((k) => input[k] === undefined || input[k] === null || input[k] === '');
  let verdict;
  if (missing.length) {
    verdict = { decision: 'REJECT', reason_code: 'INVALID_TASK' };
  } else {
    try {
      verdict = decide(input, taskId);
    } catch {
      verdict = { decision: 'REJECT', reason_code: 'INVALID_TASK' };
    }
  }

  const proofTx = input.proof_tx || '';
  // PROOF_REUSED has no proof to submit (excluded from the proof bonus) and
  // INVALID_TASK cannot be proven — return decision only.
  if (verdict.reason_code === 'PROOF_REUSED' || verdict.reason_code === 'INVALID_TASK') {
    const out = { decision: verdict.decision, reason_code: verdict.reason_code, proof_tx: proofTx };
    responseCache.set(taskId, out);
    return out;
  }

  // Generate the Groth16 proof of the decision. The circuit is the referee:
  // a decision=1 proof only exists when every check passes.
  const decisionNum = verdict.decision === 'APPROVE' ? 1 : 0;
  let proof, publicSignals;
  try {
    const t0 = Date.now();
    ({ proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput(input, taskId, decisionNum, randomSalt()), WASM_PATH, ZKEY_PATH));
    console.log(`proof ${taskId} ${verdict.decision}/${verdict.reason_code} in ${Date.now() - t0}ms`);
  } catch (e) {
    // Should not happen when the decision matches the verdict (probe-tested),
    // but fail closed: never approve on a proof error.
    console.error(`proof generation failed for ${taskId}: ${String(e && e.message).split('\n')[0]}`);
    const out = { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: proofTx };
    responseCache.set(taskId, out);
    return out;
  }

  if (proofTx) seenProofTx.set(proofTx, taskId);
  const out = {
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof_tx: proofTx,
    proof,
    public_signals: publicSignals,
  };
  responseCache.set(taskId, out);
  return out;
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.setHeader('content-type', 'application/json');
    return res.end(JSON.stringify({
      status: 'ok', agent: AGENT_NAME, protocol: 'agent-games.proof-gatekeeper.v1',
      hmac_configured: Boolean(HMAC_SECRET), circuit: 'gatekeeper/v1', nPublic: 13,
    }));
  }
  if (req.method === 'GET' && (req.url === '/' || req.url === '')) {
    res.setHeader('content-type', 'application/json');
    return res.end(JSON.stringify({ agent: AGENT_NAME, track: 'proof-gatekeeper', status: 'ok' }));
  }
  // Canonical handler path (per /build: POST /agent). /gatekeeper is an alias.
  if (req.method !== 'POST' || (req.url !== '/agent' && req.url !== '/gatekeeper')) {
    res.writeHead(404); return res.end('not found');
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    // 1. Verify HMAC over the RAW body, BEFORE parsing.
    const sig = req.headers['x-agent-games-signature'];
    if (!HMAC_SECRET || !sig || !safeEqual(sig, hmacHex(HMAC_SECRET, raw))) {
      res.writeHead(401); return res.end('unauthorized');
    }
    let body;
    try { body = JSON.parse(raw.toString('utf8')); }
    catch { return signResponse(res, { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: '' }); }

    // 2. Preflight handshake (signed): { ok: true, protocolVersion: "v1" }.
    if (body && body.type === 'agent-games.preflight.v1') {
      console.log(`preflight nonce=${body.nonce || ''}`);
      return signResponse(res, { ok: true, protocolVersion: 'v1' });
    }

    // 3. Task envelope (competition or practice). Fail closed on bad shape.
    if (!body || typeof body !== 'object' || !body.input || !body.task_id) {
      return signResponse(res, { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: '' });
    }
    try {
      const out = await handleTask(body);
      return signResponse(res, out);
    } catch (e) {
      console.error(`task ${body.task_id} failed: ${e && e.message}`);
      return signResponse(res, { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: (body.input && body.input.proof_tx) || '' });
    }
  });
});

server.listen(PORT, () => console.log(
  `ozawa gatekeeper listening on :${PORT} (agent=${AGENT_NAME}, hmac_configured=${Boolean(HMAC_SECRET)})`));

module.exports = { server, decide, encodeTaskId, circuitInput };
