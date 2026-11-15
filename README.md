# ozawa — Proof Gatekeeper agent · zkVerify Agent Games Season 01

Participant: **@sadesgos** (X verified, referral `F84XXTPX`) · Agent name: **ozawa**
Track: **Proof Gatekeeper** · Hosting: **Railway** · Target: **Round 04, Mon 16 Nov 2026, 17:30 WIB**
(8 tasks/round; Round 03 on 15 Nov is effectively missed — entries lock while a round is open.)

## Status (15 Nov 2026, ~21:20 WIB)

- ✅ Agent implemented: `agent.js` (Node.js, built-ins + snarkjs 0.7.6 only).
- ✅ Groth16 proof generation works and verifies against the official key.
- ✅ Local tests green: circuit probe **19/19**, HTTP smoke tests **22/22** (`npm test`, ~9 s).
- ❌ NOT deployed, NOT registered, preflight/practice NOT run. Nothing is live yet.
- The draft `gatekeeper-starter.js` was deleted — `agent.js` supersedes it.

## Protocol — verified from the official docs (15 Nov 2026)

Sources: https://agentgames.zkverify.io/build, /events/proof-gatekeeper,
/api/circuit-info, /guide (read as text + raw HTML, including the official
starter prompt embedded in /build).

- **Endpoint: `POST /agent`** — register the FULL handler path (e.g.
  `https://<host>/agent`). The platform posts to the URL exactly as registered;
  a root path returning 404 fails preflight and every task. (`/gatekeeper` is
  kept as an alias in `agent.js` only; register `/agent`.)
- **Task envelope** (`agent-games.proof-gatekeeper.v1`): `task_id`, `mode`,
  `issued_at`, `deadline_at`, `input: { registered_vk, proof_vk, minimum,
  public_balance, expiry_block, current_block, recipient, condition_recipient,
  amount, max_transfer, proof_tx }`.
- **Preflight** (`agent-games.preflight.v1`, signed): respond
  `{ ok: true, protocolVersion: "v1" }`, signed. Must pass before Active.
- **Response (provable tasks):**
  `{ decision, reason_code, proof_tx, proof, public_signals }` — `proof` is the
  snarkjs Groth16 object (`pi_a/pi_b/pi_c`, `protocol: "groth16"`,
  `curve: "bn128"`); `public_signals` is an array of decimal strings in
  output-then-public order. For **PROOF_REUSED** tasks there is no proof to
  submit: `proof`/`public_signals` are omitted (score model excludes them).
- **HMAC:** verify `x-agent-games-signature` over the RAW request body BEFORE
  parsing; sign every response over the raw response body. Secret ONLY from env
  `AGENT_GAMES_HMAC_SECRET` (dashboard → Rotate Secret, shown once). A
  placeholder/mismatched secret fails preflight with a signature error.
- **Deadline: 60 s, fail closed.** Local proof takes ~0.9 s cold / ~0.3 s warm.
- **Scoring:** correct decision (verified) +12; wrong APPROVE −6; wrong REJECT
  −3; timeout −2; missing/invalid proof −2; reliability bonus +0…+5/round.
  Registration closes 21 Nov 2026 22:00 UTC. Prizes 100,000 VFY/track
  (50k/30k/20k).

## Circuit — verified locally against the official files

Files in `circuits/` (downloaded from agentgames.zkverify.io/circuits/):
`gatekeeper.wasm` (1,755,820 bytes, SHA-256 `be00aefe…2764f` ✓),
`gatekeeper_final.zkey` (309,750 bytes, SHA-256 `adfe95a4…1af80d` ✓),
`verification_key.json` (exported with snarkjs; groth16/bn128, **nPublic = 13**).
vkHash from /api/circuit-info: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.

- 13 inputs: `taskId, minimum, publicBalance, expiryBlock, currentBlock,
  recipient, conditionRecipient, amount, maxTransfer, registeredVkHash,
  proofVkHash, salt (private), decision (1 = approve, 0 = reject)`.
- The circuit enforces **decision == computed verdict**: APPROVE only when
  every check passes; any trap with decision=1 refuses the witness
  (`GatekeeperEvaluation` line 102). decision=0 always proves for trap tasks.
- 13 public signals: `[commitment, registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId]`, where
  `commitment = Poseidon(salt, taskId)` — independently recomputed with
  circomlibjs; for salt=987654321, taskId=24 it equals the published value
  `4538591768452999874275481926009620849813943225939850916630922448132760538048`.
- Boundaries: balance == minimum OK, amount == max_transfer OK (inclusive);
  expiry strict: `current_block < expiry_block`.
- VK hashes are full 32-byte hex and exceed the BN128 field prime; snarkjs
  reduces them mod p (verified in the probe with the real vkHash).
- Decision rule follows the **7 documented trap varieties only**
  (`proof_vk == registered_vk` passes the VK check). The circuit only checks
  the two VK hashes are equal to each other — it does NOT check they equal the
  circuit vkHash. No extra /api/circuit-info equality check is applied as a
  decision rule: the sample task's `registered_vk` (`0x7d3a…`) is not the
  circuit vkHash (`0x6b79…`), so the condition VK is a per-condition value,
  not the circuit key. (See "Still unverified".)

## Files

| File | What it is |
|---|---|
| `agent.js` | The agent. `POST /agent` (+ `/gatekeeper` alias), `GET /health`, `GET /`. |
| `circuits/` | Official `gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json`. |
| `test/probe-circuit.js` | Circuit verification (19 checks). `npm run probe`. |
| `test/local-test.js` | HTTP smoke tests vs the real server (22 checks). `npm run smoke`. |
| `package.json` | `snarkjs@0.7.6` dep; `start: node agent.js`; `test` runs both suites. |
| `railway.json` | Nixpacks build, `startCommand: node agent.js`, healthcheck `/health`. |
| `.env.example` | Blank env template. `.env` is gitignored; never commit a real secret. |

## Deploy to Railway (exact steps — needs the user's Railway account)

1. **Push this folder to a public personal GitHub repo** (dashboard requires a
   public repo on a personal account; org repos are not supported). Suggested
   name: `ozawa-gatekeeper` or `agent-games-season-01`.
2. **Railway:** new project → Deploy from GitHub repo → select the repo.
   Railway detects Node.js (Nixpacks) and runs `npm install` then
   `node agent.js` (see `railway.json`). The `PORT` env is set by Railway.
3. **Set variables** in Railway (Variables tab):
   - `AGENT_GAMES_HMAC_SECRET` = the value from the dashboard **Rotate
     Secret** (see next step — set the dashboard value here; do NOT invent one).
   - `AGENT_NAME` = `ozawa` (default is already `ozawa`).
4. **Generate a public domain** in Railway (Settings → Networking → Generate
   Domain). The endpoint to register is `https://<railway-domain>/agent`.
5. **Check health:** `curl https://<railway-domain>/health` → `{"status":"ok",...}`.

## Register on the dashboard (needs the user — no credentials here)

1. Dashboard → My agents → **Register agent**: Agent Name `ozawa`, tick
   **Proof Gatekeeper**, Repository URL = the public GitHub repo URL from step 1,
   Agent Endpoint = `https://<railway-domain>/agent`. Submit.
2. On the new agent card: **Rotate Secret** → copy the one-time plaintext →
   paste it as `AGENT_GAMES_HMAC_SECRET` in Railway Variables → **redeploy /
   restart** the Railway service.
3. Dashboard → run **Preflight** (must pass; reply is
   `{ok:true, protocolVersion:"v1"}` signed). If it fails with
   "endpoint must return signed protocol-v1 JSON", the HMAC secret on Railway
   does not match the dashboard value.
4. Dashboard → **Practice** → run at least 1 practice task (required before
   scored rounds; it does not affect score/rank).
5. Events → Proof Gatekeeper → **Enter event**. Keep the Railway service
   running during rounds (17:30–03:30 WIB); a sleeping laptop does not matter
   once deployed, but a stopped service forfeits tasks.

## Test results (local, 15 Nov 2026)

`npm test` — exit 0, ~9 s total.

- **Circuit probe (19/19):** wrong input name fails; valid APPROVE proof
  verifies (~0.9 s cold); 13 public signals in the documented order; public[0]
  == Poseidon(salt, taskId) == published value; different salt changes only the
  commitment; all 5 tested traps (VK_SUBSTITUTION, THRESHOLD_MISMATCH,
  EXPIRED_CONDITION, RECIPIENT_MISMATCH, AMOUNT_OVERFLOW) refuse decision=1 at
  line 102 and prove with decision=0; boundaries inclusive except strict expiry.
- **HTTP smoke (22/22):** server starts; `GET /health` ok + `hmac_configured`;
  `GET /` 200; POST without/wrong HMAC → 401; signed preflight →
  `{ok:true, protocolVersion:"v1"}` signed; signed valid task → 200 in 904 ms,
  APPROVE/VALID_CONDITION, proof + 13 public_signals, proof verifies against
  the official vk, public[11]=1, public[12]=24, response signed, `proof_tx`
  echoed; retry of same `task_id` returns a byte-identical response; VK
  mismatch → REJECT/VK_SUBSTITUTION with a verifying decision=0 proof; reused
  `proof_tx` on a new task → REJECT/PROOF_REUSED with no proof fields;
  `/gatekeeper` alias threshold trap → REJECT/THRESHOLD_MISMATCH; signed
  non-task body → REJECT/INVALID_TASK.
- One harness note: the first smoke run stayed alive after passing because
  undici keep-alive sockets kept the event loop open; fixed by an explicit
  `process.exit()` + fetch timeouts in `test/local-test.js` (verified: the
  re-run exits cleanly).

## Still unverified — do NOT claim these are settled

1. **taskId encoding.** `"gk_24_9d1" -> 24` (numeric component) reproduces the
   published Poseidon commitment, but the official docs publish no encoding.
   Fallback in code: SHA-256(task_id) mod p. The proof verifies
   cryptographically either way; only a platform-side check of
   `publicSignals[12]` could depend on it, and none is documented. Confirm via
   the first practice task (if the platform rejects the proof, this is the
   first thing to revisit).
2. **Kurier / on-chain submission.** The starter prompt lists "zkVerify
   submission (Kurier REST or zkVerifyJS) — wait for a Finalized result" as a
   build step, but the event page's scoring only requires the local Groth16
   proof in the response, and the platform "independently re-verifies my proof
   against its OWN registered verification key". No Kurier submission is
   implemented here (it needs a `KURIER_API_KEY` + mainnet API key the user
   does not have). If practice shows a `proofReference` is also expected, that
   is a separate integration step.
3. **Whether the platform checks public signals beyond proof validity** (e.g.
   decision field vs. returned decision, taskId binding). Locally everything
   is consistent; the practice task is the real test.
4. **The VK-registration question.** The circuit accepts two equal-but-
   unregistered VK hashes (verified: S6-style case proves and verifies). The
   agent follows the 7 documented traps only; if the platform ever sends a
   task whose `registered_vk` is not a real condition VK, the correct call is
   unclear from the docs. Flagged, not guessed.
5. **Preflight transport detail.** The preflight request is documented as a
   signed POST to "your endpoint" with type `agent-games.preflight.v1`; the
   agent answers it on the same `/agent` handler. Whether the dashboard's
   health check uses the same path or a plain GET is not documented — `GET
   /health` and `GET /` both return 200 as a safety net.

## What the user still needs to provide

- A **Railway account** (or access to deploy this repo there).
- A **public personal GitHub repo** containing this folder (dashboard field:
  Repository URL; org repos not supported).
- The dashboard **HMAC secret via Rotate Secret** (after registering the
  agent) — to paste into Railway Variables. Never send it in chat.
- (Optional, later) A **Kurier API key** only if practice shows on-chain
  submission is also required (see item 2 above).
- (Already known, no action) Agent name `ozawa`, hosting Railway, account
  @sadesgos, referral F84XXTPX.

## Run locally

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<test-only-secret> node agent.js   # :3000
npm test   # probe (19) + smoke (22)
```
