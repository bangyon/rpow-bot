import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';

secp.hashes.sha256 = sha256;

const enc = new TextEncoder();
const baseDir = path.resolve(process.cwd(), 'data');
const statePath = path.join(baseDir, 'state.json');
const configPath = path.join(baseDir, 'config.json');
const baseUrl = process.env.RPOW_BASE_URL || 'https://rpow.hopeware.ltd';
const defaultTarget = process.env.RPOW_TARGET || 'alpha';
const port = Number(process.env.PORT || 8787);
const autostart = process.env.RPOW_AUTOSTART !== 'false';
const retryDelayMs = Number(process.env.RPOW_RETRY_DELAY_MS || 1500);
const nodeInfoRefreshMs = Number(process.env.RPOW_NODE_INFO_REFRESH_MS || 20000);
const envPrivateKeyHex = (process.env.RPOW_PRIVATE_KEY_HEX || '').trim();
const supportedTargets = ['alpha', 'beta'];

function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(value) {
  if (!value || value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) throw new Error('invalid hex');
  return Uint8Array.from(value.match(/.{1,2}/g).map((pair) => Number.parseInt(pair, 16)));
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

function html(res, body) {
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

function trailingZeroBits(bytes) {
  let bits = 0;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    const byte = bytes[i];
    if (byte === 0) {
      bits += 8;
      continue;
    }
    let j = 0;
    while (((byte >> j) & 1) === 0) j += 1;
    return bits + j;
  }
  return bits;
}

function walletFromEnv() {
  if (!envPrivateKeyHex) return null;
  const priv = hexToBytes(envPrivateKeyHex);
  if (priv.length !== 32) throw new Error('RPOW_PRIVATE_KEY_HEX must be 32 bytes hex');
  return { privHex: hex(priv), pubHex: hex(secp.schnorr.getPublicKey(priv)) };
}

function randomWallet() {
  const priv = secp.utils.randomSecretKey();
  return { privHex: hex(priv), pubHex: hex(secp.schnorr.getPublicKey(priv)) };
}

function defaultState() {
  return {
    wallet: walletFromEnv() || randomWallet(),
    target: defaultTarget,
    activeTarget: null,
    running: false,
    totalMints: 0,
    lastMintAt: null,
    lastError: null,
    lastChallenge: null,
    lastResult: null,
    hashes: 0,
    hashesPerSecond: 0,
    webhookUrl: '',
    registry: [],
    nodeInfo: {},
  };
}

let state = defaultState();
let config = { dashboardToken: process.env.RPOW_DASHBOARD_TOKEN || '' };
let saveChain = Promise.resolve();
let saveQueued = false;
let nodes = [];
let worker = null;
let currentStatus = 'idle';
let currentNote = '';
let currentError = null;
let stopRequested = false;
let submitInFlight = false;
let startTimer = null;
let challengeTimeout = null;
let refreshTimer = null;
let startedAt = Date.now();

async function ensureDataDir() {
  await fs.mkdir(baseDir, { recursive: true });
}

async function loadConfig() {
  try {
    const parsed = JSON.parse(await fs.readFile(configPath, 'utf8'));
    if (parsed && typeof parsed.dashboardToken === 'string') config = parsed;
  } catch {}
}

async function saveState() {
  saveQueued = true;
  saveChain = saveChain.then(async () => {
    if (!saveQueued) return;
    saveQueued = false;
    await ensureDataDir();
    const tmp = `${statePath}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(state, null, 2) + '\n');
    await fs.rename(tmp, statePath);
  });
  return saveChain;
}

async function loadState() {
  await ensureDataDir();
  try {
    const parsed = JSON.parse(await fs.readFile(statePath, 'utf8'));
    const fallback = defaultState();
    state = {
      ...fallback,
      ...parsed,
      wallet: { ...fallback.wallet, ...(parsed.wallet || {}) },
      registry: Array.isArray(parsed.registry) ? parsed.registry : [],
      nodeInfo: parsed.nodeInfo && typeof parsed.nodeInfo === 'object' ? parsed.nodeInfo : {},
      activeTarget: typeof parsed.activeTarget === 'string' ? parsed.activeTarget : null,
    };
  } catch {
    state = defaultState();
    await saveState();
  }
  if (walletFromEnv()) state.wallet = walletFromEnv();
}

function requireAuth(req) {
  if (!config.dashboardToken) return true;
  const auth = req.headers.authorization || '';
  return auth.startsWith('Bearer ') && auth.slice(7) === config.dashboardToken;
}

function availableTargets() {
  return supportedTargets.filter((id) => nodes.some((node) => node.id === id));
}

function selectedTargets() {
  if (state.target === 'both') return availableTargets();
  return supportedTargets.includes(state.target) && nodes.some((node) => node.id === state.target) ? [state.target] : [];
}

function nextTarget() {
  const targets = selectedTargets();
  if (!targets.length) return null;
  if (state.target !== 'both') return targets[0];
  if (!state.activeTarget || !targets.includes(state.activeTarget)) return targets[0];
  const index = targets.indexOf(state.activeTarget);
  return targets[(index + 1) % targets.length];
}

async function authHeader(privHex, url, method, payload) {
  const priv = hexToBytes(privHex);
  const pubHex = hex(secp.schnorr.getPublicKey(priv));
  const createdAt = Math.floor(Date.now() / 1000);
  const tags = [['u', url], ['method', method.toUpperCase()]];
  if (payload) tags.push(['payload', hex(sha256(enc.encode(payload)))]);
  const eventBody = JSON.stringify([0, pubHex, createdAt, 27235, tags, '']);
  const eventIdBytes = sha256(enc.encode(eventBody));
  const sigHex = hex(await secp.schnorr.sign(eventIdBytes, priv));
  return 'Nostr ' + Buffer.from(JSON.stringify({
    id: hex(eventIdBytes),
    pubkey: pubHex,
    created_at: createdAt,
    kind: 27235,
    tags,
    content: '',
    sig: sigHex,
  })).toString('base64');
}

async function signedFetch(nodeId, apiPath, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const body = typeof options.body === 'string' ? options.body : options.body ? JSON.stringify(options.body) : '';
  const signedUrl = `${baseUrl}${apiPath}`;
  const requestUrl = `${baseUrl}/${nodeId}${apiPath}`;
  const headers = { authorization: await authHeader(state.wallet.privHex, signedUrl, method, body), accept: 'application/json' };
  if (body) headers['content-type'] = 'application/json';
  const response = await fetch(requestUrl, { method, headers, body: body || undefined });
  const text = await response.text();
  const data = text ? safeJson(text) ?? { raw: text } : null;
  if (!response.ok) throw new Error(data?.message || data?.error || `${response.status}`);
  return data;
}

async function publicJson(url) {
  const response = await fetch(url, { headers: { accept: 'application/json' } });
  const text = await response.text();
  const data = text ? safeJson(text) ?? { raw: text } : null;
  if (!response.ok) throw new Error(data?.message || data?.error || `${response.status}`);
  return data;
}

async function webhook(event, nodeId = state.activeTarget || state.target) {
  const webhookUrl = state.webhookUrl || process.env.RPOW_WEBHOOK_URL || '';
  if (!webhookUrl) return;
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...event, nodeId, target: state.target, ts: new Date().toISOString() }),
    });
  } catch {}
}

async function refreshRegistry() {
  try {
    const registry = await publicJson(`${baseUrl}/amm-api/registry`);
    nodes = Array.isArray(registry) ? registry.filter((node) => node && node.mineable !== false && supportedTargets.includes(node.id)) : [];
    state.registry = nodes.map((node) => ({ id: node.id, name: node.name || node.id, baseUrl: node.baseUrl || `/${node.id}`, status: node.status || '' }));
    if (state.target !== 'both' && !nodes.some((node) => node.id === state.target) && nodes[0]) state.target = nodes[0].id;
    if (state.target === 'both' && !availableTargets().length && nodes[0]) state.target = nodes[0].id;
    await saveState();
  } catch (error) {
    currentError = `registry refresh failed: ${error.message}`;
  }
}

async function refreshNodeInfo() {
  const targets = state.target === 'both' ? availableTargets() : (state.target ? [state.target] : []);
  for (const target of targets) {
    try {
      state.nodeInfo[target] = await publicJson(`${baseUrl}/${target}/node-info`);
    } catch (error) {
      currentError = `node info failed: ${error.message}`;
    }
  }
  await saveState();
}

async function fetchChallenge(nodeId) {
  const challenge = await signedFetch(nodeId, '/challenge', { method: 'POST' });
  if (!challenge?.challenge_id || !challenge?.nonce_prefix) throw new Error('bad challenge response');
  return challenge;
}

async function submitMint(nodeId, challenge, solutionNonce, hashes) {
  const payload = JSON.stringify({ challenge_id: challenge.challenge_id, solution_nonce: String(solutionNonce) });
  const result = await signedFetch(nodeId, '/mint', { method: 'POST', body: payload });
  state.totalMints += 1;
  state.lastMintAt = new Date().toISOString();
  state.lastError = null;
  state.lastResult = { ...result, nodeId, challenge_id: challenge.challenge_id, solution_nonce: String(solutionNonce), hashes: String(hashes) };
  currentNote = `minted #${state.totalMints}`;
  await saveState();
  await webhook({ event: 'mint', challenge_id: challenge.challenge_id, nodeId, solution_nonce: String(solutionNonce), hashes: String(hashes), result }, nodeId);
  return result;
}

function clearTimers() {
  if (startTimer) clearTimeout(startTimer);
  if (challengeTimeout) clearTimeout(challengeTimeout);
  startTimer = null;
  challengeTimeout = null;
}

function scheduleRestart(delay = retryDelayMs) {
  if (!state.running || stopRequested) return;
  if (startTimer) clearTimeout(startTimer);
  startTimer = setTimeout(() => {
    startTimer = null;
    startMining().catch((error) => {
      currentError = `restart failed: ${error.message}`;
    });
  }, delay);
}

function updateProgress(msg) {
  state.hashes = Number(msg.hashes || 0);
  state.hashesPerSecond = msg.elapsed_ms ? Math.round((state.hashes / Math.max(msg.elapsed_ms, 1)) * 1000) : 0;
  currentStatus = 'mining';
}

function killWorker() {
  if (worker) worker.postMessage({ type: 'abort' });
}

async function startMining() {
  if (!state.running || worker || submitInFlight) return;
  if (!nodes.length) await refreshRegistry();
  const targetId = nextTarget();
  if (!targetId) {
    currentError = `target ${state.target} not available`;
    state.running = false;
    await saveState();
    await webhook({ event: 'error', error: currentError });
    return;
  }

  state.activeTarget = targetId;
  stopRequested = false;
  currentError = null;
  currentStatus = 'getting-challenge';
  currentNote = state.target === 'both' ? `cycling ${targetId}` : '';
  await saveState();

  try {
    const challenge = await fetchChallenge(targetId);
    state.lastChallenge = { ...challenge, nodeId: targetId };
    await saveState();
    await webhook({ event: 'challenge', nodeId: targetId, challenge_id: challenge.challenge_id, difficulty_bits: challenge.difficulty_bits, expires_at: challenge.expires_at }, targetId);

    worker = new Worker(new URL('./miner.worker.mjs', import.meta.url));
    worker.on('message', async (msg) => {
      if (!msg || typeof msg !== 'object') return;
      if (msg.type === 'progress') {
        updateProgress(msg);
        return;
      }
      if (msg.type === 'found') {
        clearTimers();
        if (worker) await worker.terminate().catch(() => {});
        worker = null;
        submitInFlight = true;
        currentStatus = 'submitting';
        try {
          const result = await submitMint(targetId, challenge, msg.solution_nonce, msg.hashes);
          currentNote = `success ${targetId} ${result?.token?.value ?? ''}`.trim();
        } catch (error) {
          currentError = `mint failed: ${error.message}`;
          state.lastError = currentError;
          await saveState();
          await webhook({ event: 'error', error: currentError, nodeId: targetId, challenge_id: challenge.challenge_id, solution_nonce: msg.solution_nonce }, targetId);
        } finally {
          submitInFlight = false;
          if (state.running && !stopRequested) scheduleRestart();
        }
        return;
      }
      if (msg.type === 'aborted') {
        clearTimers();
        if (worker) await worker.terminate().catch(() => {});
        worker = null;
        currentStatus = stopRequested ? 'idle' : 'aborted';
        if (state.running && !stopRequested) scheduleRestart();
      }
    });
    worker.on('error', async (error) => {
      currentError = `worker error: ${error.message}`;
      state.lastError = currentError;
      await saveState();
      await webhook({ event: 'error', error: currentError, nodeId: targetId }, targetId);
      worker = null;
      submitInFlight = false;
      if (state.running && !stopRequested) scheduleRestart();
    });
    worker.on('exit', () => {
      worker = null;
      clearTimers();
    });

    const expiresAt = new Date(challenge.expires_at).getTime();
    challengeTimeout = setTimeout(() => killWorker(), Math.max(1000, expiresAt - Date.now() - 5000));
    worker.postMessage({ type: 'start', nonce_prefix: challenge.nonce_prefix, difficulty_bits: challenge.difficulty_bits });
  } catch (error) {
    currentError = `challenge failed: ${error.message}`;
    state.lastError = currentError;
    currentStatus = 'error';
    await saveState();
    await webhook({ event: 'error', error: currentError, nodeId: targetId }, targetId);
    if (state.running && !stopRequested) scheduleRestart();
  }
}

async function setRunning(next) {
  state.running = next;
  if (next) {
    stopRequested = false;
    currentNote = 'starting';
    await saveState();
    await webhook({ event: 'start' });
    await startMining();
  } else {
    stopRequested = true;
    clearTimers();
    if (worker) await worker.terminate().catch(() => {});
    worker = null;
    currentStatus = 'idle';
    currentNote = 'stopped';
    await saveState();
    await webhook({ event: 'stop' });
  }
}

async function setTarget(target) {
  if (!target) throw new Error('missing target');
  if (!['alpha', 'beta', 'both'].includes(target)) throw new Error('unsupported target');
  state.target = target;
  state.activeTarget = null;
  state.lastError = null;
  await saveState();
  if (state.running) {
    stopRequested = true;
    clearTimers();
    if (worker) await worker.terminate().catch(() => {});
    worker = null;
    stopRequested = false;
    scheduleRestart(250);
  }
}

async function setWebhookUrl(url) {
  state.webhookUrl = url || '';
  await saveState();
}

function publicState() {
  return {
    running: state.running,
    status: currentStatus,
    target: state.target,
    activeTarget: state.activeTarget,
    walletPubHex: state.wallet.pubHex,
    totalMints: state.totalMints,
    lastMintAt: state.lastMintAt,
    lastError: state.lastError || currentError,
    lastResult: state.lastResult,
    lastChallenge: state.lastChallenge,
    hashes: state.hashes,
    hashesPerSecond: state.hashesPerSecond,
    note: currentNote,
    webhookUrl: state.webhookUrl ? 'set' : '',
    registry: state.registry,
    nodeInfo: state.target === 'both' ? state.nodeInfo : state.nodeInfo[state.target] || null,
    uptimeMs: Date.now() - startedAt,
  };
}

function dashboardHtml() {
  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8" />',
    '<meta name="viewport" content="width=device-width, initial-scale=1" />',
    '<title>rpow bot</title>',
    '<style>',
    '  :root{color-scheme:dark;--bg:#09090b;--panel:#111827;--border:#243044;--text:#e5e7eb;--muted:#94a3b8;--accent:#34d399;--warn:#f59e0b;--err:#f87171}',
    '  *{box-sizing:border-box} body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:radial-gradient(circle at top,#0f172a,#09090b 60%);color:var(--text)}',
    '  .wrap{max-width:1100px;margin:0 auto;padding:24px} h1{margin:0 0 6px;font-size:28px} .sub{color:var(--muted);margin-bottom:18px}',
    '  .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px} .card{grid-column:span 6;background:rgba(17,24,39,.9);border:1px solid var(--border);border-radius:16px;padding:16px;box-shadow:0 16px 50px rgba(0,0,0,.24)}',
    '  .card.full{grid-column:1/-1} .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.kv{display:grid;grid-template-columns:180px 1fr;gap:8px 12px;font-size:14px}.k{color:var(--muted)} .v{word-break:break-all}',
    '  .pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);border-radius:999px;padding:6px 10px;font-size:12px;color:var(--muted);background:rgba(15,23,42,.7)}',
    '  .ok{color:var(--accent)} .bad{color:var(--err)} .warn{color:var(--warn)} button,input,select{border-radius:12px;border:1px solid var(--border);background:#0f172a;color:var(--text);padding:10px 12px;font:inherit}',
    '  button{cursor:pointer} button.primary{background:linear-gradient(135deg,#10b981,#06b6d4);border:none;color:#04111b;font-weight:700} button.ghost{background:transparent} .muted{color:var(--muted)}',
    '  input,select{width:100%} .actions{display:flex;gap:10px;flex-wrap:wrap} .actions button{min-width:110px} .login{display:grid;gap:10px;max-width:420px} .hidden{display:none!important}',
    '  .list{display:grid;gap:8px} .item{display:flex;justify-content:space-between;gap:10px;padding:10px 12px;border:1px solid var(--border);border-radius:12px;background:rgba(15,23,42,.45)}',
    '  .small{font-size:12px;color:var(--muted)} .statusline{font-size:14px;line-height:1.6} pre{margin:0;white-space:pre-wrap;word-break:break-word}',
    '  @media (max-width:900px){.card{grid-column:1/-1}.kv{grid-template-columns:1fr}}',
    '</style>',
    '</head>',
    '<body>',
    '  <div class="wrap">',
    '    <h1>rpow bot</h1>',
    '    <div class="sub">Auto-mining for rpow.hopeware.ltd with dashboard, webhook notifications, and both-node cycling.</div>',
    '    <div class="grid">',
    '      <div class="card full">',
    '        <div class="row" style="justify-content:space-between;align-items:flex-start">',
    '          <div>',
    '            <div class="pill" id="statePill">loading…</div>',
    '            <div class="statusline" id="statusLine" style="margin-top:10px">connecting…</div>',
    '          </div>',
    '          <div class="actions">',
    '            <button class="primary" id="startBtn">Start</button>',
    '            <button class="ghost" id="stopBtn">Stop</button>',
    '            <button class="ghost" id="refreshBtn">Refresh</button>',
    '          </div>',
    '        </div>',
    '      </div>',
    '      <div class="card"><div class="kv" id="stats"></div></div>',
    '      <div class="card">',
    '        <div class="login" id="loginBox">',
    '          <div class="muted">Dashboard token</div>',
    '          <input id="tokenInput" placeholder="paste token" autocomplete="off" />',
    '          <div class="actions">',
    '            <button class="primary" id="saveTokenBtn">Unlock</button>',
    '            <button class="ghost" id="forgetTokenBtn">Forget</button>',
    '          </div>',
    '          <div class="small">Saved locally in this browser. The API also requires this token.</div>',
    '        </div>',
    '        <div id="controls" class="hidden">',
    '          <div class="row">',
    '            <div style="flex:1;min-width:180px"><div class="muted" style="margin-bottom:6px">Target</div><select id="targetSelect"></select></div>',
    '            <div style="flex:2;min-width:260px"><div class="muted" style="margin-bottom:6px">Webhook URL</div><input id="webhookInput" placeholder="https://example.com/webhook" /></div>',
    '          </div>',
    '          <div class="actions" style="margin-top:12px"><button class="primary" id="saveWebhookBtn">Save webhook</button><button class="ghost" id="toggleBtn">Toggle running</button></div>',
    '        </div>',
    '      </div>',
    '      <div class="card full"><div class="row" style="justify-content:space-between"><strong>Known nodes</strong><span class="small">auto-refreshed</span></div><div class="list" id="nodesList" style="margin-top:10px"></div></div>',
    '      <div class="card full"><div class="row" style="justify-content:space-between"><strong>Recent activity</strong><span class="small">local state only</span></div><pre id="activity" style="margin-top:10px" class="small">waiting…</pre></div>',
    '    </div>',
    '  </div>',
    '  <script>',
    '    const els = { statePill: document.getElementById("statePill"), statusLine: document.getElementById("statusLine"), stats: document.getElementById("stats"), nodesList: document.getElementById("nodesList"), activity: document.getElementById("activity"), loginBox: document.getElementById("loginBox"), controls: document.getElementById("controls"), tokenInput: document.getElementById("tokenInput"), targetSelect: document.getElementById("targetSelect"), webhookInput: document.getElementById("webhookInput") };',
    '    const savedToken = localStorage.getItem("rpow-bot-token") || "";',
    '    if (savedToken) els.tokenInput.value = savedToken;',
    '    function headers(extra = {}) { const token = localStorage.getItem("rpow-bot-token") || ""; const h = { accept: "application/json", ...extra }; if (token) h.authorization = "Bearer " + token; return h; }',
    '    async function api(path, options = {}) { const response = await fetch(path, { ...options, headers: headers(options.headers || {}) }); const text = await response.text(); const data = text ? JSON.parse(text) : null; if (!response.ok) throw new Error(data?.message || data?.error || response.statusText); return data; }',
    '    function render(data) {',
    '      const locked = !localStorage.getItem("rpow-bot-token");',
    '      els.loginBox.classList.toggle("hidden", !locked);',
    '      els.controls.classList.toggle("hidden", locked);',
    '      const targetLabel = data.target === "both" ? "both" : (data.target || "no target");',
    '      const activeLabel = data.activeTarget ? " · active " + data.activeTarget : "";',
    '      els.statePill.textContent = (data.running ? "running" : "idle") + " · " + targetLabel + activeLabel;',
    '      els.statePill.className = "pill " + (data.running ? "ok" : "warn");',
    '      els.statusLine.innerHTML = ["status: <b>" + (data.status || "—") + "</b>", data.note ? "note: " + data.note : "", data.lastError ? "<span class=\"bad\">error: " + data.lastError + "</span>" : ""].filter(Boolean).join(" · ");',
    '      const stats = { "wallet pubkey": data.walletPubHex, "mode": data.target, "active target": data.activeTarget || "—", "mints": data.totalMints, "hashes": data.hashes, "speed": data.hashesPerSecond ? data.hashesPerSecond.toLocaleString() + " h/s" : "—", "last mint": data.lastMintAt || "—", "webhook": data.webhookUrl || "—", "uptime": Math.floor((data.uptimeMs || 0) / 1000) + "s" };',
    '      els.stats.innerHTML = Object.entries(stats).map(([k, v]) => "<div class=\"k\">" + k + "</div><div class=\"v\">" + (v ?? "—") + "</div>").join("");',
    '      const options = [{ id: "both", name: "rPOW A + B" }].concat((data.registry || []));',
    '      els.targetSelect.innerHTML = options.map((node) => "<option value=\"" + node.id + "\" " + (node.id === data.target ? "selected" : "") + ">" + node.id + " — " + node.name + "</option>").join("");',
    '      els.webhookInput.value = data.webhookUrl || "";',
    '      els.nodesList.innerHTML = (data.registry || []).length ? data.registry.map((node) => {',
    '        const info = data.target === "both" ? (data.nodeInfo && data.nodeInfo[node.id]) : (data.target === node.id ? data.nodeInfo : null);',
    '        return "<div class=\"item\"><div><b>" + node.id + "</b> <span class=\"small\">" + node.name + "</span>" + (info ? "<div class=\"small\">difficulty " + info.difficulty_bits + " · users " + info.user_count + " · supply " + info.current_supply + "/" + info.max_supply + "</div>" : "") + "</div><div class=\"small\">" + (node.baseUrl || "") + "</div></div>";',
    '      }).join("") : "<div class=\"small\">no nodes loaded yet</div>";',
    '      const lines = [];',
    '      lines.push("running: " + data.running);',
    '      if (data.lastChallenge) lines.push("last challenge: " + data.lastChallenge.challenge_id + " @ " + (data.lastChallenge.nodeId || data.activeTarget || data.target));',
    '      if (data.lastResult) lines.push("last result: " + JSON.stringify(data.lastResult));',
    '      if (data.lastError) lines.push("last error: " + data.lastError);',
    '      els.activity.textContent = lines.join("\n");',
    '    }',
    '    async function load() { try { render(await api("/api/status")); } catch (error) { els.statePill.textContent = "locked"; els.statePill.className = "pill warn"; els.statusLine.textContent = error.message; } }',
    '    document.getElementById("saveTokenBtn").onclick = async () => { const token = els.tokenInput.value.trim(); if (!token) return; localStorage.setItem("rpow-bot-token", token); await load(); };',
    '    document.getElementById("forgetTokenBtn").onclick = async () => { localStorage.removeItem("rpow-bot-token"); await load(); };',
    '    document.getElementById("refreshBtn").onclick = load;',
    '    document.getElementById("startBtn").onclick = async () => { await api("/api/control", { method: "POST", body: JSON.stringify({ action: "start" }) }); await load(); };',
    '    document.getElementById("stopBtn").onclick = async () => { await api("/api/control", { method: "POST", body: JSON.stringify({ action: "stop" }) }); await load(); };',
    '    document.getElementById("toggleBtn").onclick = async () => { await api("/api/control", { method: "POST", body: JSON.stringify({ action: "toggle" }) }); await load(); };',
    '    document.getElementById("saveWebhookBtn").onclick = async () => { await api("/api/control", { method: "POST", body: JSON.stringify({ action: "set-webhook", webhookUrl: els.webhookInput.value.trim() }) }); await load(); };',
    '    els.targetSelect.onchange = async () => { await api("/api/control", { method: "POST", body: JSON.stringify({ action: "target", target: els.targetSelect.value }) }); await load(); };',
    '    load(); setInterval(load, 5000);',
    '  </script>',
    '</body>',
    '</html>',
  ].join('\n');
}

async function handleRequest(req, res) {
  const url = new URL(req.url || '/', 'http://127.0.0.1');
  try {
    if (req.method === 'GET' && url.pathname === '/') return html(res, dashboardHtml());
    if (req.method === 'GET' && url.pathname === '/api/status') {
      if (!requireAuth(req)) return json(res, 401, { error: 'unauthorized' });
      return json(res, 200, publicState());
    }
    if (req.method === 'POST' && url.pathname === '/api/control') {
      if (!requireAuth(req)) return json(res, 401, { error: 'unauthorized' });
      const body = safeJson(await new Promise((resolve) => {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      })) || {};
      const action = String(body.action || '').toLowerCase();
      if (action === 'start') await setRunning(true);
      else if (action === 'stop') await setRunning(false);
      else if (action === 'toggle') await setRunning(!state.running);
      else if (action === 'set-webhook') await setWebhookUrl(String(body.webhookUrl || '').trim());
      else if (action === 'target') await setTarget(String(body.target || '').trim());
      else throw new Error('unknown action');
      return json(res, 200, publicState());
    }
    if (req.method === 'GET' && url.pathname === '/api/export') {
      if (!requireAuth(req)) return json(res, 401, { error: 'unauthorized' });
      return json(res, 200, { walletPubHex: state.wallet.pubHex, target: state.target, activeTarget: state.activeTarget });
    }
    return json(res, 404, { error: 'not found' });
  } catch (error) {
    return json(res, 500, { error: error.message });
  }
}

async function bootstrap() {
  await loadConfig();
  await loadState();
  await refreshRegistry();
  await refreshNodeInfo();
  refreshTimer = setInterval(() => {
    refreshRegistry().catch(() => {});
    refreshNodeInfo().catch(() => {});
  }, nodeInfoRefreshMs);
  if (autostart) {
    state.running = true;
    await saveState();
    setTimeout(() => startMining().catch(() => {}), 800);
  }
}

if (process.argv[1] && process.argv[1].endsWith('server.mjs')) {
  await bootstrap();
  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch((error) => json(res, 500, { error: error.message }));
  });
  server.listen(port, '0.0.0.0', () => console.log(`rpow bot listening on ${port}`));

  const shutdown = async () => {
    stopRequested = true;
    clearTimers();
    if (worker) await worker.terminate().catch(() => {});
    if (refreshTimer) clearInterval(refreshTimer);
    server.close(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
