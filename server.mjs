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
const port = Number(process.env.PORT || 8787);
const rpowBaseUrl = process.env.RPOW_BASE_URL || 'https://rpow.hopeware.ltd';
const rpow2ApiBase = process.env.RPOW2_API_BASE || 'https://api.rpow2.com';
const defaultTarget = process.env.RPOW_TARGET || 'both';
const autostart = process.env.RPOW_AUTOSTART !== 'false';
const retryDelayMs = Number(process.env.RPOW_RETRY_DELAY_MS || 1500);
const nodeInfoRefreshMs = Number(process.env.RPOW_NODE_INFO_REFRESH_MS || 20000);
const rpow2RefreshMs = Number(process.env.RPOW2_REFRESH_MS || 30000);
const telegramReportMs = Number(process.env.RPOW_TELEGRAM_REPORT_MS || 10 * 60 * 1000);
const telegramPollMs = Number(process.env.RPOW_TELEGRAM_POLL_MS || 15000);
const rpowPrivateKeyHex = (process.env.RPOW_PRIVATE_KEY_HEX || '').trim();
const rpow2SessionCookie = (process.env.RPOW2_SESSION_COOKIE || '').trim();
const telegramToken = (process.env.RPOW_TELEGRAM_BOT_TOKEN || '').trim();
const telegramChatIdEnv = (process.env.RPOW_TELEGRAM_CHAT_ID || '').trim();

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
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

function html(res, body) {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(body) });
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
  if (!rpowPrivateKeyHex) return null;
  const priv = hexToBytes(rpowPrivateKeyHex);
  if (priv.length !== 32) throw new Error('RPOW_PRIVATE_KEY_HEX must be 32 bytes hex');
  return { privHex: hex(priv), pubHex: hex(secp.schnorr.getPublicKey(priv)) };
}

function randomWallet() {
  const priv = secp.utils.randomSecretKey();
  return { privHex: hex(priv), pubHex: hex(secp.schnorr.getPublicKey(priv)) };
}

function defaultState() {
  return {
    rpow: {
      wallet: walletFromEnv() || randomWallet(),
      target: defaultTarget,
      activeTarget: null,
      running: true,
      totalMints: 0,
      lastMintAt: null,
      lastError: null,
      lastChallenge: null,
      lastResult: null,
      hashes: 0,
      hashesPerSecond: 0,
      registry: [],
      nodeInfo: {},
      walletConfigured: !!rpowPrivateKeyHex,
    },
    rpow2: {
      running: !!rpow2SessionCookie,
      totalMints: 0,
      lastMintAt: null,
      lastError: null,
      lastChallenge: null,
      lastResult: null,
      hashes: 0,
      hashesPerSecond: 0,
      me: null,
      ledger: null,
      cookieConfigured: !!rpow2SessionCookie,
    },
    telegram: {
      chatId: telegramChatIdEnv || '',
      botUsername: '',
      lastUpdateId: 0,
      lastReportAt: null,
      lastDiscoveredAt: null,
    },
  };
}

let state = defaultState();
let config = { dashboardToken: '' };
let stateWrite = Promise.resolve();
let stateDirty = false;
let rpowWorker = null;
let rpow2Worker = null;
let rpowStopRequested = false;
let rpow2StopRequested = false;
let rpowSubmitInFlight = false;
let rpow2SubmitInFlight = false;
let rpowStartTimer = null;
let rpow2StartTimer = null;
let rpowChallengeTimeout = null;
let rpow2ChallengeTimeout = null;
let telegramPollBusy = false;
let telegramReportTimer = null;
let telegramPollTimer = null;
let nodeInfoTimer = null;
let rpow2MetaTimer = null;
let startedAt = Date.now();
let overallError = null;

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
  stateDirty = true;
  stateWrite = stateWrite.then(async () => {
    if (!stateDirty) return;
    stateDirty = false;
    await ensureDataDir();
    const tmp = `${statePath}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(state, null, 2) + '\n');
    await fs.rename(tmp, statePath);
  });
  return stateWrite;
}

async function loadState() {
  await ensureDataDir();
  try {
    const parsed = JSON.parse(await fs.readFile(statePath, 'utf8'));
    const fallback = defaultState();
    state = {
      ...fallback,
      ...parsed,
      rpow: { ...fallback.rpow, ...(parsed.rpow || {}), wallet: { ...fallback.rpow.wallet, ...(parsed.rpow?.wallet || {}) } },
      rpow2: { ...fallback.rpow2, ...(parsed.rpow2 || {}) },
      telegram: { ...fallback.telegram, ...(parsed.telegram || {}) },
    };
  } catch {
    state = defaultState();
    await saveState();
  }
  if (walletFromEnv()) state.rpow.wallet = walletFromEnv();
  state.rpow.walletConfigured = !!rpowPrivateKeyHex;
  state.rpow2.cookieConfigured = !!rpow2SessionCookie;
}

function requireAuth(req) {
  if (!config.dashboardToken) return true;
  const auth = req.headers.authorization || '';
  return auth.startsWith('Bearer ') && auth.slice(7) === config.dashboardToken;
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

async function fetchJson(url, options = {}) {
  const response = await fetch(url, { ...options, headers: { accept: 'application/json', ...(options.headers || {}) } });
  const text = await response.text();
  const data = text ? safeJson(text) ?? { raw: text } : null;
  if (!response.ok) throw new Error(data?.message || data?.error || `${response.status}`);
  return data;
}

async function signedFetch(nodeId, apiPath, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const body = typeof options.body === 'string' ? options.body : options.body ? JSON.stringify(options.body) : '';
  const signedUrl = `${rpowBaseUrl}${apiPath}`;
  const requestUrl = `${rpowBaseUrl}/${nodeId}${apiPath}`;
  const headers = { authorization: await authHeader(state.rpow.wallet.privHex, signedUrl, method, body), accept: 'application/json' };
  if (body) headers['content-type'] = 'application/json';
  const response = await fetch(requestUrl, { method, headers, body: body || undefined });
  const text = await response.text();
  const data = text ? safeJson(text) ?? { raw: text } : null;
  if (!response.ok) throw new Error(data?.message || data?.error || `${response.status}`);
  return data;
}

async function telegramFetch(method, body) {
  if (!telegramToken) throw new Error('telegram token missing');
  const response = await fetch(`https://api.telegram.org/bot${telegramToken}/${method}`, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  const data = text ? safeJson(text) ?? { raw: text } : null;
  if (!response.ok || !data?.ok) throw new Error(data?.description || data?.error || `${response.status}`);
  return data.result;
}

function clearRpowTimers() {
  if (rpowStartTimer) clearTimeout(rpowStartTimer);
  if (rpowChallengeTimeout) clearTimeout(rpowChallengeTimeout);
  rpowStartTimer = null;
  rpowChallengeTimeout = null;
}

function clearRpow2Timers() {
  if (rpow2StartTimer) clearTimeout(rpow2StartTimer);
  if (rpow2ChallengeTimeout) clearTimeout(rpow2ChallengeTimeout);
  rpow2StartTimer = null;
  rpow2ChallengeTimeout = null;
}

function scheduleRpowRestart(delay = retryDelayMs) {
  if (!state.rpow.running || rpowStopRequested) return;
  if (rpowStartTimer) clearTimeout(rpowStartTimer);
  rpowStartTimer = setTimeout(() => {
    rpowStartTimer = null;
    startRpowCycle().catch((error) => { state.rpow.lastError = `restart failed: ${error.message}`; saveState().catch(() => {}); });
  }, delay);
}

function scheduleRpow2Restart(delay = retryDelayMs) {
  if (!state.rpow2.running || rpow2StopRequested) return;
  if (rpow2StartTimer) clearTimeout(rpow2StartTimer);
  rpow2StartTimer = setTimeout(() => {
    rpow2StartTimer = null;
    startRpow2Cycle().catch((error) => { state.rpow2.lastError = `restart failed: ${error.message}`; saveState().catch(() => {}); });
  }, delay);
}

function availableRpowTargets() {
  return supportedTargets.filter((id) => state.rpow.registry.some((node) => node.id === id));
}

function selectRpowTargets() {
  if (state.rpow.target === 'both') return availableRpowTargets();
  return supportedTargets.includes(state.rpow.target) && state.rpow.registry.some((node) => node.id === state.rpow.target) ? [state.rpow.target] : [];
}

function nextRpowTarget() {
  const targets = selectRpowTargets();
  if (!targets.length) return null;
  if (state.rpow.target !== 'both') return targets[0];
  if (!state.rpow.activeTarget || !targets.includes(state.rpow.activeTarget)) return targets[0];
  const index = targets.indexOf(state.rpow.activeTarget);
  return targets[(index + 1) % targets.length];
}

async function refreshRpowRegistry() {
  try {
    const registry = await fetchJson(`${rpowBaseUrl}/amm-api/registry`);
    state.rpow.registry = Array.isArray(registry)
      ? registry.filter((node) => node && node.mineable !== false && supportedTargets.includes(node.id)).map((node) => ({
          id: node.id,
          name: node.name || node.id,
          baseUrl: node.baseUrl || `/${node.id}`,
          status: node.status || '',
        }))
      : [];
    if (state.rpow.target !== 'both' && !state.rpow.registry.some((node) => node.id === state.rpow.target) && state.rpow.registry[0]) {
      state.rpow.target = state.rpow.registry[0].id;
    }
    if (state.rpow.target === 'both' && !availableRpowTargets().length && state.rpow.registry[0]) {
      state.rpow.target = state.rpow.registry[0].id;
    }
    await saveState();
  } catch (error) {
    state.rpow.lastError = `registry refresh failed: ${error.message}`;
    overallError = state.rpow.lastError;
  }
}

async function refreshRpowNodeInfo() {
  const targets = state.rpow.target === 'both' ? availableRpowTargets() : (state.rpow.target ? [state.rpow.target] : []);
  for (const target of targets) {
    try {
      state.rpow.nodeInfo[target] = await fetchJson(`${rpowBaseUrl}/${target}/node-info`);
    } catch (error) {
      state.rpow.lastError = `node info failed: ${error.message}`;
      overallError = state.rpow.lastError;
    }
  }
  await saveState();
}

async function refreshRpow2Meta() {
  if (!state.rpow2.running) return;
  try {
    state.rpow2.me = await fetchJson(`${rpow2ApiBase}/me`, { headers: { cookie: `rpow_session=${rpow2SessionCookie}` } });
    state.rpow2.ledger = await fetchJson(`${rpow2ApiBase}/ledger`, { headers: { cookie: `rpow_session=${rpow2SessionCookie}` } });
    await saveState();
  } catch (error) {
    state.rpow2.lastError = `meta refresh failed: ${error.message}`;
    overallError = state.rpow2.lastError;
  }
}

async function submitRpowMint(targetId, challenge, solutionNonce, hashes) {
  const payload = JSON.stringify({ challenge_id: challenge.challenge_id, solution_nonce: String(solutionNonce) });
  const result = await signedFetch(targetId, '/mint', { method: 'POST', body: payload });
  state.rpow.totalMints += 1;
  state.rpow.lastMintAt = new Date().toISOString();
  state.rpow.lastError = null;
  state.rpow.lastResult = { ...result, nodeId: targetId, challenge_id: challenge.challenge_id, solution_nonce: String(solutionNonce), hashes: String(hashes) };
  await saveState();
  return result;
}

async function submitRpow2Mint(challenge, solutionNonce, hashes) {
  const response = await fetch(`${rpow2ApiBase}/mint`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: `rpow_session=${rpow2SessionCookie}`, accept: 'application/json' },
    body: JSON.stringify({ challenge_id: challenge.challenge_id, solution_nonce: String(solutionNonce) }),
  });
  const text = await response.text();
  const data = text ? safeJson(text) ?? { raw: text } : null;
  if (!response.ok) throw new Error(data?.message || data?.error || `${response.status}`);
  state.rpow2.totalMints += 1;
  state.rpow2.lastMintAt = new Date().toISOString();
  state.rpow2.lastError = null;
  state.rpow2.lastResult = { ...data, challenge_id: challenge.challenge_id, solution_nonce: String(solutionNonce), hashes: String(hashes) };
  await saveState();
  return data;
}

function updateProgress(which, msg) {
  const hashes = Number(msg.hashes || 0);
  const elapsedMs = Number(msg.elapsed_ms || 1);
  const speed = Math.round((hashes / Math.max(elapsedMs, 1)) * 1000);
  if (which === 'rpow') {
    state.rpow.hashes = hashes;
    state.rpow.hashesPerSecond = speed;
  } else {
    state.rpow2.hashes = hashes;
    state.rpow2.hashesPerSecond = speed;
  }
  saveState().catch(() => {});
}

async function startRpowCycle() {
  if (!state.rpow.running || rpowWorker || rpowSubmitInFlight) return;
  if (!state.rpow.registry.length) await refreshRpowRegistry();
  const targetId = nextRpowTarget();
  if (!targetId) {
    state.rpow.lastError = `target ${state.rpow.target} not available`;
    overallError = state.rpow.lastError;
    state.rpow.running = false;
    await saveState();
    return;
  }
  rpowStopRequested = false;
  state.rpow.activeTarget = targetId;
  state.rpow.lastError = null;
  await saveState();
  try {
    const challenge = await signedFetch(targetId, '/challenge', { method: 'POST' });
    state.rpow.lastChallenge = { ...challenge, nodeId: targetId };
    await saveState();
    rpowWorker = new Worker(new URL('./miner.worker.mjs', import.meta.url));
    rpowWorker.on('message', async (msg) => {
      if (!msg || typeof msg !== 'object') return;
      if (msg.type === 'progress') return updateProgress('rpow', msg);
      if (msg.type === 'found') {
        clearRpowTimers();
        if (rpowWorker) await rpowWorker.terminate().catch(() => {});
        rpowWorker = null;
        rpowSubmitInFlight = true;
        try {
          const result = await submitRpowMint(targetId, challenge, msg.solution_nonce, msg.hashes);
          state.rpow.lastResult = { ...(state.rpow.lastResult || {}), token: result?.token || result?.tokenSummary || null };
          state.rpow.lastError = null;
          await saveState();
        } catch (error) {
          state.rpow.lastError = `mint failed: ${error.message}`;
          overallError = state.rpow.lastError;
          await saveState();
        } finally {
          rpowSubmitInFlight = false;
          if (state.rpow.running && !rpowStopRequested) scheduleRpowRestart();
        }
        return;
      }
      if (msg.type === 'aborted') {
        clearRpowTimers();
        if (rpowWorker) await rpowWorker.terminate().catch(() => {});
        rpowWorker = null;
        if (state.rpow.running && !rpowStopRequested) scheduleRpowRestart();
      }
    });
    rpowWorker.on('error', async (error) => {
      state.rpow.lastError = `worker error: ${error.message}`;
      overallError = state.rpow.lastError;
      await saveState();
      rpowWorker = null;
      rpowSubmitInFlight = false;
      if (state.rpow.running && !rpowStopRequested) scheduleRpowRestart();
    });
    rpowWorker.on('exit', () => {
      rpowWorker = null;
      clearRpowTimers();
    });
    const expiresAt = new Date(challenge.expires_at).getTime();
    rpowChallengeTimeout = setTimeout(() => {
      if (rpowWorker) rpowWorker.postMessage({ type: 'abort' });
    }, Math.max(1000, expiresAt - Date.now() - 5000));
    rpowWorker.postMessage({ type: 'start', nonce_prefix: challenge.nonce_prefix, difficulty_bits: challenge.difficulty_bits });
  } catch (error) {
    state.rpow.lastError = `challenge failed: ${error.message}`;
    overallError = state.rpow.lastError;
    await saveState();
    if (state.rpow.running && !rpowStopRequested) scheduleRpowRestart();
  }
}

async function startRpow2Cycle() {
  if (!state.rpow2.running || rpow2Worker || rpow2SubmitInFlight || !rpow2SessionCookie) return;
  rpow2StopRequested = false;
  state.rpow2.lastError = null;
  await saveState();
  try {
    const challenge = await fetchJson(`${rpow2ApiBase}/challenge`, {
      method: 'POST',
      headers: { cookie: `rpow_session=${rpow2SessionCookie}` },
    });
    state.rpow2.lastChallenge = challenge;
    await saveState();
    rpow2Worker = new Worker(new URL('./miner.worker.mjs', import.meta.url));
    rpow2Worker.on('message', async (msg) => {
      if (!msg || typeof msg !== 'object') return;
      if (msg.type === 'progress') return updateProgress('rpow2', msg);
      if (msg.type === 'found') {
        clearRpow2Timers();
        if (rpow2Worker) await rpow2Worker.terminate().catch(() => {});
        rpow2Worker = null;
        rpow2SubmitInFlight = true;
        try {
          await submitRpow2Mint(challenge, msg.solution_nonce, msg.hashes);
          state.rpow2.lastError = null;
          await saveState();
        } catch (error) {
          state.rpow2.lastError = `mint failed: ${error.message}`;
          overallError = state.rpow2.lastError;
          await saveState();
        } finally {
          rpow2SubmitInFlight = false;
          if (state.rpow2.running && !rpow2StopRequested) scheduleRpow2Restart();
        }
        return;
      }
      if (msg.type === 'aborted') {
        clearRpow2Timers();
        if (rpow2Worker) await rpow2Worker.terminate().catch(() => {});
        rpow2Worker = null;
        if (state.rpow2.running && !rpow2StopRequested) scheduleRpow2Restart();
      }
    });
    rpow2Worker.on('error', async (error) => {
      state.rpow2.lastError = `worker error: ${error.message}`;
      overallError = state.rpow2.lastError;
      await saveState();
      rpow2Worker = null;
      rpow2SubmitInFlight = false;
      if (state.rpow2.running && !rpow2StopRequested) scheduleRpow2Restart();
    });
    rpow2Worker.on('exit', () => {
      rpow2Worker = null;
      clearRpow2Timers();
    });
    const expiresAt = new Date(challenge.expires_at).getTime();
    rpow2ChallengeTimeout = setTimeout(() => {
      if (rpow2Worker) rpow2Worker.postMessage({ type: 'abort' });
    }, Math.max(1000, expiresAt - Date.now() - 5000));
    rpow2Worker.postMessage({ type: 'start', nonce_prefix: challenge.nonce_prefix, difficulty_bits: challenge.difficulty_bits });
  } catch (error) {
    state.rpow2.lastError = `challenge failed: ${error.message}`;
    overallError = state.rpow2.lastError;
    await saveState();
    if (state.rpow2.running && !rpow2StopRequested) scheduleRpow2Restart();
  }
}

async function pollTelegramUpdates() {
  if (!telegramToken || telegramPollBusy) return;
  telegramPollBusy = true;
  try {
    if (!state.telegram.botUsername) {
      try {
        const me = await telegramFetch('getMe');
        state.telegram.botUsername = me?.username || '';
        await saveState();
      } catch {}
    }
    const updates = await telegramFetch('getUpdates?timeout=10&offset=' + String((state.telegram.lastUpdateId || 0) + 1));
    for (const upd of updates || []) {
      if (typeof upd?.update_id === 'number') state.telegram.lastUpdateId = Math.max(state.telegram.lastUpdateId || 0, upd.update_id);
      const chatId = upd?.message?.chat?.id ?? upd?.channel_post?.chat?.id ?? upd?.callback_query?.message?.chat?.id;
      if (chatId != null && !state.telegram.chatId) {
        state.telegram.chatId = String(chatId);
        state.telegram.lastDiscoveredAt = new Date().toISOString();
        await saveState();
        await sendTelegramMessage('Telegram linked. You will get reports every ' + Math.round(telegramReportMs / 60000) + ' minutes.');
      }
    }
  } catch (error) {
    overallError = `telegram poll failed: ${error.message}`;
  } finally {
    telegramPollBusy = false;
  }
}

async function sendTelegramMessage(text) {
  if (!telegramToken || !state.telegram.chatId) return false;
  await telegramFetch('sendMessage', { chat_id: state.telegram.chatId, text, disable_web_page_preview: true });
  state.telegram.lastReportAt = new Date().toISOString();
  await saveState();
  return true;
}

function fmtTime(iso) {
  return iso ? new Date(iso).toLocaleString('en-US', { timeZone: 'Asia/Jakarta' }) : '—';
}


function strOrDash(value) {
  return value === null || value === undefined || value === '' ? '—' : String(value);
}

function buildRpowMinerTab(nodeId) {
  const label = nodeId === 'alpha' ? 'RPOW A' : 'RPOW B';
  const nodeInfo = state.rpow.nodeInfo[nodeId] || null;
  const target = state.rpow.target;
  const active = target === 'both' ? state.rpow.activeTarget === nodeId : target === nodeId;
  const status = !state.rpow.running ? 'stopped' : active ? 'active' : target === 'both' ? 'waiting' : 'idle';
  const statusLine = nodeInfo
    ? `${label} ${status} · difficulty ${strOrDash(nodeInfo.difficulty_bits)} · supply ${strOrDash(nodeInfo.current_supply)}/${strOrDash(nodeInfo.max_supply)}`
    : `${label} ${status} · waiting for node data`;
  const metrics = {
    status,
    target,
    'active target': state.rpow.activeTarget || '—',
    'wallet configured': state.rpow.walletConfigured ? 'yes' : 'no',
    'wallet pubkey': state.rpow.wallet.pubHex || '—',
    mints: String(state.rpow.totalMints),
    hashes: String(state.rpow.hashes),
    speed: state.rpow.hashesPerSecond ? state.rpow.hashesPerSecond.toLocaleString() + ' h/s' : '—',
    'last mint': state.rpow.lastMintAt ? fmtTime(state.rpow.lastMintAt) : '—',
    difficulty: strOrDash(nodeInfo?.difficulty_bits),
    supply: nodeInfo ? strOrDash(nodeInfo.current_supply) + '/' + strOrDash(nodeInfo.max_supply) : '—',
    'tokens to halving': strOrDash(nodeInfo?.tokens_to_halving),
    'node pubkey': strOrDash(nodeInfo?.signing_pubkey_hex),
  };
  const activity = [
    'status: ' + status,
    state.rpow.lastChallenge?.nodeId === nodeId ? 'challenge: ' + state.rpow.lastChallenge.challenge_id : '',
    state.rpow.lastResult?.nodeId === nodeId ? 'last result: ' + JSON.stringify(state.rpow.lastResult) : '',
    state.rpow.lastError ? 'last error: ' + state.rpow.lastError : '',
  ].filter(Boolean);
  return {
    id: nodeId,
    title: label,
    status,
    statusLine,
    metrics,
    activity,
    running: state.rpow.running,
    active,
    nodeInfo,
    totalMints: state.rpow.totalMints,
    hashes: state.rpow.hashes,
    hashesPerSecond: state.rpow.hashesPerSecond,
    lastMintAt: state.rpow.lastMintAt,
    lastError: state.rpow.lastError,
    lastChallenge: state.rpow.lastChallenge?.nodeId === nodeId ? state.rpow.lastChallenge : null,
    lastResult: state.rpow.lastResult?.nodeId === nodeId ? state.rpow.lastResult : null,
  };
}

function buildRpow2Tab() {
  const me = state.rpow2.me || null;
  const ledger = state.rpow2.ledger || null;
  const status = !state.rpow2.running ? 'stopped' : state.rpow2.lastError ? 'error' : 'active';
  const statusLine = state.rpow2.lastError ? 'error: ' + state.rpow2.lastError : state.rpow2.running ? 'running' : 'stopped';
  const metrics = {
    status,
    'cookie configured': state.rpow2.cookieConfigured ? 'yes' : 'no',
    running: state.rpow2.running ? 'yes' : 'no',
    mints: String(state.rpow2.totalMints),
    hashes: String(state.rpow2.hashes),
    speed: state.rpow2.hashesPerSecond ? state.rpow2.hashesPerSecond.toLocaleString() + ' h/s' : '—',
    balance: me ? strOrDash(me.balance_base_units || me.balance) : '—',
    reward: ledger ? strOrDash(ledger.current_reward_base_units) : '—',
    difficulty: ledger ? strOrDash(ledger.current_difficulty_bits) : '—',
    'last mint': state.rpow2.lastMintAt ? fmtTime(state.rpow2.lastMintAt) : '—',
    'last challenge': state.rpow2.lastChallenge?.challenge_id || '—',
  };
  const activity = [
    'status: ' + status,
    state.rpow2.lastError ? 'last error: ' + state.rpow2.lastError : '',
    state.rpow2.lastResult ? 'last result: ' + JSON.stringify(state.rpow2.lastResult) : '',
  ].filter(Boolean);
  return {
    id: 'rpow2',
    title: 'RPOW2',
    status,
    statusLine,
    metrics,
    activity,
    running: state.rpow2.running,
    active: state.rpow2.running,
    me,
    ledger,
    totalMints: state.rpow2.totalMints,
    hashes: state.rpow2.hashes,
    hashesPerSecond: state.rpow2.hashesPerSecond,
    lastMintAt: state.rpow2.lastMintAt,
    lastError: state.rpow2.lastError,
    lastChallenge: state.rpow2.lastChallenge,
    lastResult: state.rpow2.lastResult,
  };
}

function buildTabsData() {
  return {
    rpow2: buildRpow2Tab(),
    rpowA: buildRpowMinerTab('alpha'),
    rpowB: buildRpowMinerTab('beta'),
  };
}

function telegramLine(tab) {
  if (tab.id === 'rpow2') {
    return tab.title + ': ' + tab.status + ' | mints=' + tab.metrics.mints + ' | balance=' + tab.metrics.balance + ' | reward=' + tab.metrics.reward + ' | diff=' + tab.metrics.difficulty;
  }
  return tab.title + ': ' + tab.status + ' | mints=' + tab.metrics.mints + ' | hashes=' + tab.metrics.hashes + ' | speed=' + tab.metrics.speed + ' | diff=' + tab.metrics.difficulty + ' | supply=' + tab.metrics.supply + ' | to-halving=' + tab.metrics['tokens to halving'];
}

function dashboardHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>rpow monitor</title>
  <style>
    :root{color-scheme:dark;--bg:#09090b;--card:#111827;--border:#243044;--text:#e5e7eb;--muted:#94a3b8;--accent:#34d399;--warn:#f59e0b;--err:#f87171;--tab:#0f172a}
    *{box-sizing:border-box} body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;background:radial-gradient(circle at top,#0f172a,#09090b 60%);color:var(--text)}
    .wrap{max-width:1100px;margin:0 auto;padding:20px} h1{margin:0 0 6px;font-size:28px} .sub{color:var(--muted);margin-bottom:16px;line-height:1.45}
    .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px} .card{grid-column:span 6;background:rgba(17,24,39,.92);border:1px solid var(--border);border-radius:16px;padding:16px;box-shadow:0 16px 50px rgba(0,0,0,.24)} .card.full{grid-column:1/-1}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between} .kv{display:grid;grid-template-columns:180px 1fr;gap:8px 12px;font-size:14px}
    .k{color:var(--muted)} .v{word-break:break-all} .pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);border-radius:999px;padding:6px 10px;font-size:12px;color:var(--muted);background:rgba(15,23,42,.7)}
    .ok{color:var(--accent)} .warn{color:var(--warn)} .bad{color:var(--err)} .small{font-size:12px;color:var(--muted)} .statusline{font-size:14px;line-height:1.6} pre{margin:0;white-space:pre-wrap;word-break:break-word}
    .list{display:grid;gap:8px} .item{display:flex;justify-content:space-between;gap:10px;padding:10px 12px;border:1px solid var(--border);border-radius:12px;background:rgba(15,23,42,.45)}
    .tabs{display:flex;gap:8px;flex-wrap:wrap}.tab-btn{border:1px solid var(--border);background:var(--tab);color:var(--text);padding:10px 12px;border-radius:12px;cursor:pointer;font:inherit}.tab-btn.active{border-color:var(--accent);box-shadow:0 0 0 1px rgba(52,211,153,.18) inset}.tab-btn .sub{display:block;font-size:11px;margin-top:4px;color:var(--muted)}
    @media (max-width:900px){.card{grid-column:1/-1}.kv{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>rpow monitor</h1>
    <div class="sub">Public status page for RPOW2, RPOW A, and RPOW B. Open it on your phone while the laptop is off.</div>
    <div class="grid">
      <div class="card full">
        <div class="row">
          <div>
            <div class="pill" id="statePill">loading…</div>
            <div class="statusline" id="statusLine" style="margin-top:10px">connecting…</div>
          </div>
          <div class="small" id="telegramMeta">loading…</div>
        </div>
      </div>

      <div class="card full">
        <div class="row" style="margin-bottom:10px">
          <strong>Tabs</strong>
          <span class="small">RPOW2 + RPOW A + RPOW B</span>
        </div>
        <div class="tabs" id="tabBar"></div>
      </div>

      <div class="card">
        <div class="row" style="margin-bottom:10px">
          <strong id="tabTitle">Tab</strong>
          <span class="small" id="tabStatus">waiting…</span>
        </div>
        <div class="kv" id="tabMetrics"></div>
      </div>

      <div class="card">
        <div class="row" style="margin-bottom:10px">
          <strong>Activity</strong>
          <span class="small">selected tab</span>
        </div>
        <pre id="tabActivity" class="small">waiting…</pre>
      </div>

      <div class="card full">
        <div class="row" style="margin-bottom:10px"><strong>Known RPOW nodes</strong><span class="small">auto-refreshed</span></div>
        <div class="list" id="nodesList"></div>
      </div>

      <div class="card full">
        <div class="row" style="margin-bottom:10px"><strong>Recent activity</strong><span class="small">local state only</span></div>
        <pre id="activity" class="small">waiting…</pre>
      </div>

      <div class="card full">
        <div class="row" style="margin-bottom:10px"><strong>Telegram</strong><span class="small">reports every ${Math.round(telegramReportMs / 60000)} min</span></div>
        <div class="small" id="telegramStatus">loading…</div>
      </div>
    </div>
  </div>
  <script>
    let selectedTab = 'rpow2';
    let lastData = null;

    function fmt(v) {
      return v === null || v === undefined || v === '' ? '—' : String(v);
    }

    function renderMetrics(tab) {
      const metrics = tab.metrics || {};
      return Object.entries(metrics).map(function(entry) {
        const k = entry[0];
        const v = entry[1];
        return '<div class="k">' + k + '</div><div class="v">' + fmt(v) + '</div>';
      }).join('');
    }

    function renderTabs(data) {
      const tabs = data.tabs || {};
      const order = ['rpow2', 'rpowA', 'rpowB'];
      const bar = document.getElementById('tabBar');
      bar.innerHTML = order.map(function(key) {
        const tab = tabs[key];
        const active = selectedTab === key ? ' active' : '';
        const title = tab ? tab.title : key;
        const status = tab ? tab.status : '—';
        return '<button class="tab-btn' + active + '" data-tab="' + key + '">' + title + '<span class="sub">' + status + '</span></button>';
      }).join('');
      bar.querySelectorAll('button[data-tab]').forEach(function(btn) {
        btn.addEventListener('click', function() {
          selectedTab = btn.getAttribute('data-tab') || 'rpow2';
          if (lastData) render(lastData);
        });
      });
    }

    function renderSelectedTab(data) {
      const tab = (data.tabs && data.tabs[selectedTab]) || (data.tabs && data.tabs.rpow2) || null;
      if (!tab) return;
      document.getElementById('tabTitle').textContent = tab.title || selectedTab;
      document.getElementById('tabStatus').textContent = tab.statusLine || tab.status || '—';
      document.getElementById('tabMetrics').innerHTML = renderMetrics(tab);
      document.getElementById('tabActivity').textContent = (tab.activity || []).join('\n') || 'waiting…';
      document.getElementById('telegramMeta').textContent = data.telegram && data.telegram.botUsername ? 'linked to @' + data.telegram.botUsername : 'waiting for Telegram link';
      document.getElementById('telegramStatus').textContent = data.telegram && data.telegram.chatId ? 'linked to chat ' + data.telegram.chatId : 'send /start to the bot once to link Telegram';
    }

    function render(data) {
      lastData = data;
      if (!data.tabs || !data.tabs[selectedTab]) selectedTab = 'rpow2';
      const overallActive = data.tabs && (data.tabs.rpow2?.running || data.tabs.rpowA?.running || data.tabs.rpowB?.running);
      const overallError = data.overallError;
      const statePill = document.getElementById('statePill');
      const statusLine = document.getElementById('statusLine');
      statePill.textContent = overallActive ? 'running' : 'idle';
      statePill.className = 'pill ' + (overallActive ? 'ok' : 'warn');
      statusLine.innerHTML = overallError ? '<span class="bad">' + overallError + '</span>' : 'all good';

      renderTabs(data);
      renderSelectedTab(data);

      const rpow = data.rpow || {};
      const rpow2 = data.rpow2 || {};
      const nodesList = document.getElementById('nodesList');
      nodesList.innerHTML = (rpow.registry || []).length ? rpow.registry.map(function(node) {
        const info = rpow.target === 'both' ? (rpow.nodeInfo && rpow.nodeInfo[node.id]) : (rpow.nodeInfo && rpow.nodeInfo[rpow.activeTarget || rpow.target]);
        return '<div class="item"><div><b>' + node.id + '</b> <span class="small">' + node.name + '</span>' + (info ? '<div class="small">difficulty ' + info.difficulty_bits + ' · users ' + info.user_count + ' · supply ' + info.current_supply + '/' + info.max_supply + '</div>' : '') + '</div><div class="small">' + (node.baseUrl || '') + '</div></div>';
      }).join('') : '<div class="small">no nodes loaded yet</div>';

      const activity = [];
      activity.push('RPOW: ' + (rpow.running ? 'running' : 'stopped') + ' | target=' + fmt(rpow.target) + ' | active=' + fmt(rpow.activeTarget));
      if (rpow.lastChallenge) activity.push('rpow challenge: ' + rpow.lastChallenge.challenge_id + ' @ ' + fmt(rpow.lastChallenge.nodeId || rpow.activeTarget || rpow.target));
      if (rpow.lastResult) activity.push('rpow last result: ' + JSON.stringify(rpow.lastResult));
      activity.push('RPOW2: ' + (rpow2.running ? 'running' : 'stopped') + ' | mints=' + fmt(rpow2.totalMints));
      if (rpow2.lastChallenge) activity.push('rpow2 challenge: ' + rpow2.lastChallenge.challenge_id);
      if (rpow2.lastResult) activity.push('rpow2 last result: ' + JSON.stringify(rpow2.lastResult));
      if (data.telegram && data.telegram.chatId) activity.push('telegram: linked to chat ' + data.telegram.chatId);
      document.getElementById('activity').textContent = activity.join('\n');
    }

    async function load() {
      try {
        const response = await fetch('/api/status', { headers: { accept: 'application/json' } });
        const data = await response.json();
        if (!response.ok) throw new Error(data && data.error ? data.error : response.statusText);
        render(data);
      } catch (error) {
        document.getElementById('statePill').textContent = 'offline';
        document.getElementById('statePill').className = 'pill warn';
        document.getElementById('statusLine').textContent = error.message;
      }
    }

    load();
    setInterval(load, 5000);
  </script>
</body>
</html>`;
}

function publicState() {
  const tabs = buildTabsData();
  return {
    rpow: {
      running: state.rpow.running,
      target: state.rpow.target,
      activeTarget: state.rpow.activeTarget,
      walletPubHex: state.rpow.wallet.pubHex,
      walletConfigured: state.rpow.walletConfigured,
      totalMints: state.rpow.totalMints,
      lastMintAt: state.rpow.lastMintAt,
      lastError: state.rpow.lastError,
      lastResult: state.rpow.lastResult,
      lastChallenge: state.rpow.lastChallenge,
      hashes: state.rpow.hashes,
      hashesPerSecond: state.rpow.hashesPerSecond,
      registry: state.rpow.registry,
      nodeInfo: state.rpow.nodeInfo,
    },
    rpow2: {
      running: state.rpow2.running,
      cookieConfigured: state.rpow2.cookieConfigured,
      totalMints: state.rpow2.totalMints,
      lastMintAt: state.rpow2.lastMintAt,
      lastError: state.rpow2.lastError,
      lastResult: state.rpow2.lastResult,
      lastChallenge: state.rpow2.lastChallenge,
      hashes: state.rpow2.hashes,
      hashesPerSecond: state.rpow2.hashesPerSecond,
      me: state.rpow2.me,
      ledger: state.rpow2.ledger,
    },
    tabs,
    telegram: {
      chatId: state.telegram.chatId,
      botUsername: state.telegram.botUsername,
      lastReportAt: state.telegram.lastReportAt,
      lastDiscoveredAt: state.telegram.lastDiscoveredAt,
    },
    overallError,
    uptimeMs: Date.now() - startedAt,
  };
}

async function sendTelegramReport() {
  if (!telegramToken || !state.telegram.chatId) return false;
  const tabs = buildTabsData();
  const text = [
    'rpow monitor report',
    telegramLine(tabs.rpow2),
    telegramLine(tabs.rpowA),
    telegramLine(tabs.rpowB),
    'Updated: ' + new Date().toISOString(),
  ].join('\n');
  await telegramFetch('sendMessage', { chat_id: state.telegram.chatId, text, disable_web_page_preview: true });
  state.telegram.lastReportAt = new Date().toISOString();
  await saveState();
  return true;
}


async function bootstrap() {
  await loadConfig();
  await loadState();
  if (autostart && state.rpow.running) setTimeout(() => startRpowCycle().catch(() => {}), 800);
  if (autostart && state.rpow2.running) setTimeout(() => startRpow2Cycle().catch(() => {}), 1200);
  if (telegramToken) {
    setTimeout(() => pollTelegramUpdates().catch(() => {}), 2500);
    telegramPollTimer = setInterval(() => pollTelegramUpdates().catch(() => {}), telegramPollMs);
    telegramReportTimer = setInterval(() => sendTelegramReport().catch(() => {}), telegramReportMs);
  }
  nodeInfoTimer = setInterval(() => {
    refreshRpowRegistry().catch(() => {});
    refreshRpowNodeInfo().catch(() => {});
  }, nodeInfoRefreshMs);
  rpow2MetaTimer = setInterval(() => refreshRpow2Meta().catch(() => {}), rpow2RefreshMs);
  await refreshRpowRegistry();
  await refreshRpowNodeInfo();
  await refreshRpow2Meta();
}

async function readBody(req) {
  return await new Promise((resolve) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

async function handleRequest(req, res) {
  const url = new URL(req.url || '/', 'http://127.0.0.1');
  try {
    if (req.method === 'GET' && url.pathname === '/') return html(res, dashboardHtml());
    if (req.method === 'GET' && url.pathname === '/api/status') return json(res, 200, publicState());
    return json(res, 404, { error: 'not found' });
  } catch (error) {
    return json(res, 500, { error: error.message });
  }
}

async function shutdown() {
  rpowStopRequested = true;
  rpow2StopRequested = true;
  clearRpowTimers();
  clearRpow2Timers();
  if (rpowWorker) await rpowWorker.terminate().catch(() => {});
  if (rpow2Worker) await rpow2Worker.terminate().catch(() => {});
  if (nodeInfoTimer) clearInterval(nodeInfoTimer);
  if (rpow2MetaTimer) clearInterval(rpow2MetaTimer);
  if (telegramPollTimer) clearInterval(telegramPollTimer);
  if (telegramReportTimer) clearInterval(telegramReportTimer);
}

if (process.argv[1] && process.argv[1].endsWith('server.mjs')) {
  await bootstrap();
  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch((error) => json(res, 500, { error: error.message }));
  });
  server.listen(port, '0.0.0.0', () => console.log(`rpow monitor listening on ${port}`));
  process.on('SIGINT', async () => { await shutdown(); server.close(() => process.exit(0)); });
  process.on('SIGTERM', async () => { await shutdown(); server.close(() => process.exit(0)); });
}
