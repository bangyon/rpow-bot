import { parentPort } from 'node:worker_threads';
import { sha256 } from '@noble/hashes/sha2.js';

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

function hexToBytes(value) {
  return Uint8Array.from(value.match(/.{1,2}/g).map((pair) => Number.parseInt(pair, 16)));
}

let abortRequested = false;

parentPort.on('message', (msg) => {
  if (!msg || typeof msg !== 'object') return;
  if (msg.type === 'abort') abortRequested = true;
  if (msg.type !== 'start') return;
  abortRequested = false;
  const prefix = hexToBytes(String(msg.nonce_prefix || ''));
  const difficultyBits = Number(msg.difficulty_bits || 0);
  const buf = new Uint8Array(prefix.length + 8);
  buf.set(prefix, 0);
  let nonce = 0n;
  let hashes = 0n;
  const start = performance.now();
  let lastProgress = start;
  while (!abortRequested) {
    let n = nonce;
    for (let i = 0; i < 8; i += 1) {
      buf[prefix.length + i] = Number(n & 0xffn);
      n >>= 8n;
    }
    const digest = sha256(buf);
    if (trailingZeroBits(digest) >= difficultyBits) {
      parentPort.postMessage({ type: 'found', solution_nonce: nonce.toString(), hashes: hashes.toString() });
      return;
    }
    nonce += 1n;
    hashes += 1n;
    if ((hashes & 0xffffn) === 0n) {
      const now = performance.now();
      if (now - lastProgress > 250) {
        parentPort.postMessage({ type: 'progress', hashes: hashes.toString(), elapsed_ms: Math.round(now - start) });
        lastProgress = now;
      }
    }
  }
  parentPort.postMessage({ type: 'aborted' });
});
