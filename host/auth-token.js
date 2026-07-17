// Shared secret that authenticates connections on the local TCP control channel
// between the MCP servers and the native messaging host.
//
// The token lives in a 0600 file next to config.json, so only the current user
// can read it. That is the whole access-control model: any local process that
// can read the file is already running as the user (and could drive the browser
// by other means anyway), while other local users — who can still reach the
// loopback port — cannot read the token and are therefore rejected.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const dir = path.join(os.homedir(), ".config", "open-claude-in-chrome");
const tokenPath = path.join(dir, "token");

function tryRead() {
  try {
    const t = fs.readFileSync(tokenPath, "utf-8").trim();
    return t || null;
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
}

// Read the shared token, creating it on first use. Concurrent starts (multiple
// sessions, the native host) converge on a single token: the create is atomic
// (write a temp file, then hard-link it into place), so whoever loses the race
// just reads the winner's token.
export function getAuthToken() {
  const existing = tryRead();
  if (existing) return existing;

  try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch {}

  const token = crypto.randomBytes(32).toString("hex");
  const tmp = `${tokenPath}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, token, { mode: 0o600 });
    fs.linkSync(tmp, tokenPath); // throws EEXIST if another process got there first
    return token;
  } catch {
    const other = tryRead();
    if (other) return other;
    throw new Error("open-claude-in-chrome: could not establish auth token");
  } finally {
    try { fs.unlinkSync(tmp); } catch {}
  }
}

// --- Mutual HMAC challenge-response ---
//
// The token NEVER crosses the wire. Instead of sending it in cleartext, a peer
// proves knowledge of it; the primary proves itself back. This closes the
// rogue-primary MITM: an attacker (including another local user) who binds the
// loopback port first cannot forge the server proof without the token, so peers
// refuse to trust it and never forward tool traffic its way. It also means a
// rogue can't even LEARN the token by impersonating a primary.
//
// Messages (newline-delimited JSON):
//   peer   -> primary : {type:"<role>_hello", nonce, mac: HMAC(token, "peer:<role>:<nonce>")}
//   primary -> peer   : {type:"server_proof",               mac: HMAC(token, "server:<role>:<nonce>")}
// <role> is "client" or "native", which prevents replaying one role's proof as another.

function hmacHex(token, msg) {
  return crypto.createHmac("sha256", token).update(msg).digest("hex");
}
function ctEqHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
const NONCE_MIN_LEN = 16; // generated nonces are 64 hex chars; reject anything implausibly short

// Peer side: build an outgoing hello.
export function makePeerHello(token, role) {
  const nonce = crypto.randomBytes(32).toString("hex");
  return { nonce, mac: hmacHex(token, `peer:${role}:${nonce}`) };
}
// Primary side: verify an incoming hello.
export function checkPeerHello(token, role, nonce, mac) {
  if (typeof nonce !== "string" || nonce.length < NONCE_MIN_LEN) return false;
  return ctEqHex(mac, hmacHex(token, `peer:${role}:${nonce}`));
}
// Primary side: build the proof that it is the legitimate primary.
export function makeServerProof(token, role, nonce) {
  return hmacHex(token, `server:${role}:${nonce}`);
}
// Peer side: verify the primary's proof (bound to the nonce this peer generated).
export function checkServerProof(token, role, nonce, mac) {
  if (typeof nonce !== "string" || nonce.length < NONCE_MIN_LEN) return false;
  return ctEqHex(mac, hmacHex(token, `server:${role}:${nonce}`));
}
