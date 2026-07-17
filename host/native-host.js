#!/usr/bin/env node

// Native Messaging Host for Open Claude in Chrome extension.
// Launched by Chrome when the extension calls connectNative().
// Bridges between Chrome native messaging (stdin/stdout, 4-byte LE length prefix + JSON)
// and the MCP server (TCP on localhost).

import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { getAuthToken, makePeerHello, checkServerProof } from "./auth-token.js";

const DEFAULT_PORT = 18765;

function getPort() {
  const configPath = path.join(
    os.homedir(),
    ".config",
    "open-claude-in-chrome",
    "config.json"
  );
  try {
    const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    return config.port || DEFAULT_PORT;
  } catch {
    return DEFAULT_PORT;
  }
}

// --- Native messaging protocol (Chrome <-> this process) ---

function readNativeMessage(buffer) {
  const messages = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const len = buffer.readUInt32LE(offset);
    if (offset + 4 + len > buffer.length) break;
    const json = buffer.subarray(offset + 4, offset + 4 + len).toString("utf-8");
    try {
      messages.push(JSON.parse(json));
    } catch (e) {
      // skip malformed
    }
    offset += 4 + len;
  }
  return { messages, remainder: buffer.subarray(offset) };
}

function writeNativeMessage(obj) {
  const json = JSON.stringify(obj);
  const buf = Buffer.from(json, "utf-8");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(buf.length, 0);
  process.stdout.write(Buffer.concat([header, buf]));
}

// --- TCP connection to MCP server ---

let tcpSocket = null;
let tcpBuffer = Buffer.alloc(0);
let reconnectTimer = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 60; // 30 seconds at 500ms intervals
const TCP_PORT = getPort();
const AUTH_TOKEN = getAuthToken();

// Mutual-auth state. We do NOT forward anything to/from the primary until it
// proves it knows the shared token (server_proof). Otherwise a rogue process
// that merely binds the loopback port could impersonate the primary and drive
// the browser (the rogue-primary MITM). The token itself is never sent.
let primaryVerified = false;
let pendingProofNonce = null;
let proofTimer = null;

function connectTcp() {
  if (tcpSocket) return;

  tcpSocket = new net.Socket();

  tcpSocket.connect(TCP_PORT, "127.0.0.1", () => {
    if (reconnectTimer) {
      clearInterval(reconnectTimer);
      reconnectTimer = null;
    }
    primaryVerified = false;
    // Send our hello: nonce + HMAC. The token is never put on the wire.
    const hello = makePeerHello(AUTH_TOKEN, "native");
    pendingProofNonce = hello.nonce;
    tcpSocket.write(JSON.stringify({ type: "native_hello", nonce: hello.nonce, mac: hello.mac }) + "\n");
    // If the primary doesn't prove itself within 2s, it's a rogue (or dead) — drop it.
    proofTimer = setTimeout(() => {
      if (!primaryVerified && tcpSocket) {
        try { tcpSocket.destroy(); } catch {}
      }
    }, 2000);
  });

  tcpSocket.on("data", (chunk) => {
    // newline-delimited JSON from MCP server
    tcpBuffer = Buffer.concat([tcpBuffer, chunk]);

    // Gate: until the primary proves itself, the first line MUST be a valid
    // server_proof. Hold everything else (and never forward to the extension).
    if (!primaryVerified) {
      const nl = tcpBuffer.indexOf(10);
      if (nl === -1) {
        if (tcpBuffer.length > 8192) { try { tcpSocket.destroy(); } catch {} } // junk, not a proof
        return;
      }
      const line = tcpBuffer.subarray(0, nl).toString("utf-8").trim();
      tcpBuffer = tcpBuffer.subarray(nl + 1);
      let msg;
      try { msg = JSON.parse(line); } catch {}
      if (!msg || msg.type !== "server_proof" || !checkServerProof(AUTH_TOKEN, "native", pendingProofNonce, msg.mac)) {
        // Rogue primary or malformed handshake — refuse to bridge.
        try { tcpSocket.destroy(); } catch {}
        return;
      }
      primaryVerified = true;
      reconnectAttempts = 0; // count only verified connections toward the give-up cap
      if (proofTimer) { clearTimeout(proofTimer); proofTimer = null; }
      // fall through and process any data that followed the proof
    }

    let newlineIdx;
    while ((newlineIdx = tcpBuffer.indexOf(10)) !== -1) {
      const line = tcpBuffer.subarray(0, newlineIdx).toString("utf-8").trim();
      tcpBuffer = tcpBuffer.subarray(newlineIdx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        // Forward to extension via native messaging
        writeNativeMessage(msg);
      } catch {
        // skip malformed
      }
    }
  });

  tcpSocket.on("error", () => {
    tcpSocket = null;
  });

  tcpSocket.on("close", () => {
    tcpSocket = null;
    primaryVerified = false;
    if (proofTimer) { clearTimeout(proofTimer); proofTimer = null; }
    if (!reconnectTimer) {
      reconnectTimer = setInterval(() => {
        reconnectAttempts++;
        if (reconnectAttempts > MAX_RECONNECT_ATTEMPTS) {
          // MCP server is gone — exit cleanly so we don't linger as a zombie
          clearInterval(reconnectTimer);
          process.exit(0);
        }
        if (!tcpSocket) connectTcp();
      }, 500);
    }
  });
}

// --- Main: bridge stdin (from extension) <-> TCP (to MCP server) ---

let stdinBuffer = Buffer.alloc(0);

process.stdin.on("data", (chunk) => {
  stdinBuffer = Buffer.concat([stdinBuffer, chunk]);
  const { messages, remainder } = readNativeMessage(stdinBuffer);
  stdinBuffer = remainder;

  for (const msg of messages) {
    // Forward to MCP server via TCP — only once the primary has authenticated.
    if (tcpSocket && !tcpSocket.destroyed && primaryVerified) {
      tcpSocket.write(JSON.stringify(msg) + "\n");
    }
  }
});

process.stdin.on("end", () => {
  // Extension disconnected
  if (tcpSocket) tcpSocket.destroy();
  process.exit(0);
});

// Start TCP connection
connectTcp();
