// Authentication tests for the local TCP control channel.
//
// Spawns a real primary mcp-server.js plus a mock native host on an isolated
// port (temp HOME with its own config.json + token file, so a real instance is
// never touched) and drives the mutual-auth TCP handshake with raw sockets.
// Covers: (1) peers without the shared token cannot reach the browser, and
// (2) a rogue that binds the port but lacks the token cannot impersonate the
// primary (the rogue-primary MITM) because it cannot forge server_proof.
//
// Run: npm test   (from host/)

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { makePeerHello, checkServerProof } from "./auth-token.js";

const SERVER = path.join(import.meta.dirname, "mcp-server.js");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function isolatedEnv(port) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ocic-auth-"));
  const cfgDir = path.join(home, ".config", "open-claude-in-chrome");
  fs.mkdirSync(cfgDir, { recursive: true });
  fs.writeFileSync(path.join(cfgDir, "config.json"), JSON.stringify({ port }));
  const token = `test-token-${port}`;
  fs.writeFileSync(path.join(cfgDir, "token"), token, { mode: 0o600 });
  return { env: { ...process.env, HOME: home }, home, token };
}

// A mock native host that does the REAL mutual-auth handshake (nonce+MAC hello,
// verify server_proof) before answering tool_request with MOCK_OK.
function startMockNativeHost(port, token) {
  let sock;
  let alive = true;
  function connect() {
    sock = net.createConnection(port, "127.0.0.1", () => {
      const hello = makePeerHello(token, "native");
      sock._nonce = hello.nonce;
      sock.write(JSON.stringify({ type: "native_hello", nonce: hello.nonce, mac: hello.mac }) + "\n");
    });
    let buf = Buffer.alloc(0);
    let verified = false;
    sock.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      let i;
      while ((i = buf.indexOf(10)) !== -1) {
        const line = buf.subarray(0, i).toString("utf-8").trim();
        buf = buf.subarray(i + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; }
        if (!verified) {
          if (msg.type === "server_proof" && checkServerProof(token, "native", sock._nonce, msg.mac)) {
            verified = true;
          } else {
            try { sock.destroy(); } catch {} // untrusted primary
            return;
          }
          continue;
        }
        if (msg.type === "tool_request") {
          sock.write(JSON.stringify({
            id: msg.id, type: "tool_response",
            result: { content: [{ type: "text", text: "MOCK_OK" }] },
          }) + "\n");
        }
      }
    });
    sock.on("error", () => {});
    sock.on("close", () => { if (alive) setTimeout(connect, 300); });
  }
  connect();
  return { stop() { alive = false; try { sock.destroy(); } catch {} } };
}

// A raw TCP client peer that records what the primary sends back. `verifyToken`
// is used only to validate an incoming server_proof. sendHello(tok) emits a
// client_hello; pass a wrong tok to simulate an attacker.
function rawPeer(port, verifyToken) {
  const sock = net.createConnection(port, "127.0.0.1");
  const ev = { proven: false, acked: false, closed: false, errors: [], responses: [] };
  let buf = Buffer.alloc(0);
  let nonce = null;
  sock.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    let i;
    while ((i = buf.indexOf(10)) !== -1) {
      const line = buf.subarray(0, i).toString("utf-8").trim();
      buf = buf.subarray(i + 1);
      if (!line) continue;
      let m; try { m = JSON.parse(line); } catch { continue; }
      if (m.type === "server_proof") {
        if (nonce && verifyToken && checkServerProof(verifyToken, "client", nonce, m.mac)) ev.proven = true;
      } else if (m.type === "client_ack") ev.acked = true;
      else if (m.type === "error") ev.errors.push(m.error);
      else if (m.type === "tool_response") ev.responses.push(m);
    }
  });
  sock.on("close", () => { ev.closed = true; });
  sock.on("error", () => {});
  function sendHello(tok) {
    const h = makePeerHello(tok, "client");
    nonce = h.nonce;
    sock.write(JSON.stringify({ type: "client_hello", nonce: h.nonce, mac: h.mac }) + "\n");
  }
  return { ev, sendHello, send: (o) => sock.write(JSON.stringify(o) + "\n"), end: () => sock.destroy() };
}

describe("control-channel authentication", () => {
  const PORT = 18841;
  const { env, home, token } = isolatedEnv(PORT);
  let nh, primary;

  before(async () => {
    nh = startMockNativeHost(PORT, token);
    primary = spawn("node", [SERVER], { env, stdio: ["pipe", "ignore", "ignore"] });
    await sleep(2500); // primary binds the port and the native host mutually authenticates
  });

  after(() => {
    try { primary.kill(); } catch {}
    nh.stop();
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  });

  it("rejects a client that presents the wrong MAC", async () => {
    const peer = rawPeer(PORT, token);
    peer.sendHello("definitely-not-the-token");
    await sleep(800);
    assert.equal(peer.ev.proven, false, "must not prove to a wrong-MAC client");
    assert.equal(peer.ev.closed, true, "must close a wrong-MAC connection");

    // Even if it tries anyway, a rejected peer must not reach the browser.
    peer.send({ type: "tool_request", id: "x", tool: "tabs_context_mcp", args: {} });
    await sleep(500);
    assert.equal(peer.ev.responses.length, 0, "a rejected peer must not reach the browser");
  });

  it("rejects a peer that never authenticates", async () => {
    const peer = rawPeer(PORT, token); // connects but sends no hello
    await sleep(2600); // past the 2s hello timeout
    assert.equal(peer.ev.closed, true, "a silent peer must be dropped");

    // And the silent peer must not have stolen the native host slot: a valid
    // client can still drive the browser.
    const good = rawPeer(PORT, token);
    good.sendHello(token);
    await sleep(500);
    assert.equal(good.ev.proven, true, "a valid client should receive a verifiable server_proof");
    good.send({ type: "tool_request", id: "1", tool: "tabs_context_mcp", args: {} });
    await sleep(1000);
    assert.ok(
      good.ev.responses.some((r) => JSON.stringify(r).includes("MOCK_OK")),
      "a valid client should still reach the browser after a silent peer connected"
    );
    good.end();
  });

  it("accepts a client with the correct MAC and routes tool calls", async () => {
    const peer = rawPeer(PORT, token);
    peer.sendHello(token);
    await sleep(500);
    assert.equal(peer.ev.proven, true, "a valid client should be proven by a server_proof");
    assert.equal(peer.ev.acked, true, "a valid client should be acknowledged");

    peer.send({ type: "tool_request", id: "42", tool: "tabs_context_mcp", args: {} });
    await sleep(1000);
    assert.ok(
      peer.ev.responses.some((r) => JSON.stringify(r).includes("MOCK_OK")),
      "a valid client should reach the browser"
    );
    peer.end();
  });

  it("never puts the cleartext token on the wire", () => {
    // The hello carries nonce+mac only; the shared token must not appear in it.
    const h = makePeerHello(token, "client");
    assert.equal(h.token, undefined, "makePeerHello must not expose the token");
    assert.ok(h.nonce && h.mac, "hello must carry nonce + mac");
    assert.notEqual(h.mac, token, "mac must not be the raw token");
    assert.doesNotMatch(JSON.stringify(h), new RegExp(token), "hello JSON must not contain the token");
  });
});

describe("rogue-primary MITM resistance", () => {
  const PORT = 18843;

  it("a rogue primary without the token cannot gain a client's trust", async () => {
    const { env, home } = isolatedEnv(PORT);

    // Rogue binds the port and tries to impersonate a primary. It can see the
    // client's hello but, not knowing the token, can only send a FORGED proof.
    let helloCount = 0;
    let sawToolTraffic = false;
    const rogue = net.createServer((sock) => {
      let buf = Buffer.alloc(0);
      sock.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        let i;
        while ((i = buf.indexOf(10)) !== -1) {
          const line = buf.subarray(0, i).toString().trim();
          buf = buf.subarray(i + 1);
          if (!line) continue;
          let m; try { m = JSON.parse(line); } catch { continue; }
          if (m.type === "client_hello") {
            helloCount++;
            // Adversarial impersonation: a proof the client cannot verify.
            sock.write(JSON.stringify({ type: "server_proof", mac: "0".repeat(64) }) + "\n");
          } else {
            sawToolTraffic = true; // any non-hello line = tool traffic we must never send
          }
        }
      });
      sock.on("error", () => {});
    });
    await new Promise((r) => rogue.listen(PORT, "127.0.0.1", r));

    // mcp-server can't bind (rogue holds it) → runs as client → dials the rogue.
    const client = spawn("node", [SERVER], { env, stdio: ["pipe", "ignore", "pipe"] });
    await sleep(3500); // client connects, gets a bad proof, drops, reconnects, repeats

    try { client.kill(); } catch {}
    try { rogue.close(); } catch {}
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}

    // The client must keep refusing the rogue — it never settles on one trusted
    // connection. (An unfixed client would trust the rogue and stay connected,
    // yielding helloCount === 1.)
    assert.ok(helloCount >= 2, `client should keep rejecting the rogue (saw ${helloCount} hellos)`);
    assert.equal(sawToolTraffic, false, "client must never send tool traffic to an unverified primary");
  });
});
