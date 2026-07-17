[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/noemica-io-open-claude-in-chrome-badge.png)](https://mseep.ai/app/noemica-io-open-claude-in-chrome)

**English** | [繁體中文](README.zh-TW.md)

<p align="center">
  <img src="extension/icons/icon128.png" width="96" alt="Open Claude in Chrome">
</p>

<h1 align="center">Open Claude in Chrome</h1>

<p align="center">
  <em>Official Claude in Chrome gives you 58 blocked domains and two browsers.<br/>
  <strong>Open Claude in Chrome gives you the whole web.</strong></em>
  <br/>
  <sub>Clean-room reimplementation of Anthropic's browser extension. No blocklist. Any Chromium browser. 100% feature &amp; performance parity.</sub>
  <br/>
  <sub>by <a href="https://noemica.io">noemica</a></sub>
</p>

<p align="center">
  <a href="#whats-different">What's different</a> ·
  <a href="#installation">Install</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#security">Security</a> ·
  <a href="https://youtu.be/n4-2fjOsGhw">Demo</a> ·
  <a href="https://www.noemica.io/blog/reverse-engineered-claude-in-chrome">How I built it</a>
</p>

---

<p align="center">
  <a href="https://youtu.be/n4-2fjOsGhw">
    <img src="https://img.youtube.com/vi/n4-2fjOsGhw/maxresdefault.jpg" alt="Demo — Claude on Tinder, Reddit, and Robinhood" width="820"/>
  </a>
  <br/>
  <sub><em>Watch Claude navigate Tinder, Reddit, and Robinhood — sites the official extension can't reach.</em></sub>
</p>

---

The official [Claude in Chrome](https://code.claude.com/docs/en/chrome) extension gives Claude Code full browser automation — as long as you stay within Anthropic's allowlist of "safe" sites. Open Claude in Chrome is a clean-room reimplementation that strips the restrictions while keeping all 19 MCP tools and matching the official extension's performance.

## What's Different

| | Claude in Chrome | Open Claude in Chrome |
|---|---|---|
| **Domain blocklist** | 58 blocked domains across 11 categories | No blocklist. Navigate anywhere. |
| **Browser support** | Chrome and Edge only | Any Chromium browser (Chrome, Edge, Brave, Arc, Opera, Vivaldi, etc.) |
| **Source code** | Closed source | Open source (MIT) |
| **Tools** | 18 MCP tools | Same tools + `upload_local_file` (19 total) |
| **Performance** | Baseline | Identical |

### Blocked Domains in the Official Extension

| Category | Blocked Sites |
|----------|--------------|
| Banking | Chase, BofA, Wells Fargo, Citibank |
| Investing/Brokerage | Schwab, Fidelity, Robinhood, E-Trade, Wealthfront, Betterment |
| Payments/Transfers | PayPal, Venmo, Cash App, Zelle, Stripe, Square, Wise, Western Union, MoneyGram, Adyen, Checkout.com |
| BNPL | Klarna, Affirm, Afterpay |
| Neobanks/Fintech | SoFi, Chime, Mercury, Brex, Ramp |
| Crypto | Coinbase, Binance, Kraken, MetaMask |
| Gambling | DraftKings, FanDuel, Bet365, Bovada, PokerStars, BetMGM, Caesars |
| Dating | Tinder, Bumble, Hinge, Match, OKCupid |
| Adult | Pornhub, XVideos, XNXX |
| News/Media | NYT, WSJ, Barron's, MarketWatch, Bloomberg, Reuters, Economist, Wired, Vogue |
| Social Media | Reddit |

Open Claude in Chrome has **none of these restrictions**.

## Architecture

```
Claude Code <--stdio MCP--> mcp-server.js <--TCP 127.0.0.1:18765--> native-host.js <--native messaging--> Extension <--> Browser
```

Three components:
1. **Extension** — Manifest V3 with CDP-based browser automation (all 19 tools)
2. **MCP Server** — Node.js process started by Claude Code, exposes tools via MCP
3. **Native Messaging Host** — Bridge between the MCP server and the extension

## Security

The MCP server and the browser's native messaging host communicate over a local TCP control channel on `127.0.0.1:18765`. Because driving this channel can run arbitrary JavaScript in your authenticated browser tabs, every connection is **mutually authenticated**.

**Shared token.** A 256-bit secret is generated on first use and stored at `~/.config/open-claude-in-chrome/token` (file mode `0600`, directory `0700`), readable only by your user. The same token is shared by the MCP server (primary + client sessions) and the native host.

**Mutual HMAC challenge-response — the token never crosses the wire.** On connect, a peer (a client MCP server or the native host) sends a fresh random nonce plus `HMAC(token, "peer:<role>:<nonce>")`. The primary verifies it and replies with `HMAC(token, "server:<role>:<nonce>")`, bound to that same nonce. The peer only trusts the connection — and only then forwards any tool traffic — once it verifies that proof. `<role>` is `client` or `native` and is bound into the tag, so one role's proof can't be replayed as another. Both sides drop the connection if no valid proof arrives within 2 seconds.

**Rogue-primary resistance.** A local process — including another local user on the machine — that binds the port first cannot impersonate the primary: without the token it cannot forge the server proof, so peers refuse to verify, forward nothing, and reconnect to find the real primary.

> **Threat model:** anyone who can read the token file is already running as you (and could drive the browser by other means). The authentication above specifically prevents a *token-less* local attacker from hijacking the channel or learning the token.

## Installation

### Prerequisites

- **Node.js** v18+
- **Any Chromium browser** (Chrome, Edge, Brave, Arc, Opera, Vivaldi, etc.) — Chrome/Chromium 116+ required
- **Claude Code** v2.0.73+

### Step 1: Install dependencies

```bash
cd host
npm install
cd ..
```

### Step 2: Load the extension

1. Go to `chrome://extensions` (or `brave://extensions` / `edge://extensions`)
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `extension/` directory
4. Copy the **extension ID** shown under the extension name

### Step 3: Register native messaging

**macOS / Linux** (`install.sh`):

```bash
./install.sh <your-extension-id>
```

If you use multiple browsers, pass all IDs:

```bash
./install.sh <chrome-id> <brave-id> <arc-id>
```

**Windows** (`install.cmd`):

```cmd
install.cmd <your-extension-id>
```

- Registers **Chrome / Edge / Brave** (only those whose `.exe` is found under `%ProgramFiles%`), via per-user registry keys (`HKCU\…\NativeMessagingHosts\…`, no administrator needed).
- Writes the manifest to `%LOCALAPPDATA%\Google\Chrome\NativeMessagingHosts\…`, generates `host\native-host-wrapper.cmd`, resolves Node via `where node`, and runs `npm install` if needed.

### Step 4: Restart your browser

Close **all** windows and reopen. The browser reads native messaging host configs on startup.

### Step 5: Add to Claude Code

```bash
claude mcp add open-claude-in-chrome -- node /absolute/path/to/host/mcp-server.js
```

Find the absolute path with:

```bash
echo "node $(pwd)/host/mcp-server.js"
```

## Verification

Start a new Claude Code session and test:

```
Navigate to reddit.com and take a screenshot
```

Reddit loads. No domain restriction.

## Available Tools

All 19 tools (parity with Claude in Chrome, plus `upload_local_file`):

| Tool | Description |
|------|-------------|
| `tabs_context_mcp` | Get tab group context |
| `tabs_create_mcp` | Create new tab |
| `navigate` | Navigate to URL, back, forward |
| `computer` | Mouse, keyboard, screenshots (14 actions) |
| `read_page` | Accessibility tree with element refs |
| `get_page_text` | Extract article/main text |
| `find` | Find elements by text/attributes |
| `form_input` | Set form values by ref |
| `javascript_tool` | Execute JS in page context |
| `read_console_messages` | Console output (filtered) |
| `read_network_requests` | Network activity |
| `resize_window` | Resize browser window |
| `upload_image` | Upload screenshot to file input (stub) |
| `upload_local_file` | Upload local files from disk to a file input via CDP file-chooser intercept |
| `gif_creator` | GIF recording (stub) |
| `shortcuts_list` | List shortcuts (stub) |
| `shortcuts_execute` | Run shortcut (stub) |
| `switch_browser` | Switch browser (stub) |
| `update_plan` | Present plan (auto-approved) |

## Updating After Code Changes

No build step. All files are plain JavaScript. After pulling or editing code:

| What changed | What to do |
|---|---|
| `extension/background.js` or `extension/content.js` or `extension/manifest.json` | Reload the extension: `brave://extensions` > click the reload icon |
| `host/mcp-server.js` | Kill stale servers and reconnect: `pkill -f "node.*mcp-server"` then `/mcp` in Claude Code |
| `host/native-host.js` | Restart the browser (close all windows, reopen) |
| `install.sh` / `install.cmd` or native host name changed | Re-run the installer with your extension ID, restart browser, re-add MCP |
| Tests | `cd host && npm test` |

### Quick reset (nuclear option)

If things are broken and you're not sure why:

```bash
# 1. Kill all MCP servers
pkill -f "node.*mcp-server"

# 2. Re-run install
./install.sh <your-extension-id>

# 3. Restart browser (close all windows, reopen)

# 4. Reload extension in brave://extensions

# 5. Reconnect in Claude Code
# /mcp
```

## Multiple Sessions

Multiple Claude Code sessions can share the same browser extension. The first session becomes the "primary" (owns the TCP port), and subsequent sessions connect as clients through the primary. All sessions can use the browser simultaneously.

If the primary session dies, a surviving client **automatically promotes itself to primary** — re-binding the port and re-authenticating the native host — so other sessions keep working without manual intervention. Every connection (primary ↔ client, primary ↔ native host) is protected by the mutual authentication described in [Security](#security).

If a session disconnects, kill stale servers and reconnect:

```bash
pkill -f "node.*mcp-server"
# then /mcp in each Claude Code session
```

## Tests

```bash
cd host
npm test    # runs `node --test`
```

Covers control-channel authentication, rogue-primary MITM resistance (both the client and native-host directions), and multi-session self-healing. See `host/auth.test.mjs` and `host/multi-session.test.mjs`.

## Troubleshooting

### Extension not connecting

1. Verify the extension is loaded and enabled
2. Check that the installer was run with the correct extension ID
3. Restart the browser completely (all windows)
4. Verify the native messaging host manifest exists. It's named `com.anthropic.open_claude_in_chrome.json` and lives in:
   - **Chrome**
     - macOS: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
     - Linux: `~/.config/google-chrome/NativeMessagingHosts/`
     - Windows: `%LOCALAPPDATA%\Google\Chrome\NativeMessagingHosts\` (plus a `HKCU\Software\Google\Chrome\NativeMessagingHosts\…` registry key)
   - **Brave** — replace `Google/Chrome` with `BraveSoftware/Brave-Browser`
   - **Edge** — replace `Google/Chrome` with `Microsoft/Edge`

### MCP server not found

Use an absolute path:
```bash
claude mcp add open-claude-in-chrome -- node /absolute/path/to/host/mcp-server.js
```

### "Browser extension is not connected"

The MCP server started but the native host hasn't connected. Try:
1. Open any webpage (wakes the service worker)
2. Check service worker logs: `chrome://extensions` > "Inspect views: service worker"
3. Verify the wrapper exists: `host/native-host-wrapper.sh` (macOS/Linux) or `host\native-host-wrapper.cmd` (Windows)

### Tools fail immediately after reconnect

Stale MCP server processes from previous sessions may be holding the port. Fix:

```bash
pkill -f "node.*mcp-server"
```

Then `/mcp` in Claude Code to reconnect. The fresh server will bind the port and accept the native host connection.

### Port conflict

Default port is 18765. To change:
1. Create `~/.config/open-claude-in-chrome/config.json`:
   ```json
   { "port": 19000 }
   ```
2. Restart browser and Claude Code

### API Error: "Unexpected content chunk type `tool_reference`" (400)

When Claude Code has enough tools (across **all** your MCP servers plus its built-ins), it activates **Tool Search** mode and emits `tool_reference` content blocks in the request. Some backends reject those with a 400 — notably **AWS Bedrock**, **Vertex AI**, some **OpenAI-compatible proxies**, and older model snapshots.

**Fix #1 — disable Tool Search (recommended, zero cost, no change to the tool surface):**

Set the environment variable before launching Claude Code:
```bash
export ENABLE_TOOL_SEARCH=false
```
This stops Claude Code from emitting `tool_reference` blocks entirely. Note that when your `ANTHROPIC_BASE_URL` points at a **non-first-party** host (i.e. a proxy/Bedrock/Vertex gateway), Claude Code **already auto-disables** Tool Search — so you may only need this on setups that still route through a first-party host. This is strictly preferable to shrinking the tool surface, because it keeps full parity **and** costs nothing.

**Fix #2 — opt-in tool consolidation (fallback, only if you can't set the env var):**

This server can merge 7 related tools into 4 discriminated-union tools, lowering its own registered count from **19 → 16**. It is **off by default** to preserve parity with the official extension. Enable it in `~/.config/open-claude-in-chrome/config.json`:
```json
{ "consolidateTools": true }
```
(or set `OCIC_CONSOLIDATE_TOOLS=true` in the environment), then restart the browser and Claude Code.

Consolidations applied when enabled:

| Consolidated tool | Replaces | Discriminator |
| --- | --- | --- |
| `tabs_mcp` | `tabs_context_mcp`, `tabs_create_mcp` | `action: "context" \| "create"` |
| `read_debug` | `read_console_messages`, `read_network_requests` | `type: "console" \| "network"` |
| `shortcuts` | `shortcuts_list`, `shortcuts_execute` | `action: "list" \| "execute"` |
| `read_page_text` | `get_page_text` | (plain-text alias) |

`resize_window`, `upload_image`, and `upload_local_file` are intentionally **not** merged — folding a resize into `read_page` would make a "read" silently resize the window, and single-`type` unions add friction for no reduction. Because consolidation only trims **this** server's count (not the global total that triggers Tool Search) and only marginally reduces the schema token footprint, Fix #1 is the better lever for most users.

## License

MIT

Built by [Sebastian Sosa](https://github.com/CakeCrusher) ([Noemica](https://noemica.io))
