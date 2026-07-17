[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/noemica-io-open-claude-in-chrome-badge.png)](https://mseep.ai/app/noemica-io-open-claude-in-chrome)

[English](README.md) | **繁體中文**

<p align="center">
  <img src="extension/icons/icon128.png" width="96" alt="Open Claude in Chrome">
</p>

<h1 align="center">Open Claude in Chrome</h1>

<p align="center">
  <em>官方 Claude in Chrome 封鎖了 58 個網域、只支援兩款瀏覽器。<br/>
  <strong>Open Claude in Chrome 給你整個網路。</strong></em>
  <br/>
  <sub>Anthropic 瀏覽器擴充功能的 clean-room 重新實作。無封鎖清單。任何 Chromium 瀏覽器皆可。100% 功能與效能一致。</sub>
  <br/>
  <sub>by <a href="https://noemica.io">noemica</a></sub>
</p>

<p align="center">
  <a href="#有何不同">有何不同</a> ·
  <a href="#安裝">安裝</a> ·
  <a href="#架構">架構</a> ·
  <a href="#安全性">安全性</a> ·
  <a href="https://youtu.be/n4-2fjOsGhw">Demo</a> ·
  <a href="https://www.noemica.io/blog/reverse-engineered-claude-in-chrome">開發紀錄</a>
</p>

---

<p align="center">
  <a href="https://youtu.be/n4-2fjOsGhw">
    <img src="https://img.youtube.com/vi/n4-2fjOsGhw/maxresdefault.jpg" alt="Demo — Claude on Tinder, Reddit, and Robinhood" width="820"/>
  </a>
  <br/>
  <sub><em>看 Claude 操控 Tinder、Reddit、Robinhood —— 官方擴充功能到不了的網站。</em></sub>
</p>

---

官方 [Claude in Chrome](https://code.claude.com/docs/en/chrome) 擴充功能讓 Claude Code 擁有完整的瀏覽器自動化能力 —— 前提是你只能待在 Anthropic 的「安全」網站白名單裡。Open Claude in Chrome 是 clean-room 重新實作,移除這些限制,同時保留全部 19 個 MCP 工具並維持與官方擴充功能一致的效能。

## 有何不同

| | Claude in Chrome | Open Claude in Chrome |
|---|---|---|
| **網域封鎖清單** | 11 類共 58 個被封鎖的網域 | 無封鎖清單,任意導航 |
| **瀏覽器支援** | 僅 Chrome 與 Edge | 任何 Chromium 瀏覽器(Chrome、Edge、Brave、Arc、Opera、Vivaldi 等) |
| **原始碼** | 閉源 | 開源(MIT) |
| **工具** | 18 個 MCP 工具 | 相同工具 + `upload_local_file`(共 19 個) |
| **效能** | 基準 | 一致 |

### 官方擴充功能封鎖的網域

| 分類 | 被封鎖網站 |
|----------|--------------|
| 銀行 | Chase、BofA、Wells Fargo、Citibank |
| 投資/券商 | Schwab、Fidelity、Robinhood、E-Trade、Wealthfront、Betterment |
| 支付/轉帳 | PayPal、Venmo、Cash App、Zelle、Stripe、Square、Wise、Western Union、MoneyGram、Adyen、Checkout.com |
| 先買後付 | Klarna、Affirm、Afterpay |
| 數位銀行/金融科技 | SoFi、Chime、Mercury、Brex、Ramp |
| 加密貨幣 | Coinbase、Binance、Kraken、MetaMask |
| 博弈 | DraftKings、FanDuel、Bet365、Bovada、PokerStars、BetMGM、Caesars |
| 約會 | Tinder、Bumble、Hinge、Match、OKCupid |
| 成人 | Pornhub、XVideos、XNXX |
| 新聞/媒體 | NYT、WSJ、Barron's、MarketWatch、Bloomberg、Reuters、Economist、Wired、Vogue |
| 社群媒體 | Reddit |

Open Claude in Chrome **完全沒有這些限制**。

## 架構

```
Claude Code <--stdio MCP--> mcp-server.js <--TCP 127.0.0.1:18765--> native-host.js <--native messaging--> Extension <--> Browser
```

三個元件:
1. **Extension(擴充功能)** — Manifest V3,以 CDP 進行瀏覽器自動化(全部 19 個工具)
2. **MCP Server(MCP 伺服器)** — 由 Claude Code 啟動的 Node.js 行程,透過 MCP 暴露工具
3. **Native Messaging Host(原生訊息主機)** — MCP 伺服器與擴充功能之間的橋接

## 安全性

MCP 伺服器與瀏覽器的原生訊息主機之間,透過 `127.0.0.1:18765` 的本機 TCP 控制通道溝通。由於驅動這條通道等於可在你已登入的瀏覽器分頁執行任意 JavaScript,因此**每一條連線都經過雙向驗證**。

**共享權杖。** 首次使用時會產生一組 256-bit 密鑰,存放於 `~/.config/open-claude-in-chrome/token`(檔案權限 `0600`、目錄 `0700`),只有你本人能讀取。MCP 伺服器(primary 與 client session)與原生訊息主機共用同一支權杖。

**雙向 HMAC challenge-response —— 權杖永不送上線。** 連線時,peer(client MCP 伺服器或原生訊息主機)送出全新的隨機 nonce 加上 `HMAC(token, "peer:<role>:<nonce>")`。primary 驗證通過後,回覆 `HMAC(token, "server:<role>:<nonce>")` 並綁定該 nonce。peer 只有在驗證這組 proof 通過後,才會信任連線、開始轉發任何工具流量。`<role>` 為 `client` 或 `native`,並綁進 HMAC 標籤,因此無法把某個角色的 proof 當成另一個角色重放。雙方若 2 秒內收不到有效 proof 即斷線。

**Rogue-primary 防護。** 任何本機行程 —— 包含**同一台機器的其他本機使用者** —— 即使先佔住該 port,也無法假冒 primary:沒有權杖就偽造不出 server proof,於是 peer 不會驗證通過、不轉發任何東西,並重新連線尋找真正的 primary。

> **威脅模型:** 能讀取權杖檔的人,本就已經是你的身份執行程式(本就能用其他方式驅動瀏覽器)。上述驗證專門用來防止**沒有權杖**的本機攻擊者劫持通道或竊取權杖。

## 安裝

### 前置需求

- **Node.js** v18+
- **任何 Chromium 瀏覽器**(Chrome、Edge、Brave、Arc、Opera、Vivaldi 等)— 需要 Chrome/Chromium 116+
- **Claude Code** v2.0.73+

### 步驟 1:安裝相依套件

```bash
cd host
npm install
cd ..
```

### 步驟 2:載入擴充功能

1. 打開 `chrome://extensions`(或 `brave://extensions` / `edge://extensions`)
2. 開啟 **Developer mode(開發人員模式)**
3. 點 **Load unpacked(載入未封裝項目)** 並選擇 `extension/` 目錄
4. 複製擴充功能名稱下方的 **extension ID**

### 步驟 3:註冊原生訊息主機

**macOS / Linux**(`install.sh`):

```bash
./install.sh <你的-extension-id>
```

若同時用多個瀏覽器,把每個 ID 都傳進去:

```bash
./install.sh <chrome-id> <brave-id> <arc-id>
```

**Windows**(`install.cmd`):

```cmd
install.cmd <你的-extension-id>
```

- 註冊 **Chrome / Edge / Brave**(僅偵測到 `%ProgramFiles%` 下 `.exe` 的才註冊),以 per-user 機碼(`HKCU\…\NativeMessagingHosts\…`,不需管理員)寫入登錄。
- 將 manifest 寫到 `%LOCALAPPDATA%\Google\Chrome\NativeMessagingHosts\…`、產生 `host\native-host-wrapper.cmd`、用 `where node` 解析 Node,並視需要跑 `npm install`。

### 步驟 4:完全重啟瀏覽器

**關閉所有視窗**再重開。瀏覽器只有在啟動時才會讀取原生訊息主機設定。

### 步驟 5:加到 Claude Code

```bash
claude mcp add open-claude-in-chrome -- node /absolute/path/to/host/mcp-server.js
```

取絕對路徑:

```bash
echo "node $(pwd)/host/mcp-server.js"
```

## 驗證

開一個新的 Claude Code session 並測試:

```
Navigate to reddit.com and take a screenshot
```

Reddit 成功載入,沒有網域限制。

## 可用工具

全部 19 個工具(與 Claude in Chrome 同位,外加 `upload_local_file`):

| 工具 | 說明 |
|------|-------------|
| `tabs_context_mcp` | 取得分頁群組脈絡 |
| `tabs_create_mcp` | 建立新分頁 |
| `navigate` | 導航到 URL、前進/後退 |
| `computer` | 滑鼠、鍵盤、截圖(14 個動作) |
| `read_page` | 附元素 ref 的無障礙樹 |
| `get_page_text` | 擷取文章/主要文字 |
| `find` | 依文字/屬性尋找元素 |
| `form_input` | 依 ref 設定表單值 |
| `javascript_tool` | 在頁面情境執行 JS |
| `read_console_messages` | 主控台輸出(可過濾) |
| `read_network_requests` | 網路活動 |
| `resize_window` | 調整瀏覽器視窗大小 |
| `upload_image` | 上傳截圖到 file input(stub) |
| `upload_local_file` | 透過 CDP file-chooser 攔截,將本機檔案上傳到 file input |
| `gif_creator` | GIF 錄製(stub) |
| `shortcuts_list` | 列出快捷功能(stub) |
| `shortcuts_execute` | 執行快捷功能(stub) |
| `switch_browser` | 切換瀏覽器(stub) |
| `update_plan` | 提出計畫(自動核可) |

## 變更程式碼後更新

無 build 步驟,所有檔案都是純 JavaScript。pull 或編輯後:

| 變更項目 | 處理方式 |
|---|---|
| `extension/background.js`、`extension/content.js` 或 `extension/manifest.json` | 重新載入擴充功能:`brave://extensions` > 點重新載入圖示 |
| `host/mcp-server.js` | 殺掉佔住 port 的舊行程並重連:`pkill -f "node.*mcp-server"`,再到 Claude Code 裡 `/mcp` |
| `host/native-host.js` | 完全重啟瀏覽器(關閉所有視窗再開) |
| `install.sh` / `install.cmd` 或原生訊息主機名稱變更 | 重新執行安裝腳本(傳入 extension ID)、重啟瀏覽器、重新加入 MCP |
| 測試 | `cd host && npm test` |

### Quick reset(終極重置)

若不知為何壞掉:

```bash
# 1. 殺掉所有 MCP 伺服器
pkill -f "node.*mcp-server"

# 2. 重新安裝
./install.sh <你的-extension-id>

# 3. 重啟瀏覽器(關閉所有視窗再開)

# 4. 在 brave://extensions 重新載入擴充功能

# 5. 在 Claude Code 重連
# /mcp
```

## 多重 Session

多個 Claude Code session 可共用同一個擴充功能。第一個 session 成為「primary」(擁有 TCP port),之後的 session 以 client 身分透過 primary 連線。所有 session 可同時使用瀏覽器。

若 primary session 死亡,**存活的 client 會自動升級為 primary** —— 重新綁定 port 並重新驗證原生訊息主機 —— 讓其他 session 不需手動介入也能繼續運作。每一條連線(primary ↔ client、primary ↔ 原生訊息主機)都受[安全性](#安全性)所述的雙向驗證保護。

若某個 session 斷線,殺掉舊行程並重連:

```bash
pkill -f "node.*mcp-server"
# 然後在每個 Claude Code session 裡 /mcp
```

## 測試

```bash
cd host
npm test    # 執行 `node --test`
```

涵蓋控制通道驗證、rogue-primary MITM 防護(client 與 native-host 兩個方向)、以及多 session 自癒。詳見 `host/auth.test.mjs` 與 `host/multi-session.test.mjs`。

## 疑難排解

### 擴充功能連不上

1. 確認擴充功能已載入並啟用
2. 確認安裝腳本用了正確的 extension ID
3. 完全重啟瀏覽器(所有視窗)
4. 確認原生訊息主機 manifest 存在。檔名為 `com.anthropic.open_claude_in_chrome.json`,位於:
   - **Chrome**
     - macOS:`~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
     - Linux:`~/.config/google-chrome/NativeMessagingHosts/`
     - Windows:`%LOCALAPPDATA%\Google\Chrome\NativeMessagingHosts\`(外加 `HKCU\Software\Google\Chrome\NativeMessagingHosts\…` 登錄機碼)
   - **Brave** — 把 `Google/Chrome` 換成 `BraveSoftware/Brave-Browser`
   - **Edge** — 把 `Google/Chrome` 換成 `Microsoft/Edge`

### 找不到 MCP 伺服器

用絕對路徑:
```bash
claude mcp add open-claude-in-chrome -- node /absolute/path/to/host/mcp-server.js
```

### 「Browser extension is not connected」

MCP 伺服器已啟動但原生訊息主機尚未連上。試試:
1. 隨便開一個網頁(喚醒 service worker)
2. 看 service worker log:`chrome://extensions` >「Inspect views: service worker」
3. 確認 wrapper 存在:`host/native-host-wrapper.sh`(macOS/Linux)或 `host\native-host-wrapper.cmd`(Windows)

### 重連後工具立刻失敗

前一個 session 的舊 MCP 伺服器可能還佔著 port。修法:

```bash
pkill -f "node.*mcp-server"
```

再到 Claude Code 裡 `/mcp` 重連。新的伺服器會綁定 port 並接受原生訊息主機連線。

### Port 衝突

預設 port 為 18765。要變更:
1. 建立 `~/.config/open-claude-in-chrome/config.json`:
   ```json
   { "port": 19000 }
   ```
2. 重啟瀏覽器與 Claude Code

### API Error:「Unexpected content chunk type `tool_reference`」(400)

當 Claude Code 的工具數量夠多(**所有** MCP 伺服器加上內建工具),會啟用 **Tool Search** 模式並在請求中送出 `tool_reference` 內容區塊。某些後端會以 400 拒絕 —— 尤其是 **AWS Bedrock**、**Vertex AI**、某些 **OpenAI 相容代理**,以及較舊的 model snapshot。

**解法 #1 —— 關閉 Tool Search(推薦,零成本、不改工具面):**

啟動 Claude Code 前設定環境變數:
```bash
export ENABLE_TOOL_SEARCH=false
```
這會讓 Claude Code 完全不送出 `tool_reference` 區塊。注意:當你的 `ANTHROPIC_BASE_URL` 指向**非第一方**主機(即代理/Bedrock/Vertex 閘道)時,Claude Code **已自動關閉** Tool Search —— 所以只有仍走第一方主機的設定才需要這個。這比縮減工具面更好,因為維持完全同位**且**不花成本。

**解法 #2 —— opt-in 工具合併(備案,僅當無法設定環境變數時):**

本伺服器可把 7 個相關工具合併成 4 個 discriminated-union 工具,將自身的註冊工具數從 **19 → 16**。**預設關閉**以維持與官方擴充功能的同位。在 `~/.config/open-claude-in-chrome/config.json` 啟用:
```json
{ "consolidateTools": true }
```
(或在環境設定 `OCIC_CONSOLIDATE_TOOLS=true`),再重啟瀏覽器與 Claude Code。

啟用時套用的合併:

| 合併後工具 | 取代 | 判別欄位 |
| --- | --- | --- |
| `tabs_mcp` | `tabs_context_mcp`、`tabs_create_mcp` | `action: "context" \| "create"` |
| `read_debug` | `read_console_messages`、`read_network_requests` | `type: "console" \| "network"` |
| `shortcuts` | `shortcuts_list`、`shortcuts_execute` | `action: "list" \| "execute"` |
| `read_page_text` | `get_page_text` | (純文字別名) |

`resize_window`、`upload_image`、`upload_local_file` 刻意**不合併** —— 把 resize 折進 `read_page` 會讓「讀取」默默改變視窗大小,而單一 `type` 的 union 只增加摩擦卻沒減少數量。由於合併只縮減**本伺服器**的工具數(而非觸發 Tool Search 的全域總數),且對 schema token 的縮減有限,對多數使用者而言解法 #1 是更好的手段。

## 授權

MIT

Built by [Sebastian Sosa](https://github.com/CakeCrusher)([Noemica](https://noemica.io))
