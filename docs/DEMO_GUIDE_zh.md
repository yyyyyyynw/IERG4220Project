# AuthLab Demo Guide（給老師看）— 繁體中文

這份指南說明兩件事：

1. 這個專案的 **workflow** 是什麼。
2. Demo 當天要 **怎麼操作**、要講什麼、以及出問題時怎麼辦。

---

## 1. 專案 workflow（一句話）

> 先建立一個可控制、可觀察的登入系統 AuthLab，再用真實瀏覽器與虛擬認證器跑受控實驗，最後把原始結果分析成表格、圖表與報告。

```text
研究問題與威脅模型
        ↓
AuthLab（Flask relying party）
  密碼 + TOTP / 同步 passkey / 硬體 FIDO2 金鑰
  復原碼 / Email 重設 / session 撤銷
        ↓
experiments/harness.py
  Playwright + Chrome CDP 虛擬認證器
  app.lvh.me:5010（真 RP）
  evil.app.lvh.me:5011（惡意反向代理）
        ↓
experiments/run_experiments.py
  25 個情境 × 3–5 次 + 延遲 + 錯誤路徑
        ↓
experiments/results/results.json（原始資料）
        ↓
experiments/analyze.py
  Wilson 信賴區間、延遲統計、KLM、五張圖
        ↓
docs/REPORT.md、docs/INTERIM_REPORT.pdf、docs/slides.md
```

重點：**AuthLab 是被測試的系統；experiments 是測試方法；results 是證據；docs 是論述。**

---

## 2. Demo 前 10 分鐘檢查清單

- [ ] Chrome 已安裝（實驗 harness 使用 `channel="chrome"`）。
- [ ] Python 3.11+，且已安裝 `requirements.txt`。
- [ ] 5010／5011 沒有被其他程式占用。
- [ ] 用一個乾淨的 demo 資料庫，不要用到舊測試資料。
- [ ] 簡報、`docs/INTERIM_REPORT.pdf`、`experiments/results/summary.md` 已先開好。
- [ ] 若要用 passkey：確認 Mac 有 Touch ID，或先打開 Chrome DevTools 的 WebAuthn 虛擬認證器。
- [ ] 若不用手機驗證器：先確認 TOTP 指令可用（見 §4.3）。
- [ ] 不要把完整實驗 suite 放在 demo 現場跑（6–10 分鐘，風險高）。

### 2.1 確認 port 沒有被占用

```bash
lsof -nP -iTCP:5010 -sTCP:LISTEN
lsof -nP -iTCP:5011 -sTCP:LISTEN
```

如果有舊的 `run.py`：

```bash
pkill -f "run.py" || true
```

### 2.2 用乾淨的 demo 資料庫啟動

```bash
cd /Users/janezheng/Downloads/4220Project
AUTHLAB_DB=./demo.sqlite3 python3 run.py
```

開啟：

```text
http://localhost:5010
```

> 一定要用 `localhost`，不要用 `127.0.0.1`。預設 WebAuthn RP ID 是
> `localhost`，RP ID 必須是 origin host 的後綴。

> `run.py` 使用 `use_reloader=False`；如果你剛改了程式碼，必須重新啟動才看得到。

---

## 3. 建議的 10 分鐘 demo 腳本

### 0:00–1:30　先講問題，不要先講程式

可以這樣說：

> 這個專案比較三種登入方式：密碼 + TOTP、同步 passkey、硬體 FIDO2 金鑰。
> 但我不只看「登入當下能不能擋釣魚」，也看「裝置遺失後怎麼復原」。
> 因為帳號的安全強度，往往取決於最弱的復原路徑。

接著指出三個研究問題：

1. 即時釣魚能不能接管帳號？
2. 捕獲的 TOTP 或 WebAuthn assertion 能不能重放？
3. 裝置遺失、備份、復原碼、Email 重設會不會重新打開攻擊面？

### 1:30–5:00　操作 AuthLab

#### 步驟 1：首頁與語言切換

1. 開啟 `http://localhost:5010`。
2. 右上角點 `繁體中文`，展示介面切成繁體中文。
3. 再點 `EN` 切回英文。

可以說：

> 介面支援 English / 繁體中文，語言存在 cookie，不影響任何表單 ID 或
> WebAuthn 行為；英文仍是預設，所以自動化實驗不受影響。

#### 步驟 2：建立帳號

1. 點「Create account／建立帳號」。
2. 輸入：
   - Username：`demo01`
   - Password：`DemoPass!2026`
   - Confirm：`DemoPass!2026`
3. 按「Create account／建立帳號」。

預期：進入 `/enroll`，看到：

- TOTP QR code
- TOTP secret（`#totp-secret`）
- 10 組一次性復原碼
- 「Add synced passkey」「Add hardware key」按鈕

可以說：

> 註冊時同時產生 TOTP secret 與一次性復原碼；復原碼只顯示一次，資料庫只存
> scrypt 雜湊。

#### 步驟 3：用 TOTP 登入

先登出：

1. 右上角「Sign out／登出」。
2. 點「Sign in／登入」。
3. 選「Password + TOTP」。
4. 輸入 `demo01` 與 `DemoPass!2026`，按「Continue to TOTP」。
5. 輸入目前的 6 位數 TOTP。

如果沒有手機驗證器，直接在終端機用頁面上顯示的 secret 產生：

```bash
cd /Users/janezheng/Downloads/4220Project
python3 -c "from authlab.security import totp_at; print(totp_at('貼上你的_TOTP_SECRET')[0])"
```

把輸出的 6 位數貼到 `#totp-code`。

預期：進入 `/dashboard`。

可以說：

> 這裡的 TOTP 驗證有伺服器端 `totp_last_step`，所以同一組碼不能重複使用；
> 但這只防重放，不防即時釣魚。後面的 P1/P1b 就是在區分這兩件事。

#### 步驟 4：看 dashboard

在 `/dashboard` 指出：

- **WebAuthn credentials**：目前沒有，等等新增。
- **Account recovery**：剩下幾組未使用復原碼。
- **Recent sessions**：目前 session 的方法、建立時間、到期時間。
- **Audit log**：註冊、密碼步驟、TOTP、登入等事件。

可以說：

> 這個 dashboard 直接讀資料庫，不是前端假資料；實驗 harness 也會讀同樣的
> ground-truth state 來判定實驗結果。

#### 步驟 5：新增 passkey（可選，但很推薦）

1. 在 `/enroll` 或 dashboard 點「Add synced passkey／新增通行金鑰」。
2. Chrome 會跳出 Touch ID／平台認證器提示。
3. 完成後頁面重新載入，credentials 表格會出現一筆 passkey。

如果沒有 Touch ID，用 Chrome DevTools 虛擬認證器：

1. 按 `Option + Command + I` 打開 DevTools。
2. 右上三點 → More tools → WebAuthn。
3. 勾選「Enable virtual authenticator environment」。
4. 按「Add」新增 authenticator：
   - Protocol：`CTAP2`
   - Transport：`internal`
   - Resident keys：勾選
   - User verification：勾選
5. 回到 AuthLab，點「Add synced passkey」。

可以說：

> 平台 passkey 是 backup-eligible 的 WebAuthn 憑證；它綁定 RP ID 與 origin。
> 但「綁定」只有在 RP 真的檢查 origin 時才有意義，這是後面 P3/P4 的重點。

#### 步驟 6：復原流程（可選，建議用另一個測試帳號）

1. 登出。
2. 前往 `/recovery`。
3. 輸入使用者名稱，按「Send reset link／寄送重設連結」。
4. 因為 demo 模式 `SHOW_RECOVERY_LINK=1`，頁面會出現「Demo email」連結。
5. 點連結，設定新密碼。
6. 看到「Password reset／密碼已重設」頁面與新的 TOTP secret。

可以說：

> Email 重設 token 是 256-bit、資料庫只存 SHA-256、15 分鐘過期、一次性。
> 重設成功後會撤銷所有舊 session、刪除舊復原碼、輪替 TOTP secret。
> 這就是「復原流程本身也是認證面」的具體實作。

> 注意：重設會讓目前帳號的 TOTP 改變。Demo 時建議用 `demo02` 之類的
> 第二個帳號，避免把主要 demo 帳號弄亂。

### 5:00–7:00　展示實驗結果

不需要現場跑完整 suite。直接開這些檔案：

```text
experiments/results/summary.md
experiments/results/klm.md
experiments/results/latency.csv
figures/phishing.png
figures/replay_recovery.png
figures/latency.png
figures/klm.png
```

用 `summary.md` 的表格講這幾個數字：

| 情境 | 結果 | 要點 |
|---|---:|---|
| P1 密碼 + TOTP 即時轉送 | 5/5 成功 | TOTP 可被即時釣魚 |
| P1b 重放同一組 TOTP | 5/5 被擋 | 防重放 ≠ 防釣魚 |
| P3 passkey 嚴格 origin 檢查 | 0/5 成功 | 正確 verifier 擋下 relay |
| P4 passkey 寬鬆 origin 檢查 | 5/5 成功 | 同一個 credential，換 verifier 就失守 |
| P6 硬體金鑰嚴格 origin | 0/5 成功 | 硬體金鑰也一樣 |
| P7 硬體金鑰寬鬆 origin | 5/5 成功 | 問題在 RP，不在憑證 |
| R5 落後 counter 的克隆 | 3/3 被擋 | counter 可偵測 rollback |
| R6 偽造超前 counter 的克隆 | 3/3 被接受 | counter 不是克隆偵測器 |
| S1 同步 passkey 還原 | 5/5 成功 | 裝置遺失可復原 |
| S2/S3 沒有備份的平台憑證／硬體金鑰 | 3/3 鎖死 | 復原才是弱點 |
| S6 復原碼重複使用 | 3/3 被擋 | 一次性 |
| S7 Email reset 不變量 | 3/3 成立 | 一次性、撤銷、輪替 |

核心結論可以這樣說：

> Passkey 和硬體金鑰不是「自動」抗釣魚。同一個 credential，在 strict
> verifier 下 0/5 被攻破，在 permissive verifier 下 5/5 被攻破。
> 真正決定安全的是 RP 有沒有正確檢查 origin、challenge、RP ID 與 UV。
> 另外，復原流程是每一種方法的共同弱點。

### 7:00–8:30　展示報告與專案結構

打開：

```text
docs/INTERIM_REPORT.pdf
docs/INTERIM_REPORT.md
docs/REPORT.md
docs/slides.md
```

可以說：

> 這份 interim report 包含 protocol analysis、AuthLab 實作、25 個情境、
> 初步結果、討論、限制與剩下工作。中文摘要在前面，英文正文在後面。
> 我沒有捏造人類受試者資料；human study 目前是 ready-to-run protocol，
> 放在 `survey/`。

### 8:30–10:00　限制與未來工作

主動講限制，會讓 demo 更可信：

- 使用 Chrome CDP 虛擬認證器，不是實體金鑰；協定是真的，運輸與韌體不是。
- 沒有模擬 vendor sync cloud，只模擬 BE/BS 與非單調 counter 的可觀察效果。
- 迴環網路，沒有 WAN latency 與真實 Email 遞送。
- 每情境 3–5 次，Wilson 區間很寬；這些是協定性質，不是母體估計。
- 沒有人類受試者資料；KLM 是分析模型，不是實測。
- 未來工作：clean-machine rerun、可選的實體金鑰／其他瀏覽器驗證、最終報告與簡報。

---

## 4. 進階：15 分鐘版（加一段 live 實驗）

如果你想要現場示範「strict 擋下、permissive 放行」，可以在 demo 中段加這段。
它只需要 1–2 分鐘，而且比跑完整 suite 安全。

### 4.1 先停止一般 app

harness 會使用 5010／5011：

```bash
pkill -f "run.py" || true
```

### 4.2 跑 P3 + P4

```bash
cd /Users/janezheng/Downloads/4220Project
python3 - <<'PY'
from experiments.harness import Lab
from experiments import run_experiments as rx

with Lab() as lab:
    strict = rx.scenario_p3_passkey_strict(lab)
    permissive = rx.scenario_p4_passkey_permissive(lab)
    print("P3 strict origin check:", strict["successes"], "/", strict["trials"])
    print("P4 permissive origin check:", permissive["successes"], "/", permissive["trials"])
PY
```

預期輸出：

```text
P3 strict origin check: 0 / 5
P4 permissive origin check: 5 / 5
```

可以說：

> 這兩個情境使用同一個 passkey、同一個 challenge 類型、同一個 relay，
> 唯一差別是 RP 是否相信 `clientDataJSON` 裡的 origin。strict 全部拒絕，
> permissive 全部接受。這就是「verifier correctness dominates」的實驗證據。

> 這段會啟動 headless Chrome 與兩個 loopback server，約 1–2 分鐘。
> 跑完會自動刪除暫存資料庫。它**不會**覆寫 `experiments/results/results.json`。

### 4.3 跑完後重新啟動一般 app

```bash
AUTHLAB_DB=./demo.sqlite3 python3 run.py
```

---

## 5. 如果想重新產生完整結果（不建議在 demo 現場做）

```bash
pkill -f "run.py" || true
python3 experiments/run_experiments.py   # 約 6–10 分鐘
python3 experiments/analyze.py            # 重新產生表格與圖
```

注意：

- 會覆寫 `experiments/results/results.json`、`summary.md`、`latency.csv`、
  `klm.md` 與 `figures/*.png`。
- 協定結果應該穩定；延遲數字會因機器而異。
- 如果只是 demo，直接使用已 checked-in 的結果即可。

---

## 6. 常見問題與故障排除

### Q1：瀏覽器說 passkey 不能用 / 沒有平台認證器

用 Chrome DevTools 的 WebAuthn 虛擬認證器（見 §3 步驟 5），或跳過 passkey，
直接展示 checked-in 的 P3/P4 結果。

### Q2：TOTP 一直說過期

TOTP 每 30 秒換一次。重新執行：

```bash
python3 -c "from authlab.security import totp_at; print(totp_at('你的_SECRET')[0])"
```

然後立刻貼上。伺服器接受 ±1 個時間步長，但不要用太舊的碼。

### Q3：`Address already in use` / port 5010 被占用

```bash
lsof -nP -iTCP:5010 -sTCP:LISTEN
pkill -f "run.py" || true
```

如果是 macOS Control Center 占用 5000，這個專案已經改用 5010，不需要處理。

### Q4：`app.lvh.me` 無法解析

完整實驗需要：

```bash
ping -c 1 app.lvh.me
ping -c 1 evil.app.lvh.me
```

如果沒有解析到 `127.0.0.1`，在 `/etc/hosts` 加入：

```text
127.0.0.1 app.lvh.me evil.app.lvh.me
```

### Q5：demo 資料庫想重來

```bash
pkill -f "run.py" || true
rm -f demo.sqlite3
AUTHLAB_DB=./demo.sqlite3 python3 run.py
```

`demo.sqlite3` 已被 `.gitignore` 的 `*.sqlite3` 規則忽略，不會被 commit。

### Q6：老師問「為什麼沒有真人實驗？」

> 我有準備完整的 human-subject protocol、問卷與分析流程，放在 `survey/`。
> 但沒有 ethics approval 與 recruitment 的情況下，我不會把合成資料當成真人
> 資料。KLM 是分析模型，用來估算互動成本，不是人類受試者量測。

### Q7：老師問「為什麼只有 3–5 次？」

> 這些不是隨機抽樣的使用者研究，而是確定性的協定情境。3–5 次用來暴露
> flakiness；Wilson 區間很寬，我在報告中明確說明它們描述的是二項不確定性，
> 不是母體攻擊率。

---

## 7. 最低限度 demo（如果只剩 3 分鐘）

1. 開 `http://localhost:5010`，切換 `EN | 繁體中文`。
2. 開 `experiments/results/summary.md`，指出 P1 5/5、P3 0/5、P4 5/5。
3. 開 `figures/phishing.png`。
4. 說一句結論：

> 同一個 passkey，在 strict verifier 下 0/5 被攻破，在 permissive verifier
> 下 5/5 被攻破。抗釣魚不是憑證的屬性，是整個系統的屬性；而復原流程是
> 每一種方法最弱的環節。

---

## 8. Demo 當天攜帶的清單

- [ ] 這份 `docs/DEMO_GUIDE_zh.md`
- [ ] `docs/INTERIM_REPORT.pdf`
- [ ] `experiments/results/summary.md`
- [ ] `figures/phishing.png`
- [ ] `figures/replay_recovery.png`
- [ ] `figures/latency.png`
- [ ] `figures/klm.png`
- [ ] 已啟動的 AuthLab（`AUTHLAB_DB=./demo.sqlite3 python3 run.py`）
- [ ] 備用：Chrome DevTools WebAuthn 虛擬認證器已設定好
- [ ] 備用：TOTP 產生指令已測過
- [ ] 備用：若 live demo 失敗，直接切到 checked-in 結果與 PDF
