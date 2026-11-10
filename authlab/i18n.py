"""Small, dependency-free UI translation layer for AuthLab.

AuthLab ships two interface languages:

``en``
    English (the default; the experiment harness relies on this default).
``zh-Hant``
    Traditional Chinese (繁體中文).

The active language is stored in a cookie rather than in the session so that
it survives logout and works on pages that do not require authentication.
Only presentation text is translated: form field IDs, names, endpoints, and
all security decisions stay exactly as they are.
"""
from __future__ import annotations

from flask import has_request_context, request

COOKIE_NAME = "authlab_lang"
DEFAULT_LOCALE = "en"
SUPPORTED_LOCALES = ("en", "zh-Hant")
LOCALE_LABELS = {"en": "EN", "zh-Hant": "繁體中文"}

# key: (English, Traditional Chinese)
_STRINGS: dict[str, tuple[str, str]] = {
    # ------------------------------------------------------------------
    # Shared shell
    # ------------------------------------------------------------------
    "nav.overview": ("Overview", "總覽"),
    "nav.dashboard": ("Dashboard", "控制台"),
    "nav.lab": ("Lab", "實驗室"),
    "nav.signout": ("Sign out", "登出"),
    "nav.signin": ("Sign in", "登入"),
    "nav.create_account": ("Create account", "建立帳號"),
    "footer.note": (
        "AuthLab — controlled WebAuthn/TOTP testbed. Research and teaching use only.",
        "AuthLab — 受控的 WebAuthn/TOTP 測試平台，僅供研究與教學使用。",
    ),
    "footer.lab_mode": ("LAB MODE", "實驗模式"),
    "lang.label": ("Language", "語言"),
    "lang.english": ("English", "English"),
    "lang.chinese": ("Traditional Chinese", "繁體中文"),
    # ------------------------------------------------------------------
    # Landing page
    # ------------------------------------------------------------------
    "index.title": ("AuthLab — beyond TOTP", "AuthLab — 超越 TOTP"),
    "index.eyebrow": ("Beyond TOTP", "超越 TOTP"),
    "index.h1a": ("Three ways to sign in.", "三種登入方式，"),
    "index.h1b": ("Three different threat models.", "三種不同的威脅模型。"),
    "index.lede": (
        "A controlled testbed for comparing <strong>password + TOTP</strong>, "
        "<strong>synced passkeys</strong>, and <strong>hardware FIDO2 keys</strong> "
        "under phishing, replay, device loss, backup, and account recovery.",
        "一個受控測試平台，用來比較<strong>密碼 + TOTP</strong>、"
        "<strong>同步通行金鑰</strong>與<strong>硬體 FIDO2 金鑰</strong>"
        "在釣魚、重放、裝置遺失、備份與帳號復原情境下的表現。",
    ),
    "index.create_test_account": ("Create a test account", "建立測試帳號"),
    "index.signin": ("Sign in", "登入"),
    "index.open_lab": ("Open lab console", "開啟實驗控制台"),
    "index.tag_know": ("Something you know", "你知道的東西"),
    "index.tag_synced": ("Synced credential", "同步憑證"),
    "index.tag_have": ("Something you have", "你擁有的東西"),
    "index.totp_title": ("Password + TOTP", "密碼 + TOTP"),
    "index.totp_desc": (
        "Phishable in real time. Replay protection depends on the verifier "
        "enforcing a monotonic counter. Recovery usually collapses to email.",
        "可被即時釣魚。重放保護取決於驗證端是否強制單調計數器。"
        "復原流程通常只能依賴 Email。",
    ),
    "index.totp_bad1": ("Not origin-bound", "未綁定來源"),
    "index.totp_bad2": ("Codes can be relayed", "驗證碼可被轉送"),
    "index.totp_good1": ("Works everywhere", "到處都能用"),
    "index.passkey_title": ("Synced passkey", "同步通行金鑰"),
    "index.passkey_desc": (
        "Origin-bound WebAuthn credential, end-to-end encrypted by the platform "
        "sync fabric. Device loss is survivable; cloud-account compromise becomes "
        "the recovery single point of failure.",
        "綁定來源的 WebAuthn 憑證，由平台同步機制端到端加密。裝置遺失仍可復原；"
        "但雲端帳號一旦被入侵，就會成為復原流程的單點故障。",
    ),
    "index.passkey_good1": ("Phishing-resistant", "可抵抗釣魚"),
    "index.passkey_good2": ("Survives device loss", "裝置遺失仍可復原"),
    "index.passkey_warn1": ("Sync account is a SPOF", "同步帳號是單點故障"),
    "index.hw_title": ("Hardware FIDO2 key", "硬體 FIDO2 金鑰"),
    "index.hw_desc": (
        "Origin-bound, non-exportable key material and a monotonic signature "
        "counter. No sync: loss requires a second key or a recovery code.",
        "綁定來源、不可匯出的金鑰材料，以及單調遞增的簽章計數器。不支援同步："
        "遺失時需要第二把金鑰或復原碼。",
    ),
    "index.hw_good1": ("Phishing-resistant", "可抵抗釣魚"),
    "index.hw_good2": ("Clone detection", "可偵測克隆"),
    "index.hw_warn1": ("Device loss is permanent", "裝置遺失即永久失去"),
    "index.measure_title": ("What the project measures", "專案測量的項目"),
    "index.m_phishing": ("Phishing", "釣魚"),
    "index.m_phishing_desc": (
        "real-time relay, lookalike origin, origin-check bugs",
        "即時轉送、相似來源、來源檢查錯誤",
    ),
    "index.m_replay": ("Replay", "重放"),
    "index.m_replay_desc": (
        "TOTP windows, challenge reuse, signature counters",
        "TOTP 時間窗、challenge 重用、簽章計數器",
    ),
    "index.m_recovery": ("Recovery", "復原"),
    "index.m_recovery_desc": (
        "sync restore, backup key, email token, recovery codes",
        "同步還原、備用金鑰、Email 權杖、復原碼",
    ),
    "index.m_usability": ("Usability", "可用性"),
    "index.m_usability_desc": (
        "ceremony latency, interaction cost, KLM estimates",
        "認證延遲、互動成本、KLM 估算",
    ),
    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------
    "register.title": ("Create account — AuthLab", "建立帳號 — AuthLab"),
    "register.eyebrow": ("Step 1 of 2", "步驟 1／2"),
    "register.h1": ("Create a test account", "建立測試帳號"),
    "register.lede": (
        "You will get a TOTP secret and one-time recovery codes, then you can "
        "enrol a platform passkey and/or a hardware security key.",
        "你會取得 TOTP 密鑰與一次性復原碼，接著可以註冊平台通行金鑰及／或"
        "硬體安全金鑰。",
    ),
    "register.muted": (
        "Use a disposable password. This is a research testbed.",
        "請使用一次性密碼。這是研究測試平台。",
    ),
    "register.username": ("Username", "使用者名稱"),
    "register.password": ("Password", "密碼"),
    "register.confirm": ("Confirm password", "確認密碼"),
    "register.hint": (
        "At least 10 characters. Do not reuse a real password.",
        "至少 10 個字元，請勿重複使用真實密碼。",
    ),
    "register.submit": ("Create account", "建立帳號"),
    "register.have_account": ("Already have an account?", "已經有帳號了？"),
    "register.signin": ("Sign in", "登入"),
    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------
    "login.title": ("Sign in — AuthLab", "登入 — AuthLab"),
    "login.eyebrow": ("Controlled comparison", "受控比較"),
    "login.h1": ("Sign in", "登入"),
    "login.lede": (
        "Choose a method. Each one is instrumented; failed and successful "
        "ceremonies are written to the audit log.",
        "選擇一種登入方式。每種方式都有記錄，成功與失敗的認證流程都會寫入"
        "稽核紀錄。",
    ),
    "login.tab_password": ("Password + TOTP", "密碼 + TOTP"),
    "login.tab_passkey": ("Synced passkey", "同步通行金鑰"),
    "login.tab_hardware": ("Hardware key", "硬體金鑰"),
    "login.username": ("Username", "使用者名稱"),
    "login.password": ("Password", "密碼"),
    "login.continue_totp": ("Continue to TOTP", "繼續輸入 TOTP"),
    "login.passkey_desc": (
        "Uses a discoverable WebAuthn credential. No username is typed; the "
        "authenticator returns the account handle.",
        "使用可探索的 WebAuthn 憑證。不需輸入使用者名稱，認證器會回傳帳號 "
        "handle。",
    ),
    "login.passkey_btn": ("Sign in with passkey", "使用通行金鑰登入"),
    "login.hardware_desc": (
        "A hardware key normally stores a non-resident credential, so the "
        "account name is needed to build the allow-list.",
        "硬體金鑰通常儲存非 resident 憑證，因此需要帳號名稱來建立允許清單。",
    ),
    "login.hardware_btn": ("Sign in with security key", "使用安全金鑰登入"),
    # ------------------------------------------------------------------
    # TOTP challenge
    # ------------------------------------------------------------------
    "totp.title": ("TOTP — AuthLab", "TOTP — AuthLab"),
    "totp.eyebrow": ("Step 2 of 2", "步驟 2／2"),
    "totp.h1": ("Enter your TOTP code", "輸入 TOTP 驗證碼"),
    "totp.lede": (
        "Signing in as <strong>{username}</strong>. The server accepts a ±1 "
        "time-step window and records the highest counter it has seen.",
        "正在以 <strong>{username}</strong> 登入。伺服器接受 ±1 個時間步長的"
        "視窗，並記錄曾見過的最大計數器。",
    ),
    "totp.code_label": ("6-digit code", "6 位數驗證碼"),
    "totp.submit": ("Verify and sign in", "驗證並登入"),
    "totp.note": (
        "TOTP is phishable in real time: a relay can submit this code before the "
        "window closes.",
        "TOTP 可被即時釣魚：轉送者可在時間窗關閉前提交這組驗證碼。",
    ),
    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------
    "dashboard.title": ("Dashboard — AuthLab", "控制台 — AuthLab"),
    "dashboard.signed_in_with": ("Signed in with {method}", "登入方式：{method}"),
    "dashboard.lede": (
        "Session and credential state, straight from the database.",
        "直接從資料庫讀取的 session 與憑證狀態。",
    ),
    "dashboard.session_active": ("session active", "Session 使用中"),
    "dashboard.recovery_warning": (
        "You are in a recovery session. Set a new password and rotate TOTP "
        "before continuing.",
        "你目前處於復原 session。請先設定新密碼並輪替 TOTP 再繼續。",
    ),
    "dashboard.new_password": ("New password", "新密碼"),
    "dashboard.confirm": ("Confirm", "確認"),
    "dashboard.set_password": ("Set password", "設定密碼"),
    "dashboard.webauthn_credentials": ("WebAuthn credentials", "WebAuthn 憑證"),
    "table.label": ("Label", "標籤"),
    "table.kind": ("Kind", "類型"),
    "table.be_bs": ("BE/BS", "BE/BS"),
    "table.counter": ("Counter", "計數器"),
    "table.last_used": ("Last used", "上次使用"),
    "table.never": ("never", "從未"),
    "dashboard.revoke": ("revoke", "撤銷"),
    "dashboard.confirm_revoke": (
        "Revoke this credential?",
        "確定要撤銷這個憑證？",
    ),
    "dashboard.no_credentials": (
        "No WebAuthn credentials. Add one below.",
        "尚無 WebAuthn 憑證，請在下方新增。",
    ),
    "dashboard.add_passkey": ("Add passkey", "新增通行金鑰"),
    "dashboard.add_hardware": ("Add hardware key", "新增硬體金鑰"),
    "dashboard.account_recovery": ("Account recovery", "帳號復原"),
    "dashboard.recovery_left": (
        "<strong>{n}</strong> unused recovery code(s).",
        "尚有 <strong>{n}</strong> 組未使用的復原碼。",
    ),
    "dashboard.recovery_note": (
        "Recovery codes are a single-use fallback. After a password reset, every "
        "session is revoked and TOTP is rotated.",
        "復原碼是一次性備援。密碼重設後，所有 session 都會被撤銷，TOTP 也會"
        "輪替。",
    ),
    "dashboard.open_recovery": ("Open recovery", "開啟復原"),
    "dashboard.confirm_revoke_all": (
        "Revoke ALL credentials, codes, and sessions?",
        "確定要撤銷所有憑證、復原碼與 session？",
    ),
    "dashboard.revoke_everything": ("Revoke everything", "全部撤銷"),
    "dashboard.recent_sessions": ("Recent sessions", "最近的 session"),
    "table.method": ("Method", "方式"),
    "table.created": ("Created", "建立時間"),
    "table.expires": ("Expires", "到期時間"),
    "table.state": ("State", "狀態"),
    "table.revoked": ("revoked", "已撤銷"),
    "table.active": ("active", "使用中"),
    "dashboard.audit_log": ("Audit log", "稽核紀錄"),
    "table.event": ("Event", "事件"),
    "table.ok": ("OK", "結果"),
    "table.detail": ("Detail", "詳細內容"),
    # ------------------------------------------------------------------
    # Enrolment
    # ------------------------------------------------------------------
    "enroll.title": ("Enrol authenticators — AuthLab", "註冊認證器 — AuthLab"),
    "enroll.eyebrow": ("Step 2 of 2", "步驟 2／2"),
    "enroll.h1": ("Enrol your authenticators", "註冊你的認證器"),
    "enroll.lede": (
        "The password/TOTP path is already active. Add a platform passkey and/or "
        "a hardware security key to compare them.",
        "密碼／TOTP 路徑已啟用。新增平台通行金鑰及／或硬體安全金鑰以進行比較。",
    ),
    "enroll.go_dashboard": ("Go to dashboard", "前往控制台"),
    "enroll.authenticator_app": ("Authenticator app", "驗證器應用程式"),
    "enroll.scan_secret": (
        "Scan this secret in any RFC 6238 TOTP app.",
        "在任何支援 RFC 6238 的 TOTP 應用程式中掃描此密鑰。",
    ),
    "enroll.provisioning_uri": ("Provisioning URI", "佈建 URI"),
    "enroll.qr_alt": ("TOTP QR code", "TOTP QR 碼"),
    "enroll.webauthn_credentials": ("WebAuthn credentials", "WebAuthn 憑證"),
    "enroll.webauthn_desc": (
        "Platform passkeys are syncable when the provider supports it; hardware "
        "keys are device-bound.",
        "平台通行金鑰在供應商支援時可同步；硬體金鑰則綁定裝置。",
    ),
    "enroll.add_passkey": ("Add synced passkey", "新增同步通行金鑰"),
    "enroll.add_hardware": ("Add hardware key", "新增硬體金鑰"),
    "table.backup": ("Backup", "備份"),
    "enroll.device_bound": ("device-bound", "綁定裝置"),
    "enroll.no_credentials": ("No WebAuthn credentials yet.", "尚無 WebAuthn 憑證。"),
    "enroll.recovery_codes": ("One-time recovery codes", "一次性復原碼"),
    "enroll.codes_warning": (
        "Save these now. They are shown once and each can be used once. In a real "
        "deployment they would be downloaded or printed.",
        "請立即保存。這些只會顯示一次，且每組只能使用一次。實際部署時會提供"
        "下載或列印。",
    ),
    "enroll.codes_stored": (
        "Recovery codes are stored hashed. Regenerate them if you did not save "
        "the originals.",
        "復原碼以雜湊形式儲存。若未保存原始碼，請重新產生。",
    ),
    "enroll.confirm_regenerate": (
        "Invalidate all existing recovery codes?",
        "確定要讓所有現有復原碼失效？",
    ),
    "enroll.regenerate": ("Regenerate recovery codes", "重新產生復原碼"),
    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------
    "recovery.title": ("Account recovery — AuthLab", "帳號復原 — AuthLab"),
    "recovery.eyebrow": ("Fallback path", "備援路徑"),
    "recovery.h1": ("Account recovery", "帳號復原"),
    "recovery.lede": (
        "Recovery is where strong authentication often quietly degrades. Every "
        "path here is instrumented and single-use.",
        "復原流程往往是強認證悄悄被削弱的地方。這裡的每條路徑都有記錄，且僅能"
        "使用一次。",
    ),
    "recovery.email_reset": ("Email reset token", "Email 重設權杖"),
    "recovery.username": ("Username", "使用者名稱"),
    "recovery.send_link": ("Send reset link", "寄送重設連結"),
    "recovery.demo_email": ("Demo email.", "示範 Email。"),
    "recovery.demo_email_body": (
        "In production this link is emailed. It is shown here so the experiment "
        "can follow it.",
        "實際部署時會以 Email 寄送此連結。這裡直接顯示，以便實驗追蹤。",
    ),
    "recovery.token_note": (
        "Tokens are 256-bit, hashed at rest, expire in 15 minutes, and are "
        "consumed atomically.",
        "權杖為 256 位元、以雜湊形式儲存、15 分鐘後過期，並以原子操作消耗。",
    ),
    "recovery.recovery_code": ("Recovery code", "復原碼"),
    "recovery.code_desc": (
        "Each code is stored with scrypt and is valid once.",
        "每組復原碼以 scrypt 儲存，且僅能使用一次。",
    ),
    "recovery.code_label": ("One-time code", "一次性代碼"),
    "recovery.use_code": ("Use recovery code", "使用復原碼"),
    "recovery.code_note": (
        "If you have lost every authenticator, this is the last self-service "
        "path. It intentionally does not require a passkey.",
        "若所有認證器都已遺失，這是最後的自助路徑。此路徑刻意不要求通行金鑰。",
    ),
    # ------------------------------------------------------------------
    # Password reset
    # ------------------------------------------------------------------
    "reset.title": ("Reset password — AuthLab", "重設密碼 — AuthLab"),
    "reset.eyebrow": ("Email token accepted", "已接受 Email 權杖"),
    "reset.h1": ("Choose a new password", "選擇新密碼"),
    "reset.lede": (
        "Resetting for <strong>{username}</strong>. This will revoke every "
        "existing session, delete old recovery codes, and rotate the TOTP secret.",
        "正在為 <strong>{username}</strong> 重設密碼。這將撤銷所有現有 session、"
        "刪除舊復原碼，並輪替 TOTP 密鑰。",
    ),
    "reset.new_password": ("New password", "新密碼"),
    "reset.confirm": ("Confirm", "確認"),
    "reset.submit": ("Reset password", "重設密碼"),
    "reset_done.title": ("Password reset — AuthLab", "密碼已重設 — AuthLab"),
    "reset_done.eyebrow": ("Recovery complete", "復原完成"),
    "reset_done.h1": ("Password reset", "密碼已重設"),
    "reset_done.lede": (
        "All previous sessions were revoked. The TOTP secret was rotated, so "
        "re-enrol your authenticator app with the new secret below.",
        "所有先前的 session 都已撤銷。TOTP 密鑰已輪替，請使用下方的新密鑰重新"
        "註冊驗證器應用程式。",
    ),
    "reset_done.continue": ("Continue to sign in", "繼續登入"),
    "reset_done.new_secret": ("New TOTP secret", "新的 TOTP 密鑰"),
    "reset_done.qr_alt": ("New TOTP QR code", "新的 TOTP QR 碼"),
    "reset_done.note": (
        "Passkeys were not deleted by the reset. This is a deliberate choice: "
        "they are stronger than a password. Use “revoke all” from the dashboard "
        "if the account is believed compromised.",
        "重設不會刪除通行金鑰。這是刻意的選擇：通行金鑰比密碼更強。若懷疑帳號已"
        "遭入侵，請從控制台使用「全部撤銷」。",
    ),
    # ------------------------------------------------------------------
    # Lab console
    # ------------------------------------------------------------------
    "lab.title": ("Lab console — AuthLab", "實驗控制台 — AuthLab"),
    "lab.eyebrow": ("Instrumentation", "實驗儀器"),
    "lab.h1": ("Lab console", "實驗控制台"),
    "lab.lede": (
        "The controlled experiments run from Python, not this page. This page "
        "shows the configuration the testbed is using.",
        "受控實驗從 Python 執行，而非此頁面。此頁面顯示測試平台目前的設定。",
    ),
    "lab.lab_mode": ("LAB MODE", "實驗模式"),
    "lab.lab_off": ("lab mode off", "實驗模式關閉"),
    "lab.relying_party": ("Relying party", "依賴方（RP）"),
    "lab.rp_id": ("RP ID", "RP ID"),
    "lab.origins": ("Accepted origins", "接受的來源"),
    "lab.counter_policy": ("Counter policy", "計數器政策"),
    "lab.endpoints": ("Lab endpoints", "實驗端點"),
    "lab.endpoints_value": ("/lab/* (token required)", "/lab/*（需要權杖）"),
    "lab.run_experiments": ("Run the experiments", "執行實驗"),
    "lab.results_written": ("Results are written to", "結果寫入"),
    "lab.figures_written": ("and figures to", "，圖表寫入"),
    "lab.harness_note": (
        "The harness launches Chrome with CDP virtual authenticators, so no "
        "physical security key is required.",
        "測試框架會啟動 Chrome 並使用 CDP 虛擬認證器，因此不需要實體安全金鑰。",
    ),
    "lab.method_password_totp": ("password+TOTP", "密碼+TOTP"),
    "lab.method_passkey_hardware": (
        "passkey / hardware",
        "通行金鑰／硬體金鑰",
    ),
    "lab.method_synced_passkey": ("synced passkey", "同步通行金鑰"),
    "lab.method_hardware": ("hardware key", "硬體金鑰"),
    "lab.method_all": ("all", "全部"),
    "lab.period": (".", "。"),
    "lab.scenarios": ("Scenarios", "實驗情境"),
    "table.scenario": ("Scenario", "情境"),
    "table.expected": ("Expected control", "預期控制"),
    "lab.p1_name": ("Real-time phishing relay", "即時釣魚轉送"),
    "lab.p1_expected": (
        "fails only if replay/rate controls hold",
        "僅在重放／速率控制生效時失敗",
    ),
    "lab.p2_name": ("Naive lookalike origin", "簡易相似來源"),
    "lab.p2_expected": (
        "no credential for attacker RP ID",
        "攻擊者 RP ID 沒有可用憑證",
    ),
    "lab.p3_name": (
        "Relay through lookalike subdomain, strict RP",
        "透過相似子網域轉送，嚴格 RP",
    ),
    "lab.p3_expected": ("origin check rejects", "來源檢查拒絕"),
    "lab.p4_name": ("Same relay, permissive RP", "相同轉送，寬鬆 RP"),
    "lab.p4_expected": ("accepts — misconfiguration", "接受 — 設定錯誤"),
    "lab.r1_name": ("TOTP replay", "TOTP 重放"),
    "lab.r1_expected": ("monotonic counter rejects", "單調計數器拒絕"),
    "lab.r2_name": ("WebAuthn assertion replay", "WebAuthn assertion 重放"),
    "lab.r2_expected": ("challenge single-use rejects", "一次性 challenge 拒絕"),
    "lab.s1_name": (
        "Sync to second device, lose first",
        "同步到第二台裝置，遺失第一台",
    ),
    "lab.s1_expected": ("restore succeeds", "還原成功"),
    "lab.s2_name": ("Lose hardware key, no backup", "遺失硬體金鑰且無備份"),
    "lab.s2_expected": ("locked out", "無法登入"),
    "lab.s3_name": (
        "Lose hardware key, use backup key / code",
        "遺失硬體金鑰，使用備用金鑰／復原碼",
    ),
    "lab.s3_expected": ("recovery succeeds", "復原成功"),
    "lab.a1_name": (
        "Email token replay / expiry / session revocation",
        "Email 權杖重放／過期／session 撤銷",
    ),
    "lab.a1_expected": ("single-use + revoke", "一次性 + 撤銷"),
    "lab.u1_name": (
        "Ceremony latency and interaction cost",
        "認證延遲與互動成本",
    ),
    "lab.u1_expected": ("measured + KLM model", "量測 + KLM 模型"),
    # ------------------------------------------------------------------
    # Browser-side status strings (app.js)
    # ------------------------------------------------------------------
    "js.waiting": ("Waiting for authenticator…", "正在等待認證器…"),
    "js.enrolled": ("Enrolled: {label}", "已註冊：{label}"),
    "js.signed_in": ("Signed in as {username}", "已登入：{username}"),
    "js.unknown_error": ("Unknown error", "未知錯誤"),
    "js.cancelled": (
        "Cancelled or no matching credential.",
        "已取消，或找不到符合的憑證。",
    ),
    "js.security_error": (
        "Security error: origin/RP ID mismatch.",
        "安全性錯誤：來源／RP ID 不符。",
    ),
    "js.already_registered": (
        "This authenticator is already registered.",
        "此認證器已經註冊。",
    ),
}

# Route-level messages are plain English strings raised in the blueprints.
# Keeping them as keys means the routes do not need to know about locales.
_MESSAGES_ZH: dict[str, str] = {
    "Username must be 1-64 characters (letters, digits, . _ -).":
        "使用者名稱必須為 1–64 個字元（字母、數字、. _ -）。",
    "Passwords do not match.": "兩次輸入的密碼不一致。",
    "That username is already taken.": "此使用者名稱已被使用。",
    "Too many attempts. Try later.": "嘗試次數過多，請稍後再試。",
    "Invalid username or password.": "使用者名稱或密碼不正確。",
    "Invalid or already-used code.": "驗證碼無效或已被使用。",
    "If that account exists, a reset link has been sent.":
        "若該帳號存在，重設連結已寄出。",
    "This reset link is invalid, used, or expired.":
        "此重設連結無效、已使用或已過期。",
    "This reset link has already been used.": "此重設連結已被使用。",
    "Invalid username or recovery code.": "使用者名稱或復原碼不正確。",
    "That recovery code has already been used.": "此復原碼已被使用。",
    "Password must be at least 10 characters.": "密碼長度至少需 10 個字元。",
    "Password is too long.": "密碼太長。",
    "Password is too common.": "密碼太常見。",
    "Password must not contain the username.": "密碼不能包含使用者名稱。",
}

# Session/credential method names shown in tables.
_METHODS: dict[str, tuple[str, str]] = {
    "password_totp": ("Password + TOTP", "密碼 + TOTP"),
    "recovery_code": ("Recovery code", "復原碼"),
    "registration": ("Registration", "註冊"),
    "passkey": ("Passkey", "通行金鑰"),
    "hardware": ("Hardware key", "硬體金鑰"),
}

# Audit-log event identifiers shown in the dashboard.
_EVENTS: dict[str, tuple[str, str]] = {
    "register": ("register", "註冊"),
    "password_ok": ("password ok", "密碼驗證通過"),
    "password_login": ("password login", "密碼登入"),
    "totp_login": ("TOTP login", "TOTP 登入"),
    "login": ("login", "登入"),
    "logout": ("logout", "登出"),
    "webauthn_register": ("WebAuthn register", "WebAuthn 註冊"),
    "webauthn_login": ("WebAuthn login", "WebAuthn 登入"),
    "lab_webauthn_login": ("lab WebAuthn login", "實驗室 WebAuthn 登入"),
    "credential_revoked": ("credential revoked", "憑證撤銷"),
    "recovery_codes_regenerated": ("recovery codes regenerated", "復原碼重新產生"),
    "recovery_request": ("recovery request", "復原請求"),
    "recovery_code_login": ("recovery code login", "復原碼登入"),
    "password_reset": ("password reset", "密碼重設"),
    "password_changed": ("password changed", "密碼變更"),
    "revoke_all": ("revoke all", "全部撤銷"),
}


def normalize_locale(value: str | None) -> str:
    """Map a requested locale onto one of the two supported interfaces."""
    if not value:
        return DEFAULT_LOCALE
    value = value.strip().lower().replace("_", "-")
    if value in {"zh", "zh-hant", "zh-tw", "zh-hk", "zh-mo", "zh-cn", "zh-sg",
                 "zh-hans", "cn", "tw", "hk", "chinese", "traditional"}:
        # AuthLab only ships Traditional Chinese; Simplified requests get it too.
        return "zh-Hant"
    return DEFAULT_LOCALE


def get_locale() -> str:
    if not has_request_context():
        return DEFAULT_LOCALE
    return normalize_locale(request.cookies.get(COOKIE_NAME))


def _lookup(key: str, locale: str) -> str | None:
    pair = _STRINGS.get(key)
    if pair is not None:
        return pair[1] if locale == "zh-Hant" else pair[0]
    if locale == "zh-Hant":
        return _MESSAGES_ZH.get(key)
    return None


def t(key: str, **kwargs) -> str:
    """Translate a catalog key or an English route message.

    Unknown keys are returned unchanged, so this is safe to call on any string.
    """
    locale = get_locale()
    text = _lookup(key, locale)
    if text is None:
        text = _lookup(key, DEFAULT_LOCALE)
    if text is None:
        text = key
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            pass
    return text


def translate_message(value) -> str:
    """Jinja filter used for flashed and route-level messages."""
    if value is None:
        return ""
    if not isinstance(value, str):
        return value
    return t(value)


def method_label(value: str | None) -> str:
    """Jinja filter for session/credential method names."""
    if not value:
        return "—"
    pair = _METHODS.get(value)
    if pair is None:
        return str(value).replace("_", " ")
    return pair[1] if get_locale() == "zh-Hant" else pair[0]


def event_label(value: str | None) -> str:
    """Jinja filter for audit-log event identifiers."""
    if not value:
        return "—"
    pair = _EVENTS.get(value)
    if pair is None:
        return str(value).replace("_", " ")
    return pair[1] if get_locale() == "zh-Hant" else pair[0]


def locale_context() -> dict:
    """Values injected into every Jinja template."""
    locale = get_locale()
    # ``Referrer-Policy: no-referrer`` means the language switch needs an
    # explicit return path. Keep it a local path and decode defensively.
    query = request.query_string.decode("utf-8", "replace") if has_request_context() else ""
    next_url = (request.path if has_request_context() else "/")
    if query:
        next_url = f"{next_url}?{query}"
    return {
        "locale": locale,
        "is_zh": locale == "zh-Hant",
        "locale_labels": LOCALE_LABELS,
        "next_url": next_url,
    }
