// ==UserScript==
// @name          domain-key
// @namespace     https://github.com/qa296/domain-key
// @version       1.1.1
// @description   根据域名 + 密码种子，自动生成高强度唯一密码
// @description:en Generate strong unique passwords based on domain + your secret seed
// @author        qa296
// @match         *://*/*
// @grant         GM_setValue
// @grant         GM_getValue
// @grant         GM_registerMenuCommand
// @grant         GM_notification
// @license       MIT
// @run-at        document-end
// ==/UserScript==


(function () {
  "use strict";

  // 配置
  const STORAGE_KEY = "dpg_secret_seed";
  const PASSWORD_LENGTH = 12;
  const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const LOWER = "abcdefghijklmnopqrstuvwxyz";
  const DIGIT = "1234567890";
  const SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?";
  const CHARSET = UPPER + LOWER + DIGIT + SPECIAL;

  // 域名提取
  function extractDomainKey(hostname) {
    let domain = hostname.replace(/^www\./i, "");
    const parts = domain.split(".");

    const twoPartTLD = new Set([
      "co", "com", "org", "net", "gov", "edu", "ac", "ne", "or", "go",
    ]);

    let mainPart;
    if (
      parts.length >= 3 &&
      parts[parts.length - 1].length <= 3 &&
      twoPartTLD.has(parts[parts.length - 2])
    ) {
      mainPart = parts[parts.length - 3];
    } else if (parts.length >= 2) {
      mainPart = parts[parts.length - 2];
    } else {
      mainPart = parts[0];
    }

    return mainPart.toLowerCase();
  }

  // 密码生成 PBKDF2拉伸(seed→PRK) + HKDF派生(→64B) + 强制4类字符 + 拒绝采样 + Fisher-Yates
  async function generatePassword(domainKey, seed, suffix = "") {
    const encoder = new TextEncoder();

    // 拉伸:PBKDF2-SHA512,10万次迭代,salt = domainKey → 256bit PRK
    const baseKey = await crypto.subtle.importKey(
      "raw", encoder.encode(seed), "PBKDF2", false, ["deriveBits"]
    );
    const prk = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-512", salt: encoder.encode(domainKey), iterations: 100000 },
      baseKey, 256
    );

    // 派生:HKDF-SHA512,salt/domainKey + info/suffix 结构化传参,无字符串拼接 → 512bit 密钥流
    const hkKey = await crypto.subtle.importKey("raw", prk, "HKDF", false, ["deriveBits"]);
    const stream = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-512", salt: encoder.encode(domainKey), info: encoder.encode(suffix) },
      hkKey, 512
    );

    const hashArray = new Uint8Array(stream);
    let offset = 0;

    function nextByte() {
      if (offset >= hashArray.length) offset = 0;
      return hashArray[offset++];
    }

    function unbiasedIndex(n, use2bytes) {
      if (n <= 1) return 0;
      const max = use2bytes ? 65536 : 256;
      const threshold = max - (max % n);
      while (true) {
        const val = use2bytes ? ((nextByte() << 8) | nextByte()) : nextByte();
        if (val < threshold) return val % n;
      }
    }

    const chars = [];
    chars.push(UPPER[unbiasedIndex(UPPER.length, false)]);
    chars.push(LOWER[unbiasedIndex(LOWER.length, false)]);
    chars.push(DIGIT[unbiasedIndex(DIGIT.length, false)]);
    chars.push(SPECIAL[unbiasedIndex(SPECIAL.length, false)]);

    for (let i = 4; i < PASSWORD_LENGTH; i++) {
      chars.push(CHARSET[unbiasedIndex(CHARSET.length, true)]);
    }

    for (let i = chars.length - 1; i > 0; i--) {
      const j = unbiasedIndex(i + 1, false);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join("");
  }

  // 页面用户名/邮箱检测
  function detectPageUsername() {
    const emailInput = document.querySelector('input[type="email"]');
    if (emailInput && emailInput.value) return emailInput.value;

    const textInputs = document.querySelectorAll('input[type="text"], input:not([type])');
    for (const inp of textInputs) {
      const attr = (inp.name + " " + inp.id + " " + inp.placeholder).toLowerCase();
      if (/user|email|account|login|username/.test(attr) && inp.value) {
        return inp.value;
      }
    }
    return "";
  }

  // 后缀输入弹窗
  function showSuffixDialog(domainKey) {
    return new Promise((resolve) => {
      const existing = document.getElementById("dpg-suffix-overlay");
      if (existing) existing.remove();

const detectedUser = detectPageUsername();
const defaultValue = detectedUser || "";

const overlay = document.createElement("div");
      overlay.id = "dpg-suffix-overlay";
      Object.assign(overlay.style, {
        position: "fixed",
        inset: "0",
        background: "rgba(0,0,0,0.45)",
        zIndex: "999999",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontFamily: '"Segoe UI", system-ui, sans-serif',
      });

      const dialog = document.createElement("div");
      Object.assign(dialog.style, {
        background: "#fff",
        borderRadius: "4px",
        padding: "16px 20px",
        maxWidth: "340px",
        width: "90%",
        boxShadow: "0 2px 8px rgba(0,0,0,0.2)",
        color: "#222",
      });

const detectedHint =
  detectedUser
    ? `<p style="margin:4px 0 0 0; font-size:11px; color:#999;">检测到: ${escapeHtml(detectedUser)}</p>`
    : "";

      dialog.innerHTML = `
        <h3 style="margin:0 0 10px 0; font-size:14px;">账号后缀</h3>
        <p style="margin:0 0 10px 0; color:#666; font-size:12px;">
          添加后缀区分同站多账号，留空则使用默认生成。
        </p>
        <div style="display:flex; gap:6px; align-items:center;">
          <input id="dpg-suffix-input" type="password"
            style="flex:1; box-sizing:border-box; padding:6px 8px; font-size:13px;
                   border:1px solid #ccc; border-radius:3px; outline:none; font-family:inherit;"
            placeholder="如：work"
            value="${escapeHtml(defaultValue)}">
          <button id="dpg-suffix-toggle" type="button"
            style="width:auto; padding:5px 10px; border:1px solid #ccc; border-radius:3px;
                   background:#fff; color:#222; cursor:pointer; font-size:12px;">显示</button>
        </div>
        ${detectedHint}
        <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:12px;">
          <button id="dpg-suffix-cancel" style="padding:5px 12px; border:1px solid #ccc; border-radius:3px;
            background:#fff; color:#222; cursor:pointer; font-size:12px;">取消</button>
          <button id="dpg-suffix-ok" style="padding:5px 12px; border:none; border-radius:3px;
            background:#4a4a4a; color:#fff; cursor:pointer; font-size:12px;">确定</button>
        </div>
      `;

      overlay.appendChild(dialog);
      document.body.appendChild(overlay);

      const input = document.getElementById("dpg-suffix-input");
      const toggle = document.getElementById("dpg-suffix-toggle");
      toggle.addEventListener("click", () => {
        if (input.type === "password") {
          input.type = "text";
          toggle.textContent = "隐藏";
        } else {
          input.type = "password";
          toggle.textContent = "显示";
        }
      });

      document.getElementById("dpg-suffix-ok").addEventListener("click", () => {
        const val = input.value.trim();
        overlay.remove();
        resolve(val);
      });

      document.getElementById("dpg-suffix-cancel").addEventListener("click", () => {
        overlay.remove();
        resolve("");
      });

      overlay.addEventListener("click", (e) => {
        if (e.target === overlay) {
          overlay.remove();
          resolve("");
        }
      });

      input.addEventListener("focus", () => (input.style.borderColor = "#666"));
      input.addEventListener("blur", () => (input.style.borderColor = "#ccc"));
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
    });
  }

  // ── UI ──────────────────────────────────────────────────────────
  const allButtons = [];

  function createButton(inputEl, domainKey) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "dpg-btn";
    btn.innerHTML = "🔑";
    btn.title = "生成密码（Shift+点击: 多账号）";
    Object.assign(btn.style, {
      position: "fixed",
      width: "auto",
      border: "1px solid #ccc",
      background: "#f5f5f5",
      cursor: "pointer",
      fontSize: "14px",
      lineHeight: "1",
      padding: "2px 6px",
      borderRadius: "2px",
      zIndex: "999999",
      transition: "border-color 0.1s",
      display: "none",
      pointerEvents: "auto",
    });
    btn.addEventListener("mouseenter", () => (btn.style.borderColor = "#999"));
    btn.addEventListener("mouseleave", () => (btn.style.borderColor = "#ccc"));

    document.body.appendChild(btn);

    function positionButton() {
      const rect = inputEl.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0 || !inputEl.offsetParent) {
        btn.style.display = "none";
        return;
      }
      btn.style.display = "";
      const btnW = btn.offsetWidth || 24;
      btn.style.top = rect.top + (rect.height - (btn.offsetHeight || 24)) / 2 + "px";
      btn.style.left = rect.right - btnW - 4 + "px";
    }

    allButtons.push(positionButton);
    requestAnimationFrame(positionButton);

    inputEl.addEventListener("focus", () => positionButton());
    inputEl.addEventListener("blur", () => { btn.style.display = "none"; });

    btn.addEventListener("mousedown", async (e) => {
      e.preventDefault();
      e.stopPropagation();

      const seed = GM_getValue(STORAGE_KEY, "");
      if (!seed) {
        showSettingsDialog();
        return;
      }

      let suffix = "";
      if (e.shiftKey) {
        suffix = await showSuffixDialog(domainKey);
      }

      const pwd = await generatePassword(domainKey, seed, suffix);
      inputEl.value = pwd;
      inputEl.focus();

      inputEl.dispatchEvent(new Event("input", { bubbles: true }));
      inputEl.dispatchEvent(new Event("change", { bubbles: true }));

      try {
        await navigator.clipboard.writeText(pwd);
      } catch {
        const ta = document.createElement("textarea");
        ta.value = pwd;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }

      showTooltip(btn, "已填充并复制");
    });
  }

  // ── Tooltip ─────────────────────────────────────────────────────
  function showTooltip(anchor, text) {
    const existing = document.querySelector(".dpg-tooltip");
    if (existing) existing.remove();

    const tip = document.createElement("div");
    tip.className = "dpg-tooltip";
    tip.textContent = text;
    Object.assign(tip.style, {
      position: "fixed",
      background: "#000",
      color: "#fff",
      fontSize: "11px",
      padding: "3px 6px",
      borderRadius: "2px",
      whiteSpace: "nowrap",
      zIndex: "1000000",
      pointerEvents: "none",
    });
    const rect = anchor.getBoundingClientRect();
    tip.style.bottom = window.innerHeight - rect.top + 6 + "px";
    tip.style.right = window.innerWidth - rect.right + "px";

    document.body.appendChild(tip);
    setTimeout(() => tip.remove(), 1500);
  }

  // 按需初始化
  document.addEventListener("focusin", (e) => {
    const input = e.target;
    if (
      input.tagName !== "INPUT" ||
      input.type !== "password" ||
      input.dataset.dpgProcessed
    ) {
      return;
    }
    input.dataset.dpgProcessed = "1";
    createButton(input, extractDomainKey(window.location.hostname));
  });

  function repositionAll() {
    allButtons.forEach((fn) => fn());
  }
  window.addEventListener("scroll", repositionAll, { passive: true });
  window.addEventListener("resize", repositionAll, { passive: true });

  // 设置对话框
  function showSettingsDialog() {
    const existing = document.getElementById("dpg-dialog-overlay");
    if (existing) existing.remove();

    const current = GM_getValue(STORAGE_KEY, "");
    const domainKey = extractDomainKey(window.location.hostname);

    const overlay = document.createElement("div");
    overlay.id = "dpg-dialog-overlay";
    Object.assign(overlay.style, {
      position: "fixed",
      inset: "0",
      background: "rgba(0,0,0,0.45)",
      zIndex: "999999",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      fontFamily: '"Segoe UI", system-ui, sans-serif',
    });

    const dialog = document.createElement("div");
    Object.assign(dialog.style, {
      background: "#fff",
      borderRadius: "4px",
      padding: "18px 22px",
      maxWidth: "400px",
      width: "90%",
      boxShadow: "0 2px 8px rgba(0,0,0,0.2)",
      color: "#222",
    });

    dialog.innerHTML = `
      <h2 style="margin:0 0 12px 0; font-size:16px;">密码种子设置</h2>
      <p style="margin:0 0 12px 0; color:#666; font-size:12px;">
        用域名 + 种子生成唯一密码，请牢记你的种子。
      </p>
      <label style="display:block; font-size:13px; font-weight:600; margin-bottom:6px;">
        密码种子
      </label>
      <textarea id="dpg-seed-input"
        style="width:100%; box-sizing:border-box; padding:8px; font-size:13px;
               border:1px solid #ccc; border-radius:3px; resize:vertical; min-height:50px;
               outline:none; font-family:inherit;"
        placeholder="至少 6 个字符">${escapeHtml(current)}</textarea>
      <p style="margin:6px 0 12px 0; font-size:11px; color:#999;">
        域名 Key: ${escapeHtml(domainKey)}
      </p>
      <div style="display:flex; gap:8px; justify-content:flex-end;">
        <button id="dpg-cancel-btn" style="padding:6px 16px; border:1px solid #ccc; border-radius:3px;
          background:#fff; cursor:pointer; font-size:13px;">取消</button>
        <button id="dpg-save-btn" style="padding:6px 16px; border:none; border-radius:3px;
          background:#4a4a4a; color:#fff; cursor:pointer; font-size:13px;">保存</button>
      </div>
    `;

    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    const textarea = document.getElementById("dpg-seed-input");
    document.getElementById("dpg-save-btn").addEventListener("click", () => {
      const val = textarea.value.trim();
      if (val.length < 6) {
        textarea.style.borderColor = "#c00";
        textarea.focus();
        return;
      }
      GM_setValue(STORAGE_KEY, val);
      overlay.remove();
      GM_notification({
        text: "密码种子已保存。刷新页面后点击 🔑 按钮即可生成密码。",
        title: "保存成功",
        timeout: 3500,
      });
    });
    document.getElementById("dpg-cancel-btn").addEventListener("click", () => overlay.remove());
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) overlay.remove();
    });
    textarea.addEventListener("focus", () => (textarea.style.borderColor = "#666"));
    textarea.addEventListener("blur", () => (textarea.style.borderColor = "#ccc"));

    textarea.focus();
    textarea.setSelectionRange(textarea.value.length, textarea.value.length);
  }

  // 工具
  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // 注册 Tampermonkey 菜单
  GM_registerMenuCommand("设置密码种子", showSettingsDialog, "S");

  // 启动
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => requestAnimationFrame(repositionAll));
  } else {
    requestAnimationFrame(repositionAll);
  }
})();
