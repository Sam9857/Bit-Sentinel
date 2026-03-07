/* ============================================================
   ipwnedyou – Cyber Threat Dashboard  |  dashboard.js
   ============================================================ */

// ─── Custom Cursor ────────────────────────────────────────────
const dot  = document.getElementById("cursor-dot");
const ring = document.getElementById("cursor-ring");
let mx = 0, my = 0, rx = 0, ry = 0;

document.addEventListener("mousemove", e => { mx = e.clientX; my = e.clientY; });

function animateCursor() {
  // Dot follows instantly
  dot.style.left = mx + "px";
  dot.style.top  = my + "px";
  // Ring lags behind
  rx += (mx - rx) * 0.12;
  ry += (my - ry) * 0.12;
  ring.style.left = rx + "px";
  ring.style.top  = ry + "px";
  requestAnimationFrame(animateCursor);
}
animateCursor();

// ─── Matrix Rain ──────────────────────────────────────────────
(function () {
  const canvas = document.getElementById("matrix-canvas");
  const ctx    = canvas.getContext("2d");
  let cols, drops;
  const chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホ";
  const fontSize = 13;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    cols  = Math.floor(canvas.width / fontSize);
    drops = new Array(cols).fill(1);
  }
  resize();
  window.addEventListener("resize", resize);

  setInterval(() => {
    ctx.fillStyle = "rgba(10,12,18,0.05)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#00e5ff";
    ctx.font = fontSize + "px monospace";
    drops.forEach((y, i) => {
      ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * fontSize, y * fontSize);
      if (y * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });
  }, 55);
})();

// ─── Toast ────────────────────────────────────────────────────
function toast(msg, type = "info", duration = 3000) {
  const container = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    el.style.transition = "opacity .3s";
    setTimeout(() => el.remove(), 350);
  }, duration);
}

// ─── Animated Counters ────────────────────────────────────────
function animateCounter(el, target, duration = 800) {
  const start    = parseInt(el.textContent) || 0;
  const startTime = performance.now();
  function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const ease     = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + (target - start) * ease);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ─── Risk Arc Canvas ──────────────────────────────────────────
function drawRiskArc(score) {
  const canvas = document.getElementById("risk-canvas");
  if (!canvas) return;
  const ctx  = canvas.getContext("2d");
  const w = canvas.width, h = canvas.height;
  const cx = w / 2, cy = h - 4;
  const r  = h - 16;

  ctx.clearRect(0, 0, w, h);

  // Background arc
  ctx.beginPath();
  ctx.arc(cx, cy, r, Math.PI, 0, false);
  ctx.lineWidth = 14;
  ctx.strokeStyle = "rgba(255,255,255,0.06)";
  ctx.stroke();

  // Colored arc
  const angle  = Math.PI + (Math.PI * score / 100);
  const color  = score <= 30 ? "#00ff88" : score <= 60 ? "#ffdd00" : "#ff3333";
  ctx.beginPath();
  ctx.arc(cx, cy, r, Math.PI, angle, false);
  ctx.lineWidth = 14;
  ctx.strokeStyle = color;
  ctx.shadowColor = color;
  ctx.shadowBlur  = 18;
  ctx.stroke();

  // Update label
  const valEl = document.getElementById("risk-value");
  if (valEl) {
    valEl.textContent = score;
    valEl.style.color = color;
    valEl.style.textShadow = `0 0 18px ${color}`;
  }
  const lvlEl = document.getElementById("risk-level");
  if (lvlEl) {
    const levels = { safe: "SAFE", suspicious: "SUSPICIOUS", danger: "DANGER" };
    const level  = score <= 30 ? "safe" : score <= 60 ? "suspicious" : "danger";
    lvlEl.textContent = levels[level];
    lvlEl.style.color = color;
  }
}

// ─── API fetch helper ─────────────────────────────────────────
async function apiFetch(url, options = {}) {
  const res  = await fetch(url, { headers: { "Content-Type": "application/json" }, ...options });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || "Request failed");
  return json;
}

// ─── Load Dashboard Status ────────────────────────────────────
async function loadStatus() {
  try {
    const data = await apiFetch("/api/status");
    setCounter("cnt-total",   data.total_threats);
    setCounter("cnt-blocked", data.blocked_ips);
    setCounter("cnt-scanned", data.total_scanned);
    const lastEl = document.getElementById("last-scan");
    if (lastEl) lastEl.textContent = data.last_scan && data.last_scan !== "Never"
      ? new Date(data.last_scan).toLocaleString()
      : "Never";
  } catch (e) { /* silent */ }
}

function setCounter(id, val) {
  const el = document.getElementById(id);
  if (el) animateCounter(el, val);
}

// ─── Load Threat Feed ─────────────────────────────────────────
async function loadThreats() {
  const feed = document.getElementById("threat-feed");
  if (!feed) return;
  try {
    const data = await apiFetch("/api/threats");
    renderThreatFeed(data.threats);
  } catch (e) { feed.innerHTML = '<div class="empty-state">Failed to load threats</div>'; }
}

function renderThreatFeed(threats) {
  const feed = document.getElementById("threat-feed");
  if (!feed) return;
  if (!threats.length) {
    feed.innerHTML = '<div class="empty-state">// No threats detected yet</div>';
    return;
  }

  feed.innerHTML = "";
  threats.forEach(t => {
    const level = t.risk_level || "safe";
    const color = t.risk_color || "#00ff88";
    const time  = t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : "";

    const types = (t.threat_types || []).map(type => {
      const cls = type.toLowerCase().includes("sql") ? "danger"
                : type.toLowerCase().includes("xss") ? "xss" : "";
      return `<span class="tag ${cls}">${type}</span>`;
    }).join("") || `<span class="tag">Clean</span>`;

    const item = document.createElement("div");
    item.className = `threat-item ${level}`;
    item.innerHTML = `
      <div class="threat-badge ${level}"></div>
      <div class="threat-ip">${t.ip}</div>
      <div class="threat-tags">${types}</div>
      <div class="threat-score" style="color:${color}">${t.risk_score || 0}</div>
      <div class="threat-time">${time}</div>
    `;
    feed.appendChild(item);
  });

  // Update average risk meter
  const avg = Math.round(threats.reduce((s, t) => s + (t.risk_score || 0), 0) / threats.length);
  drawRiskArc(avg || 0);
}

// ─── Load Blocked IPs ─────────────────────────────────────────
async function loadBlacklist() {
  const list = document.getElementById("blocked-list");
  if (!list) return;
  try {
    const data = await apiFetch("/api/blacklist");
    renderBlockedList(data.blocked_ips || []);
  } catch (e) { list.innerHTML = '<div class="empty-state">Failed to load</div>'; }
}

function renderBlockedList(ips) {
  const list = document.getElementById("blocked-list");
  if (!list) return;
  if (!ips.length) {
    list.innerHTML = '<div class="empty-state">// No blocked IPs</div>';
    return;
  }
  list.innerHTML = "";
  ips.forEach(entry => {
    // Support both old string format and new object format (Phase 2+)
    const ip     = typeof entry === "string" ? entry : entry.ip;
    const reason = typeof entry === "object" ? entry.reason   || "" : "";
    const score  = typeof entry === "object" ? entry.risk_score || 0 : 0;
    const auto   = typeof entry === "object" ? entry.auto        : false;
    const badge  = auto
      ? '<span class="auto-badge">AUTO</span>'
      : '<span class="manual-badge">MANUAL</span>';

    const item = document.createElement("div");
    item.className = "blocked-item";
    item.style.cursor = "pointer";
    item.title = "Click for IP details";
    item.innerHTML = `
      <span class="blocked-ip">⛔ ${ip} ${badge}</span>
      <div style="display:flex;gap:6px;align-items:center">
        ${score ? `<span style="color:var(--red);font-size:.72rem">${score}</span>` : ""}
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();unblockIP('${ip}')">Unblock</button>
      </div>
    `;
    item.addEventListener("click", () => openIPModal(ip));
    list.appendChild(item);
  });
}

// ─── Block IP ─────────────────────────────────────────────────
async function blockIP() {
  const input = document.getElementById("ip-input");
  const ip    = (input?.value || "").trim();
  if (!ip) { toast("Enter an IP address", "error"); return; }

  try {
    const data = await apiFetch("/api/block", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
    toast(data.message, "success");
    input.value = "";
    await loadBlacklist();
    await loadStatus();
  } catch (e) { toast(e.message, "error"); }
}

async function unblockIP(ip) {
  try {
    const data = await apiFetch("/api/unblock", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
    toast(data.message, "success");
    await loadBlacklist();
    await loadStatus();
  } catch (e) { toast(e.message, "error"); }
}

// ─── Scan Single IP ───────────────────────────────────────────
async function scanIP() {
  const input = document.getElementById("scan-ip-input");
  const ip    = (input?.value || "").trim();
  if (!ip) { toast("Enter an IP to scan", "error"); return; }

  const overlay = document.getElementById("scan-overlay");
  if (overlay) overlay.classList.add("show");

  try {
    const data = await apiFetch("/api/scan/ip", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
    toast(`Scan complete — Risk: ${data.risk_score} (${data.risk_level.toUpperCase()})`,
          data.risk_level === "danger" ? "error" : data.risk_level === "suspicious" ? "info" : "success");
    input.value = "";
    drawRiskArc(data.risk_score);
    await loadThreats();
    await loadStatus();
  } catch (e) { toast(e.message, "error"); }
  finally { if (overlay) overlay.classList.remove("show"); }
}

// ─── Upload & Scan Log File ───────────────────────────────────
function handleFileInput(e) {
  const file = e.target.files[0];
  if (file) scanLogFile(file);
}

function handleDrop(e) {
  e.preventDefault();
  const zone = document.getElementById("upload-zone");
  if (zone) zone.classList.remove("drag-over");
  const file = e.dataTransfer.files[0];
  if (file) scanLogFile(file);
}

async function scanLogFile(file) {
  const overlay = document.getElementById("upload-overlay");
  if (overlay) overlay.classList.add("show");

  const form = new FormData();
  form.append("file", file);

  try {
    const res  = await fetch("/api/scan/log", { method: "POST", body: form });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Scan failed");

    // Summary pills
    const summaryEl = document.getElementById("scan-summary");
    if (summaryEl) {
      summaryEl.innerHTML = `
        <span class="summary-pill danger">⚠ Danger: ${data.danger}</span>
        <span class="summary-pill suspicious">! Suspicious: ${data.suspicious}</span>
        <span class="summary-pill safe">✓ Safe: ${data.safe}</span>
        <span class="summary-pill" style="color:var(--accent);border-color:var(--accent)">
          IPs: ${data.unique_ips} | Lines: ${data.total_entries}
        </span>
      `;
    }
    toast(`Log scanned — ${data.total_entries} entries, ${data.danger} danger`, "success");
    await loadThreats();
    await loadStatus();
  } catch (e) { toast(e.message, "error"); }
  finally { if (overlay) overlay.classList.remove("show"); }
}

// ─── Generate Report ──────────────────────────────────────────
async function generateReport() {
  try {
    const data = await apiFetch("/api/report");
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `threat-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast("Report downloaded", "success");
  } catch (e) { toast("Failed to generate report", "error"); }
}

// ─── Clear Threats ────────────────────────────────────────────
async function clearThreats() {
  if (!confirm("Clear all threat history?")) return;
  try {
    await apiFetch("/api/clear", { method: "POST" });
    toast("Threat history cleared", "info");
    await loadThreats();
    await loadStatus();
    drawRiskArc(0);
  } catch (e) { toast("Failed to clear", "error"); }
}

// ─── Upload zone drag events ──────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const zone = document.getElementById("upload-zone");
  if (zone) {
    zone.addEventListener("dragover",  e => { e.preventDefault(); zone.classList.add("drag-over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
    zone.addEventListener("drop",      handleDrop);
    zone.addEventListener("click",     () => document.getElementById("file-input").click());
  }

  // Enter key on inputs
  document.getElementById("ip-input")?.addEventListener("keydown", e => { if (e.key === "Enter") blockIP(); });
  document.getElementById("scan-ip-input")?.addEventListener("keydown", e => { if (e.key === "Enter") scanIP(); });

  // Initial load
  drawRiskArc(0);
  loadStatus();
  loadThreats();
  loadBlacklist();

  // Auto-refresh every 15 seconds
  setInterval(() => {
    loadStatus();
    loadThreats();
    loadBlacklist();
  }, 15000);
});


/* ============================================================
   PHASE 2 — Prevention System JS
   ============================================================ */

// ─── Tabs ─────────────────────────────────────────────────────
function switchTab(id) {
  document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach(el => el.classList.remove("active"));
  document.getElementById(id)?.classList.add("active");

  const tabMap = {
    "tab-stats":     0,
    "tab-config":    1,
    "tab-whitelist": 2,
    "tab-ratelimit": 3,
    "tab-simulate":  4,
  };
  const idx = tabMap[id] ?? 0;
  document.querySelectorAll(".tab-btn")[idx]?.classList.add("active");

  // Lazy-load tab data
  if (id === "tab-stats")     loadPrevStats();
  if (id === "tab-config")    loadConfig();
  if (id === "tab-whitelist") loadWhitelist();
  if (id === "tab-ratelimit") loadRateLimits();
}

// ─── Prevention Stats ─────────────────────────────────────────
async function loadPrevStats() {
  try {
    const data = await apiFetch("/api/prevention/stats");
    const set  = (id, val) => { const el = document.getElementById(id); if (el) animateCounter(el, val); };
    set("prev-total",        data.total || 0);
    set("prev-danger",       data.danger || 0);
    set("prev-suspicious",   data.suspicious || 0);
    set("prev-safe",         data.safe || 0);
    set("prev-auto-blocked", data.auto_blocked || 0);
    const avgEl = document.getElementById("prev-avg-score");
    if (avgEl) avgEl.textContent = data.avg_score ?? "—";

    const typesEl = document.getElementById("prev-top-types");
    if (typesEl) {
      const types = data.top_threat_types || [];
      if (!types.length) {
        typesEl.innerHTML = '<span style="color:var(--text-dim);font-size:.78rem">None detected yet</span>';
      } else {
        typesEl.innerHTML = types.map(t =>
          `<span class="tag">${t.type} <strong style="color:var(--accent)">(${t.count})</strong></span>`
        ).join("");
      }
    }
  } catch (e) { /* silent */ }
}

// ─── Config ───────────────────────────────────────────────────
async function loadConfig() {
  try {
    const cfg = await apiFetch("/api/prevention/config");
    const setChk = (id, val) => { const el = document.getElementById(id); if (el) el.checked = !!val; };
    const setNum = (id, val) => { const el = document.getElementById(id); if (el) el.value = val; };
    setChk("cfg-auto-block", cfg.auto_block_enabled);
    setChk("cfg-rate-limit", cfg.rate_limit_enabled);
    setNum("cfg-threshold",  cfg.auto_block_threshold ?? 65);
    setNum("cfg-max-req",    cfg.rate_limit_max_requests ?? 100);
    setNum("cfg-window",     cfg.rate_limit_window_seconds ?? 60);
    setNum("cfg-brute",      cfg.brute_force_threshold ?? 5);
    setNum("cfg-highfreq",   cfg.high_freq_threshold ?? 100);
    setNum("cfg-maxhist",    cfg.max_threat_history ?? 500);
    updateThresholdMarker(cfg.auto_block_threshold ?? 65);
  } catch (e) { /* silent */ }
}

function updateThresholdMarker(val) {
  const marker = document.getElementById("threshold-marker");
  if (marker) marker.style.left = `${Math.min(Math.max(val, 0), 100)}%`;
}

async function saveConfig(showToast = false) {
  const g = id => document.getElementById(id);
  const payload = {
    auto_block_enabled:       g("cfg-auto-block")?.checked ?? true,
    rate_limit_enabled:       g("cfg-rate-limit")?.checked ?? true,
    auto_block_threshold:     parseInt(g("cfg-threshold")?.value  || 65),
    rate_limit_max_requests:  parseInt(g("cfg-max-req")?.value    || 100),
    rate_limit_window_seconds: parseInt(g("cfg-window")?.value    || 60),
    brute_force_threshold:    parseInt(g("cfg-brute")?.value      || 5),
    high_freq_threshold:      parseInt(g("cfg-highfreq")?.value   || 100),
    max_threat_history:       parseInt(g("cfg-maxhist")?.value    || 500),
  };

  try {
    await apiFetch("/api/prevention/config", {
      method: "POST",
      body:   JSON.stringify(payload),
    });
    if (showToast) toast("Config saved ✓", "success");
    const msgEl = document.getElementById("cfg-msg");
    if (msgEl) {
      msgEl.textContent = `Saved at ${new Date().toLocaleTimeString()}`;
      setTimeout(() => { msgEl.textContent = ""; }, 3000);
    }
    updateThresholdMarker(payload.auto_block_threshold);
  } catch (e) { toast(`Config error: ${e.message}`, "error"); }
}

// ─── Whitelist ────────────────────────────────────────────────
async function loadWhitelist() {
  const list = document.getElementById("whitelist-list");
  if (!list) return;
  try {
    const data = await apiFetch("/api/prevention/whitelist");
    const ips  = data.trusted_ips || [];
    if (!ips.length) {
      list.innerHTML = '<div class="empty-state">// No trusted IPs</div>';
      return;
    }
    list.innerHTML = "";
    ips.forEach(ip => {
      const item = document.createElement("div");
      item.className = "whitelist-item";
      item.innerHTML = `
        <span class="whitelist-ip">✅ ${ip}</span>
        <button class="btn btn-ghost btn-sm" onclick="removeWhitelist('${ip}')">Remove</button>
      `;
      list.appendChild(item);
    });
  } catch (e) { list.innerHTML = '<div class="empty-state">Failed to load</div>'; }
}

async function addWhitelist() {
  const input = document.getElementById("wl-ip-input");
  const ip    = (input?.value || "").trim();
  if (!ip) { toast("Enter an IP address", "error"); return; }
  try {
    const data = await apiFetch("/api/prevention/whitelist/add", {
      method: "POST",
      body:   JSON.stringify({ ip }),
    });
    toast(data.message || data.error, data.error ? "error" : "success");
    input.value = "";
    await loadWhitelist();
    await loadBlacklist();
  } catch (e) { toast(e.message, "error"); }
}

async function removeWhitelist(ip) {
  try {
    const data = await apiFetch("/api/prevention/whitelist/remove", {
      method: "POST",
      body:   JSON.stringify({ ip }),
    });
    toast(data.message || data.error, data.error ? "error" : "success");
    await loadWhitelist();
  } catch (e) { toast(e.message, "error"); }
}

// ─── Rate Limits ──────────────────────────────────────────────
async function loadRateLimits() {
  const tbody = document.getElementById("rl-tbody");
  if (!tbody) return;
  try {
    const data = await apiFetch("/api/prevention/ratelimit");
    const ips  = data.tracked_ips || [];
    if (!ips.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">// No active rate-limit tracking</td></tr>';
      return;
    }
    tbody.innerHTML = "";
    ips.forEach(row => {
      const pct     = Math.round((row.total / row.max) * 100);
      const fillCls = pct >= 100 ? "danger" : pct >= 70 ? "warn" : "";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="color:var(--accent);font-weight:700">${row.ip}</td>
        <td>${row.total} / ${row.max}</td>
        <td>${row.remaining}</td>
        <td>
          <span class="rl-bar"><span class="rl-bar-fill ${fillCls}" style="width:${pct}%"></span></span>
          ${pct}%
        </td>
        <td>${row.at_limit
          ? '<span style="color:var(--red);font-weight:700">⛔ YES</span>'
          : '<span style="color:var(--green)">✓ No</span>'}
        </td>
        <td>
          <button class="btn btn-ghost btn-sm" onclick="resetRateLimit('${row.ip}')">Reset</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) { tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Failed to load</td></tr>'; }
}

async function resetRateLimit(ip) {
  try {
    const data = await apiFetch("/api/prevention/ratelimit/reset", {
      method: "POST",
      body:   JSON.stringify({ ip }),
    });
    toast(data.message, "success");
    await loadRateLimits();
  } catch (e) { toast(e.message, "error"); }
}

async function resetAllRateLimits() {
  if (!confirm("Reset ALL rate limit counters?")) return;
  try {
    const data = await apiFetch("/api/prevention/ratelimit/reset", {
      method: "POST",
      body:   JSON.stringify({}),
    });
    toast(data.message, "info");
    await loadRateLimits();
  } catch (e) { toast(e.message, "error"); }
}

// ─── Simulate Auto-Block ──────────────────────────────────────
async function simulateBlock() {
  const ip    = (document.getElementById("sim-ip")?.value    || "").trim();
  const score = parseInt(document.getElementById("sim-score")?.value || 0);
  const raw   = (document.getElementById("sim-types")?.value || "").trim();
  const types = raw ? raw.split(",").map(s => s.trim()).filter(Boolean) : [];

  if (!ip) { toast("Enter an IP to simulate", "error"); return; }

  const resultEl = document.getElementById("sim-result");
  if (resultEl) resultEl.style.display = "none";

  try {
    const data = await apiFetch("/api/prevention/simulate", {
      method: "POST",
      body:   JSON.stringify({ ip, risk_score: score, threat_types: types }),
    });

    if (resultEl) {
      const isBlocked = data.action === "auto_blocked";
      const color     = isBlocked ? "var(--red)" : data.action === "no_action" ? "var(--green)" : "var(--text-dim)";
      resultEl.style.display = "block";
      resultEl.innerHTML = `
        <div style="color:${color};font-weight:700;margin-bottom:8px">
          Action: ${(data.action || "").toUpperCase().replace("_", " ")}
        </div>
        <div style="color:var(--text-dim);line-height:1.8">
          IP: <span style="color:var(--accent)">${data.ip || ip}</span><br>
          Score: <strong style="color:${color}">${score}</strong>
          &nbsp;/ Threshold: <strong>${data.threshold ?? "—"}</strong><br>
          ${data.reason ? `Reason: ${data.reason}<br>` : ""}
          ${isBlocked ? `<span style="color:var(--red)">✓ IP has been added to blacklist</span>` : ""}
        </div>
      `;
      if (isBlocked) {
        toast(`${ip} auto-blocked (score ${score})`, "error");
        await loadBlacklist();
        await loadStatus();
      } else {
        toast(`Score ${score} is below threshold — no action taken`, "info");
      }
    }
  } catch (e) { toast(e.message, "error"); }
}

// ─── Init Phase 2 ─────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Load prevention stats on first visit (default tab is stats)
  loadPrevStats();
  loadConfig();
});



/* ============================================================
   LIVE MONITORING MODE
   ============================================================ */

let _monitorRunning   = false;
let _monitorPollTimer = null;

async function toggleMonitor() {
  const btn      = document.getElementById("monitor-toggle-btn");
  const badge    = document.getElementById("monitor-badge");
  const statsBar = document.getElementById("monitor-stats-bar");
  const modeEl   = document.getElementById("monitor-mode-select");

  if (_monitorRunning) {
    // ── STOP ──────────────────────────────────────────────────
    await apiFetch("/api/live-monitoring/stop", { method: "POST" });
    _monitorRunning = false;
    clearInterval(_monitorPollTimer);
    _monitorPollTimer = null;

    btn.textContent       = "▶ Live Monitor";
    btn.style.borderColor = "rgba(0,229,255,0.3)";
    btn.style.color       = "";
    if (modeEl) modeEl.disabled = false;
    if (badge)    badge.style.display    = "none";
    if (statsBar) statsBar.style.display = "none";
    toast("Live monitoring stopped", "info");

  } else {
    // ── START ──────────────────────────────────────────────────
    const mode = modeEl ? modeEl.value : "simulate";
    if (modeEl) modeEl.disabled = true;

    const data = await apiFetch("/api/live-monitoring/start", {
      method: "POST",
      body: JSON.stringify({ interval: 4, mode: mode }),
    });

    if (data.error) {
      if (modeEl) modeEl.disabled = false;
      toast("Error: " + data.error, "error");
      return;
    }

    _monitorRunning = true;
    btn.textContent       = "⏹ Stop Monitor";
    btn.style.borderColor = "rgba(0,255,136,0.5)";
    btn.style.color       = "var(--green)";

    if (badge)    badge.style.display    = "flex";
    if (statsBar) statsBar.style.display = "block";

    const modeLabels = {
      simulate: "🎭 Simulate",
      self_tap: "🔭 Self-Tap",
      log_tail: "📄 Log-Tail",
    };
    toast("Live monitoring started — " + (modeLabels[mode] || mode), "success");

    _monitorPollTimer = setInterval(_monitorPoll, 5000);
    _monitorPoll();
  }
}

async function _monitorPoll() {
  try {
    const s = await apiFetch("/api/live-monitoring/status");

    const el = (id) => document.getElementById(id);
    if (el("mon-events"))  el("mon-events").textContent  = s.events_generated || 0;
    if (el("mon-threats")) el("mon-threats").textContent = s.threats_found    || 0;
    if (el("mon-blocked")) el("mon-blocked").textContent = s.auto_blocked     || 0;
    const modeLabels = { simulate:"🎭 Simulate", self_tap:"🔭 Self-Tap", log_tail:"📄 Log-Tail" };
    if (el("mon-mode")) el("mon-mode").textContent = modeLabels[s.mode] || s.mode || "—";

    // Thread died unexpectedly — sync UI
    if (!s.running && _monitorRunning) {
      _monitorRunning = false;
      clearInterval(_monitorPollTimer);
      const btn = el("monitor-toggle-btn");
      if (btn) { btn.textContent = "▶ Live Monitor"; btn.style.borderColor="rgba(0,229,255,0.3)"; btn.style.color=""; }
      const msel = el("monitor-mode-select");
      if (msel) msel.disabled = false;
      el("monitor-badge")?.style?.setProperty("display","none");
      el("monitor-stats-bar")?.style?.setProperty("display","none");
    }

    if (typeof loadStatus    === "function") loadStatus();
    if (typeof loadThreats   === "function") loadThreats();
    if (typeof loadBlacklist === "function") loadBlacklist();
  } catch(e) { /* silent */ }
}

// ── Real Traffic Feed (Self-Tap tab) ─────────────────────────
async function loadTapFeed() {
  try {
    const data  = await apiFetch("/api/live-monitoring/tap-feed");
    const tbody = document.getElementById("tap-tbody");
    const badge = document.getElementById("tap-enabled-badge");
    if (!tbody) return;

    if (badge) {
      badge.textContent   = data.enabled ? "TAP: ACTIVE 🟢" : "TAP: INACTIVE ⚫";
      badge.style.color   = data.enabled ? "var(--green)" : "var(--text-dim)";
      badge.style.borderColor = data.enabled ? "rgba(0,255,136,0.4)" : "var(--border)";
    }

    const rows = data.requests || [];
    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">// No requests captured yet — start Self-Tap mode and browse the dashboard</td></tr>';
      return;
    }
    const colors = { 200:"var(--green)", 304:"var(--text-dim)", 401:"var(--yellow)",
                     403:"var(--yellow)", 404:"var(--text-dim)", 500:"var(--red)" };
    tbody.innerHTML = rows.map(r => {
      const c = colors[r.status_code] || (r.status_code >= 400 ? "var(--red)" : "var(--text)");
      const t = (r.timestamp||"").replace("T"," ").substring(0,19);
      return `<tr style="cursor:pointer" onclick="openIPModal('${r.ip}')">
        <td style="font-size:.72rem;color:var(--text-dim)">${t}</td>
        <td style="color:var(--accent);font-family:var(--font-mono)">${r.ip}</td>
        <td><span class="tag">${r.method}</span></td>
        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.path}</td>
        <td style="color:${c};font-family:var(--font-mono)">${r.status_code}</td>
      </tr>`;
    }).join("");
  } catch(e) { console.warn("tap-feed:", e); }
}

// On page load: sync state if monitor was already running
(async function _syncOnLoad() {
  try {
    const s = await apiFetch("/api/live-monitoring/status");
    if (s.running) {
      _monitorRunning = true;
      const btn  = document.getElementById("monitor-toggle-btn");
      const msel = document.getElementById("monitor-mode-select");
      const badge = document.getElementById("monitor-badge");
      const bar   = document.getElementById("monitor-stats-bar");
      if (btn)  { btn.textContent="⏹ Stop Monitor"; btn.style.borderColor="rgba(0,255,136,0.5)"; btn.style.color="var(--green)"; }
      if (msel) { msel.value=s.mode||"simulate"; msel.disabled=true; }
      if (badge) badge.style.display = "flex";
      if (bar)   bar.style.display   = "block";
      _monitorPollTimer = setInterval(_monitorPoll, 5000);
    }
  } catch(e) { /* silent on startup */ }
})();


/* ── Magnetic Button Hover (sets --mx --my CSS vars for radial gradient) ─── */
(function _magneticHover() {
  document.querySelectorAll('.btn').forEach(function(btn) {
    btn.addEventListener('mousemove', function(e) {
      const r  = btn.getBoundingClientRect();
      const mx = ((e.clientX - r.left) / r.width  * 100).toFixed(1) + "%";
      const my = ((e.clientY - r.top)  / r.height * 100).toFixed(1) + "%";
      btn.style.setProperty('--mx', mx);
      btn.style.setProperty('--my', my);
    });
  });
  /* Re-run on any new content */
  const obs = new MutationObserver(function() {
    document.querySelectorAll('.btn:not([data-mag])').forEach(function(btn) {
      btn.setAttribute('data-mag','1');
      btn.addEventListener('mousemove', function(e) {
        const r  = btn.getBoundingClientRect();
        btn.style.setProperty('--mx', ((e.clientX-r.left)/r.width*100).toFixed(1)+"%");
        btn.style.setProperty('--my', ((e.clientY-r.top)/r.height*100).toFixed(1)+"%");
      });
    });
  });
  obs.observe(document.body, { childList: true, subtree: true });
})();