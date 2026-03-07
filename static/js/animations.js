/* ============================================================
   ipwnedyou — animations.js  |  Phase 4: UI Enhancement
   Full animation engine — runs independently of dashboard logic
   ============================================================ */

// ─── 1. Multi-dot Cursor Trail ────────────────────────────────
(function initCursorTrail() {
  const TRAIL_COUNT = 8;
  const dots = [];
  let mx = window.innerWidth / 2;
  let my = window.innerHeight / 2;

  for (let i = 0; i < TRAIL_COUNT; i++) {
    const d = document.createElement("div");
    d.className = "cursor-trail-dot";
    d.style.cssText = `
      position:fixed; border-radius:50%; pointer-events:none; z-index:9990;
      transform:translate(-50%,-50%);
      transition: opacity .3s;
    `;
    document.body.appendChild(d);
    dots.push({ el: d, x: mx, y: my });
  }

  document.addEventListener("mousemove", e => { mx = e.clientX; my = e.clientY; });

  function animateTrail() {
    let px = mx, py = my;
    dots.forEach((dot, i) => {
      const delay = 1 - i / TRAIL_COUNT;
      dot.x += (px - dot.x) * (0.25 - i * 0.02);
      dot.y += (py - dot.y) * (0.25 - i * 0.02);
      const size = Math.max(2, 9 - i * 1.1);
      const alpha = delay * 0.55;
      dot.el.style.left    = dot.x + "px";
      dot.el.style.top     = dot.y + "px";
      dot.el.style.width   = size + "px";
      dot.el.style.height  = size + "px";
      dot.el.style.background = `rgba(0,229,255,${alpha})`;
      dot.el.style.boxShadow  = `0 0 ${size * 1.5}px rgba(0,229,255,${alpha * 0.6})`;
      px = dot.x; py = dot.y;
    });
    requestAnimationFrame(animateTrail);
  }
  animateTrail();
})();


// ─── 2. Particle Network Background ──────────────────────────
(function initParticleNetwork() {
  const canvas = document.getElementById("particle-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const PARTICLE_COUNT = 55;
  const MAX_DIST       = 140;
  const SPEED          = 0.35;

  let W, H, particles = [];

  function resize() {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener("resize", () => { resize(); spawnParticles(); });

  function randBetween(a, b) { return a + Math.random() * (b - a); }

  function spawnParticles() {
    particles = Array.from({ length: PARTICLE_COUNT }, () => ({
      x:  Math.random() * W,
      y:  Math.random() * H,
      vx: randBetween(-SPEED, SPEED),
      vy: randBetween(-SPEED, SPEED),
      r:  randBetween(1.2, 2.8),
    }));
  }
  spawnParticles();

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Update positions
    particles.forEach(p => {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;
    });

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx   = particles[i].x - particles[j].x;
        const dy   = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < MAX_DIST) {
          const alpha = (1 - dist / MAX_DIST) * 0.18;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(0,229,255,${alpha})`;
          ctx.lineWidth   = 0.8;
          ctx.stroke();
        }
      }
    }

    // Draw dots
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle   = "rgba(0,229,255,0.55)";
      ctx.shadowColor = "rgba(0,229,255,0.4)";
      ctx.shadowBlur  = 6;
      ctx.fill();
      ctx.shadowBlur  = 0;
    });

    requestAnimationFrame(draw);
  }
  draw();
})();


// ─── 3. Glitch Text Effect ────────────────────────────────────
(function initGlitch() {
  const logo = document.querySelector(".logo");
  if (!logo) return;

  const originalHTML = logo.innerHTML;

  function glitch() {
    const chars = "!@#$%^&*<>?/\\|█▓▒░";
    const text   = "ipwnedyou";
    let   iter   = 0;
    const maxIter = 14;

    const iv = setInterval(() => {
      const scrambled = text.split("").map((ch, i) => {
        if (i < iter) return ch;
        return chars[Math.floor(Math.random() * chars.length)];
      }).join("");

      logo.innerHTML = `${scrambled} <span style="color:var(--text-dim);font-size:.7rem;letter-spacing:1px">// AI THREAT SYSTEM</span>`;

      if (++iter >= maxIter) {
        clearInterval(iv);
        logo.innerHTML = originalHTML;
      }
    }, 55);
  }

  // Glitch on load
  setTimeout(glitch, 800);

  // Glitch on hover
  let hoverTimer = null;
  logo.addEventListener("mouseenter", () => {
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(glitch, 80);
  });
})();


// ─── 4. Button Ripple Effect ──────────────────────────────────
(function initRipple() {
  function addRipple(e) {
    const btn  = e.currentTarget;
    const rect = btn.getBoundingClientRect();
    const size = Math.max(btn.offsetWidth, btn.offsetHeight) * 2;
    const x    = e.clientX - rect.left - size / 2;
    const y    = e.clientY - rect.top  - size / 2;

    const ripple = document.createElement("span");
    ripple.className = "btn-ripple";
    ripple.style.cssText = `
      position:absolute;
      width:${size}px; height:${size}px;
      left:${x}px; top:${y}px;
      border-radius:50%;
      background:rgba(255,255,255,0.18);
      transform:scale(0);
      animation:ripple-anim .55s ease-out forwards;
      pointer-events:none;
    `;
    btn.appendChild(ripple);
    setTimeout(() => ripple.remove(), 600);
  }

  // Attach to all current and future buttons via delegation
  document.addEventListener("click", e => {
    const btn = e.target.closest(".btn");
    if (btn) addRipple({ currentTarget: btn, clientX: e.clientX, clientY: e.clientY });
  });
})();


// ─── 5. CRT Scan Line ─────────────────────────────────────────
(function initScanLine() {
  const line = document.createElement("div");
  line.id = "scan-line";
  line.style.cssText = `
    position:fixed; left:0; width:100%; height:2px;
    background:linear-gradient(to right,
      transparent 0%, rgba(0,229,255,0.06) 20%,
      rgba(0,229,255,0.18) 50%,
      rgba(0,229,255,0.06) 80%, transparent 100%);
    pointer-events:none; z-index:9997;
    top:0;
  `;
  document.body.appendChild(line);

  let y = 0;
  let dir = 1;
  const H = window.innerHeight;

  function animateLine() {
    y += dir * 1.4;
    if (y > H) { y = 0; }
    line.style.top = y + "px";
    requestAnimationFrame(animateLine);
  }
  animateLine();
})();


// ─── 6. Card Entrance Animations (IntersectionObserver) ───────
(function initEntranceAnimations() {
  if (!("IntersectionObserver" in window)) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add("panel-visible");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.08, rootMargin: "0px 0px -40px 0px" });

  // Observe all panels and stat cards
  document.querySelectorAll(".panel, .stat-card, .mini-stat").forEach(el => {
    el.classList.add("panel-hidden");
    observer.observe(el);
  });

  // Re-observe dynamically added panels
  const mo = new MutationObserver(muts => {
    muts.forEach(m => m.addedNodes.forEach(node => {
      if (node.nodeType === 1) {
        node.querySelectorAll?.(".panel,.stat-card,.mini-stat").forEach(el => {
          if (!el.classList.contains("panel-visible")) {
            el.classList.add("panel-hidden");
            observer.observe(el);
          }
        });
      }
    }));
  });
  mo.observe(document.body, { childList: true, subtree: true });
})();


// ─── 7. Typewriter for Status Messages ────────────────────────
function typewrite(el, text, speed = 38) {
  if (!el) return;
  el.textContent = "";
  let i = 0;
  function tick() {
    if (i >= text.length) return;
    el.textContent += text[i++];
    setTimeout(tick, speed + Math.random() * 20);
  }
  tick();
}

// Expose globally for other scripts
window.typewrite = typewrite;


// ─── 8. Neon Pulse Rings on Threat Badges ─────────────────────
(function initNeonRings() {
  function addRings(badge) {
    if (badge.dataset.ringed) return;
    badge.dataset.ringed = "1";
    badge.style.position = "relative";

    for (let i = 0; i < 2; i++) {
      const ring = document.createElement("span");
      ring.className = "neon-ring";
      ring.style.animationDelay = `${i * 0.6}s`;
      badge.appendChild(ring);
    }
  }

  // Observe threat feed for new items
  const mo = new MutationObserver(() => {
    document.querySelectorAll(".threat-badge.danger:not([data-ringed])").forEach(addRings);
  });
  mo.observe(document.getElementById("threat-feed") || document.body,
    { childList: true, subtree: true });
})();


// ─── 9. Theme Intensity Slider ────────────────────────────────
(function initThemeSlider() {
  const slider = document.getElementById("theme-intensity");
  if (!slider) return;

  function applyIntensity(val) {
    const v = parseInt(val);
    const root = document.documentElement;
    // Scale glow and opacity effects with slider
    root.style.setProperty("--glow-accent",
      `0 0 ${10 + v * 0.16}px rgba(0,229,255,${0.2 + v * 0.003})`);
    root.style.setProperty("--glow-red",
      `0 0 ${10 + v * 0.16}px rgba(255,51,51,${0.2 + v * 0.003})`);

    // Particle canvas opacity
    const pc = document.getElementById("particle-canvas");
    if (pc) pc.style.opacity = (0.02 + v * 0.0005).toFixed(3);

    // Matrix canvas opacity
    const mc = document.getElementById("matrix-canvas");
    if (mc) mc.style.opacity = (0.01 + v * 0.0003).toFixed(3);

    // Scan line intensity
    const sl = document.getElementById("scan-line");
    if (sl) sl.style.opacity = (v / 200).toFixed(3);

    localStorage.setItem("ipwnedyou_intensity", v);
  }

  slider.addEventListener("input", e => applyIntensity(e.target.value));

  // Restore saved value
  const saved = localStorage.getItem("ipwnedyou_intensity");
  if (saved) {
    slider.value = saved;
    applyIntensity(saved);
  } else {
    applyIntensity(slider.value);
  }
})();


// ─── 10. Skeleton Loader Helper ───────────────────────────────
function showSkeleton(containerId, rows = 4) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = Array.from({ length: rows }, (_, i) =>
    `<div class="skeleton-row" style="width:${70 + Math.random() * 28}%;
      animation-delay:${i * 0.1}s"></div>`
  ).join("");
}

window.showSkeleton = showSkeleton;


// ─── 11. Animated Number Counter (improved easing) ────────────
// Override the global animateCounter with a better version
window.animateCounter = function(el, target, duration = 700) {
  if (!el) return;
  const start     = parseInt(el.textContent.replace(/\D/g, "")) || 0;
  const startTime = performance.now();

  function easeOutExpo(t) {
    return t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
  }

  function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const value    = Math.round(start + (target - start) * easeOutExpo(progress));
    el.textContent = value.toLocaleString();
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
};


// ─── 12. Hover Glow on Stat Cards ────────────────────────────
(function initCardHoverGlow() {
  document.addEventListener("mousemove", e => {
    document.querySelectorAll(".stat-card, .panel").forEach(card => {
      const rect  = card.getBoundingClientRect();
      const cx    = rect.left + rect.width  / 2;
      const cy    = rect.top  + rect.height / 2;
      const dx    = e.clientX - cx;
      const dy    = e.clientY - cy;
      const dist  = Math.sqrt(dx * dx + dy * dy);
      const range = 240;

      if (dist < range) {
        const intensity = (1 - dist / range) * 0.12;
        card.style.setProperty("--hover-glow", intensity.toFixed(3));
      } else {
        card.style.setProperty("--hover-glow", "0");
      }
    });
  });
})();


// ─── 13. Terminal Boot Sequence ───────────────────────────────
(function initBootSequence() {
  const msgs = [
    "INITIALIZING THREAT ENGINE…",
    "LOADING ANOMALY MODEL…",
    "CONNECTING TO STREAM…",
    "SYSTEM READY.",
  ];

  let existing = document.getElementById("boot-terminal");
  if (!existing) return;

  let i = 0;
  function nextMsg() {
    if (i >= msgs.length) {
      setTimeout(() => {
        existing.style.opacity = "0";
        existing.style.transition = "opacity .8s";
        setTimeout(() => existing.remove(), 900);
      }, 600);
      return;
    }
    const line = document.createElement("div");
    line.className = "boot-line";
    existing.appendChild(line);
    typewrite(line, "> " + msgs[i++], 32);
    setTimeout(nextMsg, msgs[i - 1].length * 34 + 300);
  }
  nextMsg();
})();


// ─── 14. Keyboard Shortcut Help ───────────────────────────────
(function initKeyboardShortcuts() {
  document.addEventListener("keydown", e => {
    // Ignore when typing in inputs
    if (["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) return;

    switch (e.key) {
      case "r":
      case "R":
        // Refresh dashboard data
        if (typeof loadStatus    === "function") loadStatus();
        if (typeof loadThreats   === "function") loadThreats();
        if (typeof loadBlacklist === "function") loadBlacklist();
        if (typeof toast === "function") toast("Dashboard refreshed", "info");
        break;
      case "Escape":
        // Close modals
        if (typeof closeIPModal === "function") closeIPModal();
        document.getElementById("danger-alert-overlay")?.classList.remove("show");
        break;
      case "?":
        showKeyboardHelp();
        break;
    }
  });

  function showKeyboardHelp() {
    const existing = document.getElementById("kb-help");
    if (existing) { existing.remove(); return; }

    const help = document.createElement("div");
    help.id = "kb-help";
    help.className = "kb-help-panel";
    help.innerHTML = `
      <div class="panel-title" style="margin-bottom:14px">⌨ Keyboard Shortcuts</div>
      <div class="kb-row"><kbd>R</kbd> <span>Refresh all panels</span></div>
      <div class="kb-row"><kbd>Esc</kbd> <span>Close modals / alerts</span></div>
      <div class="kb-row"><kbd>?</kbd> <span>Toggle this help</span></div>
      <div style="margin-top:14px">
        <button class="btn btn-ghost btn-sm" onclick="document.getElementById('kb-help').remove()">Close</button>
      </div>
    `;
    document.body.appendChild(help);
  }
})();