/* Threat Watcher — shared interactivity helpers
   Vanilla JS only. Drop-in safe (no globals besides TW).         */

(function () {
  const TW = (window.TW = window.TW || {});

  /* ---------- Theme + density ---------- */
  TW.applyPrefs = function () {
    const t = localStorage.getItem("tw-theme") || "dark";
    const d = localStorage.getItem("tw-density") || "mid";
    const a = localStorage.getItem("tw-accent") || "240";
    document.documentElement.setAttribute("data-theme", t);
    document.documentElement.setAttribute("data-density", d);
    // Override accent hue
    document.documentElement.style.setProperty(
      "--tw-accent",
      `oklch(0.68 0.14 ${a})`
    );
    document.documentElement.style.setProperty(
      "--tw-accent-soft",
      `oklch(0.68 0.14 ${a} / 0.14)`
    );
    document.documentElement.style.setProperty(
      "--tw-accent-line",
      `oklch(0.68 0.14 ${a} / 0.40)`
    );
  };

  TW.toggleTheme = function () {
    const cur = localStorage.getItem("tw-theme") || "dark";
    localStorage.setItem("tw-theme", cur === "dark" ? "light" : "dark");
    TW.applyPrefs();
  };

  TW.setDensity = function (d) {
    localStorage.setItem("tw-density", d);
    TW.applyPrefs();
  };

  TW.setAccent = function (h) {
    localStorage.setItem("tw-accent", h);
    TW.applyPrefs();
  };

  /* ---------- Score colour helper ---------- */
  TW.scoreClass = function (score) {
    if (score >= 0.8) return "crit";
    if (score >= 0.5) return "warn";
    if (score >= 0.25) return "info";
    return "safe";
  };

  TW.scoreLabel = function (score) {
    if (score >= 0.8) return "Critical";
    if (score >= 0.5) return "Suspicious";
    if (score >= 0.25) return "Watching";
    return "Benign";
  };

  /* ---------- Gauge renderer ---------- */
  TW.renderGauge = function (el, opts) {
    const score = opts.score ?? 0;
    const conf = opts.confidence ?? 0.9;
    const label = opts.label || "SecureScore";
    const size = el.classList.contains("tw-gauge-xl")
      ? 144
      : el.classList.contains("tw-gauge-sm")
      ? 56
      : 96;
    const stroke = size >= 144 ? 8 : size >= 96 ? 6 : 4;
    const r = size / 2 - stroke;
    const c = 2 * Math.PI * r;
    const fillOff = c * (1 - score);
    const confR = r - stroke - 2;
    const confC = 2 * Math.PI * confR;
    const confOff = confC * (1 - conf);
    const cls = TW.scoreClass(score);
    el.classList.remove("crit", "warn", "safe", "info");
    el.classList.add(cls);
    el.innerHTML = `
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        <circle class="gauge-track" cx="${size / 2}" cy="${size / 2}" r="${r}"
          fill="none" stroke-width="${stroke}"/>
        <circle class="gauge-fill" cx="${size / 2}" cy="${size / 2}" r="${r}"
          fill="none" stroke-width="${stroke}" stroke-linecap="round"
          stroke-dasharray="${c}" stroke-dashoffset="${fillOff}"/>
        ${
          confR > 6
            ? `<circle class="gauge-conf" cx="${size / 2}" cy="${
                size / 2
              }" r="${confR}" fill="none" stroke-width="1.5"
            stroke-dasharray="${confC}" stroke-dashoffset="${confOff}"/>`
            : ""
        }
      </svg>
      <div class="gauge-num">
        <div>
          <div class="v tw-num">${score.toFixed(2)}</div>
          <div class="l">${label}</div>
        </div>
      </div>`;
  };

  TW.renderAllGauges = function () {
    document.querySelectorAll("[data-gauge]").forEach((el) => {
      TW.renderGauge(el, {
        score: parseFloat(el.dataset.score),
        confidence: parseFloat(el.dataset.confidence || "0.9"),
        label: el.dataset.label || "SecureScore",
      });
    });
  };

  /* ---------- Sparkline ---------- */
  TW.renderSpark = function (el, values) {
    const w = 80,
      h = 24,
      pad = 2;
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min || 1;
    const step = (w - pad * 2) / (values.length - 1);
    const pts = values.map((v, i) => {
      const x = pad + i * step;
      const y = h - pad - ((v - min) / span) * (h - pad * 2);
      return [x, y];
    });
    const line = pts.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x},${y}`).join(" ");
    const area = `${line} L${pts[pts.length - 1][0]},${h} L${pts[0][0]},${h} Z`;
    el.innerHTML = `
      <svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}">
        <path class="area" d="${area}"/>
        <path d="${line}"/>
      </svg>`;
  };

  TW.renderAllSparks = function () {
    document.querySelectorAll("[data-spark]").forEach((el) => {
      const vals = el.dataset.spark.split(",").map(Number);
      TW.renderSpark(el, vals);
    });
  };

  /* ---------- Domain diff ---------- */
  // Render an inline diff of `target` vs the protected `base` domain.
  // Strategy: align labels, mark equal segments .same, wrong chars .swap, extra .add.
  TW.diffDomain = function (target, base) {
    if (target.startsWith("xn--")) {
      return `<span class="tw-diff"><span class="punycode">${target}</span></span>`;
    }
    // simple LCS-ish run highlight, char level
    const a = base;
    const b = target;
    let i = 0,
      j = 0;
    let out = "";
    while (i < a.length && j < b.length) {
      if (a[i] === b[j]) {
        out += `<span class="same">${b[j]}</span>`;
        i++;
        j++;
      } else {
        // peek ahead in b to find next match in a[i]
        const next = b.indexOf(a[i], j + 1);
        if (next > j && next - j < 4) {
          out += `<span class="add">${b.slice(j, next)}</span>`;
          j = next;
        } else {
          out += `<span class="swap">${b[j]}</span>`;
          j++;
          i++;
        }
      }
    }
    if (j < b.length) {
      out += `<span class="add">${b.slice(j)}</span>`;
    }
    return `<span class="tw-diff">${out}</span>`;
  };

  TW.renderAllDiffs = function () {
    document.querySelectorAll("[data-diff]").forEach((el) => {
      const base = el.dataset.diffBase;
      el.innerHTML = TW.diffDomain(el.textContent.trim(), base);
    });
  };

  /* ---------- Toast ---------- */
  TW.toast = function (msg, kind) {
    const el = document.createElement("div");
    el.className = "tw-toast";
    el.innerHTML = `<span class="tw-sev tw-sev-${kind || "info"}"></span><span>${msg}</span>`;
    document.body.appendChild(el);
    setTimeout(() => {
      el.style.transition = "opacity 200ms";
      el.style.opacity = "0";
      setTimeout(() => el.remove(), 200);
    }, 2200);
  };

  /* ---------- Tabs ---------- */
  TW.bindTabs = function () {
    document.querySelectorAll("[data-tabs]").forEach((group) => {
      const tabs = group.querySelectorAll(".tw-tab");
      tabs.forEach((t) => {
        t.addEventListener("click", () => {
          tabs.forEach((x) => x.classList.remove("active"));
          t.classList.add("active");
          const target = t.dataset.target;
          if (!target) return;
          group.parentElement.querySelectorAll("[data-tab-panel]").forEach((p) => {
            p.style.display = p.dataset.tabPanel === target ? "" : "none";
          });
        });
      });
    });
  };

  /* ---------- Switch ---------- */
  TW.bindSwitches = function () {
    document.querySelectorAll(".tw-switch").forEach((s) => {
      s.addEventListener("click", () => s.classList.toggle("on"));
    });
  };

  /* ---------- Init ---------- */
  TW.init = function () {
    TW.applyPrefs();
    document.addEventListener("DOMContentLoaded", () => {
      TW.renderAllGauges();
      TW.renderAllSparks();
      TW.renderAllDiffs();
      TW.bindTabs();
      TW.bindSwitches();
    });
  };
  TW.init();
})();
