/* Threat Watcher — theme / density / accent preferences. Vanilla JS, exposes window.TW. */
(function () {
  const TW = (window.TW = window.TW || {});

  TW.applyPrefs = function () {
    const t = localStorage.getItem("tw-theme") || "dark";
    const d = localStorage.getItem("tw-density") || "mid";
    const a = localStorage.getItem("tw-accent") || "240";
    const root = document.documentElement;
    root.setAttribute("data-theme", t);
    root.setAttribute("data-density", d);
    root.style.setProperty("--tw-accent", `oklch(0.68 0.14 ${a})`);
    root.style.setProperty("--tw-accent-soft", `oklch(0.68 0.14 ${a} / 0.14)`);
    root.style.setProperty("--tw-accent-line", `oklch(0.68 0.14 ${a} / 0.40)`);
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

  TW.applyPrefs();
})();
