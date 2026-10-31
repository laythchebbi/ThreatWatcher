/* Threat Watcher client script: theme toggle and the row actions that avoid a full form post.
   The theme itself is applied by an inline script in <head>, before first paint. */
(function () {
  const TW = (window.TW = window.TW || {});
  const root = document.documentElement;

  function syncToggle() {
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    document.querySelectorAll("[data-theme-toggle]").forEach(function (b) {
      b.setAttribute("aria-label", "Switch to " + next + " theme");
    });
  }

  TW.toggleTheme = function () {
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    try {
      localStorage.setItem("tw-theme", next);
    } catch (e) {
      /* private mode: the choice lasts for this page only */
    }
    syncToggle();
  };

  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-theme-toggle]")) TW.toggleTheme();
  });
  syncToggle();

  function post(url) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { accept: "application/json" },
    }).then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }
  TW.mentionAction = function (domainId, mentionId, action) {
    return post("/domains/" + domainId + "/mentions/" + mentionId + "/" + action);
  };
  TW.sightingAction = function (domainId, sightingId, action) {
    return post("/domains/" + domainId + "/sightings/" + sightingId + "/" + action);
  };
})();
