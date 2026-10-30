/** Sidebar entries. `soon` marks pages that arrive in Plans 2 and 3. */
const NAV = [
  { section: "Watch" },
  { id: "dashboard", label: "Dashboard", href: "/" },
  { id: "domains", label: "Domains", href: "/domains" },
  { id: "darkweb", label: "Dark web", href: "/dark-web", soon: "Plan 2" },
  { section: "Account" },
  { id: "alerts", label: "Alerts", href: "/alerts", soon: "Plan 3" },
  { id: "settings", label: "Settings", href: "/settings", soon: "Plan 3" },
];

module.exports = { NAV };
