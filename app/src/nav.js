/** Sidebar entries. `soon` marks pages not built yet. */
const NAV = [
  { section: "Watch" },
  { id: "dashboard", label: "Dashboard", href: "/" },
  { id: "domains", label: "Domains", href: "/domains" },
  { id: "darkweb", label: "Dark web", href: "/dark-web" },
  { section: "Account" },
  { id: "alerts", label: "Alerts", href: "/alerts", soon: "Soon" },
  { id: "settings", label: "Settings", href: "/settings", soon: "Soon" },
];

module.exports = { NAV };
