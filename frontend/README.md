# Threat Watcher — frontend

Express + EJS app that serves the user-facing UI. The visual design follows the bundle from Claude Design (token-based dark theme, IBM Plex typography, custom `.tw-*` component classes).

## Run

```
cp .env.example .env       # adjust PORT / BACKEND_URL if needed
npm install
npm start                  # → http://localhost:4000
```

`/` redirects to `/geolocation`. The `Geo activity` page renders a procedural world map, live event feed, top countries, ASN table, targeted assets, and a 24h trend chart.

## Layout

```
src/
  server.js              Express entry. Mounts express-ejs-layouts and /static.
  nav.js                 Sidebar nav data + icon SVG library (server-side).
  views/
    layout.ejs           Shared shell: <head>, sidebar partial, topbar partial, body slot.
    geolocation.ejs      Page body for /geolocation. Inline <style> + <script> blocks
                         are auto-extracted into the layout's <head> / pre-</body>.
    partials/
      sidebar.ejs        Iterates nav.js array; highlights active item.
      topbar.ejs         Breadcrumbs + search + scan + theme-toggle.
  public/
    css/styles.css       Tokens + component styles (copied verbatim from the design).
    js/app.js            TW.* runtime (theme, gauges, sparklines, diff, toasts).
```

## Adding a screen

1. Drop a new view at `src/views/<name>.ejs` containing only the page body
   (anything that lived inside `<div id="tw-page-content">` in the design HTML).
   You can leave `<style>…</style>` and `<script>…</script>` blocks inline —
   they're auto-extracted.
2. Add a route to `server.js`:
   ```js
   app.get("/<path>", (_req, res) =>
     res.render("<name>", { title: "…", active: "<nav-id>", crumbs: ["…", "…"] })
   );
   ```
3. If the screen needs a sidebar entry, add it to `NAV` in `nav.js` and pick an icon from `ICONS`.

## Theming

`<html>` carries `data-theme="dark"` by default. The topbar's theme toggle calls
`TW.toggleTheme()` which persists to `localStorage` and applies on next load.
Density (`data-density`) and accent hue can be swapped at runtime via
`TW.setDensity('compact'|'mid'|'comfortable')` and `TW.setAccent(<hueDeg>)`.
