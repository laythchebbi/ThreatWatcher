// Refresh the vendored MISP warninglists (CC0): parking nameservers and CDN ranges.
const fs = require("node:fs");
const path = require("node:path");

const BASE = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists";
const OUT = path.resolve(__dirname, "../data/warninglists");
const SOURCES = {
  "parking-domain-ns": ["parking-domain-ns"],
  cdn: ["cloudflare", "fastly", "akamai"],
};

async function fetchList(name) {
  const res = await fetch(`${BASE}/${name}/list.json`, { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`${name}: ${res.status}`);
  const body = /** @type {{ list: string[], version?: number }} */ (await res.json());
  return body.list;
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  for (const [file, lists] of Object.entries(SOURCES)) {
    const items = [];
    for (const name of lists) items.push(...(await fetchList(name)));
    const json = {
      source: lists.map((l) => `${BASE}/${l}/list.json`),
      updated: new Date().toISOString().slice(0, 10),
      items: [...new Set(items)],
    };
    fs.writeFileSync(path.join(OUT, `${file}.json`), JSON.stringify(json, null, 1) + "\n");
    console.log(`${file}.json: ${json.items.length} entries`);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
