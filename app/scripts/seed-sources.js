// Upsert data/darkweb-sources.json into darkweb_sources. Rows: { url, kind?, title?, enabled? }.
const fs = require("node:fs");
const path = require("node:path");
const db = require("../src/db");
const { DarkwebSource } = require("../src/models");

async function main() {
  const file = path.resolve(__dirname, "../data/darkweb-sources.json");
  const rows = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!Array.isArray(rows)) throw new Error("darkweb-sources.json must be a JSON array");
  await db.connect();
  let n = 0;
  for (const row of rows) {
    if (!row.url) continue;
    await DarkwebSource.updateOne(
      { url: row.url },
      {
        $set: { kind: row.kind || "onion", title: row.title || "", enabled: row.enabled !== false },
      },
      { upsert: true }
    );
    n += 1;
  }
  console.log(`seeded ${n} source(s) from ${path.relative(process.cwd(), file)}`);
  await db.disconnect();
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
