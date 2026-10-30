const fs = require("node:fs");
const path = require("node:path");

const DATA_DIR = path.resolve(__dirname, "../../../data/warninglists");

/** "10.0.0.0/8" → { cidr, start, end } as 32-bit values in BigInt. IPv4 only in Plan 1. */
function parseCidr(cidr) {
  const [ip, bitsRaw] = String(cidr).split("/");
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  const n = ipv4ToInt(ip);
  if (n === null || !(bits >= 0 && bits <= 32)) return null;
  const size = 1n << BigInt(32 - bits);
  const start = n - (n % size);
  return { cidr, start, end: start + size - 1n };
}

function ipv4ToInt(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = (n << 8n) + BigInt(p);
  }
  return n;
}

function ipInCidrs(ip, cidrs) {
  const n = ipv4ToInt(ip);
  if (n === null) return false;
  return cidrs.some((c) => n >= c.start && n <= c.end);
}

function readList(name) {
  const file = path.join(DATA_DIR, `${name}.json`);
  return JSON.parse(fs.readFileSync(file, "utf8")).items;
}

/** Vendored MISP warninglists (CC0). Refresh with `npm run update:warninglists`. */
function load() {
  return {
    parkingNs: new Set(readList("parking-domain-ns").map((s) => String(s).toLowerCase())),
    cdnCidrs: readList("cdn").map(parseCidr).filter(Boolean),
  };
}

/** @returns {{ parked: boolean, cdn: boolean }} */
function classifyInfra({ a = [], ns = [] }, lists) {
  const parked = ns.some((server) => {
    const host = String(server).toLowerCase();
    for (const parkingHost of lists.parkingNs) {
      if (host === parkingHost || host.endsWith(`.${parkingHost}`)) return true;
    }
    return false;
  });
  const cdn = a.some((ip) => ipInCidrs(ip, lists.cdnCidrs));
  return { parked, cdn };
}

module.exports = { load, classifyInfra, ipInCidrs, parseCidr, DATA_DIR };
