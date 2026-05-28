#!/usr/bin/env node
/**
 * One-shot ETL migrating legacy data into MongoDB collections.
 *
 * Reads from (whatever exists):
 *   - MSSQL Azure DB:  threatwatcherdb.dailyDomains, RegistredDomains
 *   - MySQL:           darkweb_leaks.sources + page indices
 *   - SQLite (Django): db.sqlite3 — auth_user
 *
 * Writes to:
 *   - threatwatcher.daily_domains
 *   - threatwatcher.registered_domains
 *   - threatwatcher.darkweb_sources
 *   - threatwatcher.darkweb_pages
 *   - threatwatcher.users
 *
 * Idempotent: uses upsert with stable natural keys (domainName + dateOfScan,
 * url, email). Run once during cutover; commit-then-delete this file.
 *
 * Required env (any subset can be omitted to skip that source):
 *   LEGACY_MSSQL_URI    e.g. mssql://user:pass@host/db
 *   LEGACY_MYSQL_URI    e.g. mysql://user:pass@host/darkweb_leaks
 *   LEGACY_SQLITE_PATH  absolute path to db.sqlite3
 *   MONGODB_URI         destination
 *
 * Usage:
 *   node scripts/migrate_to_mongo.js [--dry-run] [--batch=500]
 */
"use strict";

const path = require("node:path");
require("dotenv").config({ path: path.resolve(__dirname, "../.env") });

const mongoose = require("mongoose");

const DailyDomain = require("../src/models/dailyDomain");
const RegisteredDomain = require("../src/models/registeredDomain");
const DarkwebSource = require("../src/models/darkwebSource");
const DarkwebPage = require("../src/models/darkwebPage");
const User = require("../src/models/user");

const argv = require("node:util").parseArgs({
  options: {
    "dry-run": { type: "boolean", default: false },
    batch: { type: "string", default: "500" },
  },
}).values;

const BATCH = Number(argv.batch);
const DRY = argv["dry-run"];

function log(msg, extra = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), msg, ...extra }));
}

async function migrateMssql() {
  if (!process.env.LEGACY_MSSQL_URI) {
    log("skip:mssql", { reason: "LEGACY_MSSQL_URI not set" });
    return;
  }
  let sql;
  try {
    sql = require("mssql");
  } catch {
    log("skip:mssql", { reason: "install mssql to enable: npm i -D mssql" });
    return;
  }
  const pool = await sql.connect(process.env.LEGACY_MSSQL_URI);

  for (const [table, Model] of [
    ["dailyDomains", DailyDomain],
    ["RegistredDomains", RegisteredDomain],
  ]) {
    const result = await pool.request().query(`SELECT * FROM ${table}`);
    log("mssql:read", { table, rows: result.recordset.length });
    if (DRY) continue;
    const ops = result.recordset.map((row) => ({
      updateOne: {
        filter: { domainName: row.domainName, dateOfScan: row.dateOfScan },
        update: {
          $set: {
            domainName: row.domainName,
            mainDomain: row.MainDomain || row.mainDomain,
            similarity: Number(row.similarity) || 0,
            websimilarity: Number(row.websimilarity) || 0,
            webserver: !!row.webserver,
            substring: !!row.substring,
            xn: !!row.xn,
            links: Number(row.links) || 0,
            dateOfScan: new Date(row.dateOfScan),
          },
        },
        upsert: true,
      },
    }));
    for (let i = 0; i < ops.length; i += BATCH) {
      await Model.bulkWrite(ops.slice(i, i + BATCH), { ordered: false });
    }
    log("mongo:wrote", { collection: Model.collection.name, count: ops.length });
  }
  await pool.close();
}

async function migrateMysql() {
  if (!process.env.LEGACY_MYSQL_URI) {
    log("skip:mysql", { reason: "LEGACY_MYSQL_URI not set" });
    return;
  }
  let mysql;
  try {
    mysql = require("mysql2/promise");
  } catch {
    log("skip:mysql", { reason: "install mysql2 to enable: npm i -D mysql2" });
    return;
  }
  const conn = await mysql.createConnection(process.env.LEGACY_MYSQL_URI);
  const [sources] = await conn.query("SELECT * FROM sources");
  log("mysql:read", { table: "sources", rows: sources.length });

  if (!DRY && sources.length) {
    const ops = sources.map((row) => ({
      updateOne: {
        filter: { url: row.url },
        update: {
          $set: {
            url: row.url,
            kind: row.kind || "onion",
            title: row.title || "",
            enabled: row.enabled !== 0,
          },
        },
        upsert: true,
      },
    }));
    await DarkwebSource.bulkWrite(ops, { ordered: false });
    log("mongo:wrote", { collection: "darkweb_sources", count: ops.length });
  }

  // Many legacy installs vary in page-table naming; iterate any table whose name starts with "pages".
  const [tables] = await conn.query("SHOW TABLES");
  const pageTables = tables
    .map((row) => Object.values(row)[0])
    .filter((name) => /pages?$/i.test(name) || /content/i.test(name));
  for (const tbl of pageTables) {
    const [rows] = await conn.query(`SELECT * FROM \`${tbl}\``);
    log("mysql:read", { table: tbl, rows: rows.length });
    if (DRY || !rows.length) continue;
    const ops = rows.map((row) => ({
      updateOne: {
        filter: {
          sourceUrl: row.source_url || row.sourceUrl,
          pageUrl: row.page_url || row.pageUrl || row.url,
        },
        update: {
          $set: {
            sourceUrl: row.source_url || row.sourceUrl,
            pageUrl: row.page_url || row.pageUrl || row.url,
            title: row.title || "",
            body: row.body || row.content || "",
            crawledAt: row.crawled_at || row.crawledAt || new Date(),
          },
        },
        upsert: true,
      },
    }));
    for (let i = 0; i < ops.length; i += BATCH) {
      await DarkwebPage.bulkWrite(ops.slice(i, i + BATCH), { ordered: false });
    }
    log("mongo:wrote", { collection: "darkweb_pages", count: ops.length });
  }
  await conn.end();
}

async function migrateSqlite() {
  if (!process.env.LEGACY_SQLITE_PATH) {
    log("skip:sqlite", { reason: "LEGACY_SQLITE_PATH not set" });
    return;
  }
  let Database;
  try {
    Database = require("better-sqlite3");
  } catch {
    log("skip:sqlite", { reason: "install better-sqlite3 to enable: npm i -D better-sqlite3" });
    return;
  }
  const db = new Database(process.env.LEGACY_SQLITE_PATH, { readonly: true });
  const rows = db.prepare("SELECT email, password, first_name, last_name FROM auth_user").all();
  log("sqlite:read", { table: "auth_user", rows: rows.length });
  if (!DRY && rows.length) {
    const ops = rows.map((row) => ({
      updateOne: {
        filter: { email: row.email.toLowerCase() },
        update: {
          $set: {
            email: row.email.toLowerCase(),
            passwordHash: row.password,
            displayName: [row.first_name, row.last_name].filter(Boolean).join(" "),
            role: "analyst",
          },
        },
        upsert: true,
      },
    }));
    await User.bulkWrite(ops, { ordered: false });
    log("mongo:wrote", { collection: "users", count: ops.length });
  }
  db.close();
}

async function main() {
  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI required");
  await mongoose.connect(process.env.MONGODB_URI);
  log("start", { dryRun: DRY, batch: BATCH });
  try {
    await migrateMssql();
    await migrateMysql();
    await migrateSqlite();
  } finally {
    await mongoose.disconnect();
  }
  log("done");
}

main().catch((err) => {
  console.error("migration failed:", err);
  process.exit(1);
});
