require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { withDb } = require("./helpers/db");
const { termSchema, tooCommon } = require("../src/schemas/terms");

test("terms schema trims, lowercases and bounds length", () => {
  assert.equal(termSchema.parse("  ACME Corp "), "acme corp");
  assert.equal(termSchema.safeParse("abc").success, false, "3 chars rejected");
  assert.equal(termSchema.safeParse("x".repeat(41)).success, false, "41 chars rejected");
  assert.equal(termSchema.safeParse("acme").success, true);
});

test("tooCommon rejects a term matching more than 5% of crawled pages", async (t) => {
  const { DarkwebPage } = await withDb(t);
  const rows = [];
  for (let i = 0; i < 40; i++)
    rows.push({
      sourceUrl: "http://s.onion",
      pageUrl: `http://s.onion/${i}`,
      title: `page ${i}`,
      body: i < 3 ? "fresh dump of acme-corp creds" : "nothing to see",
      crawledAt: new Date(),
    });
  await DarkwebPage.insertMany(rows);
  assert.equal(await tooCommon("acme-corp", { DarkwebPage }), true, "3 of 40 = 7.5%");
  assert.equal(await tooCommon("zebra-bank", { DarkwebPage }), false);
});
