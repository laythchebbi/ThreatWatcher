require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { checkPosture, postureEvents } = require("../src/services/watch/posture");

// resolveTxt returns string[][] like node:dns
function resolverFrom(table) {
  return {
    resolveTxt: async (name) => {
      if (name in table) return table[name].map((s) => [s]);
      const err = new Error("ENODATA");
      err.code = "ENODATA";
      throw err;
    },
  };
}

test("grade A: strict SPF, DMARC reject with rua, DKIM found", async () => {
  const resolver = resolverFrom({
    "acme-corp.com": ["v=spf1 include:_spf.google.com include:sendgrid.net -all"],
    "_dmarc.acme-corp.com": ["v=DMARC1; p=reject; rua=mailto:dmarc@acme-corp.com"],
    "google._domainkey.acme-corp.com": ["v=DKIM1; k=rsa; p=MIIB..."],
  });
  const p = await checkPosture("acme-corp.com", { resolver });
  assert.equal(p.grade, "A");
  assert.equal(p.spf.policy, "strict");
  assert.equal(p.spf.lookups, 2);
  assert.equal(p.dmarc.policy, "reject");
  assert.equal(p.dmarc.rua, "mailto:dmarc@acme-corp.com");
  assert.deepEqual(p.dkim.selectorsFound, ["google"]);
  assert.deepEqual(p.findings, []);
});

test("grade D: DMARC p=none; grade F: no DMARC", async () => {
  const d = await checkPosture("x.com", {
    resolver: resolverFrom({ "x.com": ["v=spf1 -all"], "_dmarc.x.com": ["v=DMARC1; p=none"] }),
  });
  assert.equal(d.grade, "D");
  assert.ok(d.findings.some((f) => /p=reject/.test(f)));
  const f = await checkPosture("y.com", { resolver: resolverFrom({ "y.com": ["v=spf1 ~all"] }) });
  assert.equal(f.grade, "F");
  assert.equal(f.dmarc.present, false);
});

test("grade C: soft SPF or no DKIM; grade B: quarantine", async () => {
  const c = await checkPosture("c.com", {
    resolver: resolverFrom({
      "c.com": ["v=spf1 ~all"],
      "_dmarc.c.com": ["v=DMARC1; p=reject; rua=mailto:a@c.com"],
      "default._domainkey.c.com": ["v=DKIM1; p=x"],
    }),
  });
  assert.equal(c.grade, "C");
  const b = await checkPosture("b.com", {
    resolver: resolverFrom({
      "b.com": ["v=spf1 -all"],
      "_dmarc.b.com": ["v=DMARC1; p=quarantine; rua=mailto:a@b.com"],
      "s1._domainkey.b.com": ["v=DKIM1; p=x"],
    }),
  });
  assert.equal(b.grade, "B");
});

test("customer-provided DKIM selector is checked first", async () => {
  const p = await checkPosture("k.com", {
    dkimSelector: "mycorp2026",
    resolver: resolverFrom({
      "k.com": ["v=spf1 -all"],
      "_dmarc.k.com": ["v=DMARC1; p=reject; rua=mailto:a@k.com"],
      "mycorp2026._domainkey.k.com": ["v=DKIM1; p=x"],
    }),
  });
  assert.deepEqual(p.dkim.selectorsFound, ["mycorp2026"]);
  assert.equal(p.grade, "A");
});

test("posture_weak fires once", () => {
  const weak = { grade: "F", findings: ["Publish a DMARC record."] };
  const first = postureEvents(null, weak);
  assert.equal(first.length, 1);
  assert.equal(first[0].kind, "posture_weak");
  assert.equal(first[0].severity, "low");
  assert.deepEqual(postureEvents(weak, weak), []);
  assert.deepEqual(postureEvents({ grade: "A" }, { grade: "B" }), []);
  assert.equal(
    postureEvents({ grade: "A" }, { grade: "D" }).length,
    1,
    "a regression from A to D fires"
  );
});
