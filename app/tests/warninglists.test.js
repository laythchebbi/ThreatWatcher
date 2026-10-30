require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { load, classifyInfra, ipInCidrs, parseCidr } = require("../src/services/watch/warninglists");

test("classifyInfra marks parking NS and CDN ranges", () => {
  const lists = { parkingNs: new Set(["parkingcrew.net"]), cdnCidrs: [parseCidr("104.16.0.0/13")] };
  assert.deepEqual(classifyInfra({ a: ["104.17.5.5"], ns: ["ns2.parkingcrew.net"] }, lists), {
    parked: true,
    cdn: true,
  });
  assert.deepEqual(classifyInfra({ a: ["8.8.8.8"], ns: ["ns1.example.net"] }, lists), {
    parked: false,
    cdn: false,
  });
  assert.deepEqual(classifyInfra({ a: [], ns: [] }, lists), { parked: false, cdn: false });
});

test("ipInCidrs handles range edges and ignores IPv6", () => {
  const cidrs = [parseCidr("10.0.0.0/8")];
  assert.equal(ipInCidrs("10.255.255.255", cidrs), true);
  assert.equal(ipInCidrs("11.0.0.0", cidrs), false);
  assert.equal(ipInCidrs("2001:db8::1", cidrs), false);
});

test("load reads the vendored lists", () => {
  const lists = load();
  assert.ok(lists.parkingNs.size > 10, "parking NS list vendored");
  assert.ok(lists.cdnCidrs.length > 10, "CDN ranges vendored");
  assert.ok(lists.cdnCidrs.every((c) => typeof c.start === "bigint"));
});
