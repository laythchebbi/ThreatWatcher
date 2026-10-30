// In-memory MongoDB for tests. One server per process; each test drops the db after.
require("./env");
const { after } = require("node:test");
const mongoose = require("mongoose");
const { MongoMemoryServer } = require("mongodb-memory-server");

let serverPromise;

async function withDb(t) {
  serverPromise ||= MongoMemoryServer.create();
  const server = await serverPromise;
  if (mongoose.connection.readyState !== 1) {
    await mongoose.connect(server.getUri(), { dbName: "test" });
  }
  const models = require("../../src/models");
  await Promise.all(Object.values(models).map((m) => m.syncIndexes()));
  t.after(async () => {
    await mongoose.connection.db.dropDatabase();
  });
  return models;
}

// Stop the server once the whole file's tests are done (file-level hook).
after(async () => {
  if (mongoose.connection.readyState === 1) await mongoose.disconnect();
  if (serverPromise) await (await serverPromise).stop();
});

module.exports = { withDb };
