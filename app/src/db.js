const mongoose = require("mongoose");
const { env } = require("./config");
const logger = require("./logger");

mongoose.set("strictQuery", true);

async function connect() {
  try {
    await mongoose.connect(env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      autoIndex: env.NODE_ENV !== "production",
    });
    logger.info(
      { host: mongoose.connection.host, db: mongoose.connection.name },
      "mongo connected"
    );
  } catch (err) {
    logger.error({ err }, "mongo connection failed");
    throw err;
  }

  mongoose.connection.on("error", (err) => logger.error({ err }, "mongo error"));
  mongoose.connection.on("disconnected", () => logger.warn("mongo disconnected"));
}

async function disconnect() {
  await mongoose.disconnect();
  logger.info("mongo disconnected (clean)");
}

module.exports = { connect, disconnect, mongoose };
