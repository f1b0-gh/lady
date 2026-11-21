// Start the trusted upstream Explorer server read-only and bound to loopback.
const path = require("node:path");
const net = require("node:net");
const [explorer, databaseDirectory] = process.argv.slice(2);
if (!explorer || !databaseDirectory) {
  throw new Error("usage: node serve.cjs EXPLORER_CHECKOUT DATABASE_DIRECTORY");
}
Object.assign(process.env, {
  NODE_ENV: "production",
  MODE: "READ_ONLY",
  PORT: "8000",
  LBUG_WASM: "false",
  LBUG_IN_MEMORY: "false",
  LBUG_DIR: path.resolve(databaseDirectory),
  LBUG_FILE: "demo.lbdb",
  LBUG_BUFFER_POOL_SIZE: "268435456",
  LBUG_NUM_CORES: "1",
});
const listen = net.Server.prototype.listen;
net.Server.prototype.listen = function (port, callback) {
  return listen.call(this, port, "127.0.0.1", callback);
};
require(path.resolve(explorer, "src/server/index.js"));
