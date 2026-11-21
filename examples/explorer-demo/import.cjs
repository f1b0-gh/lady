// Import Ladybom's exported CSV using the Explorer checkout's own engine.
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");

async function main() {
  const [explorer, csvDirectory, database] = process.argv.slice(2);
  if (!explorer || !csvDirectory || !database) {
    throw new Error("usage: node import.cjs EXPLORER_CHECKOUT CSV_DIRECTORY NEW_DATABASE");
  }
  const requireExplorer = createRequire(path.resolve(explorer, "package.json"));
  const lbug = requireExplorer("@ladybugdb/core");
  const destination = path.resolve(database);
  if (fs.existsSync(destination)) throw new Error("database must not exist");
  process.chdir(path.resolve(csvDirectory));
  const db = new lbug.Database(destination, 256 * 1024 * 1024);
  const connection = new lbug.Connection(db);
  try {
    for (const statement of fs.readFileSync("load.cypher", "utf8").split(";")) {
      if (!statement.trim()) continue;
      const result = await connection.query(statement);
      console.log(JSON.stringify(await result.getAll()));
      await result.close();
    }
  } finally {
    await connection.close();
    await db.close();
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
