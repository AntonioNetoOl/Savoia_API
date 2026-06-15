// scripts/runMigration.js
require("dotenv").config();

const fs = require("fs");
const path = require("path");
const { pool } = require("../src/config/DB");

async function run() {
  const migrationArg = process.argv[2];

  if (!migrationArg) {
    console.error("Uso: node scripts/runMigration.js <arquivo.sql>");
    process.exit(1);
  }

  const migrationPath = path.resolve(process.cwd(), migrationArg);

  if (!fs.existsSync(migrationPath)) {
    console.error(`Migration não encontrada: ${migrationPath}`);
    process.exit(1);
  }

  const sql = fs.readFileSync(migrationPath, "utf8");
  const client = await pool.connect();

  try {
    console.log(`▶️ Executando migration: ${migrationArg}`);
    await client.query("BEGIN");
    await client.query(sql);
    await client.query("COMMIT");
    console.log("✅ Migration executada com sucesso.");
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("❌ Erro ao executar migration:", error.message);
    console.error(error);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

run();
