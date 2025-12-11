// src/config/DB.js
const { Pool } = require("pg");
const dotenv = require("dotenv");
dotenv.config();

const pool = new Pool({
  host: process.env.DB_HOST || process.env.PGHOST || "localhost",
  port: Number(process.env.DB_PORT || process.env.PGPORT || 5432),
  database: process.env.DB_NAME || process.env.PGDATABASE || "savoia_db",
  user: process.env.DB_USER || process.env.PGUSER || "postgres",
  password: process.env.DB_PASS || process.env.PGPASSWORD || "",
  max: 20,
  idleTimeoutMillis: 30000,
});

let loggedOnce = false;
pool.on("connect", () => {
  if (!loggedOnce) {
    console.log("✅ Banco conectado com sucesso!");
    loggedOnce = true;
  }
});

pool.on("error", (err) => {
  console.error("❌ Erro no pool do Postgres:", err);
});

const query = (text, params) => pool.query(text, params);

async function withTx(fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const res = await fn(client);
    await client.query("COMMIT");
    return res;
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

module.exports = { query, withTx, pool };
