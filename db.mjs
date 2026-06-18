import pkg from "pg";
const { Pool } = pkg;

const required = ["PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD"];

for (const key of required) {
  if (!process.env[key]) {
    throw new Error(`${key} is not set`);
  }
}

// Safe debug: do NOT print password
console.log("PGHOST =", process.env.PGHOST);
console.log("PGPORT =", process.env.PGPORT);
console.log("PGDATABASE =", process.env.PGDATABASE);
console.log("PGUSER =", process.env.PGUSER);

const pool = new Pool({
  host: process.env.PGHOST,
  port: Number(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  ssl: {
    rejectUnauthorized: false
  }
});

export async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password_hash TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      action TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log("✅ PostgreSQL ready");
}

export async function run(query, values = []) {
  return await pool.query(query, values);
}

export async function get(query, values = []) {
  const result = await pool.query(query, values);
  return result.rows[0];
}