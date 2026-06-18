import pkg from "pg";
const { Pool } = pkg;

// ✅ Connect using Render DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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

  console.log("✅ PostgreSQL ready");
}

// ✅ Helper for INSERT / UPDATE
export async function run(query, values = []) {
  return await pool.query(query, values);
}

// ✅ Helper to get one record
export async function get(query, values = []) {
  const result = await pool.query(query, values);
  return result.rows[0];
}