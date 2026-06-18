import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";

sqlite3.verbose();

export const db = new sqlite3.Database("./cloudinfrastructure.db");

// ✅ RUN helper
export function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

// ✅ GET helper
export function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// ✅ INIT DATABASE
export async function initDB() {
  // ✅ ONE clean table structure (with name included)
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password_hash TEXT
    )
  `);

  // ✅ Create demo user (for testing login)
  const user = await get(
    "SELECT * FROM users WHERE email = ?",
    ["demo@mail.com"]
  );

  if (!user) {
    const hash = await bcrypt.hash("123456", 10);

    await run(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      ["Demo User", "demo@mail.com", hash]
    );
  }

  console.log("✅ Database ready");
}