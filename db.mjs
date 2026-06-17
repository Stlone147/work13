import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";

sqlite3.verbose();

export const db = new sqlite3.Database("./cloudinfrastructure.db");

export function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

export function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

export async function initDB() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password_hash TEXT
    )
  `);

  const user = await get(
    "SELECT * FROM users WHERE email = ?",
    ["demo@mail.com"]
  );

  if (!user) {
    const hash = await bcrypt.hash("123456", 10);
    await run(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)",
      ["demo@mail.com", hash]
    );
  }

  console.log("✅ Database ready");
}