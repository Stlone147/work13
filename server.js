import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { sendResetEmail } from "./email.mjs";
import { initDB, run, get } from "./db.mjs";

const app = express();

// ✅ CLEAN CORS (VERY IMPORTANT)
app.use(
  cors({
    origin: [
      "https://cloudinfrastructuresolution.com",
      "https://www.cloudinfrastructuresolution.com",
      "http://localhost:3000",
      "http://127.0.0.1:5500"
    ],
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

// ✅ Parse JSON
app.use(express.json());

// ✅ Initialize DB
await initDB();

// ✅ JWT Secret
const SECRET = process.env.JWT_SECRET;

if (!SECRET) {
  throw new Error("JWT_SECRET is not set");
}

// =========================
// ✅ ROOT ROUTE
// =========================
app.get("/", (req, res) => {
  res.send("✅ Backend running");
});

// =========================
// ✅ SIGNUP
// =========================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const existingUser = await get(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (existingUser) {
      return res.status(400).json({ message: "Email exists" });
    }

    const password_hash = await bcrypt.hash(password, 10);

    await run(
      "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3)",
      [name, email, password_hash]
    );

    res.json({ message: "✅ Signup successful" });

  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// =========================
// ✅ LOGIN
// =========================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await get(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({ message: "Wrong password" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });

  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// =========================
// ✅ AUTH MIDDLEWARE
// =========================
function verifyToken(req, res, next) {
  const header = req.headers.authorization;

  if (!header) return res.status(401).json({ message: "No token" });

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

// =========================
// ✅ USER PROFILE
// =========================
app.get("/me", verifyToken, async (req, res) => {
  const user = await get(
    "SELECT id, name, email FROM users WHERE id = $1",
    [req.user.id]
  );

  res.json({ user });
});

// =========================
// ✅ STATS
// =========================
app.get("/stats", async (req, res) => {
  const result = await run("SELECT COUNT(*) AS count FROM users");

  res.json({
    totalUsers: result.rows[0].count
  });
});

// =========================
// ✅ FORGOT PASSWORD
// =========================
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await get(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (!user) {
      return res.json({
        message: "If email exists, reset link sent"
      });
    }

    const token = crypto.randomBytes(32).toString("hex");

    const hash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    await run(
      `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '1 hour')`,
      [user.id, hash]
    );

    const resetLink =
      `${process.env.FRONTEND_URL}/reset-password.html?token=${token}`;

    await sendResetEmail(email, resetLink);

    res.json({ message: "✅ Reset email sent" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error" });
  }
});

// =========================
// ✅ RESET PASSWORD
// =========================
app.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const hash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const record = await get(
      `SELECT * FROM password_reset_tokens
       WHERE token_hash = $1 AND used = false
       AND expires_at > NOW()`,
      [hash]
    );

    if (!record) {
      return res.status(400).json({ message: "Invalid token" });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await run(
      "UPDATE users SET password_hash = $1 WHERE id = $2",
      [passwordHash, record.user_id]
    );

    await run(
      "UPDATE password_reset_tokens SET used = true WHERE id = $1",
      [record.id]
    );

    res.json({ message: "✅ Password reset success" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error" });
  }
});

// =========================
// ✅ START SERVER
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("✅ Server running on port " + PORT);
});