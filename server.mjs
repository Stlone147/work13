import "dotenv/config";
import express from "express";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import { initDB, run, get } from "./db.mjs";

const app = express();

app.use(express.json());
app.use(express.static("."));

await initDB();

// Optional email transporter
const transporter =
  process.env.EMAIL_USER && process.env.EMAIL_PASS
    ? nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      })
    : null;

// Home
app.get("/", (req, res) => {
  res.send("✅ CloudInfrastructureSolution backend running");
});

// ✅ SIGNUP
app.post("/signup", async (req, res) => {
  try {
    console.log("✅ SIGNUP ROUTE HIT");
    console.log("BODY:", req.body);

    const { name, email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    // Check if user already exists
    const existing = await get(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (existing) {
      return res.status(400).json({
        message: "User already exists"
      });
    }

    // Hash password
    const hash = await bcrypt.hash(password, 10);

    // Save user
    await run(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)",
      [email, hash]
    );

    // ✅ Success response
    res.json({
      message: "✅ Account created successfully"
    });

  } catch (error) {
    console.error("❌ signup error:", error);
    res.status(500).json({
      message: "Server error"
    });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    console.log("✅ LOGIN ROUTE HIT");
    console.log("BODY:", req.body);

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    const user = await get(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (!user) {
      return res.status(400).json({
        message: "Invalid email or password"
      });
    }

    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(400).json({
        message: "Invalid email or password"
      });
    }

    res.json({
      message: "✅ Login successful"
    });
  } catch (error) {
    console.error("❌ login error:", error);
    res.status(500).json({
      message: "Server error"
    });
  }
});

// Forgot password
app.post("/forgot-password", async (req, res) => {
  try {
    console.log("✅ FORGOT PASSWORD ROUTE HIT");
    console.log("BODY:", req.body);

    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email is required"
      });
    }

    const user = await get(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (!user) {
      return res.json({
        message: "If account exists, reset link sent"
      });
    }

    await run(`
      CREATE TABLE IF NOT EXISTS reset_tokens (
        user_id INTEGER,
        token TEXT
      )
    `);

    const token = crypto.randomBytes(32).toString("hex");

    await run(
      "INSERT INTO reset_tokens (user_id, token) VALUES (?, ?)",
      [user.id, token]
    );

    const resetLink = `http://localhost:3000/reset.html?token=${token}`;

    if (transporter) {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Password Reset",
        html: `
          <h3>Reset your password</h3>
          <p>Click the link below to reset your password:</p>
          <p><a href="${resetLink}">${resetLink}</a></p>
        `
      });

      console.log("📧 Reset email sent to:", email);
      res.json({
        message: "📧 Reset link sent to your email"
      });
    } else {
      console.log("🔗 RESET LINK:", resetLink);
      res.json({
        message: "Reset link generated (check terminal)"
      });
    }
  } catch (error) {
    console.error("❌ forgot-password error:", error);
    res.status(500).json({
      message: "Server error"
    });
  }
});

// Reset password
app.post("/reset-password", async (req, res) => {
  try {
    console.log("✅ RESET PASSWORD ROUTE HIT");
    console.log("BODY:", req.body);

    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({
        message: "Token and password are required"
      });
    }

    const record = await get(
      "SELECT * FROM reset_tokens WHERE token = ?",
      [token]
    );

    if (!record) {
      return res.status(400).json({
        message: "Invalid or expired reset token"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await run(
      "UPDATE users SET password_hash = ? WHERE id = ?",
      [hashedPassword, record.user_id]
    );

    await run(
      "DELETE FROM reset_tokens WHERE token = ?",
      [token]
    );

    res.json({
      message: "✅ Password reset successful"
    });
  } catch (error) {
    console.error("❌ reset-password error:", error);
    res.status(500).json({
      message: "Server error"
    });
  }
});

app.listen(3000, () => {
  console.log("✅ Server running on http://localhost:3000");
});