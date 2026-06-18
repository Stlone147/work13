import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { initDB, run, get } from "./db.mjs";

const app = express();

// ✅ Allow frontend to connect
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

// ✅ Initialize database
await initDB();

// ✅ Secret key for JWT
const SECRET = process.env.JWT_SECRET || "mysecretkey";

// ✅ Test route
app.get("/", (req, res) => {
  res.send("✅ CloudInfrastructureSolution backend running");
});


// =========================
// ✅ SIGNUP ROUTE
// =========================
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // Check if user already exists
    const existingUser = await get(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // Save user
    await run(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name, email, password_hash]
    );

    res.json({ message: "✅ Signup successful" });
  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// =========================
// ✅ LOGIN ROUTE
// =========================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Missing fields" });
    }

    const user = await get(
      "SELECT * FROM users WHERE email = ?",
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
      {
        id: user.id,
        email: user.email,
        name: user.name
      },
      SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "✅ Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
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
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}


// =========================
// ✅ PROTECTED ROUTE FOR DASHBOARD
// =========================
app.get("/me", verifyToken, async (req, res) => {
  try {
    const user = await get(
      "SELECT id, name, email FROM users WHERE id = ?",
      [req.user.id]
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ user });
  } catch (err) {
    console.error("ME ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// =========================
// ✅ LOGOUT ROUTE
// =========================
app.post("/logout", (req, res) => {
  // JWT logout is handled on the frontend by deleting the token
  res.json({ message: "✅ Logged out" });
});


// =========================
// ✅ START SERVER
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});