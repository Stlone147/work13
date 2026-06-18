import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { initDB, run, get } from "./db.mjs";

const app = express();

// ✅ FIXED CORS (NO BROKEN HTML)
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

// ✅ Initialize PostgreSQL
await initDB();

// ✅ Secure JWT secret
const SECRET = process.env.JWT_SECRET;

if (!SECRET) {
  throw new Error("JWT_SECRET is not set");
}

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

    // ✅ Check if user exists (PostgreSQL syntax)
    const existingUser = await get(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // ✅ Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // ✅ Insert user (PostgreSQL syntax)
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
// ✅ LOGIN ROUTE
// =========================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Missing fields" });
    }

    // ✅ Fetch user (PostgreSQL syntax)
    const user = await get(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // ✅ Compare password
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({ message: "Wrong password" });
    }

    // ✅ Generate JWT
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
// ✅ PROTECTED ROUTE
// =========================
app.get("/me", verifyToken, async (req, res) => {
  try {
    const user = await get(
      "SELECT id, name, email FROM users WHERE id = $1",
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
  res.json({ message: "✅ Logged out" });
});


// =========================
// ✅ START SERVER
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});