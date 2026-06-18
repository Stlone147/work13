import express from "express";
import cors from "cors";
import { initDB } from "./db.mjs";

const app = express();

app.use(cors());
app.use(express.json());

await initDB();

app.get("/", (req, res) => {
  res.send("✅ CloudInfrastructureSolution backend running");
});

// ✅ SIGNUP
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    res.json({ message: "✅ Signup successful" });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Missing fields" });
    }

    res.json({ message: "✅ Login successful" });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});