import express from "express";
import { initDB } from "./db.mjs";

const app = express();

// allow JSON data
app.use(express.json());

// initialize database
await initDB();

// test route
app.get("/", (req, res) => {
  res.send("✅ CloudInfrastructureSolution backend running");
});

// ✅ VERY IMPORTANT FOR DEPLOYMENT
const PORT = process.env.PORT || 3000;

// start server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
