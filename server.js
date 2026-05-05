import express from "express";
import mongoose from "mongoose";
import fetch from "node-fetch";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";

dotenv.config();

// ─────────────────────────────────────────
// ENV CHECK
// ─────────────────────────────────────────
const REQUIRED_ENV = ["MONGO_URI", "OPENROUTER_KEY", "JWT_SECRET"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) throw new Error(`Missing env: ${key}`);
}

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MAX_HISTORY = 20;

// ─────────────────────────────────────────
// APP
// ─────────────────────────────────────────
const app = express();

// ✅ SECURE CORS (your Netlify frontend only)
app.use(cors({
  origin: "https://sgchatbotofficial.netlify.app"
}));

app.use(express.json({ limit: "16kb" }));

// ─────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
});

// ─────────────────────────────────────────
// DATABASE
// ─────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.log("DB error:", err.message));

// ─────────────────────────────────────────
// USER MODEL
// ─────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

// ─────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ reply: "No token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ reply: "Invalid token" });
  }
}

// ─────────────────────────────────────────
// SIGNUP
// ─────────────────────────────────────────
app.post("/signup", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Missing fields" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    await User.create({ email, password: hash });

    res.json({ message: "Account created" });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

// ─────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({ token, email });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ─────────────────────────────────────────
// CHAT
// ─────────────────────────────────────────
app.post("/chat", chatLimiter, auth, async (req, res) => {
  try {
    const messages = req.body.messages?.slice(-MAX_HISTORY);

    if (!Array.isArray(messages)) {
      return res.status(400).json({ reply: "Invalid messages" });
    }

    const response = await fetch(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.OPENROUTER_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "openai/gpt-4o-mini",
          messages,
        }),
      }
    );

    if (!response.ok) {
      return res.status(500).json({ reply: "AI service error" });
    }

    const data = await response.json();

    res.json({
      reply: data?.choices?.[0]?.message?.content || "No response",
    });
  } catch {
    res.status(500).json({ reply: "Server error" });
  }
});

// ─────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// ─────────────────────────────────────────
// ROOT
// ─────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ message: "SG ChatBOT API running" });
});

// ─────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
