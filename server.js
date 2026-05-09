import express from "express";
import mongoose from "mongoose";
import fetch from "node-fetch";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import rateLimit from "express-rate-limit";
import multer from "multer";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });

// ─────────────────────────────────────────
// ENV CHECK
// ─────────────────────────────────────────
const REQUIRED_ENV = ["MONGO_URI", "OPENROUTER_KEY", "JWT_SECRET"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) throw new Error(`Missing required env variable: ${key}`);
}

const JWT_SECRET  = process.env.JWT_SECRET;
const PORT        = process.env.PORT || 3000;
const MAX_HISTORY = 20;

// ─────────────────────────────────────────
// APP
// ─────────────────────────────────────────
const app = express();
app.set("trust proxy", 1);

app.use(cors({
  origin: [
    "https://sgchatbotofficial.netlify.app",
    "https://sg-chatbot-a2h.pages.dev",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5500",
  ],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(express.json({ limit: "16kb" }));

// ─────────────────────────────────────────
// MULTER
// ─────────────────────────────────────────
const storage = multer.memoryStorage();
const upload  = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ─────────────────────────────────────────
// RATE LIMIT
// ─────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, max: 30 });

// ─────────────────────────────────────────
// DB
// ─────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

// ─────────────────────────────────────────
// USER MODEL
// ─────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

// ─────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ reply: "Authorization token missing." });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ reply: "Invalid or expired token." });
  }
}

// ─────────────────────────────────────────
// SIGNUP
// ─────────────────────────────────────────
app.post("/signup", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: "User already exists" });

    const hash = await bcrypt.hash(password, 12);
    await User.create({ email, password: hash });
    res.json({ message: "Account created" });
  } catch {
    res.status(500).json({ message: "Signup error" });
  }
});

// ─────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid login" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid login" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch {
    res.status(500).json({ message: "Login error" });
  }
});

// ─────────────────────────────────────────
// CHAT
// ─────────────────────────────────────────
app.post("/chat", chatLimiter, auth, upload.single("file"), async (req, res) => {
  try {

    // ── Parse messages ──
    let messages;
    try {
      messages = typeof req.body.messages === "string"
        ? JSON.parse(req.body.messages)
        : req.body.messages;
    } catch {
      return res.status(400).json({ reply: "Invalid messages format." });
    }

    if (!Array.isArray(messages) || messages.length === 0)
      return res.status(400).json({ reply: "Invalid messages" });

    const trimmed = messages.slice(-MAX_HISTORY);

    // ── ✅ System prompt — inject once only ──
    if (trimmed[0]?.role !== "system") {
      trimmed.unshift({
        role: "system",
        content:
          "You are SG ChatBOT — a smart, helpful AI assistant built by Mohammed Sadid Rahman. " +
          "Be natural, direct and concise. Never start with generic greetings like 'Hello! How can I assist you today?'. " +
          "Answer the user's question immediately and clearly.",
      });
    }

    // ── ✅ Image support ──
    if (req.file) {
      const base64   = req.file.buffer.toString("base64");
      const mimeType = req.file.mimetype;
      const lastMsg  = trimmed[trimmed.length - 1];

      if (lastMsg?.role === "user" && mimeType.startsWith("image/")) {
        lastMsg.content = [
          {
            type: "text",
            text: typeof lastMsg.content === "string" && lastMsg.content
              ? lastMsg.content
              : "Analyze this image.",
          },
          {
            type: "image_url",
            image_url: { url: `data:${mimeType};base64,${base64}` },
          },
        ];
      }
    }

    // ── ✅ FREE models only ──
    const hasImage = trimmed.some(
      m => Array.isArray(m.content) && m.content.some(p => p.type === "image_url")
    );

    const primaryModel  = hasImage
      ? "meta-llama/llama-3.2-11b-vision-instruct:free"
      : "deepseek/deepseek-chat-v3-0324:free";

    const fallbackModel = "meta-llama/llama-3.1-8b-instruct:free";

    // ── OpenRouter call ──
    async function callOpenRouter(model) {
      return fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization:  `Bearer ${process.env.OPENROUTER_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://sg-chatbot-a2h.pages.dev",
          "X-Title":      "SG ChatBOT",
        },
        body: JSON.stringify({ model, messages: trimmed }),
      });
    }

    let response = await callOpenRouter(primaryModel);

    // ✅ Fallback if primary model fails
    if (!response.ok) {
      const errText = await response.text();
      console.error(`❌ Primary model (${primaryModel}) failed:`, errText);

      response = await callOpenRouter(fallbackModel);

      if (!response.ok) {
        const fallbackErr = await response.text();
        console.error(`❌ Fallback model (${fallbackModel}) failed:`, fallbackErr);
        return res.status(500).json({ reply: "AI temporarily unavailable. Please try again." });
      }
    }

    const data  = await response.json();
    const reply = data?.choices?.[0]?.message?.content || "No response from AI.";
    res.json({ reply });

  } catch (err) {
    console.error("❌ Chat error:", err);
    res.status(500).json({ reply: "Server error. Please try again." });
  }
});

// ─────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ message: "SG ChatBOT API running ✅" });
});

// ─────────────────────────────────────────
// SERVER START
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
