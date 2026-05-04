import express        from "express";
import mongoose       from "mongoose";
import fetch          from "node-fetch";
import bcrypt         from "bcryptjs";
import jwt            from "jsonwebtoken";
import cors           from "cors";
import dotenv         from "dotenv";
import path           from "path";
import rateLimit      from "express-rate-limit";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });

// ─────────────────────────────────────────
//  ENV VALIDATION
// ─────────────────────────────────────────
const REQUIRED_ENV = ["MONGO_URI", "OPENROUTER_KEY", "JWT_SECRET"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) throw new Error(`Missing required env variable: ${key}`);
}

const JWT_SECRET  = process.env.JWT_SECRET;
const PORT        = process.env.PORT || 3000;
const MAX_HISTORY = 20;

// ─────────────────────────────────────────
//  APP SETUP
// ─────────────────────────────────────────
const app = express();

app.use(cors());
app.use(express.json({ limit: "16kb" }));

// ✅ FIXED STATIC PATH
app.use(express.static(path.join(__dirname, "public")));

// ─────────────────────────────────────────
//  RATE LIMITERS
// ─────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { message: "Too many attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { reply: "Rate limit exceeded. Please slow down." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─────────────────────────────────────────
//  DATABASE
// ─────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

// ─────────────────────────────────────────
//  USER SCHEMA
// ─────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// ─────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return false;
  return messages.every(
    (m) =>
      m &&
      typeof m === "object" &&
      ["user", "assistant", "system"].includes(m.role) &&
      typeof m.content === "string" &&
      m.content.trim().length > 0
  );
}

// ─────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ reply: "Authorization token missing." });
  }

  const token = header.slice(7).trim();
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    const message =
      err.name === "TokenExpiredError"
        ? "Session expired. Please log in again."
        : "Invalid token.";
    return res.status(401).json({ reply: message });
  }
}

// ─────────────────────────────────────────
//  SIGNUP
// ─────────────────────────────────────────
app.post("/signup", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Email and password are required." });

    if (!isValidEmail(email))
      return res.status(400).json({ message: "Invalid email format." });

    if (password.length < 8 || password.length > 128)
      return res.status(400).json({ message: "Password must be 8–128 characters." });

    const exists = await User.findOne({ email: email.toLowerCase().trim() });
    if (exists)
      return res.status(409).json({ message: "An account with this email already exists." });

    const hash = await bcrypt.hash(password, 12);
    await User.create({ email, password: hash });

    res.status(201).json({ message: "Account created successfully." });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error during signup." });
  }
});

// ─────────────────────────────────────────
//  LOGIN
// ─────────────────────────────────────────
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Email and password are required." });

    if (!isValidEmail(email))
      return res.status(400).json({ message: "Invalid email format." });

    const user = await User.findOne({ email: email.toLowerCase().trim() });

    const dummyHash = "$2a$12$invalidhashfortimingprotectiononly.......";
    const passwordToCheck = user ? user.password : dummyHash;
    const match = await bcrypt.compare(password, passwordToCheck);

    if (!user || !match)
      return res.status(401).json({ message: "Invalid email or password." });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, email: user.email });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error during login." });
  }
});

// ─────────────────────────────────────────
//  CHAT
// ─────────────────────────────────────────
app.post("/chat", chatLimiter, auth, async (req, res) => {
  try {
    const { messages } = req.body;

    if (!isValidMessages(messages))
      return res.status(400).json({ reply: "Invalid or empty message history." });

    const trimmed = messages.slice(-MAX_HISTORY);

    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENROUTER_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "openai/gpt-4o-mini",
        messages: trimmed,
      }),
    });

    const data = await response.json();
    const reply = data?.choices?.[0]?.message?.content || "No response from AI.";

    res.json({ reply });
  } catch (err) {
    console.error("Chat error:", err);
    res.status(500).json({ reply: "Server error. Please try again." });
  }
});

// ─────────────────────────────────────────
//  HEALTH
// ─────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
  });
});

// ✅ FIXED ROOT ROUTE
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ─────────────────────────────────────────
//  404
// ─────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ message: "Route not found." });
});

// ─────────────────────────────────────────
//  START
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});