import express        from "express";
import mongoose       from "mongoose";
import fetch          from "node-fetch";
import bcrypt         from "bcryptjs";
import jwt            from "jsonwebtoken";
import cors           from "cors";
import dotenv         from "dotenv";
import path           from "path";
import rateLimit      from "express-rate-limit";
import multer         from "multer";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });

const REQUIRED_ENV = ["MONGO_URI", "OPENROUTER_KEY", "JWT_SECRET"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) throw new Error(`Missing required env variable: ${key}`);
}

const JWT_SECRET  = process.env.JWT_SECRET;
const PORT        = process.env.PORT || 3000;
const MAX_HISTORY = 20;

const app = express();

app.set("trust proxy", 1);

app.use(cors({
  origin: [
    "https://sgchatbotofficial.netlify.app",
    "http://localhost:3000",
    "http://127.0.0.1:5500",
  ],
}));
app.use(express.json({ limit: "16kb" }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
});

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return false;
  return messages.every((m) =>
    m && typeof m === "object" &&
    ["user", "assistant", "system"].includes(m.role) &&
    (typeof m.content === "string" || Array.isArray(m.content))
  );
}

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

app.post("/signup", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const exists = await User.findOne({ email });
    if (exists)
      return res.status(409).json({ message: "User already exists" });

    const hash = await bcrypt.hash(password, 12);
    await User.create({ email, password: hash });

    res.json({ message: "Account created" });
  } catch {
    res.status(500).json({ message: "Signup error" });
  }
});

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

app.post("/chat", chatLimiter, auth, async (req, res) => {
  try {
    const { messages } = req.body;

    if (!isValidMessages(messages))
      return res.status(400).json({ reply: "Invalid messages" });

    const trimmed = messages.slice(-MAX_HISTORY);

    const model = "deepseek/deepseek-chat-v3-0324:free";

    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENROUTER_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ model, messages: trimmed }),
    });

    // ✅ FIX 1: API fail handle
    if (!response.ok) {
      return res.json({
        reply: "AI temporarily unavailable. Please try again."
      });
    }

    const data = await response.json();

    const reply =
      data?.choices?.[0]?.message?.content ??
      "AI cannot respond right now.";

    res.json({ reply });

  } catch (err) {
    console.error(err);
    res.status(500).json({ reply: "Server error" });
  }
});

app.get("/", (req, res) => {
  res.json({ message: "SG ChatBOT API running ✅" });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
