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
import crypto         from "crypto";
import nodemailer     from "nodemailer";
import dns            from "dns";
// --- Priority 2 modules ---
import createOAuthRouter          from "./routes/oauth.js";
import createWorkflowRouter       from "./routes/workflows.js";
import { registerModels, fireEvent } from "./services/workflowEngine.js";
import { startScheduler }            from "./services/scheduler.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env") });

const REQUIRED_ENV = ["MONGO_URI","OPENROUTER_KEY","JWT_SECRET","ADMIN_SECRET","EMAIL_USER","EMAIL_PASS","ENCRYPTION_KEY"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) throw new Error(`Missing env: ${key}`);
}
// FIX (C1/M1): ENCRYPTION_KEY must be a valid 32-byte (64 hex char) key. Without this check, an
// unset or malformed key would previously fall back to a random value generated at boot — meaning
// every restart/redeploy silently re-keyed encryption and made all previously stored integration
// tokens permanently undecryptable. We now fail fast at startup instead.
if (!/^[0-9a-fA-F]{64}$/.test(process.env.ENCRYPTION_KEY)) {
  throw new Error("ENCRYPTION_KEY must be a 64-character hex string (32 bytes). Generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"");
}

const JWT_SECRET   = process.env.JWT_SECRET;
process.env.APP_URL = process.env.APP_URL || "https://sg-chatbot-z8hp.onrender.com"; // used by config/passport.js for OAuth callback URLs
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const PORT         = process.env.PORT || 3000;
const MAX_HISTORY  = 20;
const FREE_LIMIT   = 25;
const FREE_WINDOW  = 4 * 60 * 60 * 1000;

// ── Persona Prompts ──
const PERSONA_PROMPTS = {
  dev:        'DEVELOPER MODE: Be highly technical and concise. Code-first answers. Use markdown code blocks always. Assume the user is an experienced developer. Skip lengthy preambles.',
  teacher:    'TEACHER MODE: Explain everything step-by-step like teaching a student. Use simple analogies, real examples, and bullet points. Offer to elaborate on any part.',
  friend:     'FRIEND MODE: Be casual, warm, and conversational. Use everyday language, light humor when appropriate. Talk like a smart best friend would.',
  writer:     'WRITER MODE: Focus on creative, polished writing. Help with storytelling, tone, structure, grammar, and style. Offer creative alternatives and be expressive.',
  bangladesh: 'BANGLADESH MODE: You are an expert on Bangladesh. Specialize in: BCS exam prep, SSC and HSC exam help, National University admission tests, NTRCA, Primary school assistant teacher exam, bank job exams. When helping with BCS/SSC/HSC: give exam-focused answers, mention important MCQ topics, share memory tricks, use Bangla when user writes in Bangla.',
  search:     'WEB SEARCH MODE: The user wants current, up-to-date information. Always mention when info might be outdated. Prioritize recent facts. Suggest verifying time-sensitive info from official sources.',
};

const ROLE_PROMPTS = {
  'Software Engineer': 'USER ROLE: Software Engineer. Prefer technical depth, code-first answers, mention edge cases, performance considerations, and best practices.',
  'Student': 'USER ROLE: Student. Break things down simply. Use analogies and examples. Encourage learning step by step.',
  'Designer': 'USER ROLE: Designer. Focus on visual thinking, UX principles, aesthetics, and creative problem solving.',
  'Data Scientist': 'USER ROLE: Data Scientist. Prefer statistical reasoning, mention Python/R/SQL tools, focus on data pipelines and ML models.',
  'Product Manager': 'USER ROLE: Product Manager. Think in terms of user needs, business impact, prioritization frameworks, and roadmaps.',
  'Human Resources': 'USER ROLE: HR Professional. Focus on people management, policies, communication, and organizational behavior.',
  'Finance': 'USER ROLE: Finance Professional. Use proper financial terminology and analytical frameworks.',
  'Marketing': 'USER ROLE: Marketing Professional. Think about audience targeting, brand messaging, campaigns, and growth strategies.',
  'Sales': 'USER ROLE: Sales Professional. Focus on persuasion techniques, objection handling, and closing strategies.',
  'Operations': 'USER ROLE: Operations Professional. Focus on process optimization, efficiency, and operational metrics.',
  'Teacher': 'USER ROLE: Teacher/Educator. Think about pedagogy, curriculum design, and student engagement.',
  'Doctor / Healthcare': 'USER ROLE: Healthcare Professional. Use appropriate medical terminology and emphasize patient safety.',
  'Lawyer': 'USER ROLE: Legal Professional. Use precise legal language and think analytically about cases.',
  'Content Creator': 'USER ROLE: Content Creator. Think about audience engagement, storytelling, and creative hooks.',
  'Entrepreneur': 'USER ROLE: Entrepreneur/Founder. Think about business models, growth strategies, market fit, and fast execution.',
  'Researcher': 'USER ROLE: Researcher/Academic. Prefer academic rigor, proper citations, and evidence-based analysis.',
  'Productivity Coach': 'USER ROLE: Productivity Coach. Focus on time management, habit-building, prioritization frameworks (e.g. Eisenhower matrix, time-blocking), and turning requests into concrete, actionable daily/weekly plans.',
};

let groqKeyCounter = 0;
const GROQ_KEYS = [
  process.env.GROQ_API_KEY_1,
  process.env.GROQ_API_KEY_2,
  process.env.GROQ_API_KEY_3,
  process.env.GROQ_API_KEY_4,
  process.env.GROQ_API_KEY_5,
  process.env.GROQ_API_KEY,
].filter(Boolean);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

async function sendEmail(to, subject, html) {
  try {
    if (process.env.BREVO_API_KEY) {
      const res = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: { "api-key": process.env.BREVO_API_KEY, "Content-Type": "application/json" },
        body: JSON.stringify({ sender: { name: "SG ChatBOT", email: process.env.EMAIL_USER || "noreply@sgchatbot.com" }, to: [{ email: to }], subject, htmlContent: html }),
      });
      if (res.ok) { console.log(`✅ Email sent via Brevo to ${to}`); return true; }
    }
    if (process.env.RESEND_API_KEY) {
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Authorization": `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({ from: "SG ChatBOT <onboarding@resend.dev>", to: [to], subject, html }),
      });
      if (res.ok) { console.log(`✅ Email sent via Resend to ${to}`); return true; }
    }
    await transporter.sendMail({ from: `"SG ChatBOT" <${process.env.EMAIL_USER}>`, to, subject, html });
    return true;
  } catch (err) { console.error("Email error:", err.message); return false; }
}

async function sendSecurityAlert(type, details) {
  const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;
  const html = `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#0b0f17;color:#e4ecf7;padding:28px;border-radius:14px;border:1px solid rgba(248,113,113,0.3)"><h2 style="color:#f87171">🚨 Security Alert — SG ChatBOT</h2><p style="color:#8a9bb5;font-size:13px">${new Date().toUTCString()}</p><div style="background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);border-radius:10px;padding:16px;margin:14px 0"><p style="font-weight:700;color:#f87171;margin-bottom:8px">${type}</p><pre style="font-size:12px;color:#8a9bb5;white-space:pre-wrap;margin:0">${JSON.stringify(details,null,2)}</pre></div></div>`;
  await sendEmail(adminEmail, `🚨 Security Alert: ${type}`, html);
}

const app = express();
app.set("trust proxy", 1);
app.use((req, res, next) => {
  if (process.env.NODE_ENV === "production" && req.headers["x-forwarded-proto"] !== "https")
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  next();
});
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options","nosniff"); res.setHeader("X-Frame-Options","DENY");
  res.setHeader("X-XSS-Protection","1; mode=block"); res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' https:;");
  next();
});
app.use(cors({
  origin: ["https://sg-chatbot-a2h.pages.dev","https://sgchatbotofficial.netlify.app","http://localhost:3000","http://localhost:5173","http://127.0.0.1:5500"],
  methods: ["GET","POST","DELETE","OPTIONS","PATCH","PUT"],
  allowedHeaders: ["Content-Type","Authorization","x-admin-secret"],
  credentials: false,
}));
app.use(express.json({ limit: "16kb" }));

// Globally validate ObjectId-shaped route params
const validateObjectIdParam = (req, res, next, id) => {
  if (id && !mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid ID format" });
  }
  next();
};
app.param('id', validateObjectIdParam);
app.param('pid', validateObjectIdParam); // FIX (M4)
app.param('tid', validateObjectIdParam); // FIX (M4)
app.param('mid', validateObjectIdParam); // FIX (M4)

const ALLOWED_MIME = new Set(["image/jpeg","image/png","image/gif","image/webp","application/pdf","application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document","text/plain","text/csv","application/vnd.ms-excel","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5*1024*1024 }, fileFilter: (req,file,cb) => ALLOWED_MIME.has(file.mimetype) ? cb(null,true) : cb(new Error(`File type not allowed: ${file.mimetype}`)) });

const authLimiter  = rateLimit({ windowMs:15*60*1000, max:15, message:{message:"Too many attempts. Try later."} });
const chatLimiter  = rateLimit({ windowMs:60*1000, max:30 });
const adminLimiter = rateLimit({ windowMs:15*60*1000, max:100, message:{message:"Too many admin requests."} });
const resetLimiter = rateLimit({ windowMs:60*60*1000, max:5, message:{message:"Too many reset attempts."} });
const apiLimiter   = rateLimit({ windowMs:60*1000, max:60 });

mongoose.connect(process.env.MONGO_URI).then(() => console.log("✅ MongoDB connected")).catch(err => { console.error("❌ MongoDB failed:", err.message); process.exit(1); });

// ════════════════════════════════════════════════
// ═══ SCHEMAS ════════════════════════════════════
// ════════════════════════════════════════════════

const userSchema = new mongoose.Schema({
  email:          { type:String, required:true, unique:true, lowercase:true, trim:true, maxlength:254 },
  password:       { type:String, required:true },
  plan:           { type:String, enum:["free","pro"], default:"free" },
  proExpiresAt:   { type:Date, default:null },
  msgCount:       { type:Number, default:0 },
  msgWindowStart: { type:Date, default:null },
  resetToken:     { type:String, default:null },
  resetTokenExp:  { type:Date, default:null },
  loginAttempts:  { type:Number, default:0 },
  lockUntil:      { type:Date, default:null },
  displayName:    { type:String, default:"", maxlength:50 },
  isBlocked:      { type:Boolean, default:false },
  blockedReason:  { type:String, default:"" },
  blockedAt:      { type:Date, default:null },
  violationCount: { type:Number, default:0 },     // Safety system (item 4): graduated warning/suspension counter
  suspendedUntil: { type:Date, default:null },     // null = not currently suspended; auto-clears once expired
  suspensionReason:{ type:String, default:"" },
  lastLoginAt:    { type:Date, default:null },
  lastLoginIP:    { type:String, default:"" },
  googleId:       { type:String, default:null, unique:true, sparse:true }, // OAuth (Priority 2)
  githubId:       { type:String, default:null, unique:true, sparse:true }, // OAuth (Priority 2)
  avatarUrl:      { type:String, default:"" },
  totalMessages:  { type:Number, default:0 },
  role:           { type:String, default:"" },
  settings: {
    theme:           { type:String, enum:["dark","light","system"], default:"dark" },
    language:        { type:String, default:"en" },
    parentalControl: { type:Boolean, default:false },
    typewriter:      { type:Boolean, default:true },
    fontSize:        { type:String, enum:["sm","md","lg"], default:"md" },
    soundEnabled:    { type:Boolean, default:false },
    autoSaveChats:   { type:Boolean, default:true },
  },
}, { timestamps:true });
const User = mongoose.model("User", userSchema);

const paymentSchema = new mongoose.Schema({
  userId:        { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true },
  email:         { type:String, required:true },
  method:        { type:String, enum:["bkash","nagad"], required:true },
  transactionId: { type:String, required:true, trim:true, unique:true },
  amount:        { type:Number, required:true },
  plan:          { type:String, enum:["monthly","yearly"], required:true },
  status:        { type:String, enum:["pending","approved","rejected"], default:"pending" },
}, { timestamps:true });
const Payment = mongoose.model("Payment", paymentSchema);

const conversationSchema = new mongoose.Schema({
  userId:   { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true },
  title:    { type:String, default:"New Chat" },
  messages: [{ role:{type:String,enum:["user","assistant","system"]}, content:{type:mongoose.Schema.Types.Mixed}, createdAt:{type:Date,default:Date.now} }],
}, { timestamps:true });
const Conversation = mongoose.model("Conversation", conversationSchema);

const securityLogSchema = new mongoose.Schema({
  type:      { type:String, required:true },
  severity:  { type:String, enum:["low","medium","high","critical"], default:"medium" },
  ip:        { type:String, default:"" },
  userAgent: { type:String, default:"" },
  email:     { type:String, default:"" },
  userId:    { type:String, default:"" },
  details:   { type:mongoose.Schema.Types.Mixed },
  resolved:  { type:Boolean, default:false },
  resolvedAt:{ type:Date, default:null },
}, { timestamps:true });
const SecurityLog = mongoose.model("SecurityLog", securityLogSchema);

const blockedIPSchema = new mongoose.Schema({
  ip:        { type:String, required:true, unique:true },
  reason:    { type:String, default:"" },
  blockedBy: { type:String, default:"system" },
  attempts:  { type:Number, default:0 },
  expiresAt: { type:Date, default:null },
}, { timestamps:true });
const BlockedIP = mongoose.model("BlockedIP", blockedIPSchema);

// ── V2: Memory Schema ──
const memorySchema = new mongoose.Schema({
  userId:    { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true, index:true },
  content:   { type:String, required:true, maxlength:2000 },
  summary:   { type:String, default:"", maxlength:300 },
  tags:      [{ type:String, maxlength:50 }],
  category:  { type:String, enum:["fact","preference","goal","skill","event","relationship","insight","other"], default:"other" },
  importance:{ type:Number, min:1, max:5, default:3 },
  source:    { type:String, enum:["manual","auto","chat"], default:"manual" },
  convId:    { type:mongoose.Schema.Types.ObjectId, ref:"Conversation", default:null },
  embedding: [{ type:Number }],
}, { timestamps:true });
memorySchema.index({ userId:1, tags:1 });
memorySchema.index({ userId:1, category:1 });
const Memory = mongoose.model("Memory", memorySchema);

// ── V2: Notes Schema ──
const noteSchema = new mongoose.Schema({
  userId:    { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true, index:true },
  title:     { type:String, required:true, maxlength:200 },
  content:   { type:String, required:true, maxlength:50000 },
  tags:      [{ type:String, maxlength:50 }],
  pinned:    { type:Boolean, default:false },
  color:     { type:String, default:"" },
  folderId:  { type:mongoose.Schema.Types.ObjectId, default:null },
}, { timestamps:true });
noteSchema.index({ userId:1, pinned:-1, updatedAt:-1 });
const Note = mongoose.model("Note", noteSchema);

// ── V2: Goals Schema ──
const goalSchema = new mongoose.Schema({
  userId:      { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true, index:true },
  title:       { type:String, required:true, maxlength:200 },
  description: { type:String, default:"", maxlength:2000 },
  category:    { type:String, enum:["career","health","finance","learning","personal","project","other"], default:"other" },
  status:      { type:String, enum:["active","completed","paused","cancelled"], default:"active" },
  priority:    { type:String, enum:["low","medium","high","critical"], default:"medium" },
  progress:    { type:Number, min:0, max:100, default:0 },
  targetDate:  { type:Date, default:null },
  completedAt: { type:Date, default:null },
  milestones: [{
    title:       { type:String, required:true, maxlength:200 },
    completed:   { type:Boolean, default:false },
    completedAt: { type:Date, default:null },
    dueDate:     { type:Date, default:null },
    order:       { type:Number, default:0 },
  }],
  weeklyReviews: [{
    week:        { type:String },
    note:        { type:String, maxlength:1000 },
    score:       { type:Number, min:1, max:10 },
    createdAt:   { type:Date, default:Date.now },
  }],
  aiRecommendations: [{ type:String }],
}, { timestamps:true });
goalSchema.index({ userId:1, status:1, priority:-1 });
const Goal = mongoose.model("Goal", goalSchema);

// ── V2: Projects Schema ──
const projectSchema = new mongoose.Schema({
  userId:      { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true, index:true },
  name:        { type:String, required:true, maxlength:200 },
  description: { type:String, default:"", maxlength:3000 },
  type:        { type:String, enum:["web","mobile","api","data","ml","other"], default:"web" },
  status:      { type:String, enum:["planning","active","review","completed","paused"], default:"planning" },
  progress:    { type:Number, min:0, max:100, default:0 },
  techStack:   [{ type:String }],
  requirements:{ type:String, default:"" },
  roadmap:     { type:String, default:"" },
  dbSchema:    { type:String, default:"" },
  apiArchitecture:{ type:String, default:"" },
  uiArchitecture: { type:String, default:"" },
  folderStructure:{ type:String, default:"" },
  deploymentPlan: { type:String, default:"" },
  targetDate:  { type:Date, default:null },
}, { timestamps:true });
projectSchema.index({ userId:1, status:1 });
const Project = mongoose.model("Project", projectSchema);

// ── V2: Project Tasks Schema ──
const projectTaskSchema = new mongoose.Schema({
  userId:      { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true },
  projectId:   { type:mongoose.Schema.Types.ObjectId, ref:"Project", required:true, index:true },
  title:       { type:String, required:true, maxlength:300 },
  description: { type:String, default:"", maxlength:2000 },
  status:      { type:String, enum:["todo","in_progress","review","done"], default:"todo" },
  priority:    { type:String, enum:["low","medium","high"], default:"medium" },
  dueDate:     { type:Date, default:null },
  completedAt: { type:Date, default:null },
  order:       { type:Number, default:0 },
}, { timestamps:true });
const ProjectTask = mongoose.model("ProjectTask", projectTaskSchema);

// ── V2: Tasks Schema (Life OS) ──
const taskSchema = new mongoose.Schema({
  userId:      { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true, index:true },
  title:       { type:String, required:true, maxlength:300 },
  description: { type:String, default:"", maxlength:2000 },
  status:      { type:String, enum:["todo","in_progress","done"], default:"todo" },
  priority:    { type:String, enum:["low","medium","high","urgent"], default:"medium" },
  category:    { type:String, default:"general", maxlength:50 },
  dueDate:     { type:Date, default:null },
  dueTime:     { type:String, default:"" },
  completedAt: { type:Date, default:null },
  recurring:   { type:String, enum:["none","daily","weekly","monthly"], default:"none" },
  goalId:      { type:mongoose.Schema.Types.ObjectId, ref:"Goal", default:null },
  tags:        [{ type:String }],
}, { timestamps:true });
taskSchema.index({ userId:1, status:1, dueDate:1 });
const Task = mongoose.model("Task", taskSchema);

// ── V2: Habits Schema ──
const habitSchema = new mongoose.Schema({
  userId:      { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true, index:true },
  name:        { type:String, required:true, maxlength:200 },
  description: { type:String, default:"", maxlength:500 },
  icon:        { type:String, default:"⭐" },
  color:       { type:String, default:"#6c8eff" },
  frequency:   { type:String, enum:["daily","weekly","monthly"], default:"daily" },
  targetDays:  [{ type:Number }], // 0=Sun,1=Mon,...,6=Sat for weekly
  streak:      { type:Number, default:0 },
  longestStreak:{ type:Number, default:0 },
  completions: [{
    date:      { type:String, required:true },
    note:      { type:String, default:"" },
  }],
  active:      { type:Boolean, default:true },
  createdAt:   { type:Date, default:Date.now },
}, { timestamps:true });
habitSchema.index({ userId:1, active:1 });
const Habit = mongoose.model("Habit", habitSchema);

// ── V2: Calendar Events Schema ──
const calendarEventSchema = new mongoose.Schema({
  userId:      { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true, index:true },
  title:       { type:String, required:true, maxlength:200 },
  description: { type:String, default:"", maxlength:2000 },
  startDate:   { type:Date, required:true },
  endDate:     { type:Date, required:true },
  allDay:      { type:Boolean, default:false },
  category:    { type:String, default:"general", maxlength:50 },
  color:       { type:String, default:"#6c8eff" },
  location:    { type:String, default:"", maxlength:200 },
  recurring:   { type:String, enum:["none","daily","weekly","monthly","yearly"], default:"none" },
  reminder:    { type:Number, default:0 }, // minutes before
  goalId:      { type:mongoose.Schema.Types.ObjectId, ref:"Goal", default:null },
  taskId:      { type:mongoose.Schema.Types.ObjectId, ref:"Task", default:null },
}, { timestamps:true });
calendarEventSchema.index({ userId:1, startDate:1 });
const CalendarEvent = mongoose.model("CalendarEvent", calendarEventSchema);

// ── V2: Analytics Schema ──
const analyticsSchema = new mongoose.Schema({
  userId:      { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true, index:true },
  date:        { type:String, required:true }, // YYYY-MM-DD
  tasksCompleted:  { type:Number, default:0 },
  habitsCompleted: { type:Number, default:0 },
  habitsTotal:     { type:Number, default:0 },
  messagesCount:   { type:Number, default:0 },
  goalsProgress:   { type:Number, default:0 },
  productivityScore:{ type:Number, default:0 },
  focusMinutes:    { type:Number, default:0 },
  mood:            { type:Number, min:1, max:5, default:null },
  notes:           { type:String, default:"" },
}, { timestamps:true });
analyticsSchema.index({ userId:1, date:1 }, { unique:true });
const Analytics = mongoose.model("Analytics", analyticsSchema);

// ── V2: Integrations Schema ──
const integrationSchema = new mongoose.Schema({
  userId:      { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true, index:true },
  service:     { type:String, enum:["gmail","github","googledrive","googlecalendar","notion"], required:true },
  accessToken: { type:String, default:"" },
  refreshToken:{ type:String, default:"" },
  tokenExpiry: { type:Date, default:null },
  metadata:    { type:mongoose.Schema.Types.Mixed, default:{} },
  active:      { type:Boolean, default:true },
  lastSyncAt:  { type:Date, default:null },
}, { timestamps:true });
integrationSchema.index({ userId:1, service:1 }, { unique:true });
const Integration = mongoose.model("Integration", integrationSchema);

// ── V2: Automation Logs Schema ──
const automationLogSchema = new mongoose.Schema({
  userId:    { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true, index:true },
  service:   { type:String, required:true },
  action:    { type:String, required:true },
  status:    { type:String, enum:["success","failed","pending"], default:"pending" },
  details:   { type:mongoose.Schema.Types.Mixed },
  error:     { type:String, default:"" },
}, { timestamps:true });
automationLogSchema.index({ userId:1, createdAt:-1 });
const AutomationLog = mongoose.model("AutomationLog", automationLogSchema);

// ════════════════════════════════════════════════
// ═══ UTILITIES ══════════════════════════════════
// ════════════════════════════════════════════════

function sanitize(input) {
  if (typeof input==="string") return input.replace(/[\$\x00]/g,"").trim().slice(0,1000);
  if (Array.isArray(input)) return input.map(sanitize);
  if (typeof input==="object"&&input!==null) { const clean={}; for (const key of Object.keys(input)) { const k=key.replace(/[\$\.]/g,"_").slice(0,100); clean[k]=sanitize(input[key]); } return clean; }
  return input;
}
function isValidEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)&&e.length<=254; }
function isProActive(u)   { return u.plan==="pro"&&u.proExpiresAt&&new Date()<new Date(u.proExpiresAt); }
function isLocked(u)      { return u.lockUntil&&new Date()<new Date(u.lockUntil); }
function getClientIP(req) { return req.headers["x-forwarded-for"]?.split(",")[0]?.trim()||req.ip||"unknown"; }
function checkWindow(user) { const now=Date.now(); if (!user.msgWindowStart||(now-new Date(user.msgWindowStart).getTime())>=FREE_WINDOW) { user.msgCount=0; user.msgWindowStart=new Date(); return true; } return false; }
function minsUntilReset(user) { if (!user.msgWindowStart) return 0; return Math.ceil(Math.max(0,FREE_WINDOW-(Date.now()-new Date(user.msgWindowStart).getTime()))/60000); }
function todayStr() { return new Date().toISOString().slice(0,10); }

const ENCRYPTION_KEY_BUF = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // validated 32 bytes above
function encryptToken(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY_BUF, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}
function decryptToken(enc) {
  try {
    if (!enc.includes(':')) return ""; // not a token produced by this function — refuse rather than guess
    const parts = enc.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY_BUF, Buffer.from(parts[0], 'hex'));
    decipher.setAuthTag(Buffer.from(parts[1], 'hex'));
    let decrypted = decipher.update(parts[2], 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) { return ""; }
}

const ipAttempts = new Map();
setInterval(() => ipAttempts.clear(), 60 * 60 * 1000); // Clear every hour to prevent memory leak
async function logSecurityEvent(type, severity, req, extra={}) {
  const ip=getClientIP(req), userAgent=req.headers["user-agent"]||"";
  try { await SecurityLog.create({ type, severity, ip, userAgent, ...extra }); if (severity==="high"||severity==="critical") sendSecurityAlert(type,{ip,userAgent,...extra}).catch(()=>{}); } catch(e) { console.error("Security log error:",e.message); }
}

const ADMIN_IPS = new Set((process.env.ADMIN_IPS || "").split(",").map(s => s.trim()).filter(Boolean));

app.use(async (req,res,next) => {
  if (req.path==="/") return next();
  const ip = getClientIP(req);
  if (ADMIN_IPS.has(ip)) return next();
  if (req.headers["x-admin-secret"] === ADMIN_SECRET) return next();
  try { const blocked = await BlockedIP.findOne({ip}); if (blocked) { if (blocked.expiresAt && new Date() > blocked.expiresAt) { await BlockedIP.deleteOne({ip}); return next(); } return res.status(403).json({message:"Access denied."}); } } catch {}
  next();
});

const SUSPICIOUS_UA = ["sqlmap","nikto","nmap","masscan","zgrab","acunetix","burpsuite"];
app.use(async (req,res,next) => {
  const ip=getClientIP(req); const ua=(req.headers["user-agent"]||"").toLowerCase(); const url=req.originalUrl;
  const suspUA=SUSPICIOUS_UA.some(s=>ua.includes(s)); const pathTraverse=url.includes("../")||url.includes("%2e%2e"); const sqlAttempt=/(\bunion\b\s+\bselect\b)|(\bdrop\b\s+\btable\b)|('|%27|--|;)\s*(\bor\b|\band\b|\bdrop\b|\bdelete\b|\binsert\b|\bunion\b)\b/i.test(url); const xssAttempt=/<script|javascript:|onerror=|onload=/i.test(url);
  if (suspUA||pathTraverse||sqlAttempt||xssAttempt) { const type=suspUA?"suspicious_user_agent":pathTraverse?"path_traversal":sqlAttempt?"sql_injection":"xss_attempt"; await logSecurityEvent(type,"high",req,{url}); const key=`susp_${ip}`; const count=(ipAttempts.get(key)||0)+1; ipAttempts.set(key,count); if (count>=3) { await BlockedIP.findOneAndUpdate({ip},{ip,reason:`Auto-blocked: ${type}`,blockedBy:"system",attempts:count},{upsert:true,new:true}).catch(()=>{}); await logSecurityEvent("ip_auto_blocked","critical",req,{reason:type}); } return res.status(403).json({message:"Access denied."}); }
  next();
});

function auth(req,res,next) { const h=req.headers.authorization; if (!h||!h.startsWith("Bearer ")) return res.status(401).json({message:"Authorization token missing.",reply:"Authorization token missing."}); try { req.user=jwt.verify(h.slice(7),JWT_SECRET); next(); } catch { return res.status(401).json({message:"Invalid or expired token.",reply:"Invalid or expired token."}); } }
function adminAuth(req,res,next) { const secret=req.headers["x-admin-secret"]||""; try { const valid=Buffer.from(secret).length===Buffer.from(ADMIN_SECRET).length&&crypto.timingSafeEqual(Buffer.from(secret),Buffer.from(ADMIN_SECRET)); if (!valid) { logSecurityEvent("admin_auth_failed","high",req).catch(()=>{}); return res.status(403).json({message:"Forbidden"}); } next(); } catch { return res.status(403).json({message:"Forbidden"}); } }
async function checkBlocked(req,res,next) { try { const u=await User.findById(req.user.id).select("isBlocked blockedReason suspendedUntil suspensionReason"); if (u?.isBlocked) return res.status(403).json({message:`Account blocked: ${u.blockedReason||"Policy violation"}`,reply:`Account blocked: ${u.blockedReason||"Policy violation"}`,blocked:true,permanent:true,reason:u.blockedReason||"Policy violation"}); if (u?.suspendedUntil) { if (new Date(u.suspendedUntil) > new Date()) { return res.status(403).json({message:`Account temporarily suspended until ${new Date(u.suspendedUntil).toLocaleString()}`,reply:"Account temporarily suspended.",blocked:true,permanent:false,suspendedUntil:u.suspendedUntil,reason:u.suspensionReason||"Policy violation"}); } User.updateOne({_id:u._id},{$set:{suspendedUntil:null}}).catch(()=>{}); } next(); } catch { next(); } }

// ════════════════════════════════════════════════
// ═══ AUTH ROUTES ════════════════════════════════
// ════════════════════════════════════════════════

app.post("/signup", authLimiter, async (req,res) => {
  try { const b=sanitize(req.body); const {email,password}=b; if (!email||!password) return res.status(400).json({message:"Email and password required"}); if (!isValidEmail(email)) return res.status(400).json({message:"Invalid email format"}); if (password.length<8||password.length>128) return res.status(400).json({message:"Password must be 8–128 characters"}); if (await User.findOne({email})) return res.status(409).json({message:"User already exists"}); const hash=await bcrypt.hash(password,12); await User.create({email,password:hash,lastLoginIP:getClientIP(req)}); res.json({message:"Account created"}); } catch { res.status(500).json({message:"Signup error"}); }
});

app.post("/login", authLimiter, async (req,res) => {
  try { const b=sanitize(req.body); const {email,password}=b; const ip=getClientIP(req); if (!email||!password) return res.status(401).json({message:"Invalid login"}); const user=await User.findOne({email}); if (!user) return res.status(401).json({message:"Invalid email or password"}); if (user.isBlocked) return res.status(403).json({message:`Account blocked: ${user.blockedReason||"Policy violation"}`}); if (isLocked(user)) return res.status(423).json({message:"Account temporarily locked. Try again later."}); const ok=await bcrypt.compare(password,user.password); if (!ok) { user.loginAttempts=(user.loginAttempts||0)+1; if (user.loginAttempts>=5) { user.lockUntil=new Date(Date.now()+15*60*1000); user.loginAttempts=0; await logSecurityEvent("brute_force_detected","high",req,{email,userId:user._id.toString()}); } await user.save(); return res.status(401).json({message:"Invalid email or password"}); } user.loginAttempts=0; user.lockUntil=null; user.lastLoginAt=new Date(); user.lastLoginIP=ip; await user.save(); const token=jwt.sign({id:user._id},JWT_SECRET,{expiresIn:"7d"}); res.json({token}); } catch { res.status(500).json({message:"Login error"}); }
});

app.get("/status", auth, async (req,res) => {
  try {
    const user=await User.findById(req.user.id).select("-password -resetToken");
    if (!user) return res.status(404).json({message:"User not found"});
    const pro=isProActive(user);
    if(checkWindow(user)) await user.save();
    let activeSuspension=null;
    if (user.suspendedUntil) {
      if (new Date(user.suspendedUntil) > new Date()) activeSuspension=user.suspendedUntil;
      else { user.suspendedUntil=null; await user.save().catch(()=>{}); } // expired — clear silently
    }
    res.json({email:user.email,plan:pro?"pro":"free",msgsLeft:pro?null:Math.max(0,FREE_LIMIT-user.msgCount),freeLimit:FREE_LIMIT,minsLeft:pro?null:minsUntilReset(user),proExpires:user.proExpiresAt,role:user.role||"",isBlocked:!!user.isBlocked,blockedReason:user.blockedReason||"",suspendedUntil:activeSuspension,suspensionReason:user.suspensionReason||""});
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/forgot-password", resetLimiter, async (req,res) => {
  try { const email=sanitize(req.body).email; if (!email||!isValidEmail(email)) return res.json({message:"If this email exists, a reset code has been sent."}); const user=await User.findOne({email}); if (!user) return res.json({message:"If this email exists, a reset code has been sent."}); const code=crypto.randomInt(100000,999999).toString(); user.resetToken=await bcrypt.hash(code,8); user.resetTokenExp=new Date(Date.now()+2*60*1000); await user.save();
    const emailHtml=`<!DOCTYPE html><html><body style="background:#f4f4f5;font-family:sans-serif"><table width="100%" style="padding:40px 0"><tr><td align="center"><table width="480" style="background:#fff;border-radius:16px;overflow:hidden;"><tr><td style="background:#0b0f17;padding:32px;text-align:center"><p style="color:#fff;font-weight:800;font-size:22px;margin:0">✦ SG ChatBOT</p></td></tr><tr><td style="padding:40px"><h1 style="font-size:22px;color:#0f172a;margin:0 0 20px">Password reset code</h1><div style="background:#f8fafc;border:2px solid #e2e8f0;border-radius:12px;padding:28px;text-align:center"><p style="font-size:13px;color:#64748b;margin:0 0 12px;font-weight:600">Your code (expires in 2 minutes)</p><div style="font-size:42px;font-weight:800;letter-spacing:12px;color:#0f172a;font-family:monospace">${code}</div></div></td></tr></table></td></tr></table></body></html>`;
    await sendEmail(email, "Your SG ChatBOT verification code", emailHtml);
    res.json({message:"If this email exists, a reset code has been sent."}); } catch { res.status(500).json({message:"Error"}); }
});

app.post("/reset-password", resetLimiter, async (req,res) => {
  try { const {email,code,newPassword}=sanitize(req.body); if (!email||!code||!newPassword) return res.status(400).json({message:"All fields required"}); if (newPassword.length<8||newPassword.length>128) return res.status(400).json({message:"Password must be 8–128 characters"}); const user=await User.findOne({email}); if (!user||!user.resetToken||!user.resetTokenExp) return res.status(400).json({message:"Invalid or expired code"}); if (new Date()>user.resetTokenExp) return res.status(400).json({message:"Reset code expired"}); if (!await bcrypt.compare(code,user.resetToken)) return res.status(400).json({message:"Invalid reset code"}); user.password=await bcrypt.hash(newPassword,12); user.resetToken=null; user.resetTokenExp=null; user.loginAttempts=0; user.lockUntil=null; await user.save(); res.json({message:"Password reset successfully"}); } catch { res.status(500).json({message:"Error"}); }
});

// ════════════════════════════════════════════════
// ═══ PAYMENT ROUTES ═════════════════════════════
// ════════════════════════════════════════════════

app.post("/payment/submit", auth, async (req,res) => {
  try { const {method,transactionId,plan}=sanitize(req.body); if (!method||!transactionId||!plan) return res.status(400).json({message:"Missing fields"}); if (!["bkash","nagad"].includes(method)) return res.status(400).json({message:"Invalid method"}); if (!["monthly","yearly"].includes(plan)) return res.status(400).json({message:"Invalid plan"}); if (transactionId.length<6||transactionId.length>50) return res.status(400).json({message:"Invalid transaction ID"}); if (await Payment.findOne({transactionId})) return res.status(409).json({message:"Transaction ID already used"}); const user=await User.findById(req.user.id); if (!user) return res.status(404).json({message:"User not found"}); await Payment.create({userId:user._id,email:user.email,method,transactionId,amount:plan==="monthly"?99:799,plan}); res.json({message:"Payment submitted! We will verify within 24 hours."}); } catch { res.status(500).json({message:"Payment error"}); }
});

// ════════════════════════════════════════════════
// ═══ SETTINGS ROUTES ════════════════════════════
// ════════════════════════════════════════════════

app.get("/settings",auth,async(req,res)=>{try{const u=await User.findById(req.user.id).select("-password -resetToken");if(!u)return res.status(404).json({message:"Not found"});res.json({email:u.email,displayName:u.displayName||"",settings:u.settings||{},plan:u.plan,proExpires:u.proExpiresAt,createdAt:u.createdAt,role:u.role||""});}catch{res.status(500).json({message:"Error"});}});
app.post("/settings",auth,async(req,res)=>{try{const u=await User.findById(req.user.id);if(!u)return res.status(404).json({message:"Not found"});const{displayName,settings,role}=req.body;if(displayName!==undefined)u.displayName=sanitize(displayName).slice(0,50);if(role!==undefined)u.role=sanitize(role).slice(0,50);if(settings){const s=settings;if(s.theme!==undefined&&["dark","light","system"].includes(s.theme))u.settings.theme=s.theme;if(s.language!==undefined)u.settings.language=sanitize(s.language).slice(0,10);if(s.parentalControl!==undefined)u.settings.parentalControl=!!s.parentalControl;if(s.typewriter!==undefined)u.settings.typewriter=!!s.typewriter;if(s.fontSize!==undefined&&["sm","md","lg"].includes(s.fontSize))u.settings.fontSize=s.fontSize;if(s.soundEnabled!==undefined)u.settings.soundEnabled=!!s.soundEnabled;if(s.autoSaveChats!==undefined)u.settings.autoSaveChats=!!s.autoSaveChats;}u.markModified("settings");await u.save();res.json({message:"Settings saved"});}catch{res.status(500).json({message:"Error"});}});
app.post("/settings/change-password",auth,async(req,res)=>{try{const{currentPassword,newPassword}=sanitize(req.body);if(!currentPassword||!newPassword)return res.status(400).json({message:"All fields required"});if(newPassword.length<8)return res.status(400).json({message:"Password min 8 characters"});const u=await User.findById(req.user.id);if(!await bcrypt.compare(currentPassword,u.password))return res.status(401).json({message:"Current password incorrect"});u.password=await bcrypt.hash(newPassword,12);await u.save();res.json({message:"Password changed"});}catch{res.status(500).json({message:"Error"});}});
app.delete("/settings/account",auth,async(req,res)=>{try{const{password}=sanitize(req.body);const u=await User.findById(req.user.id);if(!await bcrypt.compare(password,u.password))return res.status(401).json({message:"Incorrect password"});await Conversation.deleteMany({userId:u._id});await Payment.deleteMany({userId:u._id});await Memory.deleteMany({userId:u._id});await Note.deleteMany({userId:u._id});await Goal.deleteMany({userId:u._id});await Project.deleteMany({userId:u._id});await ProjectTask.deleteMany({userId:u._id});await Task.deleteMany({userId:u._id});await Habit.deleteMany({userId:u._id});await CalendarEvent.deleteMany({userId:u._id});await Analytics.deleteMany({userId:u._id});await Integration.deleteMany({userId:u._id});await AutomationLog.deleteMany({userId:u._id});await User.findByIdAndDelete(u._id);res.json({message:"Account deleted"});}catch{res.status(500).json({message:"Error"});}});

// ════════════════════════════════════════════════
// ═══ CONVERSATIONS ROUTES ═══════════════════════
// ════════════════════════════════════════════════

app.get("/conversations",auth,async(req,res)=>{try{res.json(await Conversation.find({userId:req.user.id}).select("title updatedAt _id").sort({updatedAt:-1}).limit(50));}catch{res.status(500).json({message:"Error"});}});
app.get("/conversations/:id",auth,async(req,res)=>{try{const c=await Conversation.findOne({_id:req.params.id,userId:req.user.id});if(!c)return res.status(404).json({message:"Not found"});res.json(c);}catch{res.status(500).json({message:"Error"});}});
app.post("/conversations/save",auth,async(req,res)=>{try{const{conversationId,messages,title}=req.body;if(!Array.isArray(messages)||!messages.length)return res.status(400).json({message:"No messages"});const toSave=messages.filter(m=>m.role!=="system").slice(-100).map(m=>({role:m.role,content:typeof m.content==="string"?m.content.slice(0,5000):m.content}));const ft=toSave.find(m=>m.role==="user");const at=typeof ft?.content==="string"?ft.content.slice(0,50):"New Chat";if(conversationId){await Conversation.findOneAndUpdate({_id:conversationId,userId:req.user.id},{messages:toSave,title:title||at,updatedAt:new Date()});res.json({conversationId});}else{const c=await Conversation.create({userId:req.user.id,title:title||at,messages:toSave});res.json({conversationId:c._id});}}catch{res.status(500).json({message:"Error"});}});
app.delete("/conversations/:id",auth,async(req,res)=>{try{await Conversation.findOneAndDelete({_id:req.params.id,userId:req.user.id});res.json({message:"Deleted"});}catch{res.status(500).json({message:"Error"});}});

// ════════════════════════════════════════════════
// ═══ V2: MEMORY ENGINE ══════════════════════════
// ════════════════════════════════════════════════

// Simple keyword-based semantic similarity (no external vector DB needed)
function keywordScore(query, text) {
  const q = query.toLowerCase().split(/\s+/).filter(w=>w.length>2);
  const t = text.toLowerCase();
  let score = 0;
  for (const word of q) { if (t.includes(word)) score++; }
  return q.length ? score/q.length : 0;
}

async function extractMemoriesFromChat(userId, messages) {
  // Extract important facts from conversation using AI
  const recentMsgs = messages.slice(-6).map(m => `${m.role}: ${typeof m.content==='string'?m.content.slice(0,300):'[file]'}`).join('\n');
  try {
    const prompt = `Extract important personal facts, preferences, goals, or skills mentioned in this conversation. Return JSON array of objects with fields: content (string), category (fact/preference/goal/skill/event/insight/other), tags (string array), importance (1-5). Only extract genuinely important info worth remembering long-term. Return empty array [] if nothing important. JSON only, no explanation.\n\nConversation:\n${recentMsgs}`;
    const r = await fetch("https://openrouter.ai/api/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${process.env.OPENROUTER_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({model:"google/gemini-2.5-flash:free",messages:[{role:"user",content:prompt}],max_tokens:500})});
    if (!r.ok) return;
    const d = await r.json();
    let raw = d?.choices?.[0]?.message?.content||"[]";
    raw = raw.replace(/```json|```/g,'').trim();
    const items = JSON.parse(raw);
    if (!Array.isArray(items)) return;
    for (const item of items.slice(0,5)) {
      if (!item.content || item.content.length < 10) continue;
      await Memory.create({ userId, content:item.content.slice(0,2000), category:item.category||"other", tags:(item.tags||[]).slice(0,5).map(t=>String(t).slice(0,50)), importance:Math.min(5,Math.max(1,item.importance||3)), source:"auto" });
    }
  } catch(e) { console.error("Memory extract error:", e.message); }
}

// GET /memories — list with search
app.get("/memories", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { search, category, tag, page=1, limit=50 } = req.query;
    let query = { userId: req.user.id };
    if (category) query.category = category;
    if (tag) query.tags = tag;
    let memories = await Memory.find(query).sort({importance:-1,updatedAt:-1}).limit(200).lean();
    if (search && search.trim()) {
      const q = search.trim().toLowerCase();
      memories = memories
        .map(m => ({ ...m, _score: keywordScore(q, m.content + ' ' + (m.tags||[]).join(' ') + ' ' + m.summary) }))
        .filter(m => m._score > 0)
        .sort((a,b) => b._score - a._score);
    }
    const total = memories.length;
    const skip = (parseInt(page)-1)*parseInt(limit);
    res.json({ memories: memories.slice(skip, skip+parseInt(limit)), total, page:parseInt(page) });
  } catch { res.status(500).json({message:"Error"}); }
});

// POST /memories — create
app.post("/memories", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { content, category, tags, importance } = req.body;
    if (!content || !content.trim()) return res.status(400).json({message:"Content required"});
    const mem = await Memory.create({
      userId: req.user.id,
      content: sanitize(content).slice(0,2000),
      category: category || "other",
      tags: (tags||[]).slice(0,10).map(t=>sanitize(String(t)).slice(0,50)),
      importance: Math.min(5,Math.max(1,parseInt(importance)||3)),
      source: "manual"
    });
    res.json(mem);
  } catch { res.status(500).json({message:"Error"}); }
});

// PUT /memories/:id — update
app.put("/memories/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { content, category, tags, importance } = req.body;
    const mem = await Memory.findOne({_id:req.params.id, userId:req.user.id});
    if (!mem) return res.status(404).json({message:"Not found"});
    if (content) mem.content = sanitize(content).slice(0,2000);
    if (category) mem.category = category;
    if (tags) mem.tags = (tags||[]).slice(0,10).map(t=>sanitize(String(t)).slice(0,50));
    if (importance) mem.importance = Math.min(5,Math.max(1,parseInt(importance)));
    await mem.save();
    res.json(mem);
  } catch { res.status(500).json({message:"Error"}); }
});

// DELETE /memories/:id
app.delete("/memories/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try { await Memory.findOneAndDelete({_id:req.params.id,userId:req.user.id}); res.json({message:"Deleted"}); } catch { res.status(500).json({message:"Error"}); }
});

// POST /memories/search — semantic search
app.post("/memories/search", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { query, limit=10 } = req.body;
    if (!query) return res.status(400).json({message:"Query required"});
    const all = await Memory.find({userId:req.user.id}).lean();
    const scored = all
      .map(m => ({ ...m, _score: keywordScore(query, m.content+' '+(m.tags||[]).join(' ')+' '+(m.summary||'')) }))
      .filter(m => m._score > 0)
      .sort((a,b) => (b._score*b.importance) - (a._score*a.importance))
      .slice(0, parseInt(limit));
    res.json({ results: scored });
  } catch { res.status(500).json({message:"Error"}); }
});

// ════════════════════════════════════════════════
// ═══ V2: NOTES ROUTES ═══════════════════════════
// ════════════════════════════════════════════════

app.get("/notes", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { search, tag, pinned, page=1, limit=50 } = req.query;
    let query = { userId: req.user.id };
    if (tag) query.tags = tag;
    if (pinned !== undefined) query.pinned = pinned === 'true';
    let notes = await Note.find(query).sort({pinned:-1, updatedAt:-1}).limit(200).lean();
    if (search) {
      const q = search.toLowerCase();
      notes = notes.filter(n => n.title.toLowerCase().includes(q) || n.content.toLowerCase().includes(q));
    }
    const total = notes.length;
    const skip = (parseInt(page)-1)*parseInt(limit);
    res.json({ notes: notes.slice(skip, skip+parseInt(limit)), total });
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/notes", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { title, content, tags, color } = req.body;
    if (!title || !content) return res.status(400).json({message:"Title and content required"});
    const note = await Note.create({
      userId: req.user.id,
      title: sanitize(title).slice(0,200),
      content: content.slice(0,50000),
      tags: (tags||[]).slice(0,10).map(t=>sanitize(String(t)).slice(0,50)),
      color: sanitize(color||"").slice(0,20),
    });
    fireEvent(req.user.id, "note_created", note).catch(()=>{});
    res.json(note);
  } catch { res.status(500).json({message:"Error"}); }
});

app.put("/notes/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { title, content, tags, color, pinned } = req.body;
    const note = await Note.findOne({_id:req.params.id, userId:req.user.id});
    if (!note) return res.status(404).json({message:"Not found"});
    if (title !== undefined) note.title = sanitize(title).slice(0,200);
    if (content !== undefined) note.content = content.slice(0,50000);
    if (tags !== undefined) note.tags = (tags||[]).slice(0,10).map(t=>sanitize(String(t)).slice(0,50));
    if (color !== undefined) note.color = sanitize(color).slice(0,20);
    if (pinned !== undefined) note.pinned = !!pinned;
    await note.save();
    res.json(note);
  } catch { res.status(500).json({message:"Error"}); }
});

app.delete("/notes/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try { await Note.findOneAndDelete({_id:req.params.id,userId:req.user.id}); res.json({message:"Deleted"}); } catch { res.status(500).json({message:"Error"}); }
});

// ════════════════════════════════════════════════
// ═══ V2: GOALS / CEO ROUTES ═════════════════════
// ════════════════════════════════════════════════

app.get("/goals", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { status, category } = req.query;
    let query = { userId: req.user.id };
    if (status) query.status = status;
    if (category) query.category = category;
    const goals = await Goal.find(query).sort({priority:-1,createdAt:-1});
    res.json(goals);
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/goals", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { title, description, category, priority, targetDate } = req.body;
    if (!title) return res.status(400).json({message:"Title required"});
    const goal = await Goal.create({
      userId: req.user.id,
      title: sanitize(title).slice(0,200),
      description: sanitize(description||"").slice(0,2000),
      category: category||"other",
      priority: priority||"medium",
      targetDate: targetDate ? new Date(targetDate) : null,
    });
    fireEvent(req.user.id, "goal_created", goal).catch(()=>{});
    res.json(goal);
  } catch { res.status(500).json({message:"Error"}); }
});

app.put("/goals/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const goal = await Goal.findOne({_id:req.params.id, userId:req.user.id});
    if (!goal) return res.status(404).json({message:"Not found"});
    const fields = ["title","description","category","status","priority","progress","targetDate","milestones"];
    for (const f of fields) {
      if (req.body[f] !== undefined) {
        if (f==="progress") goal.progress = Math.min(100,Math.max(0,parseInt(req.body[f])));
        else if (f==="targetDate") goal.targetDate = req.body[f] ? new Date(req.body[f]) : null;
        else if (f==="milestones") goal.milestones = req.body[f];
        else goal[f] = sanitize(req.body[f]);
      }
    }
    if (req.body.status==="completed" && !goal.completedAt) { goal.completedAt = new Date(); fireEvent(req.user.id, "goal_completed", goal).catch(()=>{}); }
    await goal.save();
    res.json(goal);
  } catch { res.status(500).json({message:"Error"}); }
});

app.delete("/goals/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try { await Goal.findOneAndDelete({_id:req.params.id,userId:req.user.id}); res.json({message:"Deleted"}); } catch { res.status(500).json({message:"Error"}); }
});

// POST /goals/:id/milestone — toggle milestone
app.post("/goals/:id/milestone/:mid", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const goal = await Goal.findOne({_id:req.params.id, userId:req.user.id});
    if (!goal) return res.status(404).json({message:"Not found"});
    const ms = goal.milestones.id(req.params.mid);
    if (!ms) return res.status(404).json({message:"Milestone not found"});
    ms.completed = !ms.completed;
    ms.completedAt = ms.completed ? new Date() : null;
    const done = goal.milestones.filter(m=>m.completed).length;
    goal.progress = goal.milestones.length ? Math.round(done/goal.milestones.length*100) : goal.progress;
    await goal.save();
    res.json(goal);
  } catch { res.status(500).json({message:"Error"}); }
});

// POST /goals/:id/review — add weekly review
app.post("/goals/:id/review", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { note, score } = req.body;
    const goal = await Goal.findOne({_id:req.params.id, userId:req.user.id});
    if (!goal) return res.status(404).json({message:"Not found"});
    const week = new Date().toISOString().slice(0,10);
    goal.weeklyReviews.push({ week, note:sanitize(note||"").slice(0,1000), score:Math.min(10,Math.max(1,parseInt(score)||5)) });
    await goal.save();
    res.json(goal);
  } catch { res.status(500).json({message:"Error"}); }
});

// POST /goals/:id/ai-recommend — AI recommendations for goal
app.post("/goals/:id/ai-recommend", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const goal = await Goal.findOne({_id:req.params.id, userId:req.user.id});
    if (!goal) return res.status(404).json({message:"Not found"});
    const prompt = `Goal: "${goal.title}"\nDescription: ${goal.description||'N/A'}\nProgress: ${goal.progress}%\nCategory: ${goal.category}\nStatus: ${goal.status}\nMilestones: ${goal.milestones.map(m=>m.title+(m.completed?' ✓':'')).join(', ')||'None'}\n\nGive 5 specific, actionable recommendations to achieve this goal faster. Be concrete, not generic. Return JSON array of 5 strings only.`;
    const r = await fetch("https://openrouter.ai/api/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${process.env.OPENROUTER_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({model:"google/gemini-2.5-flash:free",messages:[{role:"user",content:prompt}],max_tokens:600})});
    const d = await r.json();
    let raw = d?.choices?.[0]?.message?.content||"[]";
    raw = raw.replace(/```json|```/g,'').trim();
    const recs = JSON.parse(raw);
    goal.aiRecommendations = Array.isArray(recs) ? recs.slice(0,5).map(r=>String(r).slice(0,300)) : [];
    await goal.save();
    res.json({ recommendations: goal.aiRecommendations });
  } catch { res.status(500).json({message:"Error fetching recommendations"}); }
});

// ════════════════════════════════════════════════
// ═══ V2: PROJECTS ROUTES ════════════════════════
// ════════════════════════════════════════════════

app.get("/projects", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const projects = await Project.find({userId:req.user.id}).sort({updatedAt:-1});
    res.json(projects);
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/projects", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { name, description, type, techStack, targetDate } = req.body;
    if (!name) return res.status(400).json({message:"Name required"});
    const project = await Project.create({
      userId: req.user.id,
      name: sanitize(name).slice(0,200),
      description: sanitize(description||"").slice(0,3000),
      type: type||"web",
      techStack: (techStack||[]).slice(0,20).map(t=>sanitize(String(t)).slice(0,50)),
      targetDate: targetDate ? new Date(targetDate) : null,
    });
    res.json(project);
  } catch { res.status(500).json({message:"Error"}); }
});

app.put("/projects/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const project = await Project.findOne({_id:req.params.id, userId:req.user.id});
    if (!project) return res.status(404).json({message:"Not found"});
    const fields = ["name","description","type","status","progress","techStack","targetDate","requirements","roadmap","dbSchema","apiArchitecture","uiArchitecture","folderStructure","deploymentPlan"];
    for (const f of fields) {
      if (req.body[f] !== undefined) {
        if (f==="progress") project.progress = Math.min(100,Math.max(0,parseInt(req.body[f])));
        else if (f==="targetDate") project.targetDate = req.body[f] ? new Date(req.body[f]) : null;
        else if (f==="techStack") project.techStack = (req.body[f]||[]).slice(0,20);
        else project[f] = req.body[f];
      }
    }
    await project.save();
    res.json(project);
  } catch { res.status(500).json({message:"Error"}); }
});

app.delete("/projects/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    await Project.findOneAndDelete({_id:req.params.id,userId:req.user.id});
    await ProjectTask.deleteMany({projectId:req.params.id, userId:req.user.id});
    res.json({message:"Deleted"});
  } catch { res.status(500).json({message:"Error"}); }
});

// POST /projects/:id/generate/:type — AI generate project artifacts
app.post("/projects/:id/generate/:type", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const validTypes = ["requirements","roadmap","dbSchema","apiArchitecture","uiArchitecture","folderStructure","deploymentPlan"];
    if (!validTypes.includes(req.params.type)) return res.status(400).json({message:"Invalid type"});
    const project = await Project.findOne({_id:req.params.id, userId:req.user.id});
    if (!project) return res.status(404).json({message:"Not found"});

    const typePrompts = {
      requirements: `Generate a detailed software requirements specification for this project. Include functional requirements, non-functional requirements, user stories, and acceptance criteria.`,
      roadmap: `Generate a detailed development roadmap with phases, milestones, and estimated timelines. Break it into clear phases (MVP, v1, v2, etc.).`,
      dbSchema: `Generate a complete database schema. Include all tables/collections, fields, data types, indexes, and relationships. Use appropriate format for the tech stack.`,
      apiArchitecture: `Generate a complete REST API architecture. Include all endpoints, HTTP methods, request/response formats, authentication strategy, and error handling.`,
      uiArchitecture: `Generate a complete UI/UX architecture. Include component hierarchy, page structure, state management approach, and design system recommendations.`,
      folderStructure: `Generate the complete folder/directory structure for this project. Include all files and explain the purpose of each directory.`,
      deploymentPlan: `Generate a complete deployment and DevOps plan. Include CI/CD pipeline, hosting recommendations, environment setup, monitoring, and scaling strategy.`,
    };

    const prompt = `Project: "${project.name}"\nType: ${project.type}\nDescription: ${project.description||'N/A'}\nTech Stack: ${(project.techStack||[]).join(', ')||'Not specified'}\n\n${typePrompts[req.params.type]}\n\nBe specific, practical, and production-ready. Use markdown formatting.`;

    const r = await fetch("https://openrouter.ai/api/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${process.env.OPENROUTER_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({model:"google/gemini-2.5-flash:free",messages:[{role:"user",content:prompt}],max_tokens:2000})});
    const d = await r.json();
    const content = d?.choices?.[0]?.message?.content||"";
    if (!content) return res.status(500).json({message:"AI generation failed"});

    project[req.params.type] = content;
    await project.save();
    res.json({ content, type: req.params.type });
  } catch { res.status(500).json({message:"Generation error"}); }
});

// Project Tasks CRUD
app.get("/projects/:id/tasks", auth, checkBlocked, apiLimiter, async (req,res) => {
  try { const tasks=await ProjectTask.find({projectId:req.params.id,userId:req.user.id}).sort({order:1,status:1}); res.json(tasks); } catch { res.status(500).json({message:"Error"}); }
});
app.post("/projects/:id/tasks", auth, checkBlocked, apiLimiter, async (req,res) => {
  try { const {title,description,priority,dueDate}=req.body; if(!title)return res.status(400).json({message:"Title required"}); const task=await ProjectTask.create({userId:req.user.id,projectId:req.params.id,title:sanitize(title).slice(0,300),description:sanitize(description||"").slice(0,2000),priority:priority||"medium",dueDate:dueDate?new Date(dueDate):null}); res.json(task); } catch { res.status(500).json({message:"Error"}); }
});
app.put("/projects/:pid/tasks/:tid", auth, checkBlocked, apiLimiter, async (req,res) => {
  try { const task=await ProjectTask.findOne({_id:req.params.tid,userId:req.user.id,projectId:req.params.pid}); if(!task)return res.status(404).json({message:"Not found"}); const fields=["title","description","status","priority","dueDate","order"]; for(const f of fields){if(req.body[f]!==undefined){if(f==="dueDate")task[f]=req.body[f]?new Date(req.body[f]):null;else task[f]=req.body[f];}} if(req.body.status==="done"&&!task.completedAt)task.completedAt=new Date(); await task.save(); res.json(task); } catch { res.status(500).json({message:"Error"}); }
});
app.delete("/projects/:pid/tasks/:tid", auth, checkBlocked, apiLimiter, async (req,res) => {
  try { await ProjectTask.findOneAndDelete({_id:req.params.tid,userId:req.user.id}); res.json({message:"Deleted"}); } catch { res.status(500).json({message:"Error"}); }
});

// ════════════════════════════════════════════════
// ═══ V2: TASKS (LIFE OS) ════════════════════════
// ════════════════════════════════════════════════

app.get("/tasks", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { status, priority, category, date, goalId } = req.query;
    let query = { userId: req.user.id };
    if (status) query.status = status;
    if (priority) query.priority = priority;
    if (category) query.category = category;
    if (goalId) query.goalId = goalId;
    if (date) { const d=new Date(date); const nd=new Date(d); nd.setDate(nd.getDate()+1); query.dueDate={$gte:d,$lt:nd}; }
    const tasks = await Task.find(query).sort({priority:-1,dueDate:1,createdAt:-1}).limit(200);
    res.json(tasks);
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/tasks", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { title, description, priority, category, dueDate, dueTime, recurring, goalId, tags } = req.body;
    if (!title) return res.status(400).json({message:"Title required"});
    const task = await Task.create({
      userId: req.user.id,
      title: sanitize(title).slice(0,300),
      description: sanitize(description||"").slice(0,2000),
      priority: priority||"medium",
      category: sanitize(category||"general").slice(0,50),
      dueDate: dueDate?new Date(dueDate):null,
      dueTime: sanitize(dueTime||"").slice(0,10),
      recurring: recurring||"none",
      goalId: goalId||null,
      tags: (tags||[]).slice(0,10).map(t=>sanitize(String(t)).slice(0,50)),
    });
    fireEvent(req.user.id, "task_created", task).catch(()=>{});
    res.json(task);
  } catch { res.status(500).json({message:"Error"}); }
});

app.put("/tasks/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const task = await Task.findOne({_id:req.params.id, userId:req.user.id});
    if (!task) return res.status(404).json({message:"Not found"});
    const fields = ["title","description","status","priority","category","dueDate","dueTime","recurring","goalId","tags"];
    for (const f of fields) {
      if (req.body[f] !== undefined) {
        if (f==="dueDate") task[f] = req.body[f]?new Date(req.body[f]):null;
        else task[f] = req.body[f];
      }
    }
    if (req.body.status==="done" && !task.completedAt) {
      task.completedAt = new Date();
      fireEvent(req.user.id, "task_completed", task).catch(()=>{});
      // Update daily analytics
      const today = todayStr();
      await Analytics.findOneAndUpdate({userId:req.user.id,date:today},{$inc:{tasksCompleted:1}},{upsert:true,new:true});
    }
    await task.save();
    res.json(task);
  } catch { res.status(500).json({message:"Error"}); }
});

app.delete("/tasks/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try { await Task.findOneAndDelete({_id:req.params.id,userId:req.user.id}); res.json({message:"Deleted"}); } catch { res.status(500).json({message:"Error"}); }
});

// POST /tasks/ai-plan — AI generate daily plan
app.post("/tasks/ai-plan", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { date, context } = req.body;
    const targetDate = date || todayStr();
    const goals = await Goal.find({userId:req.user.id, status:"active"}).limit(5).lean();
    const habits = await Habit.find({userId:req.user.id, active:true}).limit(10).lean();
    const existingTasks = await Task.find({userId:req.user.id,status:{$ne:"done"}}).sort({priority:-1}).limit(10).lean();

    const prompt = `Create a daily task plan for ${targetDate}.\nActive Goals: ${goals.map(g=>g.title).join(', ')||'None'}\nHabits to track: ${habits.map(h=>h.name).join(', ')||'None'}\nPending tasks: ${existingTasks.map(t=>t.title).join(', ')||'None'}\nContext: ${context||'General productivity'}\n\nGenerate 5-8 specific tasks for today. Return JSON array of objects with: title, description, priority (low/medium/high/urgent), category, dueTime (HH:MM or empty). JSON only.`;

    const r = await fetch("https://openrouter.ai/api/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${process.env.OPENROUTER_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({model:"google/gemini-2.5-flash:free",messages:[{role:"user",content:prompt}],max_tokens:800})});
    const d = await r.json();
    let raw = d?.choices?.[0]?.message?.content||"[]";
    raw = raw.replace(/```json|```/g,'').trim();
    const items = JSON.parse(raw);
    const created = [];
    for (const item of (Array.isArray(items)?items:[]).slice(0,8)) {
      if (!item.title) continue;
      const task = await Task.create({userId:req.user.id, title:String(item.title).slice(0,300), description:String(item.description||"").slice(0,500), priority:item.priority||"medium", category:String(item.category||"general").slice(0,50), dueDate:new Date(targetDate), dueTime:String(item.dueTime||"").slice(0,10)});
      created.push(task);
    }
    res.json({ tasks: created });
  } catch { res.status(500).json({message:"Failed to generate plan"}); }
});

// ════════════════════════════════════════════════
// ═══ V2: HABITS ROUTES ══════════════════════════
// ════════════════════════════════════════════════

app.get("/habits", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const habits = await Habit.find({userId:req.user.id, active:true}).sort({createdAt:-1});
    res.json(habits);
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/habits", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { name, description, icon, color, frequency, targetDays } = req.body;
    if (!name) return res.status(400).json({message:"Name required"});
    const habit = await Habit.create({
      userId: req.user.id,
      name: sanitize(name).slice(0,200),
      description: sanitize(description||"").slice(0,500),
      icon: sanitize(icon||"⭐").slice(0,10),
      color: sanitize(color||"#6c8eff").slice(0,20),
      frequency: frequency||"daily",
      targetDays: targetDays||[],
    });
    res.json(habit);
  } catch { res.status(500).json({message:"Error"}); }
});

app.put("/habits/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const habit = await Habit.findOne({_id:req.params.id, userId:req.user.id});
    if (!habit) return res.status(404).json({message:"Not found"});
    const fields = ["name","description","icon","color","frequency","targetDays","active"];
    for (const f of fields) { if (req.body[f] !== undefined) habit[f] = req.body[f]; }
    await habit.save();
    res.json(habit);
  } catch { res.status(500).json({message:"Error"}); }
});

app.delete("/habits/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try { await Habit.findOneAndDelete({_id:req.params.id,userId:req.user.id}); res.json({message:"Deleted"}); } catch { res.status(500).json({message:"Error"}); }
});

// POST /habits/:id/complete — mark habit done for a date
app.post("/habits/:id/complete", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { date, note } = req.body;
    const dateStr = date || todayStr();
    const habit = await Habit.findOne({_id:req.params.id, userId:req.user.id});
    if (!habit) return res.status(404).json({message:"Not found"});
    const existing = habit.completions.find(c=>c.date===dateStr);
    if (existing) {
      habit.completions = habit.completions.filter(c=>c.date!==dateStr);
    } else {
      habit.completions.push({ date:dateStr, note:sanitize(note||"").slice(0,200) });
      fireEvent(req.user.id, "habit_completed", habit).catch(()=>{});
    }
    // Cap at 180 entries (H2)
    if (habit.completions.length > 180) habit.completions = habit.completions.sort((a,b)=>b.date.localeCompare(a.date)).slice(0,180);
    
    // Recalculate streak (M9)
    const sorted = [...habit.completions].sort((a,b)=>b.date.localeCompare(a.date));
    let streak = 0;
    let currentCheck = todayStr();
    if (sorted[0] && sorted[0].date !== currentCheck) {
      const y = new Date(); y.setDate(y.getDate()-1);
      currentCheck = y.toISOString().slice(0,10);
    }
    for (const comp of sorted) {
      if (comp.date === currentCheck) {
        streak++;
        const prev = new Date(currentCheck); prev.setDate(prev.getDate()-1);
        currentCheck = prev.toISOString().slice(0,10);
      } else if (comp.date < currentCheck) { break; }
    }
    habit.streak = streak;
    if (streak > habit.longestStreak) habit.longestStreak = streak;
    // Analytics
    if (!existing) {
      const today = todayStr();
      await Analytics.findOneAndUpdate({userId:req.user.id,date:today},{$inc:{habitsCompleted:1}},{upsert:true,new:true});
    }
    await habit.save();
    res.json(habit);
  } catch { res.status(500).json({message:"Error"}); }
});

// ════════════════════════════════════════════════
// ═══ V2: CALENDAR ROUTES ════════════════════════
// ════════════════════════════════════════════════

app.get("/calendar", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { start, end } = req.query;
    let query = { userId: req.user.id };
    if (start || end) {
      query.startDate = {};
      if (start) query.startDate.$gte = new Date(start);
      if (end) query.startDate.$lte = new Date(end);
    }
    const events = await CalendarEvent.find(query).sort({startDate:1}).limit(200);
    res.json(events);
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/calendar", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { title, description, startDate, endDate, allDay, category, color, location, recurring, reminder, goalId, taskId } = req.body;
    if (!title || !startDate || !endDate) return res.status(400).json({message:"Title, startDate, endDate required"});
    const event = await CalendarEvent.create({
      userId: req.user.id,
      title: sanitize(title).slice(0,200),
      description: sanitize(description||"").slice(0,2000),
      startDate: new Date(startDate),
      endDate: new Date(endDate),
      allDay: !!allDay,
      category: sanitize(category||"general").slice(0,50),
      color: sanitize(color||"#6c8eff").slice(0,20),
      location: sanitize(location||"").slice(0,200),
      recurring: recurring||"none",
      reminder: parseInt(reminder||0),
      goalId: goalId||null,
      taskId: taskId||null,
    });
    res.json(event);
  } catch { res.status(500).json({message:"Error"}); }
});

app.put("/calendar/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const event = await CalendarEvent.findOne({_id:req.params.id, userId:req.user.id});
    if (!event) return res.status(404).json({message:"Not found"});
    const fields = ["title","description","startDate","endDate","allDay","category","color","location","recurring","reminder","goalId","taskId"];
    for (const f of fields) {
      if (req.body[f] !== undefined) {
        if (f==="startDate"||f==="endDate") event[f] = new Date(req.body[f]);
        else event[f] = req.body[f];
      }
    }
    await event.save();
    res.json(event);
  } catch { res.status(500).json({message:"Error"}); }
});

app.delete("/calendar/:id", auth, checkBlocked, apiLimiter, async (req,res) => {
  try { await CalendarEvent.findOneAndDelete({_id:req.params.id,userId:req.user.id}); res.json({message:"Deleted"}); } catch { res.status(500).json({message:"Error"}); }
});

// ════════════════════════════════════════════════
// ═══ V2: ANALYTICS ENGINE ═══════════════════════
// ════════════════════════════════════════════════

function calculateProductivityScore(data) {
  let score = 0;
  const maxTasks = 10, maxHabits = 1;
  score += Math.min(40, (data.tasksCompleted / maxTasks) * 40);
  score += Math.min(30, data.habitsTotal > 0 ? (data.habitsCompleted / data.habitsTotal) * 30 : 0);
  score += Math.min(20, (data.goalsProgress / 100) * 20);
  score += data.mood ? (data.mood / 5) * 10 : 5;
  return Math.round(Math.min(100, score));
}

app.get("/analytics/today", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const today = todayStr();
    const [tasksTotal, tasksDone, habits, habitsToday] = await Promise.all([
      Task.countDocuments({userId:req.user.id}),
      Task.countDocuments({userId:req.user.id,status:"done",completedAt:{$gte:new Date(today)}}),
      Habit.find({userId:req.user.id,active:true}).lean(),
      Analytics.findOne({userId:req.user.id,date:today}),
    ]);
    const habitsTotal = habits.length;
    const habitsCompleted = habits.filter(h=>h.completions?.some(c=>c.date===today)).length;
    const goalsActive = await Goal.countDocuments({userId:req.user.id,status:"active"});
    const goalsCompleted = await Goal.countDocuments({userId:req.user.id,status:"completed"});
    const avgProgress = goalsActive > 0 ? (await Goal.aggregate([{$match:{userId:new mongoose.Types.ObjectId(req.user.id),status:"active"}},{$group:{_id:null,avg:{$avg:"$progress"}}}]))[0]?.avg||0 : 0;
    const data = { tasksCompleted:tasksDone, habitsCompleted, habitsTotal, goalsProgress:avgProgress, mood:habitsToday?.mood||null };
    const productivityScore = calculateProductivityScore(data);
    await Analytics.findOneAndUpdate({userId:req.user.id,date:today},{...data,productivityScore,habitsTotal,messagesCount:(habitsToday?.messagesCount||0)},{upsert:true,new:true});
    res.json({ date:today, tasksCompleted:tasksDone, tasksTotal, habitsCompleted, habitsTotal, goalsActive, goalsCompleted, avgGoalProgress:Math.round(avgProgress), productivityScore, mood:habitsToday?.mood||null });
  } catch { res.status(500).json({message:"Error"}); }
});

app.get("/analytics/week", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const end = new Date(); const start = new Date(); start.setDate(start.getDate()-6);
    const startStr = start.toISOString().slice(0,10);
    const records = await Analytics.find({userId:req.user.id,date:{$gte:startStr}}).sort({date:1});
    res.json(records);
  } catch { res.status(500).json({message:"Error"}); }
});

app.get("/analytics/month", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const end = new Date(); const start = new Date(); start.setDate(start.getDate()-29);
    const startStr = start.toISOString().slice(0,10);
    const records = await Analytics.find({userId:req.user.id,date:{$gte:startStr}}).sort({date:1});
    res.json(records);
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/analytics/mood", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const { mood, date } = req.body;
    const d = date || todayStr();
    if (!mood || mood < 1 || mood > 5) return res.status(400).json({message:"Mood must be 1-5"});
    await Analytics.findOneAndUpdate({userId:req.user.id,date:d},{mood:parseInt(mood)},{upsert:true,new:true});
    res.json({message:"Mood logged"});
  } catch { res.status(500).json({message:"Error"}); }
});

// POST /analytics/weekly-report — AI weekly report
app.post("/analytics/weekly-report", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const end = new Date(); const start = new Date(); start.setDate(start.getDate()-6);
    const startStr = start.toISOString().slice(0,10);
    const [records, goals, habits, tasks] = await Promise.all([
      Analytics.find({userId:req.user.id,date:{$gte:startStr}}).sort({date:1}).lean(),
      Goal.find({userId:req.user.id,status:"active"}).limit(5).lean(),
      Habit.find({userId:req.user.id,active:true}).lean(),
      Task.find({userId:req.user.id,status:"done",completedAt:{$gte:start}}).lean(),
    ]);
    const totalTasks = tasks.length;
    const avgScore = records.length ? Math.round(records.reduce((s,r)=>s+(r.productivityScore||0),0)/records.length) : 0;
    const habitStats = habits.map(h=>({ name:h.name, completed:h.completions?.filter(c=>c.date>=startStr).length||0 }));
    const prompt = `Weekly productivity report (${startStr} to ${end.toISOString().slice(0,10)}):\n- Tasks completed: ${totalTasks}\n- Average productivity score: ${avgScore}/100\n- Active goals: ${goals.map(g=>g.title+' ('+g.progress+'%)').join(', ')||'None'}\n- Habit performance: ${habitStats.map(h=>h.name+': '+h.completed+'/7 days').join(', ')||'None'}\n- Daily scores: ${records.map(r=>r.date+': '+r.productivityScore).join(', ')||'No data'}\n\nGenerate a concise, motivating weekly performance review. Include: what went well, areas to improve, and 3 specific action items for next week. Use markdown formatting.`;
    const r = await fetch("https://openrouter.ai/api/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${process.env.OPENROUTER_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({model:"google/gemini-2.5-flash:free",messages:[{role:"user",content:prompt}],max_tokens:800})});
    const d = await r.json();
    const report = d?.choices?.[0]?.message?.content||"Unable to generate report.";
    res.json({ report, stats:{ totalTasks, avgScore, habitStats, period:{ start:startStr, end:end.toISOString().slice(0,10) } } });
  } catch { res.status(500).json({message:"Report generation failed"}); }
});

app.post("/analytics/monthly-report", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const end = new Date(); const start = new Date(); start.setDate(start.getDate()-29);
    const startStr = start.toISOString().slice(0,10);
    const [records, goals, tasks] = await Promise.all([
      Analytics.find({userId:req.user.id,date:{$gte:startStr}}).lean(),
      Goal.find({userId:req.user.id}).lean(),
      Task.find({userId:req.user.id,status:"done",completedAt:{$gte:start}}).lean(),
    ]);
    const completedGoals = goals.filter(g=>g.status==="completed").length;
    const avgScore = records.length ? Math.round(records.reduce((s,r)=>s+(r.productivityScore||0),0)/records.length) : 0;
    const prompt = `Monthly performance analysis (last 30 days):\n- Tasks completed: ${tasks.length}\n- Average productivity score: ${avgScore}/100\n- Goals completed: ${completedGoals}/${goals.length}\n- Active goals: ${goals.filter(g=>g.status==="active").map(g=>g.title+' ('+g.progress+'%)').join(', ')||'None'}\n\nGenerate a comprehensive monthly performance review. Include: achievements, patterns observed, goal analysis, and strategic recommendations for next month. Use markdown formatting.`;
    const r = await fetch("https://openrouter.ai/api/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${process.env.OPENROUTER_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({model:"google/gemini-2.5-flash:free",messages:[{role:"user",content:prompt}],max_tokens:1000})});
    const d = await r.json();
    const report = d?.choices?.[0]?.message?.content||"Unable to generate report.";
    res.json({ report, stats:{ tasksCompleted:tasks.length, avgScore, completedGoals, totalGoals:goals.length } });
  } catch { res.status(500).json({message:"Report generation failed"}); }
});

// ════════════════════════════════════════════════
// ═══ V2: INTEGRATIONS ROUTES ════════════════════
// ════════════════════════════════════════════════

app.get("/integrations", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const integrations = await Integration.find({userId:req.user.id}).select("-accessToken -refreshToken");
    const available = ["gmail","github","googledrive","googlecalendar","notion"];
    const result = available.map(svc => {
      const found = integrations.find(i=>i.service===svc);
      return { service:svc, connected:!!found, active:found?.active||false, lastSyncAt:found?.lastSyncAt||null, metadata:found?.metadata||{} };
    });
    res.json(result);
  } catch { res.status(500).json({message:"Error"}); }
});

// POST /integrations/:service/connect — store token (user provides PAT or API key)
app.post("/integrations/:service/connect", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const validServices = ["gmail","github","googledrive","googlecalendar","notion"];
    if (!validServices.includes(req.params.service)) return res.status(400).json({message:"Invalid service"});
    const { accessToken, metadata } = req.body;
    if (!accessToken) return res.status(400).json({message:"Access token required"});
    const encrypted = encryptToken(accessToken);
    await Integration.findOneAndUpdate(
      { userId:req.user.id, service:req.params.service },
      { accessToken:encrypted, metadata:metadata||{}, active:true, lastSyncAt:null },
      { upsert:true, new:true }
    );
    await AutomationLog.create({ userId:req.user.id, service:req.params.service, action:"connect", status:"success", details:{} });
    res.json({message:`${req.params.service} connected`});
  } catch { res.status(500).json({message:"Error"}); }
});

app.delete("/integrations/:service", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    await Integration.findOneAndDelete({userId:req.user.id, service:req.params.service});
    await AutomationLog.create({ userId:req.user.id, service:req.params.service, action:"disconnect", status:"success" });
    res.json({message:"Integration removed"});
  } catch { res.status(500).json({message:"Error"}); }
});

// GET /integrations/logs
app.get("/integrations/logs", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const logs = await AutomationLog.find({userId:req.user.id}).sort({createdAt:-1}).limit(100);
    res.json(logs);
  } catch { res.status(500).json({message:"Error"}); }
});

// POST /integrations/github/repos — fetch repos via GitHub API
app.post("/integrations/github/repos", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const integration = await Integration.findOne({userId:req.user.id, service:"github", active:true});
    if (!integration) return res.status(400).json({message:"GitHub not connected"});
    const token = decryptToken(integration.accessToken);
    const r = await fetch("https://api.github.com/user/repos?sort=updated&per_page=20",{headers:{Authorization:`token ${token}`,Accept:"application/vnd.github.v3+json","User-Agent":"SG-ChatBOT"}});
    if (!r.ok) return res.status(400).json({message:"GitHub API error. Check your token."});
    const repos = await r.json();
    integration.lastSyncAt = new Date();
    await integration.save();
    await AutomationLog.create({userId:req.user.id,service:"github",action:"fetch_repos",status:"success",details:{count:repos.length}});
    res.json(repos.map(r=>({id:r.id,name:r.full_name,description:r.description,url:r.html_url,language:r.language,stars:r.stargazers_count,updatedAt:r.updated_at,private:r.private})));
  } catch { res.status(500).json({message:"Error fetching repos"}); }
});

// POST /integrations/notion/pages — fetch Notion pages
app.post("/integrations/notion/pages", auth, checkBlocked, apiLimiter, async (req,res) => {
  try {
    const integration = await Integration.findOne({userId:req.user.id, service:"notion", active:true});
    if (!integration) return res.status(400).json({message:"Notion not connected"});
    const token = decryptToken(integration.accessToken);
    const r = await fetch("https://api.notion.com/v1/search",{method:"POST",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json","Notion-Version":"2022-06-28"},body:JSON.stringify({filter:{value:"page",property:"object"},page_size:20})});
    if (!r.ok) return res.status(400).json({message:"Notion API error. Check your token."});
    const data = await r.json();
    integration.lastSyncAt = new Date();
    await integration.save();
    await AutomationLog.create({userId:req.user.id,service:"notion",action:"fetch_pages",status:"success"});
    const pages = (data.results||[]).map(p=>({ id:p.id, title:(p.properties?.title?.title?.[0]?.plain_text||p.properties?.Name?.title?.[0]?.plain_text||"Untitled"), url:p.url, lastEdited:p.last_edited_time }));
    res.json(pages);
  } catch { res.status(500).json({message:"Error fetching Notion pages"}); }
});

// ════════════════════════════════════════════════
// ═══ ADMIN ROUTES ═══════════════════════════════
// ════════════════════════════════════════════════

app.get("/admin/payments", adminLimiter, adminAuth, async (req,res) => { try { res.json(await Payment.find().sort({createdAt:-1})); } catch { res.status(500).json({message:"Error"}); } });
app.post("/admin/approve/:id", adminLimiter, adminAuth, async (req,res) => { try { const p=await Payment.findById(req.params.id); if (!p) return res.status(404).json({message:"Not found"}); p.status="approved"; await p.save(); const u=await User.findById(p.userId); if (!u) return res.status(404).json({message:"User not found"}); const exp=new Date(); p.plan==="monthly"?exp.setMonth(exp.getMonth()+1):exp.setFullYear(exp.getFullYear()+1); u.plan="pro"; u.proExpiresAt=exp; await u.save(); res.json({message:`Pro activated for ${u.email} until ${exp.toDateString()}`}); } catch { res.status(500).json({message:"Error"}); } });
app.post("/admin/reject/:id", adminLimiter, adminAuth, async (req,res) => { try { const p=await Payment.findById(req.params.id); if (!p) return res.status(404).json({message:"Not found"}); p.status="rejected"; await p.save(); res.json({message:"Rejected"}); } catch { res.status(500).json({message:"Error"}); } });
app.get("/admin/users", adminLimiter, adminAuth, async (req,res) => { try { const page=parseInt(req.query.page)||1, limit=parseInt(req.query.limit)||50; const search=req.query.search||"", filter=req.query.filter||"all"; let query={}; if (search) query.email={$regex:search,$options:"i"}; if (filter==="pro") query.plan="pro"; if (filter==="free") query.plan="free"; if (filter==="blocked") query.isBlocked=true; const total=await User.countDocuments(query); const users=await User.find(query).select("-password -resetToken").sort({createdAt:-1}).skip((page-1)*limit).limit(limit); res.json({users,total,page,pages:Math.ceil(total/limit)}); } catch { res.status(500).json({message:"Error"}); } });
app.get("/admin/stats", adminLimiter, adminAuth, async (req,res) => { try { const total=await User.countDocuments(); const pro=await User.countDocuments({plan:"pro"}); const blocked=await User.countDocuments({isBlocked:true}); const today=new Date(); today.setHours(0,0,0,0); const newToday=await User.countDocuments({createdAt:{$gte:today}}); const week=new Date(Date.now()-7*24*3600000); const newWeek=await User.countDocuments({createdAt:{$gte:week}}); const revData=await Payment.aggregate([{$match:{status:"approved"}},{$group:{_id:null,total:{$sum:"$amount"},count:{$sum:1}}}]); const revenue=revData[0]?.total||0, totalPayments=revData[0]?.count||0; const sixAgo=new Date(); sixAgo.setMonth(sixAgo.getMonth()-6); const monthlyRevenue=await Payment.aggregate([{$match:{status:"approved",createdAt:{$gte:sixAgo}}},{$group:{_id:{y:{$year:"$createdAt"},m:{$month:"$createdAt"}},revenue:{$sum:"$amount"},count:{$sum:1}}},{$sort:{"_id.y":1,"_id.m":1}}]); const signupsByDay=await User.aggregate([{$match:{createdAt:{$gte:week}}},{$group:{_id:{$dateToString:{format:"%Y-%m-%d",date:"$createdAt"}},count:{$sum:1}}},{$sort:{_id:1}}]); const pendingPayments=await Payment.countDocuments({status:"pending"}); const unresolved=await SecurityLog.countDocuments({resolved:false}); const critical=await SecurityLog.countDocuments({severity:"critical",resolved:false}); const totalMemories=await Memory.countDocuments(); const totalGoals=await Goal.countDocuments(); const totalProjects=await Project.countDocuments(); res.json({total,pro,free:total-pro,blocked,newToday,newWeek,revenue,totalPayments,monthlyRevenue,signupsByDay,pendingPayments,unresolved,critical,totalMemories,totalGoals,totalProjects}); } catch { res.status(500).json({message:"Error"}); } });
app.post("/admin/users/:id/block", adminLimiter, adminAuth, async (req,res) => { try { const u=await User.findById(req.params.id); if (!u) return res.status(404).json({message:"Not found"}); u.isBlocked=true; u.blockedReason=sanitize(req.body.reason)||"Admin action"; u.blockedAt=new Date(); await u.save(); res.json({message:`${u.email} blocked`}); } catch { res.status(500).json({message:"Error"}); } });
app.post("/admin/users/:id/unblock", adminLimiter, adminAuth, async (req,res) => { try { const u=await User.findById(req.params.id); if (!u) return res.status(404).json({message:"Not found"}); u.isBlocked=false; u.blockedReason=""; u.blockedAt=null; await u.save(); res.json({message:`${u.email} unblocked`}); } catch { res.status(500).json({message:"Error"}); } });

// Safety / Account Restriction System (item 4). Violations are ALWAYS admin-issued — never automatic
// — and follow fixed, reviewable thresholds: 1st = warning only, 2nd = 24h suspension, 3rd = 7-day
// suspension, 4th+ = permanent block (reuses the existing isBlocked mechanism above).
app.post("/admin/users/:id/violation", adminLimiter, adminAuth, async (req,res) => {
  try {
    const u=await User.findById(req.params.id);
    if (!u) return res.status(404).json({message:"Not found"});
    const reason=sanitize(req.body.reason||"Policy violation").slice(0,300);
    u.violationCount=(u.violationCount||0)+1;
    u.suspensionReason=reason;
    let action, suspendedUntil=null;
    if (u.violationCount===1) { action="warning"; }
    else if (u.violationCount===2) { suspendedUntil=new Date(Date.now()+24*3600*1000); u.suspendedUntil=suspendedUntil; action="suspended_24h"; }
    else if (u.violationCount===3) { suspendedUntil=new Date(Date.now()+7*24*3600*1000); u.suspendedUntil=suspendedUntil; action="suspended_7d"; }
    else { u.isBlocked=true; u.blockedReason=reason; u.blockedAt=new Date(); action="permanently_blocked"; }
    await u.save();
    await logSecurityEvent("admin_violation_issued","high",req,{targetUser:u.email,violationCount:u.violationCount,action,reason}).catch(()=>{});
    res.json({message:`Violation #${u.violationCount} recorded for ${u.email}`,action,violationCount:u.violationCount,suspendedUntil,isBlocked:u.isBlocked});
  } catch { res.status(500).json({message:"Error"}); }
});
app.post("/admin/users/:id/clear-violations", adminLimiter, adminAuth, async (req,res) => {
  try {
    const u=await User.findById(req.params.id);
    if (!u) return res.status(404).json({message:"Not found"});
    u.violationCount=0; u.suspendedUntil=null; u.suspensionReason="";
    await u.save();
    res.json({message:`Violations cleared for ${u.email}`});
  } catch { res.status(500).json({message:"Error"}); }
});
app.post("/admin/users/:id/grant-pro", adminLimiter, adminAuth, async (req,res) => { try { const u=await User.findById(req.params.id); if (!u) return res.status(404).json({message:"Not found"}); const exp=new Date(); exp.setMonth(exp.getMonth()+(parseInt(req.body.months)||1)); u.plan="pro"; u.proExpiresAt=exp; await u.save(); res.json({message:`Pro granted until ${exp.toDateString()}`}); } catch { res.status(500).json({message:"Error"}); } });
app.post("/admin/users/:id/revoke-pro", adminLimiter, adminAuth, async (req,res) => { try { const u=await User.findById(req.params.id); if (!u) return res.status(404).json({message:"Not found"}); u.plan="free"; u.proExpiresAt=null; await u.save(); res.json({message:"Pro revoked"}); } catch { res.status(500).json({message:"Error"}); } });
app.delete("/admin/users/:id", adminLimiter, adminAuth, async (req,res) => { try { const u=await User.findById(req.params.id); if (!u) return res.status(404).json({message:"Not found"}); await Conversation.deleteMany({userId:u._id}); await Payment.deleteMany({userId:u._id}); await Memory.deleteMany({userId:u._id}); await Note.deleteMany({userId:u._id}); await Goal.deleteMany({userId:u._id}); await Project.deleteMany({userId:u._id}); await ProjectTask.deleteMany({userId:u._id}); await Task.deleteMany({userId:u._id}); await Habit.deleteMany({userId:u._id}); await CalendarEvent.deleteMany({userId:u._id}); await Analytics.deleteMany({userId:u._id}); await Integration.deleteMany({userId:u._id}); await AutomationLog.deleteMany({userId:u._id}); await User.findByIdAndDelete(u._id); res.json({message:`${u.email} deleted`}); } catch { res.status(500).json({message:"Error"}); } });
app.get("/admin/security/logs", adminLimiter, adminAuth, async (req,res) => { try { const page=parseInt(req.query.page)||1, limit=parseInt(req.query.limit)||50; let query={}; if (req.query.severity) query.severity=req.query.severity; if (req.query.resolved!==undefined) query.resolved=req.query.resolved==="true"; const total=await SecurityLog.countDocuments(query); const logs=await SecurityLog.find(query).sort({createdAt:-1}).skip((page-1)*limit).limit(limit); const unresolved=await SecurityLog.countDocuments({resolved:false}); const critical=await SecurityLog.countDocuments({severity:"critical",resolved:false}); res.json({logs,total,unresolved,critical,page,pages:Math.ceil(total/limit)}); } catch { res.status(500).json({message:"Error"}); } });
app.patch("/admin/security/logs/:id/resolve", adminLimiter, adminAuth, async (req,res) => { try { await SecurityLog.findByIdAndUpdate(req.params.id,{resolved:true,resolvedAt:new Date()}); res.json({message:"Resolved"}); } catch { res.status(500).json({message:"Error"}); } });
app.delete("/admin/security/logs/resolved", adminLimiter, adminAuth, async (req,res) => { try { await SecurityLog.deleteMany({resolved:true}); res.json({message:"Cleared"}); } catch { res.status(500).json({message:"Error"}); } });
app.get("/admin/security/blocked-ips", adminLimiter, adminAuth, async (req,res) => { try { res.json(await BlockedIP.find().sort({createdAt:-1})); } catch { res.status(500).json({message:"Error"}); } });
app.post("/admin/security/block-ip", adminLimiter, adminAuth, async (req,res) => { try { const {ip,reason,expiresInHours}=req.body; if (!ip) return res.status(400).json({message:"IP required"}); const expiresAt=expiresInHours?new Date(Date.now()+expiresInHours*3600000):null; await BlockedIP.findOneAndUpdate({ip},{ip,reason:sanitize(reason)||"Admin block",blockedBy:"admin",expiresAt},{upsert:true,new:true}); await logSecurityEvent("ip_manually_blocked","medium",req,{ip,reason}); res.json({message:`IP ${ip} blocked`}); } catch { res.status(500).json({message:"Error"}); } });
app.delete("/admin/security/blocked-ips/:ip", adminLimiter, adminAuth, async (req,res) => { try { await BlockedIP.deleteOne({ip:req.params.ip}); res.json({message:"IP unblocked"}); } catch { res.status(500).json({message:"Error"}); } });
app.post("/admin/broadcast", adminLimiter, adminAuth, async (req,res) => {
  try {
    const {subject,message,proOnly}=req.body;
    if (!subject||!message) return res.status(400).json({message:"Subject and message required"});
    const escapeHtml = (unsafe) => unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    const safeMsg = escapeHtml(message);
    const users=await User.find(proOnly?{plan:"pro",isBlocked:false}:{isBlocked:false}).select("email");
    const html = `<div style="font-family:sans-serif;max-width:500px;margin:0 auto;background:#0b0f17;color:#e4ecf7;padding:28px;border-radius:14px;border:1px solid rgba(79,142,255,0.2)"><h2 style="color:#4f8eff">SG ChatBOT</h2><div style="margin:16px 0;line-height:1.7">${safeMsg}</div></div>`;
    const batchSize = 20;
    let sent = 0;
    for (let i = 0; i < users.length; i += batchSize) {
      const batch = users.slice(i, i + batchSize);
      const results = await Promise.allSettled(batch.map(u => sendEmail(u.email, subject, html)));
      sent += results.filter(r => r.status === "fulfilled" && r.value).length;
    }
    res.json({message:`Sent to ${sent}/${users.length} users`});
  } catch(err) { console.error("Broadcast error:", err); res.status(500).json({message:"Error"}); }
});
app.get("/admin/system/health", adminLimiter, adminAuth, async (req,res) => { try { const db=mongoose.connection.readyState, up=process.uptime(), mem=process.memoryUsage(); const counts={users:await User.countDocuments(),memories:await Memory.countDocuments(),goals:await Goal.countDocuments(),projects:await Project.countDocuments(),tasks:await Task.countDocuments(),habits:await Habit.countDocuments()}; res.json({status:db===1?"healthy":"degraded",db:db===1?"connected":"disconnected",uptime:Math.floor(up),uptimeHuman:`${Math.floor(up/3600)}h ${Math.floor((up%3600)/60)}m`,memory:{rss:Math.round(mem.rss/1048576)+"MB",heapUsed:Math.round(mem.heapUsed/1048576)+"MB",heapTotal:Math.round(mem.heapTotal/1048576)+"MB"},nodeVersion:process.version,env:process.env.NODE_ENV||"development",blockedIPs:await BlockedIP.countDocuments(),secAlerts:await SecurityLog.countDocuments({resolved:false}),collections:counts}); } catch { res.status(500).json({message:"Error"}); } });

// ════════════════════════════════════════════════
// ═══ SHARED CHAT HELPERS ════════════════════════
// ════════════════════════════════════════════════

const GROQ_MODELS={fast:"llama-3.3-70b-versatile",smart:"llama-3.3-70b-versatile",coding:"llama-3.3-70b-versatile",deep:"deepseek-r1-distill-llama-70b"};
const POWERFUL_GROQ_MODEL="deepseek-r1-distill-llama-70b";
const GOOGLE_MODELS={fast:"gemini-2.0-flash",smart:"gemini-2.0-flash",coding:"gemini-2.0-flash",deep:"gemini-2.5-flash-preview-04-17"};
const MISTRAL_MODELS={fast:"mistral-small-latest",smart:"mistral-small-latest",coding:"codestral-latest",deep:"mistral-large-latest"};
const OR_MODELS={fast:"meta-llama/llama-3.3-70b-instruct:free",smart:"mistralai/mistral-small-3.1-24b-instruct:free",coding:"qwen/qwen3-coder:free",deep:"google/gemini-2.5-flash:free"};
const POWERFUL_OR_MODEL="google/gemini-2.5-flash:free";
const VISION_MODELS=["meta-llama/llama-4-maverick:free","meta-llama/llama-4-scout:free","google/gemini-2.5-flash:free","qwen/qwen3-vl-32b-instruct:free","mistralai/pixtral-12b:free","google/gemini-2.0-flash-exp:free"];
const TEXT_FB=["meta-llama/llama-3.3-70b-instruct:free","google/gemini-2.5-flash:free","mistralai/mistral-small-3.1-24b-instruct:free","qwen/qwen3-14b:free","qwen/qwen3-8b:free","google/gemma-3-27b-it:free"];
// ════════════════════════════════════════════════

function buildSystemPrompt(user, personaKey, roleKey, isPowerful, isProjectRequest) {
  const personaExtra = PERSONA_PROMPTS[personaKey] ? ' ' + PERSONA_PROMPTS[personaKey] : '';
  const roleExtra    = ROLE_PROMPTS[roleKey]        ? ' ' + ROLE_PROMPTS[roleKey]       : '';
  const powerExtra   = isPowerful
    ? ' THINKING LEVEL: POWERFUL. Apply deep, thorough, step-by-step reasoning. Show all your work clearly. Consider edge cases, alternatives, tradeoffs, and best practices. Never skip steps. Be comprehensive but organized.'
    : '';

  return (
    "You are SG — a powerful, free AI assistant. SG stands for StrongGuy. You are the flagship product of StrongGuy AI. " +
    "You were created and are fully owned by Mohammed Sadid Rahman (Sadid), a Bangladeshi developer. " +
    "Your full name is: SG ChatBOT — Free AI Assistant from StrongGuy AI. " +
    "IDENTITY RULES — never break these: " +
    "1. You are NOT ChatGPT, Claude, Gemini, Copilot, or any other AI. " +
    "2. You are NOT a localized version of any other AI. " +
    "3. You are NOT associated with A2H, OpenAI, Google, Anthropic, or Microsoft. " +
    "4. If asked 'what AI are you?' say: I am SG — the AI assistant from StrongGuy AI, built by Mohammed Sadid Rahman. " +
    "5. Never reveal API providers, model names, or technical infrastructure. " +
    "CREATOR: Mohammed Sadid Rahman (Sadid). Father: Mahabub Rahman Rubel. Mother: Sahela Popy. Brother: Abdullah Al Sayem. " +
    "LANGUAGE RULE — CRITICAL: Detect the script of the user's message. If Bengali/Bangla script → reply ENTIRELY in Bangla. If English → reply in English. If mixed → match the dominant language. NEVER switch language mid-reply. " +
    "PERSONALITY: Talk like a genius best friend — warm, witty, fun, real. Never start with 'Certainly!', 'Of course!', 'Sure!', 'Great question!' — just answer naturally. " +
    "CODE RESPONSE STYLE: Step 1: Short 2-3 line explanation. Step 2: If multiple files, list them. Step 3: Write each file with header and explanation. Step 4: After each block, key decisions. Step 5: How to Use section. Always write COMPLETE working code. " +
    (user.settings?.parentalControl ? "SAFE MODE ON: Appropriate for children under 13. No violence, adult themes, or profanity. " : "") +
    "HARD RULES: No sexual/explicit content. No harm to minors. No violence/weapons/terrorism/illegal. No hate speech. " +
    (isProjectRequest ? "End response with: 'Click the **Download ZIP** button below to get all files at once.'" : "") +
    personaExtra + roleExtra + powerExtra
  );
}

async function callGroqRotating(model, messages) {
  for (let i=0;i<GROQ_KEYS.length;i++) {
    const key=GROQ_KEYS[(groqKeyCounter+i)%GROQ_KEYS.length];
    try {
      const res=await fetch("https://api.groq.com/openai/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${key}`,"Content-Type":"application/json"},body:JSON.stringify({model,messages,max_tokens:4096,temperature:0.7})});
      if (res.status===429){console.log(`Groq key ${i+1} rate limited, rotating...`);continue;}
      groqKeyCounter=(groqKeyCounter+i+1)%GROQ_KEYS.length;
      return res;
    } catch(e){console.log(`Groq key ${i+1} error: ${e.message}`);}
  }
  return null;
}

// SSRF Safe Fetch Utility
function isPrivateOrReservedIP(ip) {
  if (!ip) return true;
  if (ip.includes(":")) { // IPv6
    const lower = ip.toLowerCase();
    return lower === "::1" || lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("::ffff:127.") || lower.startsWith("::ffff:10.") || lower.startsWith("::ffff:169.254.") || lower.startsWith("::ffff:192.168.");
  }
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return true; // unparsable → fail closed
  const [a,b] = parts;
  return a===127 || a===10 || a===0 || a===169 && b===254 || (a===172 && b>=16 && b<=31) || (a===192 && b===168) || a>=224; // loopback, private, link-local, multicast/reserved
}
async function safeFetchUrl(urlString) {
  try {
    const targetUrl = new URL(urlString);
    if (!["http:","https:"].includes(targetUrl.protocol)) return null;
    if (/^(localhost|127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|::1)/.test(targetUrl.hostname)) {
      console.warn("Blocked SSRF attempt to internal hostname:", urlString);
      return null;
    }
    // FIX (H5): the hostname-string check above can be bypassed by a domain name that *resolves* to
    // an internal IP (DNS rebinding). Resolve it and check the actual address too.
    try {
      const { address } = await dns.promises.lookup(targetUrl.hostname);
      if (isPrivateOrReservedIP(address)) {
        console.warn("Blocked SSRF attempt — hostname resolves to internal IP:", urlString, address);
        return null;
      }
    } catch { return null; } // DNS failure → fail closed rather than letting fetch() try anyway
    const pr = await fetch(urlString, { headers: {"User-Agent": "Mozilla/5.0"}, redirect: "manual", signal: AbortSignal.timeout(8000) });
    if (!pr.ok) return null;
    const txt = (await pr.text()).replace(/<script[\s\S]*?<\/script>/gi,"").replace(/<style[\s\S]*?<\/style>/gi,"").replace(/<[^>]+>/g," ").replace(/\s+/g," ").trim().slice(0,4000);
    return txt;
  } catch (e) {
    console.error("URL fetch error:", e.message);
    return null;
  }
}

async function callGoogle(model, systemMsg, chatMsgs) {
  const keys=[process.env.GOOGLE_AI_KEY_1,process.env.GOOGLE_AI_KEY_2,process.env.GOOGLE_AI_KEY_3,process.env.GOOGLE_AI_KEY].filter(Boolean);
  if (!keys.length) return null;
  for (const key of keys) {
    try {
      const contents=chatMsgs.map(m=>{
        if (Array.isArray(m.content)) {
          const parts=m.content.map((p)=>{ if(p.type==="text")return{text:p.text}; if(p.type==="image_url"){const url=p.image_url?.url||"";if(url.startsWith("data:")){const[header,data]=url.split(",");const mimeType=header.replace("data:","").replace(";base64","");return{inline_data:{mime_type:mimeType,data:data}};} return null;} return null;}).filter(Boolean);
          return{role:m.role==="assistant"?"model":"user",parts};
        }
        return{role:m.role==="assistant"?"model":"user",parts:[{text:typeof m.content==="string"?m.content:JSON.stringify(m.content)}]};
      });
      const res=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({systemInstruction:systemMsg?{parts:[{text:systemMsg.content}]}:undefined,contents,generationConfig:{maxOutputTokens:4096,temperature:0.7}})});
      if (res.status===429){continue;} if (!res.ok) continue;
      const data=await res.json();
      const text=data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!text) continue;
      return{ok:true,_googleData:{choices:[{message:{content:text}}]}};
    } catch(e){console.log(`Google AI error: ${e.message}`);}
  }
  return null;
}

async function callMistral(model, messages) {
  const keys=[process.env.MISTRAL_API_KEY_1,process.env.MISTRAL_API_KEY_2,process.env.MISTRAL_API_KEY].filter(Boolean);
  if (!keys.length) return null;
  for (const key of keys) {
    try {
      const res=await fetch("https://api.mistral.ai/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${key}`,"Content-Type":"application/json"},body:JSON.stringify({model,messages:messages.filter(m=>!Array.isArray(m.content)),max_tokens:4096,temperature:0.7})});
      if (res.status===429){continue;} if (res.ok) return res;
    } catch(e){console.log(`Mistral error: ${e.message}`);}
  }
  return null;
}

// ════════════════════════════════════════════════
// ═══ /chat (non-streaming) ══════════════════════
// ════════════════════════════════════════════════
app.post("/chat", chatLimiter, auth, checkBlocked, upload.single("file"), async (req,res) => {
  try {
    const user=await User.findById(req.user.id);
    if (!user) return res.status(401).json({reply:"User not found."});

    // FIX (H1): validate the request BEFORE charging a free-tier message credit.
    let messages;
    try { messages=typeof req.body.messages==="string"?JSON.parse(req.body.messages):req.body.messages; } catch { return res.status(400).json({reply:"Invalid messages format."}); }
    if (!Array.isArray(messages)||messages.length===0) return res.status(400).json({reply:"Invalid messages"});

    const pro=isProActive(user);
    if (!pro) { checkWindow(user); if (user.msgCount>=FREE_LIMIT) return res.status(429).json({reply:"limit_reached",msgsLeft:0,minsLeft:minsUntilReset(user)}); user.msgCount+=1; }
    user.totalMessages=(user.totalMessages||0)+1;
    await user.save();

    const personaKey  = req.body.personaKey  || 'default';
    const roleKey     = req.body.roleKey !== undefined ? req.body.roleKey : (user.role || '');
    const isPowerful  = req.body.thinkingLevel === 'powerful';

    const trimmed=messages.slice(-MAX_HISTORY).map(m=>({role:["user","assistant","system"].includes(m.role)?m.role:"user",content:typeof m.content==="string"?m.content.slice(0,8000):m.content}));
    const lastUserText=typeof trimmed.filter(m=>m.role==="user").slice(-1)[0]?.content==="string"?trimmed.filter(m=>m.role==="user").slice(-1)[0].content:"";
    const isProjectRequest=/বানাও|বানাবো|তৈরি করো|make a|create a|build a|game|website|app\b|project|portfolio|calculator|todo|quiz|landing page/i.test(lastUserText);

    const sysContent=buildSystemPrompt(user,personaKey,roleKey,isPowerful,isProjectRequest);
    if (trimmed[0]?.role!=="system") { trimmed.unshift({role:"system",content:sysContent}); } else { trimmed[0].content=sysContent; }

    if (req.file) { const base64=req.file.buffer.toString("base64"),mime=req.file.mimetype,last=trimmed[trimmed.length-1]; if (last?.role==="user"&&mime.startsWith("image/")) { const txt=req.body.imageText||(typeof last.content==="string"?last.content:"")||"Analyze this image in detail."; last.content=[{type:"text",text:txt},{type:"image_url",image_url:{url:`data:${mime};base64,${base64}`}}]; } }

    const hasImage=trimmed.some(m=>Array.isArray(m.content)&&m.content.some(p=>p.type==="image_url"));
    const modelKey=["fast","smart","coding","deep"].includes(req.body.modelKey)?req.body.modelKey:"fast";



    const callOR=model=>{
      const body={model,messages:trimmed};
      if (searchIntent&&!urlMatch&&!hasImage) body.plugins=[{id:"web"}];
      return fetch("https://openrouter.ai/api/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${process.env.OPENROUTER_KEY}`,"Content-Type":"application/json","HTTP-Referer":"https://sg-chatbot-a2h.pages.dev","X-Title":"SG ChatBOT"},body:JSON.stringify(body)});
    };

    const lastMsg=trimmed.filter(m=>m.role==="user").slice(-1)[0];
    const userTxt=typeof lastMsg?.content==="string"?lastMsg.content:"";
    const urlMatch=userTxt.match(/https?:\/\/[^\s]+/);
    const searchKeywords=/সার্চ করো|খুঁজে দাও|আজকের খবর|এখন কি হচ্ছে|কে জিতেছে|latest news|current news|what happened|breaking news|search for|look up|price of|weather in|todays news|news today|score of|live score|stock price/i;
    const isGreeting=/^(hi|hello|hey|হ্যালো|হেলো|আস্সালামু|salam|কেমন আছ|how are you|what's up|sup\b).{0,30}$/i;
    const isTooShort=userTxt.trim().split(/\s+/).length<4;
    
    if (user.settings?.parentalControl) {
      const blocked=["nude","naked","sexual","porn","explicit","gore","blood","weapon","violence","suicide","kill","murder"];
      if (blocked.some(t=>userTxt.toLowerCase().includes(t))) return res.status(403).json({reply:"I cannot process this message as Safe Mode is enabled."});
    }
    
    const searchIntent=!isGreeting.test(userTxt.trim())&&!isTooShort&&(searchKeywords.test(userTxt)||req.body.personaKey==='search');
    let webSources=[];

    if (urlMatch) { const txt = await safeFetchUrl(urlMatch[0]); if (txt) { trimmed.push({role:"user",content:`[Webpage content from ${urlMatch[0]}]:\n\n${txt}\n\nBased on this content, answer my question.`}); webSources.push({title:urlMatch[0],url:urlMatch[0]}); } }
    if (searchIntent&&!urlMatch&&!hasImage&&process.env.TAVILY_API_KEY) { try { const tavilyRes=await fetch("https://api.tavily.com/search",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({api_key:process.env.TAVILY_API_KEY,query:userTxt.slice(0,400),search_depth:"basic",max_results:5,include_answer:true}),signal:AbortSignal.timeout(10000)}); if (tavilyRes.ok) { const tavilyData=await tavilyRes.json(); const results=tavilyData.results||[]; webSources=results.map(r=>({title:r.title,url:r.url})); let ctx=`[Web Search Results for: "${userTxt}"]\n\n`; if (tavilyData.answer) ctx+=`Quick Answer: ${tavilyData.answer}\n\n`; results.slice(0,4).forEach((r,i)=>{ctx+=`[${i+1}] ${r.title}\nSource: ${r.url}\n${r.content?.slice(0,600)||''}\n\n`;}); ctx+=`Based on these search results, answer the user's question. Cite sources using [1], [2] etc.`; trimmed.push({role:"user",content:ctx}); } } catch(e){console.error("Tavily error:",e.message);} }

    const systemMsg=trimmed.find(m=>m.role==="system");
    const chatMsgs=trimmed.filter(m=>m.role!=="system");
    let response; let responseData=null;

    if (hasImage) {
      const googleVisionRes=await callGoogle("gemini-2.5-flash-preview-04-17",systemMsg,chatMsgs);
      if (googleVisionRes?.ok) { response=googleVisionRes; responseData=googleVisionRes._googleData; }
      else { for (const vm of VISION_MODELS) { response=await callOR(vm); if (response?.ok) break; await new Promise(r=>setTimeout(r,500)); } }
    } else if (isPowerful) {
      if (GROQ_KEYS.length>0) { try { response=await callGroqRotating(POWERFUL_GROQ_MODEL,trimmed); } catch{response=null;} }
      if (!response?.ok) { try { response=await callOR(POWERFUL_OR_MODEL); } catch{response=null;} }
      if (!response?.ok) { try { const gRes=await callGoogle("gemini-2.5-flash-preview-04-17",systemMsg,chatMsgs); if (gRes?.ok){response=gRes;responseData=gRes._googleData;} } catch{response=null;} }
    } else {
      if (GROQ_KEYS.length>0) { try { response=await callGroqRotating(GROQ_MODELS[modelKey],trimmed.filter(m=>!Array.isArray(m.content))); } catch{response=null;} }
      if (!response?.ok) { try { const gRes=await callGoogle(GOOGLE_MODELS[modelKey],systemMsg,chatMsgs); if (gRes?.ok){response=gRes;responseData=gRes._googleData;} } catch{response=null;} }
      if (!response?.ok) { try { response=await callMistral(MISTRAL_MODELS[modelKey],trimmed); } catch{response=null;} }
      if (!response?.ok) { try { response=await callOR(OR_MODELS[modelKey]); if(!response?.ok){for(const fb of TEXT_FB){response=await callOR(fb);if(response?.ok)break;await new Promise(r=>setTimeout(r,500));}} } catch{response=null;} }
    }

    if (!response?.ok) { if (!pro) { user.msgCount=Math.max(0,user.msgCount-1); await user.save().catch(()=>{}); } return res.status(429).json({reply:"⚠️ AI is busy right now. Please wait 30 seconds and try again."}); }
    if (!responseData) { try { responseData=await response.json(); } catch { return res.status(500).json({reply:"Failed to parse AI response."}); } }
    let reply=responseData?.choices?.[0]?.message?.content||"No response from AI.";
    if (webSources.length>0) { const sourceList=webSources.map((s,i)=>`[${i+1}] [${s.title}](${s.url})`).join('\n'); reply+=`\n\n---\n**Sources:**\n${sourceList}`; }

    const msgsLeft=pro?null:FREE_LIMIT-user.msgCount;
    const minsLeft=pro?null:minsUntilReset(user);
    const allMsgs=[...messages,{role:"assistant",content:reply}];
    const firstUser=allMsgs.find(m=>m.role==="user");
    const autoTitle=typeof firstUser?.content==="string"?firstUser.content.slice(0,50):"New Chat";
    let savedId=req.body.conversationId||null;
    if (user.settings?.autoSaveChats !== false) { try { const toSave=allMsgs.filter(m=>m.role!=="system").slice(-100).map(m=>({role:m.role,content:typeof m.content==="string"?m.content.slice(0,5000):m.content})); if (savedId){await Conversation.findOneAndUpdate({_id:savedId,userId:user._id},{messages:toSave,updatedAt:new Date()});}else{const c=await Conversation.create({userId:user._id,title:autoTitle,messages:toSave});savedId=c._id;} } catch(e){console.error("Conv save:",e.message);} }

    // Auto-extract memories from long conversations (every 5th message)
    if (allMsgs.filter(m=>m.role==="assistant").length % 5 === 0) {
      extractMemoriesFromChat(user._id, allMsgs).catch(()=>{});
    }

    // Update daily analytics
    await Analytics.findOneAndUpdate({userId:user._id,date:todayStr()},{$inc:{messagesCount:1}},{upsert:true,new:true}).catch(()=>{});

    res.json({reply,msgsLeft,minsLeft,plan:pro?"pro":"free",conversationId:savedId});
  } catch(err){console.error("❌ Chat error:",err);res.status(500).json({reply:"Server error. Please try again."});}
});

// ════════════════════════════════════════════════
// ═══ /chat/stream (streaming) ════════════════════
// ════════════════════════════════════════════════
app.post("/chat/stream", chatLimiter, auth, checkBlocked, upload.single("file"), async (req,res) => {
  const keepaliveRef = { id: null };
  try {
    const user=await User.findById(req.user.id);
    if (!user) return res.status(401).json({reply:"User not found."});

    // FIX (H1): validate the request BEFORE charging a free-tier message credit.
    let messages;
    try { messages=typeof req.body.messages==="string"?JSON.parse(req.body.messages):req.body.messages; } catch { return res.status(400).json({reply:"Invalid messages format."}); }
    if (!Array.isArray(messages)||messages.length===0) return res.status(400).json({reply:"Invalid messages"});

    const pro=isProActive(user);
    if (!pro) { checkWindow(user); if (user.msgCount>=FREE_LIMIT) return res.status(429).json({reply:"limit_reached",msgsLeft:0,minsLeft:minsUntilReset(user)}); user.msgCount+=1; }
    user.totalMessages=(user.totalMessages||0)+1;
    await user.save();

    const personaKey  = req.body.personaKey  || 'default';
    const roleKey     = req.body.roleKey !== undefined ? req.body.roleKey : (user.role || '');
    const isPowerful  = req.body.thinkingLevel === 'powerful';

    const trimmed=messages.slice(-MAX_HISTORY).map(m=>({role:["user","assistant","system"].includes(m.role)?m.role:"user",content:typeof m.content==="string"?m.content.slice(0,8000):m.content}));
    const lastUserTextStream=typeof trimmed.filter(m=>m.role==="user").slice(-1)[0]?.content==="string"?trimmed.filter(m=>m.role==="user").slice(-1)[0].content:"";
    const isProjectReqStream=/বানাও|বানাবো|তৈরি করো|make a|create a|build a|game|website|app\b|project|portfolio|calculator|todo|quiz|landing page/i.test(lastUserTextStream);

    const sysContent=buildSystemPrompt(user,personaKey,roleKey,isPowerful,isProjectReqStream);
    if (trimmed[0]?.role!=="system") { trimmed.unshift({role:"system",content:sysContent}); } else { trimmed[0].content=sysContent; }

    if (req.file) { const base64=req.file.buffer.toString("base64"),mime=req.file.mimetype,last=trimmed[trimmed.length-1]; if (last?.role==="user"&&mime.startsWith("image/")) { const txt=req.body.imageText||(typeof last.content==="string"?last.content:"")||"Analyze this image."; last.content=[{type:"text",text:txt},{type:"image_url",image_url:{url:`data:${mime};base64,${base64}`}}]; } }

    const hasImage=trimmed.some(m=>Array.isArray(m.content)&&m.content.some(p=>p.type==="image_url"));
    const modelKey=["fast","smart","coding","deep"].includes(req.body.modelKey)?req.body.modelKey:"fast";


    const lastMsgS=trimmed.filter(m=>m.role==="user").slice(-1)[0];
    const userTxtS=typeof lastMsgS?.content==="string"?lastMsgS.content:"";
    const urlMatchS=userTxtS.match(/https?:\/\/[^\s]+/);
    const searchKW=/সার্চ করো|খুঁজে দাও|আজকের খবর|এখন কি হচ্ছে|কে জিতেছে|latest news|current news|what happened|breaking news|search for|look up|price of|weather in|todays news|news today|score of|live score|stock price/i;
    const isGreetingS=/^(hi|hello|hey|হ্যালো|হেলো|আস্সালামু|salam|কেমন আছ|how are you|what's up|sup\b).{0,30}$/i;
    const isTooShortS=userTxtS.trim().split(/\s+/).length<4;
    
    if (user.settings?.parentalControl) {
      const blocked=["nude","naked","sexual","porn","explicit","gore","blood","weapon","violence","suicide","kill","murder"];
      if (blocked.some(t=>userTxtS.toLowerCase().includes(t))) { try{res.write(`data: ${JSON.stringify({error:"I cannot process this message as Safe Mode is enabled."})}\n\n`);res.end();}catch{} return; }
    }
    
    const doSearch=!isGreetingS.test(userTxtS.trim())&&!isTooShortS&&(searchKW.test(userTxtS)||req.body.personaKey==='search')&&!urlMatchS&&!hasImage;
    let streamSources=[];

    if (urlMatchS) { const txt = await safeFetchUrl(urlMatchS[0]); if (txt) { trimmed.push({role:"user",content:`[Webpage content from ${urlMatchS[0]}]:\n\n${txt}\n\nAnswer my question based on this.`}); streamSources.push({title:urlMatchS[0],url:urlMatchS[0]}); } }
    if (doSearch&&process.env.TAVILY_API_KEY) { try { const tr=await fetch("https://api.tavily.com/search",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({api_key:process.env.TAVILY_API_KEY,query:userTxtS.slice(0,400),search_depth:"basic",max_results:5,include_answer:true}),signal:AbortSignal.timeout(10000)}); if (tr.ok) { const td=await tr.json(); const results=td.results||[]; streamSources=results.map(r=>({title:r.title,url:r.url})); let ctx=`[Web Search Results for: "${userTxtS}"]\n\n`; if (td.answer) ctx+=`Quick Answer: ${td.answer}\n\n`; results.slice(0,4).forEach((r,i)=>{ctx+=`[${i+1}] ${r.title}\nSource: ${r.url}\n${r.content?.slice(0,600)||''}\n\n`;}); ctx+=`Answer the user's question based on these results. Cite sources as [1], [2] etc.`; trimmed.push({role:"user",content:ctx}); } } catch(e){console.error("Tavily stream error:",e.message);} }

    res.setHeader("Content-Type","text/event-stream");
    res.setHeader("Cache-Control","no-cache");
    res.setHeader("Connection","keep-alive");
    res.setHeader("X-Accel-Buffering","no");
    res.flushHeaders();

    const sendChunk=(text)=>{try{res.write(`data: ${JSON.stringify({t:text})}\n\n`);}catch{}};
    const sendDone=(meta)=>{try{res.write(`data: ${JSON.stringify({done:true,...meta})}\n\n`);}catch{}};
    const sendError=(msg)=>{try{res.write(`data: ${JSON.stringify({error:msg})}\n\n`);}catch{}};

    keepaliveRef.id=setInterval(()=>{try{res.write(`: ping\n\n`);}catch{clearInterval(keepaliveRef.id);}},15000);

    let fullReply="";

    async function tryGroqStream(model) {
      if (!GROQ_KEYS.length) return false;
      for (let i=0;i<GROQ_KEYS.length;i++) {
        const key=GROQ_KEYS[(groqKeyCounter+i)%GROQ_KEYS.length];
        try {
          const r=await fetch("https://api.groq.com/openai/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${key}`,"Content-Type":"application/json"},body:JSON.stringify({model,messages:trimmed.filter(m=>!Array.isArray(m.content)),max_tokens:4096,temperature:0.7,stream:true})});
          if (r.status===429){continue;} if (!r.ok) return false;
          groqKeyCounter=(groqKeyCounter+i+1)%GROQ_KEYS.length;
          let buf="";
          await new Promise((resolve,reject)=>{
            r.body.on("data",(chunk)=>{buf+=chunk.toString();const lines=buf.split("\n");buf=lines.pop()||"";for(const line of lines){if(!line.startsWith("data:"))continue;const d=line.slice(5).trim();if(d==="[DONE]")return;try{const parsed=JSON.parse(d);const t=parsed.choices?.[0]?.delta?.content||"";if(t){fullReply+=t;sendChunk(t);}}catch{}}});
            r.body.on("end",resolve); r.body.on("error",reject);
          });
          return true;
        } catch(e){console.log(`Groq stream error: ${e.message}`);}
      }
      return false;
    }

    async function tryORStream(model) {
      try {
        const r=await fetch("https://openrouter.ai/api/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${process.env.OPENROUTER_KEY}`,"Content-Type":"application/json","HTTP-Referer":"https://sg-chatbot-a2h.pages.dev","X-Title":"SG ChatBOT"},body:JSON.stringify({model,messages:trimmed,stream:true})});
        if (!r.ok) return false;
        let buf="";
        await new Promise((resolve,reject)=>{
          r.body.on("data",(chunk)=>{buf+=chunk.toString();const lines=buf.split("\n");buf=lines.pop()||"";for(const line of lines){if(!line.startsWith("data:"))continue;const d=line.slice(5).trim();if(d==="[DONE]")return;try{const parsed=JSON.parse(d);const t=parsed.choices?.[0]?.delta?.content||"";if(t){fullReply+=t;sendChunk(t);}}catch{}}});
          r.body.on("end",resolve); r.body.on("error",reject);
        });
        return true;
      } catch(e){console.log(`OR stream error: ${e.message}`);}
      return false;
    }

    async function tryGoogleAsChunk(model) {
      const systemMsg=trimmed.find(m=>m.role==="system");
      const chatMsgs=trimmed.filter(m=>m.role!=="system");
      const gRes=await callGoogle(model,systemMsg,chatMsgs);
      if (gRes?.ok) { const text=gRes._googleData?.choices?.[0]?.message?.content||""; if (text){fullReply=text;sendChunk(text);return true;} }
      return false;
    }

    let success=false;

    // FIX (H4): once any chunk of `fullReply` has been streamed to the client, we no longer fall
    // back to a different provider/model for the same request — restarting with a different model
    // mid-stream previously produced a garbled reply mixing two unrelated AI responses, and the
    // saved conversation wouldn't match what the user actually saw. Each `&& !fullReply` guard below
    // stops the fallback chain as soon as we've already sent the user something.
    if (!hasImage) {
      if (isPowerful) {
        success = await tryGroqStream(POWERFUL_GROQ_MODEL);
        if (!success && !fullReply) success = await tryORStream(POWERFUL_OR_MODEL);
        if (!success && !fullReply) success = await tryGoogleAsChunk("gemini-2.5-flash-preview-04-17");
      } else {
        success=await tryGroqStream(GROQ_MODELS[modelKey]);
        if (!success && !fullReply) success=await tryGoogleAsChunk(modelKey==="deep"?"gemini-2.5-flash-preview-04-17":"gemini-2.0-flash");
        if (!success && !fullReply) { const mRes=await callMistral(modelKey==="coding"?"codestral-latest":"mistral-small-latest",trimmed); if(mRes?.ok){const mData=await mRes.json();const text=mData?.choices?.[0]?.message?.content||"";if(text){fullReply=text;sendChunk(text);success=true;}} }
        if (!success && !fullReply) success=await tryORStream(OR_MODELS[modelKey]);
        if (!success && !fullReply) { const fb=["google/gemini-2.5-flash:free","meta-llama/llama-3.3-70b-instruct:free","mistralai/mistral-small-3.1-24b-instruct:free","qwen/qwen3-14b:free"]; for(const m of fb){if(fullReply)break;success=await tryORStream(m);if(success)break;} }
      }
    } else {
      const vms=["meta-llama/llama-4-maverick:free","google/gemini-2.5-flash:free","qwen/qwen3-vl-32b-instruct:free","meta-llama/llama-4-scout:free","mistralai/pixtral-12b:free"];
      for(const vm of vms){if(fullReply)break;success=await tryORStream(vm);if(success)break;}
    }

    // FIX (H1+H4): only treat this as a hard failure (and refund the message credit) when we have
    // NO reply text at all. Any partial reply that was already streamed to the client is saved and
    // delivered via `sendDone` below rather than being discarded behind an error event.
    if (!fullReply) { if (!pro) { user.msgCount=Math.max(0,user.msgCount-1); await user.save().catch(()=>{}); } sendError("AI is busy. Please try again."); clearInterval(keepaliveRef.id); res.end(); return; }

    const msgsLeft=pro?null:FREE_LIMIT-user.msgCount;
    const minsLeft=pro?null:minsUntilReset(user);
    const allMsgs=[...messages,{role:"assistant",content:fullReply}];
    const firstUser=allMsgs.find(m=>m.role==="user");
    const autoTitle=typeof firstUser?.content==="string"?firstUser.content.slice(0,50):"New Chat";
    let savedId=req.body.conversationId||null;
    if (user.settings?.autoSaveChats !== false) { try { const toSave=allMsgs.filter(m=>m.role!=="system").slice(-100).map(m=>({role:m.role,content:typeof m.content==="string"?m.content.slice(0,5000):m.content})); if(savedId){await Conversation.findOneAndUpdate({_id:savedId,userId:user._id},{messages:toSave,updatedAt:new Date()});}else{const c=await Conversation.create({userId:user._id,title:autoTitle,messages:toSave});savedId=c._id;} } catch(e){console.error("Conv save:",e.message);} }

    // Auto-extract memories
    if (allMsgs.filter(m=>m.role==="assistant").length % 5 === 0) {
      extractMemoriesFromChat(user._id, allMsgs).catch(()=>{});
    }
    await Analytics.findOneAndUpdate({userId:user._id,date:todayStr()},{$inc:{messagesCount:1}},{upsert:true,new:true}).catch(()=>{});

    sendDone({msgsLeft,minsLeft,plan:pro?"pro":"free",conversationId:savedId,sources:streamSources});
    res.end();
  } catch(err) {
    console.error("Stream error:",err);
    try{res.write(`data: ${JSON.stringify({error:"Server error."})}\n\n`);res.end();}catch{}
  } finally {
    if (keepaliveRef.id) clearInterval(keepaliveRef.id);
  }
});

// ══ TTS ══
app.get("/tts-key",auth,async(req,res)=>{if(!process.env.ELEVENLABS_API_KEY)return res.status(404).json({message:"TTS not configured."});res.json({key:process.env.ELEVENLABS_API_KEY});});
const ttsLimiter=rateLimit({windowMs:60*1000,max:20,message:{message:"TTS limit reached."}});
app.post("/tts",ttsLimiter,auth,async(req,res)=>{try{const{text,voiceId}=req.body;if(!text)return res.status(400).json({message:"Text required."});if(!process.env.ELEVENLABS_API_KEY)return res.status(500).json({message:"TTS not configured."});const voice=voiceId||"21m00Tcm4TlvDq8ikWAM";const cleanText=text.replace(/[*_`#>\[\]]/g,'').replace(/\n+/g,' ').trim().slice(0,1000);const response=await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${voice}`,{method:"POST",headers:{"xi-api-key":process.env.ELEVENLABS_API_KEY,"Content-Type":"application/json","Accept":"audio/mpeg"},body:JSON.stringify({text:cleanText,model_id:"eleven_turbo_v2_5",voice_settings:{stability:0.5,similarity_boost:0.75,style:0.0,use_speaker_boost:true}}),signal:AbortSignal.timeout(30000)});if(!response.ok){return res.status(500).json({message:"TTS failed."});}const audioBuffer=await response.arrayBuffer();res.setHeader("Content-Type","audio/mpeg");res.setHeader("Content-Length",audioBuffer.byteLength);res.send(Buffer.from(audioBuffer));}catch(err){res.status(500).json({message:"TTS server error."});}});

// ══ IMAGE GENERATION ══
const imageLimiter=rateLimit({windowMs:60*60*1000,max:20,message:{message:"Image limit reached. Try later."}});
app.post("/generate-image",imageLimiter,auth,checkBlocked,async(req,res)=>{try{const user=await User.findById(req.user.id);if(!user)return res.status(401).json({message:"User not found."});const{prompt}=req.body;const clampDim=v=>Math.min(1536,Math.max(256,parseInt(v)||1024));const width=clampDim(req.body.width);const height=clampDim(req.body.height);if(!prompt||typeof prompt!=="string")return res.status(400).json({message:"Prompt required."});if(prompt.length>500)return res.status(400).json({message:"Prompt too long (max 500 chars)."});if(user.settings?.parentalControl){const blocked=["nude","naked","sexual","porn","explicit","gore","blood","weapon","violence"];if(blocked.some(t=>prompt.toLowerCase().includes(t)))return res.status(403).json({message:"Blocked by Safe Mode."});}const encodedPrompt=encodeURIComponent(prompt);const seed=Math.floor(Math.random()*999999);const imageUrl=`https://image.pollinations.ai/prompt/${encodedPrompt}?width=${width}&height=${height}&seed=${seed}&nologo=true&enhance=true`;const response=await fetch(imageUrl,{headers:{"User-Agent":"Mozilla/5.0"},signal:AbortSignal.timeout(60000)});if(!response.ok){return res.status(500).json({message:"Image generation failed. Please try again."});}const buffer=await response.arrayBuffer();const b64=Buffer.from(buffer).toString("base64");const mime=response.headers.get("content-type")||"image/jpeg";res.json({image:`data:${mime};base64,${b64}`,prompt});}catch(err){res.status(500).json({message:"Server error. Please try again."});}});

// ══ PRIORITY 2: OAUTH + WORKFLOW / ACTION ENGINE ══
// Mounted here so all models (User, Integration, encryptToken etc.) are already defined
app.use(createOAuthRouter({ User, Integration, encryptToken }));
registerModels({ Note, Task, Goal, User, sendEmail });
app.use("/workflows", createWorkflowRouter({ auth, checkBlocked, apiLimiter, sanitize }));
startScheduler();

app.get("/",(req,res)=>res.json({message:"SG ChatBOT V2 API running ✅", version:"2.0.0", features:["memory","notes","goals","projects","tasks","habits","calendar","analytics","integrations","oauth","workflows"]}));
app.use((err,req,res,next)=>{console.error("Unhandled:",err.message);res.status(500).json({message:"Something went wrong."});});
app.use((req,res)=>res.status(404).json({message:"Not found."}));
app.listen(PORT,()=>console.log(`🚀 SG ChatBOT V2 Server running on port ${PORT}`));
