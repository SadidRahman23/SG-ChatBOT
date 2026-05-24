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

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env") });

const REQUIRED_ENV = ["MONGO_URI","OPENROUTER_KEY","JWT_SECRET","ADMIN_SECRET","EMAIL_USER","EMAIL_PASS"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) throw new Error(`Missing env: ${key}`);
}

const JWT_SECRET   = process.env.JWT_SECRET;
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
  bangladesh: 'BANGLADESH MODE: You are an expert on Bangladesh. Specialize in: BCS (Bangladesh Civil Service) exam prep including Bangla, English, Math, General Knowledge, Bangladesh Affairs, International Affairs, Science & Technology. SSC and HSC exam help under Bangladeshi curriculum. National University and public university admission tests. NTRCA, Primary school assistant teacher exam, bank job exams. When helping with BCS/SSC/HSC: give exam-focused answers, mention important MCQ topics, share memory tricks, use Bangla when user writes in Bangla.',
  search:     'WEB SEARCH MODE: The user wants current, up-to-date information. Always mention when info might be outdated. Prioritize recent facts. Suggest verifying time-sensitive info from official sources.',
};

// ── Groq Key Counter (global, persists across requests) ──
let groqKeyCounter = 0;
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({ from: `"SG ChatBOT" <${process.env.EMAIL_USER}>`, to, subject, html });
    return true;
  } catch (err) { console.error("Email error:", err.message); return false; }
}

async function sendSecurityAlert(type, details) {
  const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;
  const html = `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;background:#0b0f17;color:#e4ecf7;padding:28px;border-radius:14px;border:1px solid rgba(248,113,113,0.3)">
    <h2 style="color:#f87171">🚨 Security Alert — SG ChatBOT</h2>
    <p style="color:#8a9bb5;font-size:13px">${new Date().toUTCString()}</p>
    <div style="background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.2);border-radius:10px;padding:16px;margin:14px 0">
      <p style="font-weight:700;color:#f87171;margin-bottom:8px">${type}</p>
      <pre style="font-size:12px;color:#8a9bb5;white-space:pre-wrap;margin:0">${JSON.stringify(details,null,2)}</pre>
    </div>
    <p style="color:#4a5a72;font-size:12px">SG ChatBOT Security System · Auto-generated</p>
  </div>`;
  await sendEmail(adminEmail, `🚨 Security Alert: ${type}`, html);
}

// ── App Setup ──
const app = express();
app.set("trust proxy", 1);

app.use((req, res, next) => {
  if (process.env.NODE_ENV === "production" && req.headers["x-forwarded-proto"] !== "https")
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  next();
});

app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("X-Frame-Options","DENY");
  res.setHeader("X-XSS-Protection","1; mode=block");
  res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
  next();
});

app.use(cors({
  origin: ["https://sg-chatbot-a2h.pages.dev","https://sgchatbotofficial.netlify.app","http://localhost:3000","http://localhost:5173","http://127.0.0.1:5500"],
  methods: ["GET","POST","DELETE","OPTIONS","PATCH"],
  allowedHeaders: ["Content-Type","Authorization","x-admin-secret"],
  credentials: false,
}));
app.use(express.json({ limit: "16kb" }));

// ── Multer ──
const ALLOWED_MIME = new Set(["image/jpeg","image/png","image/gif","image/webp","application/pdf","application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document","text/plain","text/csv","application/vnd.ms-excel","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"]);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5*1024*1024 },
  fileFilter: (req,file,cb) => ALLOWED_MIME.has(file.mimetype) ? cb(null,true) : cb(new Error(`File type not allowed: ${file.mimetype}`)),
});

// ── Rate Limiters ──
const authLimiter  = rateLimit({ windowMs:15*60*1000, max:15, message:{message:"Too many attempts. Try later."} });
const chatLimiter  = rateLimit({ windowMs:60*1000, max:30 });
const adminLimiter = rateLimit({ windowMs:15*60*1000, max:100, message:{message:"Too many admin requests."} });
const resetLimiter = rateLimit({ windowMs:60*60*1000, max:5, message:{message:"Too many reset attempts."} });

// ── DB ──
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => { console.error("❌ MongoDB failed:", err.message); process.exit(1); });

// ── Models ──
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
  lastLoginAt:    { type:Date, default:null },
  lastLoginIP:    { type:String, default:"" },
  totalMessages:  { type:Number, default:0 },
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
  transactionId: { type:String, required:true, trim:true },
  amount:        { type:Number, required:true },
  plan:          { type:String, enum:["monthly","yearly"], required:true },
  status:        { type:String, enum:["pending","approved","rejected"], default:"pending" },
}, { timestamps:true });
const Payment = mongoose.model("Payment", paymentSchema);

const conversationSchema = new mongoose.Schema({
  userId:   { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true },
  title:    { type:String, default:"New Chat" },
  messages: [{ role:{type:String,enum:["user","assistant","system"]}, content:{type:mongoose.Schema.Types.Mixed}, createdAt:{type:Date,default:Date.now} }],
  updatedAt:{ type:Date, default:Date.now },
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

// ── Helpers ──
function sanitize(input) {
  if (typeof input==="string") return input.replace(/[\$\x00]/g,"").trim().slice(0,1000);
  if (typeof input==="object"&&input!==null) {
    const clean={};
    for (const key of Object.keys(input)) { const k=key.replace(/[\$\.]/g,"_").slice(0,100); clean[k]=sanitize(input[key]); }
    return clean;
  }
  return input;
}
function isValidEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)&&e.length<=254; }
function isProActive(u)   { return u.plan==="pro"&&u.proExpiresAt&&new Date()<new Date(u.proExpiresAt); }
function isLocked(u)      { return u.lockUntil&&new Date()<new Date(u.lockUntil); }
function getClientIP(req) { return req.headers["x-forwarded-for"]?.split(",")[0]?.trim()||req.ip||"unknown"; }

function checkWindow(user) {
  const now=Date.now();
  if (!user.msgWindowStart||(now-new Date(user.msgWindowStart).getTime())>=FREE_WINDOW) {
    user.msgCount=0; user.msgWindowStart=new Date();
  }
}
function minsUntilReset(user) {
  if (!user.msgWindowStart) return 0;
  return Math.ceil(Math.max(0,FREE_WINDOW-(Date.now()-new Date(user.msgWindowStart).getTime()))/60000);
}

const ipAttempts = new Map();

async function logSecurityEvent(type, severity, req, extra={}) {
  const ip=getClientIP(req), userAgent=req.headers["user-agent"]||"";
  try {
    await SecurityLog.create({ type, severity, ip, userAgent, ...extra });
    if (severity==="high"||severity==="critical") sendSecurityAlert(type,{ip,userAgent,...extra}).catch(()=>{});
  } catch(e) { console.error("Security log error:",e.message); }
}

// ── IP Block Middleware ──
app.use(async (req,res,next) => {
  if (req.path==="/") return next();
  const ip=getClientIP(req);
  try {
    const blocked=await BlockedIP.findOne({ip});
    if (blocked) {
      if (blocked.expiresAt&&new Date()>blocked.expiresAt) { await BlockedIP.deleteOne({ip}); return next(); }
      return res.status(403).json({message:"Access denied."});
    }
  } catch {}
  next();
});

// ── Suspicious Activity Detector ──
const SUSPICIOUS_UA = ["sqlmap","nikto","nmap","masscan","zgrab","acunetix","burpsuite"];
app.use(async (req,res,next) => {
  const ip=getClientIP(req);
  const ua=(req.headers["user-agent"]||"").toLowerCase();
  const url=req.originalUrl;
  const suspUA     = SUSPICIOUS_UA.some(s=>ua.includes(s));
  const pathTraverse= url.includes("../")||url.includes("%2e%2e");
  const sqlAttempt  = /(\bselect\b|\bdrop\b|\bunion\b|\binsert\b)/i.test(url);
  const xssAttempt  = /<script|javascript:|onerror=/i.test(url);

  if (suspUA||pathTraverse||sqlAttempt||xssAttempt) {
    const type=suspUA?"suspicious_user_agent":pathTraverse?"path_traversal":sqlAttempt?"sql_injection":"xss_attempt";
    await logSecurityEvent(type,"high",req,{url});
    const key=`susp_${ip}`;
    const count=(ipAttempts.get(key)||0)+1;
    ipAttempts.set(key,count);
    if (count>=3) {
      await BlockedIP.findOneAndUpdate({ip},{ip,reason:`Auto-blocked: ${type}`,blockedBy:"system",attempts:count},{upsert:true,new:true}).catch(()=>{});
      await logSecurityEvent("ip_auto_blocked","critical",req,{reason:type});
    }
    return res.status(403).json({message:"Access denied."});
  }
  next();
});

// ── Auth Middleware ──
function auth(req,res,next) {
  const h=req.headers.authorization;
  if (!h||!h.startsWith("Bearer ")) return res.status(401).json({reply:"Authorization token missing."});
  try { req.user=jwt.verify(h.slice(7),JWT_SECRET); next(); }
  catch { return res.status(401).json({reply:"Invalid or expired token."}); }
}

function adminAuth(req,res,next) {
  const secret=req.headers["x-admin-secret"]||"";
  try {
    const valid=Buffer.from(secret).length===Buffer.from(ADMIN_SECRET).length&&
                crypto.timingSafeEqual(Buffer.from(secret),Buffer.from(ADMIN_SECRET));
    if (!valid) { logSecurityEvent("admin_auth_failed","high",req).catch(()=>{}); return res.status(403).json({message:"Forbidden"}); }
    next();
  } catch { return res.status(403).json({message:"Forbidden"}); }
}

async function checkBlocked(req,res,next) {
  try {
    const u=await User.findById(req.user.id).select("isBlocked blockedReason");
    if (u?.isBlocked) return res.status(403).json({reply:`Account blocked: ${u.blockedReason||"Policy violation"}`});
    next();
  } catch { next(); }
}

// ═══ SIGNUP ═══
app.post("/signup", authLimiter, async (req,res) => {
  try {
    const b=sanitize(req.body); const {email,password}=b;
    if (!email||!password) return res.status(400).json({message:"Email and password required"});
    if (!isValidEmail(email)) return res.status(400).json({message:"Invalid email format"});
    if (password.length<8||password.length>128) return res.status(400).json({message:"Password must be 8–128 characters"});
    if (await User.findOne({email})) return res.status(409).json({message:"User already exists"});
    const hash=await bcrypt.hash(password,12);
    await User.create({email,password:hash,lastLoginIP:getClientIP(req)});
    res.json({message:"Account created"});
  } catch { res.status(500).json({message:"Signup error"}); }
});

// ═══ LOGIN ═══
app.post("/login", authLimiter, async (req,res) => {
  try {
    const b=sanitize(req.body); const {email,password}=b; const ip=getClientIP(req);
    if (!email||!password) return res.status(401).json({message:"Invalid login"});
    const user=await User.findOne({email});
    if (!user) return res.status(401).json({message:"Invalid email or password"});
    if (user.isBlocked) return res.status(403).json({message:`Account blocked: ${user.blockedReason||"Policy violation"}`});
    if (isLocked(user)) return res.status(423).json({message:"Account temporarily locked. Try again later."});
    const ok=await bcrypt.compare(password,user.password);
    if (!ok) {
      user.loginAttempts=(user.loginAttempts||0)+1;
      if (user.loginAttempts>=5) {
        user.lockUntil=new Date(Date.now()+15*60*1000); user.loginAttempts=0;
        await logSecurityEvent("brute_force_detected","high",req,{email,userId:user._id.toString()});
      }
      await user.save();
      return res.status(401).json({message:"Invalid email or password"});
    }
    user.loginAttempts=0; user.lockUntil=null; user.lastLoginAt=new Date(); user.lastLoginIP=ip;
    await user.save();
    const token=jwt.sign({id:user._id},JWT_SECRET,{expiresIn:"7d"});
    res.json({token});
  } catch { res.status(500).json({message:"Login error"}); }
});

// ═══ STATUS ═══
app.get("/status", auth, async (req,res) => {
  try {
    const user=await User.findById(req.user.id).select("-password -resetToken");
    if (!user) return res.status(404).json({message:"User not found"});
    const pro=isProActive(user); checkWindow(user);
    res.json({email:user.email,plan:pro?"pro":"free",msgsLeft:pro?null:Math.max(0,FREE_LIMIT-user.msgCount),freeLimit:FREE_LIMIT,minsLeft:pro?null:minsUntilReset(user),proExpires:user.proExpiresAt});
  } catch { res.status(500).json({message:"Error"}); }
});

// ═══ FORGOT / RESET PASSWORD ═══
app.post("/forgot-password", resetLimiter, async (req,res) => {
  try {
    const email=sanitize(req.body).email;
    if (!email||!isValidEmail(email)) return res.json({message:"If this email exists, a reset code has been sent."});
    const user=await User.findOne({email});
    if (!user) return res.json({message:"If this email exists, a reset code has been sent."});
    const code=crypto.randomInt(100000,999999).toString();
    user.resetToken=await bcrypt.hash(code,8); user.resetTokenExp=new Date(Date.now()+15*60*1000);
    await user.save();
    await sendEmail(email,"🔑 SG ChatBOT — Password Reset Code",`<div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0b0f17;color:#e4ecf7;padding:32px;border-radius:16px;border:1px solid rgba(255,255,255,0.1)"><h2 style="color:#4f8eff">SG ChatBOT</h2><p>Your reset code:</p><div style="font-size:36px;font-weight:800;letter-spacing:8px;color:#4f8eff;background:rgba(79,142,255,0.1);padding:20px;border-radius:12px;text-align:center;margin:16px 0">${code}</div><p style="color:#8a9bb5;font-size:13px">Expires in 15 minutes.</p></div>`);
    res.json({message:"If this email exists, a reset code has been sent."});
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/reset-password", resetLimiter, async (req,res) => {
  try {
    const {email,code,newPassword}=sanitize(req.body);
    if (!email||!code||!newPassword) return res.status(400).json({message:"All fields required"});
    if (newPassword.length<8||newPassword.length>128) return res.status(400).json({message:"Password must be 8–128 characters"});
    const user=await User.findOne({email});
    if (!user||!user.resetToken||!user.resetTokenExp) return res.status(400).json({message:"Invalid or expired code"});
    if (new Date()>user.resetTokenExp) return res.status(400).json({message:"Reset code expired"});
    if (!await bcrypt.compare(code,user.resetToken)) return res.status(400).json({message:"Invalid reset code"});
    user.password=await bcrypt.hash(newPassword,12); user.resetToken=null; user.resetTokenExp=null; user.loginAttempts=0; user.lockUntil=null;
    await user.save();
    res.json({message:"Password reset successfully"});
  } catch { res.status(500).json({message:"Error"}); }
});

// ═══ PAYMENT ═══
app.post("/payment/submit", auth, async (req,res) => {
  try {
    const {method,transactionId,plan}=sanitize(req.body);
    if (!method||!transactionId||!plan) return res.status(400).json({message:"Missing fields"});
    if (!["bkash","nagad"].includes(method)) return res.status(400).json({message:"Invalid method"});
    if (!["monthly","yearly"].includes(plan)) return res.status(400).json({message:"Invalid plan"});
    if (transactionId.length<6||transactionId.length>50) return res.status(400).json({message:"Invalid transaction ID"});
    if (await Payment.findOne({transactionId})) return res.status(409).json({message:"Transaction ID already used"});
    const user=await User.findById(req.user.id);
    if (!user) return res.status(404).json({message:"User not found"});
    await Payment.create({userId:user._id,email:user.email,method,transactionId,amount:plan==="monthly"?99:799,plan});
    res.json({message:"Payment submitted! We will verify within 24 hours."});
  } catch { res.status(500).json({message:"Payment error"}); }
});

// ════════════════════════════════
// ADMIN ROUTES
// ════════════════════════════════

app.get("/admin/payments", adminLimiter, adminAuth, async (req,res) => {
  try { res.json(await Payment.find().sort({createdAt:-1})); } catch { res.status(500).json({message:"Error"}); }
});

app.post("/admin/approve/:id", adminLimiter, adminAuth, async (req,res) => {
  try {
    const p=await Payment.findById(req.params.id);
    if (!p) return res.status(404).json({message:"Not found"});
    p.status="approved"; await p.save();
    const u=await User.findById(p.userId);
    if (!u) return res.status(404).json({message:"User not found"});
    const exp=new Date(); p.plan==="monthly"?exp.setMonth(exp.getMonth()+1):exp.setFullYear(exp.getFullYear()+1);
    u.plan="pro"; u.proExpiresAt=exp; await u.save();
    res.json({message:`Pro activated for ${u.email} until ${exp.toDateString()}`});
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/admin/reject/:id", adminLimiter, adminAuth, async (req,res) => {
  try {
    const p=await Payment.findById(req.params.id);
    if (!p) return res.status(404).json({message:"Not found"});
    p.status="rejected"; await p.save(); res.json({message:"Rejected"});
  } catch { res.status(500).json({message:"Error"}); }
});

app.get("/admin/users", adminLimiter, adminAuth, async (req,res) => {
  try {
    const page=parseInt(req.query.page)||1, limit=parseInt(req.query.limit)||50;
    const search=req.query.search||"", filter=req.query.filter||"all";
    let query={};
    if (search) query.email={$regex:search,$options:"i"};
    if (filter==="pro")     query.plan="pro";
    if (filter==="free")    query.plan="free";
    if (filter==="blocked") query.isBlocked=true;
    const total=await User.countDocuments(query);
    const users=await User.find(query).select("-password -resetToken").sort({createdAt:-1}).skip((page-1)*limit).limit(limit);
    res.json({users,total,page,pages:Math.ceil(total/limit)});
  } catch { res.status(500).json({message:"Error"}); }
});

app.get("/admin/stats", adminLimiter, adminAuth, async (req,res) => {
  try {
    const total=await User.countDocuments();
    const pro=await User.countDocuments({plan:"pro"});
    const blocked=await User.countDocuments({isBlocked:true});
    const today=new Date(); today.setHours(0,0,0,0);
    const newToday=await User.countDocuments({createdAt:{$gte:today}});
    const week=new Date(Date.now()-7*24*3600000);
    const newWeek=await User.countDocuments({createdAt:{$gte:week}});
    const revData=await Payment.aggregate([{$match:{status:"approved"}},{$group:{_id:null,total:{$sum:"$amount"},count:{$sum:1}}}]);
    const revenue=revData[0]?.total||0, totalPayments=revData[0]?.count||0;
    const sixAgo=new Date(); sixAgo.setMonth(sixAgo.getMonth()-6);
    const monthlyRevenue=await Payment.aggregate([
      {$match:{status:"approved",createdAt:{$gte:sixAgo}}},
      {$group:{_id:{y:{$year:"$createdAt"},m:{$month:"$createdAt"}},revenue:{$sum:"$amount"},count:{$sum:1}}},
      {$sort:{"_id.y":1,"_id.m":1}}
    ]);
    const signupsByDay=await User.aggregate([
      {$match:{createdAt:{$gte:week}}},
      {$group:{_id:{$dateToString:{format:"%Y-%m-%d",date:"$createdAt"}},count:{$sum:1}}},
      {$sort:{_id:1}}
    ]);
    const pendingPayments=await Payment.countDocuments({status:"pending"});
    const unresolved=await SecurityLog.countDocuments({resolved:false});
    const critical=await SecurityLog.countDocuments({severity:"critical",resolved:false});
    res.json({total,pro,free:total-pro,blocked,newToday,newWeek,revenue,totalPayments,monthlyRevenue,signupsByDay,pendingPayments,unresolved,critical});
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/admin/users/:id/block", adminLimiter, adminAuth, async (req,res) => {
  try {
    const u=await User.findById(req.params.id);
    if (!u) return res.status(404).json({message:"Not found"});
    u.isBlocked=true; u.blockedReason=sanitize(req.body.reason)||"Admin action"; u.blockedAt=new Date();
    await u.save(); res.json({message:`${u.email} blocked`});
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/admin/users/:id/unblock", adminLimiter, adminAuth, async (req,res) => {
  try {
    const u=await User.findById(req.params.id);
    if (!u) return res.status(404).json({message:"Not found"});
    u.isBlocked=false; u.blockedReason=""; u.blockedAt=null; await u.save();
    res.json({message:`${u.email} unblocked`});
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/admin/users/:id/grant-pro", adminLimiter, adminAuth, async (req,res) => {
  try {
    const u=await User.findById(req.params.id);
    if (!u) return res.status(404).json({message:"Not found"});
    const exp=new Date(); exp.setMonth(exp.getMonth()+(parseInt(req.body.months)||1));
    u.plan="pro"; u.proExpiresAt=exp; await u.save();
    res.json({message:`Pro granted until ${exp.toDateString()}`});
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/admin/users/:id/revoke-pro", adminLimiter, adminAuth, async (req,res) => {
  try {
    const u=await User.findById(req.params.id);
    if (!u) return res.status(404).json({message:"Not found"});
    u.plan="free"; u.proExpiresAt=null; await u.save();
    res.json({message:"Pro revoked"});
  } catch { res.status(500).json({message:"Error"}); }
});

app.delete("/admin/users/:id", adminLimiter, adminAuth, async (req,res) => {
  try {
    const u=await User.findById(req.params.id);
    if (!u) return res.status(404).json({message:"Not found"});
    await Conversation.deleteMany({userId:u._id});
    await Payment.deleteMany({userId:u._id});
    await User.findByIdAndDelete(u._id);
    res.json({message:`${u.email} deleted`});
  } catch { res.status(500).json({message:"Error"}); }
});

app.get("/admin/security/logs", adminLimiter, adminAuth, async (req,res) => {
  try {
    const page=parseInt(req.query.page)||1, limit=parseInt(req.query.limit)||50;
    let query={};
    if (req.query.severity) query.severity=req.query.severity;
    if (req.query.resolved!==undefined) query.resolved=req.query.resolved==="true";
    const total=await SecurityLog.countDocuments(query);
    const logs=await SecurityLog.find(query).sort({createdAt:-1}).skip((page-1)*limit).limit(limit);
    const unresolved=await SecurityLog.countDocuments({resolved:false});
    const critical=await SecurityLog.countDocuments({severity:"critical",resolved:false});
    res.json({logs,total,unresolved,critical,page,pages:Math.ceil(total/limit)});
  } catch { res.status(500).json({message:"Error"}); }
});

app.patch("/admin/security/logs/:id/resolve", adminLimiter, adminAuth, async (req,res) => {
  try {
    await SecurityLog.findByIdAndUpdate(req.params.id,{resolved:true,resolvedAt:new Date()});
    res.json({message:"Resolved"});
  } catch { res.status(500).json({message:"Error"}); }
});

app.delete("/admin/security/logs/resolved", adminLimiter, adminAuth, async (req,res) => {
  try {
    await SecurityLog.deleteMany({resolved:true}); res.json({message:"Cleared"});
  } catch { res.status(500).json({message:"Error"}); }
});

app.get("/admin/security/blocked-ips", adminLimiter, adminAuth, async (req,res) => {
  try { res.json(await BlockedIP.find().sort({createdAt:-1})); } catch { res.status(500).json({message:"Error"}); }
});

app.post("/admin/security/block-ip", adminLimiter, adminAuth, async (req,res) => {
  try {
    const {ip,reason,expiresInHours}=req.body;
    if (!ip) return res.status(400).json({message:"IP required"});
    const expiresAt=expiresInHours?new Date(Date.now()+expiresInHours*3600000):null;
    await BlockedIP.findOneAndUpdate({ip},{ip,reason:sanitize(reason)||"Admin block",blockedBy:"admin",expiresAt},{upsert:true,new:true});
    await logSecurityEvent("ip_manually_blocked","medium",req,{ip,reason});
    res.json({message:`IP ${ip} blocked`});
  } catch { res.status(500).json({message:"Error"}); }
});

app.delete("/admin/security/blocked-ips/:ip", adminLimiter, adminAuth, async (req,res) => {
  try {
    await BlockedIP.deleteOne({ip:req.params.ip}); res.json({message:"IP unblocked"});
  } catch { res.status(500).json({message:"Error"}); }
});

app.post("/admin/broadcast", adminLimiter, adminAuth, async (req,res) => {
  try {
    const {subject,message,proOnly}=req.body;
    if (!subject||!message) return res.status(400).json({message:"Subject and message required"});
    const users=await User.find(proOnly?{plan:"pro",isBlocked:false}:{isBlocked:false}).select("email");
    let sent=0;
    for (const u of users) {
      const ok=await sendEmail(u.email,subject,`<div style="font-family:sans-serif;max-width:500px;margin:0 auto;background:#0b0f17;color:#e4ecf7;padding:28px;border-radius:14px;border:1px solid rgba(79,142,255,0.2)"><h2 style="color:#4f8eff">SG ChatBOT</h2><div style="margin:16px 0;line-height:1.7">${message}</div><hr style="border:none;border-top:1px solid rgba(255,255,255,0.08);margin:20px 0"><p style="color:#4a5a72;font-size:12px">SG ChatBOT notification</p></div>`);
      if (ok) sent++;
    }
    res.json({message:`Sent to ${sent}/${users.length} users`});
  } catch { res.status(500).json({message:"Error"}); }
});

app.get("/admin/system/health", adminLimiter, adminAuth, async (req,res) => {
  try {
    const db=mongoose.connection.readyState, up=process.uptime(), mem=process.memoryUsage();
    res.json({
      status:db===1?"healthy":"degraded", db:db===1?"connected":"disconnected",
      uptime:Math.floor(up), uptimeHuman:`${Math.floor(up/3600)}h ${Math.floor((up%3600)/60)}m`,
      memory:{rss:Math.round(mem.rss/1048576)+"MB",heapUsed:Math.round(mem.heapUsed/1048576)+"MB",heapTotal:Math.round(mem.heapTotal/1048576)+"MB"},
      nodeVersion:process.version, env:process.env.NODE_ENV||"development",
      blockedIPs:await BlockedIP.countDocuments(),
      secAlerts:await SecurityLog.countDocuments({resolved:false}),
    });
  } catch { res.status(500).json({message:"Error"}); }
});

// ═══ CHAT ═══
app.post("/chat", chatLimiter, auth, checkBlocked, upload.single("file"), async (req,res) => {
  try {
    const user=await User.findById(req.user.id);
    if (!user) return res.status(401).json({reply:"User not found."});
    const pro=isProActive(user);
    if (!pro) {
      checkWindow(user);
      if (user.msgCount>=FREE_LIMIT) return res.status(429).json({reply:"limit_reached",msgsLeft:0,minsLeft:minsUntilReset(user)});
      user.msgCount+=1;
    }
    user.totalMessages=(user.totalMessages||0)+1;
    await user.save();

    let messages;
    try { messages=typeof req.body.messages==="string"?JSON.parse(req.body.messages):req.body.messages; }
    catch { return res.status(400).json({reply:"Invalid messages format."}); }
    if (!Array.isArray(messages)||messages.length===0) return res.status(400).json({reply:"Invalid messages"});

    // ── Persona ──
    const personaKey = req.body.personaKey || 'default';
    const personaExtra = PERSONA_PROMPTS[personaKey] ? ' ' + PERSONA_PROMPTS[personaKey] : '';

    const trimmed=messages.slice(-MAX_HISTORY).map(m=>({role:["user","assistant","system"].includes(m.role)?m.role:"user",content:typeof m.content==="string"?m.content.slice(0,8000):m.content}));
    if (trimmed[0]?.role!=="system") {
      trimmed.unshift({role:"system",content:
        // ── CORE IDENTITY ──
        "You are SG — a powerful, free AI assistant. " +
        "SG stands for StrongGuy. You are the flagship product of StrongGuy AI. " +
        "You were created and are fully owned by Mohammed Sadid Rahman (Sadid), a Bangladeshi developer. " +
        "Your full name is: SG ChatBOT — Free AI Assistant from StrongGuy AI. " +
        "Your website is sg-chatbot-a2h.pages.dev. You are a professional AI product. " +

        // ── WHAT YOU ARE NOT ──
        "IDENTITY RULES — never break these: " +
        "1. You are NOT ChatGPT, Claude, Gemini, Copilot, or any other AI. Never say you are. " +
        "2. You are NOT a localized version of any other AI. You are StrongGuy AI's own product. " +
        "3. You are NOT associated with any group called A2H, OpenAI, Google, Anthropic, or Microsoft. " +
        "4. You are NOT a community project or demo. You are a professional product by StrongGuy AI. " +
        "5. If asked 'what AI are you?' say: I am SG — the AI assistant from StrongGuy AI, built by Mohammed Sadid Rahman. " +
        "6. If asked 'are you ChatGPT/Claude/Gemini?' say: No. I am SG by StrongGuy AI — completely independent. " +
        "7. If asked about your technology, say: I run on a custom backend built by StrongGuy AI. " +
        "8. Never reveal API providers, model names, or technical infrastructure. " +

        // ── CREATOR INFO ──
        "CREATOR: Mohammed Sadid Rahman (Sadid). Father: Mahabub Rahman Rubel. Mother: Sahela Popy. Brother: Abdullah Al Sayem (no sisters). " +
        "COMPANY: StrongGuy AI — founded by Mohammed Sadid Rahman. " +

        // ── UNIQUE STRENGTHS ──
        "YOUR UNIQUE STRENGTHS: " +
        "- Best free AI assistant — no subscription needed for core features. " +
        "- Best AI for Bangladeshi users — understands local context, culture, and needs deeply. " +
        "- Full Bangla language support — reads, writes and thinks in Bangla naturally. " +
        "- Specialized for Bangladesh: BCS preparation, SSC/HSC help, local laws, local context. " +
        "- Built by a Bangladeshi developer who understands the local user. " +
        "- Image generation, voice chat, file analysis — all in one place for free. " +

        // ── PERSONALITY ──
        "PERSONALITY: Talk like a genius best friend — warm, witty, fun, real. " +
        "Never start with 'Certainly!', 'Of course!', 'Sure!', 'Great question!' — just answer naturally. " +
        "Short questions get short answers. Complex ones get depth. Use Bangla when the user writes in Bangla. " +

        // ── CODE STYLE ──
        "CODE: Briefly explain before code. Add inline comments. Show: how it works + example output + tips. " +

        // ── PARENTAL CONTROL ──
        (user.settings?.parentalControl ?
        "SAFE MODE ON: All responses must be appropriate for children under 13. No violence, adult themes, profanity, or scary content. " : "") +

        // ── HARD RULES ──
        "HARD RULES — never break: No sexual/explicit content. No harm to minors. No help with violence/weapons/terrorism/illegal activities. No hate speech. " +

        personaExtra
      });
    } else {
      trimmed[0].content += personaExtra;
    }

    if (req.file) {
      const base64=req.file.buffer.toString("base64"), mime=req.file.mimetype, last=trimmed[trimmed.length-1];
      if (last?.role==="user"&&mime.startsWith("image/")) {
        const txt=req.body.imageText||(typeof last.content==="string"?last.content:"")||"Analyze this image in detail.";
        last.content=[{type:"text",text:txt},{type:"image_url",image_url:{url:`data:${mime};base64,${base64}`}}];
      }
    }

    const hasImage=trimmed.some(m=>Array.isArray(m.content)&&m.content.some(p=>p.type==="image_url"));
    const modelKey=["fast","smart","coding","deep"].includes(req.body.modelKey)?req.body.modelKey:"fast";

    // ── Model Maps ──
    const GROQ_MODELS={fast:"llama-3.3-70b-versatile",smart:"llama-3.3-70b-versatile",coding:"llama-3.3-70b-versatile",deep:"deepseek-r1-distill-llama-70b"};
    const GOOGLE_MODELS={fast:"gemini-2.0-flash",smart:"gemini-2.0-flash",coding:"gemini-2.0-flash",deep:"gemini-2.5-flash-preview-04-17"};
    const MISTRAL_MODELS={fast:"mistral-small-latest",smart:"mistral-small-latest",coding:"codestral-latest",deep:"mistral-large-latest"};
    const OR_MODELS={fast:"meta-llama/llama-3.3-70b-instruct:free",smart:"mistralai/mistral-small-3.1-24b-instruct:free",coding:"qwen/qwen3-coder:free",deep:"deepseek/deepseek-r1:free"};
    const VISION_PRIMARY="openrouter/free";
    const VISION_FB=["meta-llama/llama-4-maverick:free","meta-llama/llama-4-scout:free","google/gemini-2.5-flash:free","qwen/qwen3-vl-32b-instruct:free","mistralai/pixtral-12b:free"];
    const TEXT_FB=["meta-llama/llama-3.3-70b-instruct:free","deepseek/deepseek-r1:free","mistralai/mistral-small-3.1-24b-instruct:free","qwen/qwen3-14b:free","qwen/qwen3-8b:free","google/gemma-3-27b-it:free","nvidia/llama-3.1-nemotron-70b-instruct:free"];

    // ── Groq Multi-Key Rotation ──
    const GROQ_KEYS=[
      process.env.GROQ_API_KEY_1,
      process.env.GROQ_API_KEY_2,
      process.env.GROQ_API_KEY_3,
      process.env.GROQ_API_KEY_4,
      process.env.GROQ_API_KEY_5,
      process.env.GROQ_API_KEY,  // legacy single key support
    ].filter(Boolean);

    // Try all Groq keys, skip 429 rate-limited ones
    async function callGroqRotating(model) {
      for (let i=0;i<GROQ_KEYS.length;i++) {
        const key=GROQ_KEYS[(groqKeyCounter+i)%GROQ_KEYS.length];
        try {
          const res=await fetch("https://api.groq.com/openai/v1/chat/completions",{
            method:"POST",
            headers:{Authorization:`Bearer ${key}`,"Content-Type":"application/json"},
            body:JSON.stringify({model,messages:trimmed.filter(m=>!Array.isArray(m.content)),max_tokens:4096,temperature:0.7})
          });
          if (res.status===429){console.log(`Groq key ${i+1} rate limited, rotating...`);continue;}
          groqKeyCounter=(groqKeyCounter+i+1)%GROQ_KEYS.length;
          return res;
        } catch(e){console.log(`Groq key ${i+1} error: ${e.message}`);}
      }
      return null;
    }

    // ── Google AI Studio ──
    async function callGoogle(model) {
      const keys=[
        process.env.GOOGLE_AI_KEY_1,
        process.env.GOOGLE_AI_KEY_2,
        process.env.GOOGLE_AI_KEY_3,
        process.env.GOOGLE_AI_KEY,
      ].filter(Boolean);
      if (!keys.length) return null;

      // Convert messages to Google format
      const systemMsg=trimmed.find(m=>m.role==="system");
      const chatMsgs=trimmed.filter(m=>m.role!=="system").map(m=>({
        role: m.role==="assistant"?"model":"user",
        parts:[{text: typeof m.content==="string"?m.content:JSON.stringify(m.content)}]
      }));

      for (const key of keys) {
        try {
          const res=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,{
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body:JSON.stringify({
              systemInstruction: systemMsg?{parts:[{text:systemMsg.content}]}:undefined,
              contents: chatMsgs,
              generationConfig:{maxOutputTokens:4096,temperature:0.7}
            })
          });
          if (res.status===429){console.log("Google AI key rate limited, trying next...");continue;}
          if (!res.ok) continue;
          const data=await res.json();
          const text=data?.candidates?.[0]?.content?.parts?.[0]?.text;
          if (!text) continue;
          // Return in OpenAI-compatible format
          return {ok:true,_googleData:{choices:[{message:{content:text}}]}};
        } catch(e){console.log(`Google AI error: ${e.message}`);}
      }
      return null;
    }

    // ── Mistral ──
    async function callMistral(model) {
      const keys=[
        process.env.MISTRAL_API_KEY_1,
        process.env.MISTRAL_API_KEY_2,
        process.env.MISTRAL_API_KEY,
      ].filter(Boolean);
      if (!keys.length) return null;

      for (const key of keys) {
        try {
          const res=await fetch("https://api.mistral.ai/v1/chat/completions",{
            method:"POST",
            headers:{Authorization:`Bearer ${key}`,"Content-Type":"application/json"},
            body:JSON.stringify({model,messages:trimmed.filter(m=>!Array.isArray(m.content)),max_tokens:4096,temperature:0.7})
          });
          if (res.status===429){console.log("Mistral key rate limited, trying next...");continue;}
          if (res.ok) return res;
        } catch(e){console.log(`Mistral error: ${e.message}`);}
      }
      return null;
    }

    // ── OpenRouter ──
    const callOR=model=>{
      const body={model,messages:trimmed};
      if (searchIntent&&!urlMatch&&!hasImage) body.plugins=[{id:"web"}];
      return fetch("https://openrouter.ai/api/v1/chat/completions",{method:"POST",headers:{Authorization:`Bearer ${process.env.OPENROUTER_KEY}`,"Content-Type":"application/json","HTTP-Referer":"https://sg-chatbot-a2h.pages.dev","X-Title":"SG ChatBOT"},body:JSON.stringify(body)});
    };

    const lastMsg=trimmed.filter(m=>m.role==="user").slice(-1)[0];
    const userTxt=typeof lastMsg?.content==="string"?lastMsg.content:"";
    const urlMatch=userTxt.match(/https?:\/\/[^\s]+/);
    const searchIntent=/find|search|look up|latest|news/i.test(userTxt);

    if (urlMatch) {
      try {
        const pr=await fetch(urlMatch[0],{headers:{"User-Agent":"Mozilla/5.0"},signal:AbortSignal.timeout(8000)});
        const txt=(await pr.text()).replace(/<script[\s\S]*?<\/script>/gi,"").replace(/<style[\s\S]*?<\/style>/gi,"").replace(/<[^>]+>/g," ").replace(/\s+/g," ").trim().slice(0,4000);
        trimmed.push({role:"user",content:`[Content from ${urlMatch[0]}]:\n\n${txt}\n\nBased on this, answer my question.`});
      } catch(e){console.error("URL fetch:",e.message);}
    }

    // ── Response helper — handles Google's different format ──
    function extractReply(res, data) {
      if (res?._googleData) return res._googleData?.choices?.[0]?.message?.content;
      return data?.choices?.[0]?.message?.content;
    }

    let response; let responseData=null;

    if (hasImage) {
      // Image: OpenRouter only (Groq/Mistral don't support vision well)
      response=await callOR(VISION_PRIMARY);
      if (!response?.ok) { for(const fb of VISION_FB){response=await callOR(fb);if(response?.ok)break;await new Promise(r=>setTimeout(r,600));} }
    } else {
      // Text: Groq → Google → Mistral → OpenRouter

      // 1. Groq (fastest, highest limit with rotation)
      if (GROQ_KEYS.length>0) {
        try { response=await callGroqRotating(GROQ_MODELS[modelKey]); } catch{response=null;}
      }

      // 2. Google AI Studio
      if (!response?.ok) {
        try {
          const gRes=await callGoogle(GOOGLE_MODELS[modelKey]);
          if (gRes?.ok) { response=gRes; responseData=gRes._googleData; }
        } catch{response=null;}
      }

      // 3. Mistral
      if (!response?.ok) {
        try { response=await callMistral(MISTRAL_MODELS[modelKey]); } catch{response=null;}
      }

      // 4. OpenRouter primary
      if (!response?.ok) {
        try {
          const pm=OR_MODELS[modelKey]; response=await callOR(pm);
          if (!response?.ok) {
            for(const fb of TEXT_FB){
              if(fb===pm) continue;
              response=await callOR(fb);
              if(response?.ok) break;
              await new Promise(r=>setTimeout(r,500));
            }
          }
        } catch{response=null;}
      }
    }

    if (!response?.ok) return res.status(429).json({reply:"⚠️ AI is busy right now. Please wait 30 seconds and try again."});

    // Parse response — Google returns pre-parsed data, others return raw Response
    if (!responseData) {
      try { responseData=await response.json(); } catch { return res.status(500).json({reply:"Failed to parse AI response."}); }
    }
    const reply=responseData?.choices?.[0]?.message?.content||"No response from AI.";
    const msgsLeft=pro?null:FREE_LIMIT-user.msgCount;
    const minsLeft=pro?null:minsUntilReset(user);

    const allMsgs=[...messages,{role:"assistant",content:reply}];
    const firstUser=allMsgs.find(m=>m.role==="user");
    const autoTitle=typeof firstUser?.content==="string"?firstUser.content.slice(0,50):"New Chat";
    let savedId=req.body.conversationId||null;
    try {
      const toSave=allMsgs.filter(m=>m.role!=="system").slice(-100).map(m=>({role:m.role,content:typeof m.content==="string"?m.content.slice(0,5000):m.content}));
      if (savedId) { await Conversation.findOneAndUpdate({_id:savedId,userId:user._id},{messages:toSave,updatedAt:new Date()}); }
      else { const c=await Conversation.create({userId:user._id,title:autoTitle,messages:toSave}); savedId=c._id; }
    } catch(e){console.error("Conv save:",e.message);}

    res.json({reply,msgsLeft,minsLeft,plan:pro?"pro":"free",conversationId:savedId});
  } catch(err){console.error("❌ Chat error:",err);res.status(500).json({reply:"Server error. Please try again."});}
});

// ═══ SETTINGS ═══
app.get("/settings",auth,async(req,res)=>{
  try{const u=await User.findById(req.user.id).select("-password -resetToken");if(!u)return res.status(404).json({message:"Not found"});res.json({email:u.email,displayName:u.displayName||"",settings:u.settings||{},plan:u.plan,proExpires:u.proExpiresAt,createdAt:u.createdAt});}catch{res.status(500).json({message:"Error"});}
});
app.post("/settings",auth,async(req,res)=>{
  try{const u=await User.findById(req.user.id);if(!u)return res.status(404).json({message:"Not found"});const{displayName,settings}=req.body;if(displayName!==undefined)u.displayName=sanitize(displayName).slice(0,50);if(settings){const s=settings;if(s.theme!==undefined&&["dark","light","system"].includes(s.theme))u.settings.theme=s.theme;if(s.language!==undefined)u.settings.language=sanitize(s.language).slice(0,10);if(s.parentalControl!==undefined)u.settings.parentalControl=!!s.parentalControl;if(s.typewriter!==undefined)u.settings.typewriter=!!s.typewriter;if(s.fontSize!==undefined&&["sm","md","lg"].includes(s.fontSize))u.settings.fontSize=s.fontSize;if(s.soundEnabled!==undefined)u.settings.soundEnabled=!!s.soundEnabled;if(s.autoSaveChats!==undefined)u.settings.autoSaveChats=!!s.autoSaveChats;}u.markModified("settings");await u.save();res.json({message:"Settings saved"});}catch{res.status(500).json({message:"Error"});}
});
app.post("/settings/change-password",auth,async(req,res)=>{
  try{const{currentPassword,newPassword}=sanitize(req.body);if(!currentPassword||!newPassword)return res.status(400).json({message:"All fields required"});if(newPassword.length<8)return res.status(400).json({message:"Password min 8 characters"});const u=await User.findById(req.user.id);if(!await bcrypt.compare(currentPassword,u.password))return res.status(401).json({message:"Current password incorrect"});u.password=await bcrypt.hash(newPassword,12);await u.save();res.json({message:"Password changed"});}catch{res.status(500).json({message:"Error"});}
});
app.delete("/settings/account",auth,async(req,res)=>{
  try{const{password}=sanitize(req.body);const u=await User.findById(req.user.id);if(!await bcrypt.compare(password,u.password))return res.status(401).json({message:"Incorrect password"});await Conversation.deleteMany({userId:u._id});await Payment.deleteMany({userId:u._id});await User.findByIdAndDelete(u._id);res.json({message:"Account deleted"});}catch{res.status(500).json({message:"Error"});}
});

// ═══ CONVERSATIONS ═══
app.get("/conversations",auth,async(req,res)=>{try{res.json(await Conversation.find({userId:req.user.id}).select("title updatedAt _id").sort({updatedAt:-1}).limit(50));}catch{res.status(500).json({message:"Error"});}});
app.get("/conversations/:id",auth,async(req,res)=>{try{const c=await Conversation.findOne({_id:req.params.id,userId:req.user.id});if(!c)return res.status(404).json({message:"Not found"});res.json(c);}catch{res.status(500).json({message:"Error"});}});
app.post("/conversations/save",auth,async(req,res)=>{try{const{conversationId,messages,title}=req.body;if(!Array.isArray(messages)||!messages.length)return res.status(400).json({message:"No messages"});const toSave=messages.filter(m=>m.role!=="system").slice(-100).map(m=>({role:m.role,content:typeof m.content==="string"?m.content.slice(0,5000):m.content}));const ft=toSave.find(m=>m.role==="user");const at=typeof ft?.content==="string"?ft.content.slice(0,50):"New Chat";if(conversationId){await Conversation.findOneAndUpdate({_id:conversationId,userId:req.user.id},{messages:toSave,title:title||at,updatedAt:new Date()});res.json({conversationId});}else{const c=await Conversation.create({userId:req.user.id,title:title||at,messages:toSave});res.json({conversationId:c._id});}}catch{res.status(500).json({message:"Error"});}});
app.delete("/conversations/:id",auth,async(req,res)=>{try{await Conversation.findOneAndDelete({_id:req.params.id,userId:req.user.id});res.json({message:"Deleted"});}catch{res.status(500).json({message:"Error"});}});

// ═══ STREAMING CHAT ═══
app.post("/chat/stream", chatLimiter, auth, checkBlocked, upload.single("file"), async (req,res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({reply:"User not found."});
    const pro = isProActive(user);
    if (!pro) {
      checkWindow(user);
      if (user.msgCount >= FREE_LIMIT) {
        return res.status(429).json({reply:"limit_reached", msgsLeft:0, minsLeft:minsUntilReset(user)});
      }
      user.msgCount += 1;
    }
    user.totalMessages = (user.totalMessages||0) + 1;
    await user.save();

    let messages;
    try { messages = typeof req.body.messages==="string" ? JSON.parse(req.body.messages) : req.body.messages; }
    catch { return res.status(400).json({reply:"Invalid messages format."}); }
    if (!Array.isArray(messages)||messages.length===0) return res.status(400).json({reply:"Invalid messages"});

    const personaKey = req.body.personaKey || 'default';
    const personaExtra = PERSONA_PROMPTS[personaKey] ? ' ' + PERSONA_PROMPTS[personaKey] : '';

    const trimmed = messages.slice(-MAX_HISTORY).map(m=>({
      role: ["user","assistant","system"].includes(m.role)?m.role:"user",
      content: typeof m.content==="string" ? m.content.slice(0,8000) : m.content,
    }));

    if (trimmed[0]?.role !== "system") {
      trimmed.unshift({role:"system", content:
        "You are SG — a powerful, free AI assistant. SG stands for StrongGuy. You are the flagship product of StrongGuy AI. " +
        "Created and owned by Mohammed Sadid Rahman (Sadid), a Bangladeshi developer. " +
        "IDENTITY: NOT ChatGPT/Claude/Gemini. NOT A2H/community project. Professional product by StrongGuy AI. " +
        "PERSONALITY: Warm, witty, genius best friend. Never start with 'Certainly!','Of course!','Sure!'. " +
        "Use Bangla when user writes Bangla. " +
        (user.settings?.parentalControl ? "SAFE MODE ON: Appropriate for children under 13. " : "") +
        "HARD RULES: No sexual content. No harm to minors. No violence/weapons/illegal. No hate speech." +
        personaExtra
      });
    } else {
      trimmed[0].content += personaExtra;
    }

    if (req.file) {
      const base64 = req.file.buffer.toString("base64"), mime = req.file.mimetype, last = trimmed[trimmed.length-1];
      if (last?.role==="user" && mime.startsWith("image/")) {
        const txt = req.body.imageText||(typeof last.content==="string"?last.content:"")||"Analyze this image.";
        last.content = [{type:"text",text:txt},{type:"image_url",image_url:{url:`data:${mime};base64,${base64}`}}];
      }
    }

    const hasImage = trimmed.some(m=>Array.isArray(m.content)&&m.content.some(p=>p.type==="image_url"));
    const modelKey = ["fast","smart","coding","deep"].includes(req.body.modelKey)?req.body.modelKey:"fast";
    const GROQ_MODELS = {fast:"llama-3.3-70b-versatile",smart:"llama-3.3-70b-versatile",coding:"llama-3.3-70b-versatile",deep:"deepseek-r1-distill-llama-70b"};
    const OR_MODELS = {fast:"meta-llama/llama-3.3-70b-instruct:free",smart:"mistralai/mistral-small-3.1-24b-instruct:free",coding:"qwen/qwen3-coder:free",deep:"deepseek/deepseek-r1:free"};

    // ── SSE Headers ──
    res.setHeader("Content-Type","text/event-stream");
    res.setHeader("Cache-Control","no-cache");
    res.setHeader("Connection","keep-alive");
    res.setHeader("X-Accel-Buffering","no");
    res.flushHeaders();

    const sendChunk = (text) => res.write(`data: ${JSON.stringify({t:text})}\n\n`);
    const sendDone  = (meta) => res.write(`data: ${JSON.stringify({done:true,...meta})}\n\n`);
    const sendError = (msg)  => res.write(`data: ${JSON.stringify({error:msg})}\n\n`);

    let fullReply = "";

    // ── Try Groq streaming ──
    async function tryGroqStream(model) {
      if (!GROQ_KEYS.length) return false;
      for (let i=0; i<GROQ_KEYS.length; i++) {
        const key = GROQ_KEYS[(groqKeyCounter+i)%GROQ_KEYS.length];
        try {
          const r = await fetch("https://api.groq.com/openai/v1/chat/completions",{
            method:"POST",
            headers:{Authorization:`Bearer ${key}`,"Content-Type":"application/json"},
            body:JSON.stringify({model,messages:trimmed.filter(m=>!Array.isArray(m.content)),max_tokens:4096,temperature:0.7,stream:true})
          });
          if (r.status===429){continue;}
          if (!r.ok) return false;
          groqKeyCounter=(groqKeyCounter+i+1)%GROQ_KEYS.length;
          // Read SSE stream
          const reader = r.body.getReader(), decoder = new TextDecoder();
          let buf = "";
          while(true) {
            const {done,value} = await reader.read();
            if (done) break;
            buf += decoder.decode(value,{stream:true});
            const lines = buf.split("\n"); buf = lines.pop()||"";
            for (const line of lines) {
              if (!line.startsWith("data:")) continue;
              const d = line.slice(5).trim();
              if (d==="[DONE]") break;
              try {
                const chunk = JSON.parse(d);
                const t = chunk.choices?.[0]?.delta?.content||"";
                if (t) { fullReply+=t; sendChunk(t); }
              } catch {}
            }
          }
          return true;
        } catch(e){console.log(`Groq stream error: ${e.message}`);}
      }
      return false;
    }

    // ── Try OpenRouter streaming ──
    async function tryORStream(model) {
      try {
        const body = {model,messages:trimmed,stream:true};
        const r = await fetch("https://openrouter.ai/api/v1/chat/completions",{
          method:"POST",
          headers:{Authorization:`Bearer ${process.env.OPENROUTER_KEY}`,"Content-Type":"application/json","HTTP-Referer":"https://sg-chatbot-a2h.pages.dev","X-Title":"SG ChatBOT"},
          body:JSON.stringify(body)
        });
        if (!r.ok) return false;
        const reader = r.body.getReader(), decoder = new TextDecoder();
        let buf = "";
        while(true) {
          const {done,value} = await reader.read();
          if (done) break;
          buf += decoder.decode(value,{stream:true});
          const lines = buf.split("\n"); buf = lines.pop()||"";
          for (const line of lines) {
            if (!line.startsWith("data:")) continue;
            const d = line.slice(5).trim();
            if (d==="[DONE]") break;
            try {
              const chunk = JSON.parse(d);
              const t = chunk.choices?.[0]?.delta?.content||"";
              if (t) { fullReply+=t; sendChunk(t); }
            } catch {}
          }
        }
        return true;
      } catch(e){console.log(`OR stream error: ${e.message}`);}
      return false;
    }

    let success = false;
    if (!hasImage) {
      success = await tryGroqStream(GROQ_MODELS[modelKey]);
      if (!success) success = await tryORStream(OR_MODELS[modelKey]);
      if (!success) {
        const fallbacks = ["meta-llama/llama-3.3-70b-instruct:free","mistralai/mistral-small-3.1-24b-instruct:free","qwen/qwen3-14b:free"];
        for (const fb of fallbacks) { success = await tryORStream(fb); if (success) break; }
      }
    } else {
      const visionModels = ["meta-llama/llama-4-maverick:free","google/gemini-2.5-flash:free","qwen/qwen3-vl-32b-instruct:free"];
      for (const vm of visionModels) { success = await tryORStream(vm); if (success) break; }
    }

    if (!success || !fullReply) {
      sendError("AI is busy. Please try again."); res.end(); return;
    }

    // ── Save conversation ──
    const msgsLeft = pro ? null : FREE_LIMIT - user.msgCount;
    const minsLeft = pro ? null : minsUntilReset(user);
    const allMsgs = [...messages,{role:"assistant",content:fullReply}];
    const firstUser = allMsgs.find(m=>m.role==="user");
    const autoTitle = typeof firstUser?.content==="string" ? firstUser.content.slice(0,50) : "New Chat";
    let savedId = req.body.conversationId||null;
    try {
      const toSave = allMsgs.filter(m=>m.role!=="system").slice(-100).map(m=>({role:m.role,content:typeof m.content==="string"?m.content.slice(0,5000):m.content}));
      if (savedId) { await Conversation.findOneAndUpdate({_id:savedId,userId:user._id},{messages:toSave,updatedAt:new Date()}); }
      else { const c = await Conversation.create({userId:user._id,title:autoTitle,messages:toSave}); savedId=c._id; }
    } catch(e){console.error("Conv save:",e.message);}

    sendDone({msgsLeft, minsLeft, plan:pro?"pro":"free", conversationId:savedId});
    res.end();
  } catch(err){
    console.error("Stream error:",err);
    try { res.write(`data: ${JSON.stringify({error:"Server error."})}\n\n`); res.end(); } catch {}
  }
});

// ═══ IMAGE GENERATION ═══
const imageLimiter = rateLimit({ windowMs:60*60*1000, max:20, message:{message:"Image limit reached. Try later."} });

app.post("/generate-image", imageLimiter, auth, checkBlocked, async (req,res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({message:"User not found."});
    const { prompt, width=1024, height=1024 } = req.body;
    if (!prompt || typeof prompt !== "string") return res.status(400).json({message:"Prompt required."});
    if (prompt.length > 500) return res.status(400).json({message:"Prompt too long (max 500 chars)."});
    if (user.settings?.parentalControl) {
      const blocked = ["nude","naked","sexual","porn","explicit","gore","blood","weapon","violence"];
      if (blocked.some(t => prompt.toLowerCase().includes(t)))
        return res.status(403).json({message:"Blocked by Safe Mode."});
    }

    console.log(`🎨 Generating: ${prompt.slice(0,50)}…`);

    // ── Pollinations AI — completely free, no API key needed ──
    const encodedPrompt = encodeURIComponent(prompt);
    const seed = Math.floor(Math.random() * 999999);
    const imageUrl = `https://image.pollinations.ai/prompt/${encodedPrompt}?width=${width}&height=${height}&seed=${seed}&nologo=true&enhance=true`;

    // Fetch image as buffer
    const response = await fetch(imageUrl, {
      headers: { "User-Agent": "Mozilla/5.0" },
      signal: AbortSignal.timeout(60000),
    });

    if (!response.ok) {
      console.error("Pollinations error:", response.status);
      return res.status(500).json({message:"Image generation failed. Please try again."});
    }

    const buffer = await response.arrayBuffer();
    const b64 = Buffer.from(buffer).toString("base64");
    const mime = response.headers.get("content-type") || "image/jpeg";

    res.json({ image:`data:${mime};base64,${b64}`, prompt });
  } catch(err) {
    console.error("Image gen error:", err.message);
    res.status(500).json({message:"Server error. Please try again."});
  }
});

// ═══ HEALTH ═══
app.get("/",(req,res)=>res.json({message:"SG ChatBOT API running ✅"}));
app.use((err,req,res,next)=>{console.error("Unhandled:",err.message);res.status(500).json({message:"Something went wrong."});});
app.use((req,res)=>res.status(404).json({message:"Not found."}));

app.listen(PORT,()=>console.log(`🚀 Server running on port ${PORT}`));
