require("dotenv").config();

const express = require("express");
const QRCode = require("qrcode");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const https = require("https");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

const nodemailer = require("nodemailer");
const cron = require("node-cron");

// ===================== SECURITY CONSTANTS =====================
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_MASTER_KEY = process.env.ADMIN_MASTER_KEY;
const TEACHER_KEY = process.env.TEACHER_KEY;

// ===================== EMAIL TRANSPORT CONFIG =====================
let mailTransporter = null;
let isEthereal = false;
let emailSenderName = "your_college_email@gmail.com";

async function getTransporter() {
  if (mailTransporter) return mailTransporter;

  if (process.env.EMAIL_USER && process.env.EMAIL_PASS && !process.env.EMAIL_USER.includes("your_college_email")) {
    mailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
    isEthereal = false;
    emailSenderName = process.env.EMAIL_USER;
  } else {
    console.log("⚠️ Real email not set in .env. Falling back to Ethereal Mock Email.");
    const testAccount = await nodemailer.createTestAccount();
    mailTransporter = nodemailer.createTransport({
      host: "smtp.ethereal.email",
      port: 587,
      secure: false,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });
    isEthereal = true;
    emailSenderName = testAccount.user;
  }
  return mailTransporter;
}
getTransporter().catch(console.error);

if (!JWT_SECRET || !ADMIN_MASTER_KEY || !TEACHER_KEY) {
  console.error("❌ CRITICAL: Missing required environment variables. Check your .env file.");
  process.exit(1);
}

// ===================== SESSION LOCK STORAGE =====================
// Bounded map — max 5000 sessions stored (prevents memory leak)
const MAX_SESSIONS = 5000;
const usedSessions = new Map();

function addSession(sid, studentId) {
  if (usedSessions.size >= MAX_SESSIONS) {
    // Remove the oldest entry
    const firstKey = usedSessions.keys().next().value;
    usedSessions.delete(firstKey);
  }
  usedSessions.set(sid, studentId);
}

// ===================== TOKEN VERIFICATION =====================
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ error: "No token provided." });
  const actualToken = token.startsWith("Bearer ") ? token.split(" ")[1] : token;
  jwt.verify(actualToken, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Unauthorized / Invalid Token" });
    req.user = decoded;
    next();
  });
};

// Admin-only middleware
const verifyAdmin = (req, res, next) => {
  verifyToken(req, res, () => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required." });
    }
    next();
  });
};

// Admin or Teacher middleware
const verifyStaff = (req, res, next) => {
  verifyToken(req, res, () => {
    if (req.user.role !== "admin" && req.user.role !== "teacher") {
      return res.status(403).json({ error: "Staff access required." });
    }
    next();
  });
};

// ===================== RATE LIMITERS =====================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: "Too many login attempts. Please wait 15 minutes and try again." },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: { error: "Too many registration attempts. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

const attendanceLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 30,
  message: { error: "Too many attendance requests. Please slow down." },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: "Too many requests. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ===================== MIDDLEWARES =====================
// Security headers — allow inline scripts/styles for multi-page app
app.use(
  helmet({
    contentSecurityPolicy: false, // Disable strict CSP since frontend uses inline <script> tags
    crossOriginEmbedderPolicy: false,
  })
);

// CORS — allow same-origin and localhost (restrict in production via env)
// CORS_ORIGIN can be "*" to allow all, or comma-separated URLs e.g. "https://abc.onrender.com,https://myapp.com"
const rawCorsOrigin = process.env.CORS_ORIGIN || "";
const allowedOrigins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  ...(rawCorsOrigin ? rawCorsOrigin.split(",").map(o => o.trim()) : []),
];

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, curl, Render internal)
      if (!origin) return callback(null, true);
      // Allow all origins if CORS_ORIGIN=*
      if (rawCorsOrigin === "*") return callback(null, true);
      // Allow listed origins
      if (allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "DELETE", "PUT", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(generalLimiter);
app.use(express.json({ limit: "15mb" })); // Tightened from 50mb — images are already compressed
app.use(express.static("public"));

// ===================== DATABASE =====================
const primaryUri = process.env.MONGO_URI;
const localUri = "mongodb://127.0.0.1:27017/attendance";

async function connectDB() {
  try {
    await mongoose.connect(primaryUri, { serverSelectionTimeoutMS: 5000 });
    console.log("Cloud MongoDB Atlas Connected ✅");
  } catch (err) {
    console.warn("⚠️ Could not connect to MongoDB Atlas cluster:", err.message);
    console.warn("Attempting local MongoDB fallback...");
    try {
      await mongoose.connect(localUri, { serverSelectionTimeoutMS: 3000 });
      console.log("Local MongoDB Connected ✅");
    } catch (localErr) {
      console.error("\n❌ MONGODB CONNECTION FAILED!");
      console.error("----------------------------------------------------------------");
      console.error("Reason: MongoDB Atlas refused connection (IP Not Whitelisted).");
      console.error("FIX STEPS:");
      console.error("1. Go to https://cloud.mongodb.com");
      console.error("2. Navigate to Network Access -> Add IP Address");
      console.error("3. Click 'ALLOW ACCESS FROM ANYWHERE' (0.0.0.0/0) or add your current IP.");
      console.error("4. Save and restart server.js.");
      console.error("----------------------------------------------------------------\n");
    }
  }
}
connectDB();

// ===================== MODELS =====================

const Admin = mongoose.model("Admin", {
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const Teacher = mongoose.model("Teacher", {
  name: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Subject = mongoose.model("Subject", {
  name: { type: String, required: true, unique: true },
  code: { type: String, required: true, unique: true },
  teacherUsername: { type: String, default: "" },
  startTime: { type: String, default: "" },
  endTime: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
});

const Attendance = mongoose.model("Attendance", {
  studentId: String,
  class: String,
  subject: String,
  subjectName: String,
  date: String,
  time: String,
  status: { type: String, enum: ["present", "absent"], default: "present" },
  image: String,
});

const Student = mongoose.model("Student", {
  studentId: String,
  name: { type: String, default: "" },
  password: { type: String, default: "" },
  parentPhone: { type: String, default: "" },
  parentEmail: { type: String, default: "" },
  image: String,
  descriptor: [Number],
  createdAt: { type: Date, default: Date.now },
  unsubscribed: { type: Boolean, default: false },
  lastWarningEmailSentAt: { type: Date, default: null },
  lastConsecutiveWarningSentAt: { type: Date, default: null },
  // Map of "SUBJECTCODE_YYYY-MM-DD" -> true, tracks if alert was sent today for that subject
  subjectAlertsSentDates: { type: Map, of: Boolean, default: {} },
});

const Leave = mongoose.model("Leave", {
  studentId: String,
  subjectCode: String,
  date: String,
  reason: String,
  documentImage: String,
  status: { type: String, enum: ["Pending", "Approved", "Rejected"], default: "Pending" },
  createdAt: { type: Date, default: Date.now },
});

// ===================== INPUT VALIDATION HELPERS =====================
function isValidStudentId(id) {
  // Alphanumeric, 3-20 chars
  return /^[A-Z0-9]{3,20}$/.test(id);
}
function isValidUsername(u) {
  return /^[a-zA-Z0-9_]{3,30}$/.test(u);
}
function isValidPassword(p) {
  return p && p.length >= 6 && p.length <= 128;
}
function isValidPhone(p) {
  return /^[0-9]{10,15}$/.test(p);
}
function isValidEmail(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}
function sanitizeString(s) {
  if (typeof s !== "string") return "";
  return s.replace(/[<>"';&]/g, "").trim().substring(0, 200);
}

// ===================== MATH HELPER =====================
function getEuclideanDistance(desc1, desc2) {
  if (!desc1 || !desc2 || desc1.length !== 128 || desc2.length !== 128) return 1.0;
  return Math.sqrt(desc1.reduce((sum, val, i) => sum + Math.pow(val - desc2[i], 2), 0));
}

// ===================== ADMIN ROUTES =====================

// ✅ Admin Register (rate limited)
app.post("/admin/register", registerLimiter, async (req, res) => {
  try {
    const { username, password, masterKey } = req.body;
    if (masterKey !== ADMIN_MASTER_KEY) {
      // Generic error — don't reveal what key is expected
      return res.status(401).json({ error: "Invalid credentials. Registration denied." });
    }
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required." });
    }
    if (!isValidUsername(username)) {
      return res.status(400).json({ error: "Username must be 3-30 alphanumeric characters." });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }
    const existingAdmin = await Admin.findOne({ username });
    if (existingAdmin) {
      return res.status(400).json({ error: "Username already exists." });
    }
    const hashedPassword = await bcrypt.hash(password, 12); // Rounds increased to 12
    const newAdmin = new Admin({ username, password: hashedPassword });
    await newAdmin.save();
    res.json({ message: "Admin registered successfully!" });
  } catch (err) {
    console.error("❌ Admin Register Error:", err);
    res.status(500).json({ error: "Server error during registration." });
  }
});

// ✅ Admin Login (rate limited)
app.post("/admin/login", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required." });
    }
    const admin = await Admin.findOne({ username });
    // Constant-time comparison to prevent timing attacks
    if (!admin) {
      await bcrypt.compare("dummy_password_to_prevent_timing_attack", "$2b$12$invalidhashXXXXXXXXXXXXXXXXXXXX");
      return res.status(401).json({ error: "Invalid username or password." });
    }
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid username or password." });
    }
    const token = jwt.sign({ username: admin.username, role: "admin" }, JWT_SECRET, { expiresIn: "8h" });
    res.json({ message: "Login successful!", username: admin.username, token });
  } catch (err) {
    console.error("❌ Admin Login Error:", err);
    res.status(500).json({ error: "Server error during login." });
  }
});

// ===================== TEACHER ROUTES =====================

// ✅ Teacher Register (rate limited)
app.post("/teacher/register", registerLimiter, async (req, res) => {
  try {
    const { name, username, password, teacherKey } = req.body;
    if (teacherKey !== TEACHER_KEY) {
      return res.status(401).json({ error: "Invalid credentials. Registration denied." });
    }
    if (!name || !username || !password) {
      return res.status(400).json({ error: "Name, username and password required." });
    }
    if (!isValidUsername(username)) {
      return res.status(400).json({ error: "Username must be 3-30 alphanumeric characters." });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }
    const sanitizedName = sanitizeString(name);
    if (!sanitizedName) {
      return res.status(400).json({ error: "Valid name required." });
    }
    const existing = await Teacher.findOne({ username });
    if (existing) {
      return res.status(400).json({ error: "Username already exists." });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const newTeacher = new Teacher({ name: sanitizedName, username, password: hashedPassword });
    await newTeacher.save();
    res.json({ message: "Teacher registered successfully!" });
  } catch (err) {
    console.error("❌ Teacher Register Error:", err);
    res.status(500).json({ error: "Server error during registration." });
  }
});

// ✅ Teacher Login (rate limited)
app.post("/teacher/login", authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required." });
    }
    const teacher = await Teacher.findOne({ username });
    if (!teacher) {
      await bcrypt.compare("dummy", "$2b$12$invalidhashXXXXXXXXXXXXXXXXXXXX");
      return res.status(401).json({ error: "Invalid username or password." });
    }
    const isMatch = await bcrypt.compare(password, teacher.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid username or password." });
    }
    const token = jwt.sign({ username: teacher.username, role: "teacher" }, JWT_SECRET, { expiresIn: "8h" });
    res.json({ message: "Login successful!", username: teacher.username, name: teacher.name, token });
  } catch (err) {
    console.error("❌ Teacher Login Error:", err);
    res.status(500).json({ error: "Server error during login." });
  }
});

// ===================== SUBJECT ROUTES (STAFF ONLY) =====================

// ✅ Add Subject (Staff only)
app.post(["/teacher/subjects", "/admin/subjects"], verifyStaff, async (req, res) => {
  try {
    const { name, code, teacherUsername, startTime, endTime } = req.body;
    if (!name || !code) {
      return res.status(400).json({ error: "Subject name and code required." });
    }
    const sanitizedName = sanitizeString(name);
    const sanitizedCode = sanitizeString(code).toUpperCase();
    const existing = await Subject.findOne({ $or: [{ name: sanitizedName }, { code: sanitizedCode }] });
    if (existing) {
      return res.status(400).json({ error: "Subject already exists." });
    }
    const subject = new Subject({
      name: sanitizedName,
      code: sanitizedCode,
      teacherUsername: sanitizeString(teacherUsername || req.user.username || ""),
      startTime: sanitizeString(startTime || ""),
      endTime: sanitizeString(endTime || ""),
    });
    await subject.save();
    res.json({ message: "Subject added!", subject });
  } catch (err) {
    console.error("❌ Add Subject Error:", err);
    res.status(500).json({ error: "Server error." });
  }
});

// ✅ Get All Subjects (Staff only)
app.get(["/teacher/subjects", "/admin/subjects"], verifyStaff, async (req, res) => {
  try {
    const subjects = await Subject.find().sort({ name: 1 });
    res.json(subjects);
  } catch (err) {
    console.error("❌ Fetch Subjects Error:", err);
    res.status(500).json({ error: "Error fetching subjects." });
  }
});

// ✅ Delete Subject (Admin only — teachers cannot delete)
app.delete(["/teacher/subjects/:id", "/admin/subjects/:id"], verifyAdmin, async (req, res) => {
  try {
    await Subject.findByIdAndDelete(req.params.id);
    res.json({ message: "Subject deleted." });
  } catch (err) {
    console.error("❌ Delete Subject Error:", err);
    res.status(500).json({ error: "Error deleting subject." });
  }
});

// ✅ Mark Bulk Attendance per Subject (Staff only)
app.post(["/teacher/mark-subject-attendance", "/admin/mark-subject-attendance"], verifyStaff, async (req, res) => {
  try {
    const { subjectCode, subjectName, date, records } = req.body;
    if (!subjectCode || !date || !records || !Array.isArray(records)) {
      return res.status(400).json({ error: "Subject code, date, and records required." });
    }
    // Validate date format
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: "Invalid date format. Use YYYY-MM-DD." });
    }
    // Limit batch size
    if (records.length > 500) {
      return res.status(400).json({ error: "Too many records in one batch (max 500)." });
    }

    let savedCount = 0;
    let updatedCount = 0;

    for (const rec of records) {
      if (!rec.studentId || !["present", "absent"].includes(rec.status)) continue;
      const existing = await Attendance.findOne({
        studentId: rec.studentId,
        subject: sanitizeString(subjectCode).toUpperCase(),
        date: date,
      });

      if (existing) {
        existing.status = rec.status;
        existing.time = new Date().toLocaleTimeString();
        await existing.save();
        updatedCount++;
      } else {
        const newEntry = new Attendance({
          studentId: sanitizeString(rec.studentId).toUpperCase(),
          class: "BTECH",
          subject: sanitizeString(subjectCode).toUpperCase(),
          subjectName: sanitizeString(subjectName || subjectCode),
          date: date,
          time: new Date().toLocaleTimeString(),
          status: rec.status,
          image: "",
        });
        await newEntry.save();
        savedCount++;
      }
    }

    res.json({ message: `Attendance saved! ${savedCount} new, ${updatedCount} updated.` });

    // 🔔 Fire instant subject-level alerts in background (non-blocking)
    setImmediate(async () => {
      try {
        const allAttendance = await Attendance.find();
        const absentRecords = records.filter(r => r.status === "absent" && r.studentId);
        for (const rec of absentRecords) {
          await checkAndSendSubjectAlert(rec.studentId.toUpperCase(), sanitizeString(subjectCode).toUpperCase(), subjectName || subjectCode, date, allAttendance);
        }
      } catch (e) {
        console.error("❌ Subject alert background error:", e);
      }
    });
  } catch (err) {
    console.error("❌ Bulk Attendance Error:", err);
    res.status(500).json({ error: "Server error." });
  }
});

// ===================== LEAVE MANAGEMENT (ADMIN ONLY) =====================

app.get("/admin/leaves", verifyAdmin, async (req, res) => {
  try {
    const leaves = await Leave.find().sort({ createdAt: -1 });
    res.json(leaves);
  } catch (err) {
    res.status(500).json({ error: "Error fetching leaves." });
  }
});

app.post("/admin/leaves/:id", verifyAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!["Approved", "Rejected", "Pending"].includes(status)) {
      return res.status(400).json({ error: "Invalid status value." });
    }
    const leave = await Leave.findById(req.params.id);
    if (!leave) return res.status(404).json({ error: "Leave not found." });
    leave.status = status;
    await leave.save();
    res.json({ message: `Leave ${status} successfully` });
  } catch (err) {
    res.status(500).json({ error: "Error updating leave." });
  }
});

// ===================== STUDENT ROUTES =====================

// ✅ Student Login (rate limited)
app.post("/student/login", authLimiter, async (req, res) => {
  try {
    const { studentId, password } = req.body;
    if (!studentId || !password) {
      return res.status(400).json({ error: "Student ID and password required." });
    }
    const normalizedId = studentId.trim().toUpperCase();
    const student = await Student.findOne({ studentId: normalizedId });
    if (!student) {
      await bcrypt.compare("dummy", "$2b$12$invalidhashXXXXXXXXXXXXXXXXXXXX");
      return res.status(401).json({ error: "Invalid ID or password." });
    }
    if (!student.password) {
      return res.status(401).json({ error: "Account setup incomplete. Please contact admin." });
    }
    const isMatch = await bcrypt.compare(password, student.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid ID or password." });
    }
    const token = jwt.sign({ studentId: student.studentId, role: "student" }, JWT_SECRET, { expiresIn: "8h" });
    res.json({ message: "Login successful!", studentId: student.studentId, token });
  } catch (err) {
    console.error("❌ Student Login Error:", err);
    res.status(500).json({ error: "Server error during login." });
  }
});

// ✅ Get Student Profile — IDOR Fix: student can only access their OWN profile
app.get("/student/profile/:studentId", verifyToken, async (req, res) => {
  try {
    const { studentId } = req.params;
    // Students can only view their own profile; admins/teachers can view any
    if (req.user.role === "student" && req.user.studentId !== studentId) {
      return res.status(403).json({ error: "Access denied: You can only view your own profile." });
    }
    const student = await Student.findOne({ studentId }, { password: 0, descriptor: 0 });
    if (!student) return res.status(404).json({ error: "Student not found" });
    res.json(student);
  } catch (err) {
    console.error("❌ Profile fetch error:", err);
    res.status(500).json({ error: "Error fetching profile" });
  }
});

// ✅ Get Student Attendance — IDOR Fix
app.get("/student/attendance/:studentId", verifyToken, async (req, res) => {
  try {
    const { studentId } = req.params;
    if (req.user.role === "student" && req.user.studentId !== studentId) {
      return res.status(403).json({ error: "Access denied." });
    }
    const data = await Attendance.find({ studentId });
    res.json(data);
  } catch (err) {
    console.error("❌ FETCH ERROR:", err);
    res.status(500).json({ error: "Error fetching data" });
  }
});

// ✅ Get Subject-wise Attendance Summary — IDOR Fix
app.get("/student/subject-attendance/:studentId", verifyToken, async (req, res) => {
  try {
    const { studentId } = req.params;
    if (req.user.role === "student" && req.user.studentId !== studentId) {
      return res.status(403).json({ error: "Access denied." });
    }
    const subjects = await Subject.find().sort({ name: 1 });
    const attendance = await Attendance.find({ studentId });

    const subjectSummary = subjects.map((sub) => {
      const subjectRecords = attendance.filter((a) => a.subject === sub.code);
      const presentCount = subjectRecords.filter((a) => a.status === "present").length;
      const absentCount = subjectRecords.filter((a) => a.status === "absent").length;
      const totalClasses = presentCount + absentCount;
      const percentage = totalClasses > 0 ? Math.round((presentCount / totalClasses) * 100) : 0;

      return {
        subjectCode: sub.code,
        subjectName: sub.name,
        totalClasses,
        present: presentCount,
        absent: absentCount,
        percentage,
        records: subjectRecords
          .map((r) => ({ date: r.date, time: r.time, status: r.status }))
          .sort((a, b) => new Date(b.date) - new Date(a.date)),
      };
    });

    res.json(subjectSummary);
  } catch (err) {
    console.error("❌ Subject Attendance Error:", err);
    res.status(500).json({ error: "Error fetching subject attendance." });
  }
});

// ✅ Apply For Leave — IDOR Fix: use token's studentId, not body's
app.post("/student/leave", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "student") {
      return res.status(403).json({ error: "Only students can apply for leave." });
    }
    const studentId = req.user.studentId; // From verified token, not body
    const { subjectCode, date, reason, documentImage } = req.body;
    if (!subjectCode || !date || !reason || !documentImage) {
      return res.status(400).json({ error: "All fields including proof document are required." });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: "Invalid date format." });
    }
    const sanitizedReason = sanitizeString(reason);
    if (!sanitizedReason || sanitizedReason.length < 5) {
      return res.status(400).json({ error: "Please provide a valid reason (min 5 characters)." });
    }
    const leave = new Leave({
      studentId,
      subjectCode: sanitizeString(subjectCode).toUpperCase(),
      date,
      reason: sanitizedReason,
      documentImage,
    });
    await leave.save();
    res.json({ message: "Leave request submitted." });
  } catch (err) {
    res.status(500).json({ error: "Error applying for leave." });
  }
});

// ✅ Get Student Leaves — IDOR Fix
app.get("/student/leaves/:studentId", verifyToken, async (req, res) => {
  try {
    const { studentId } = req.params;
    if (req.user.role === "student" && req.user.studentId !== studentId) {
      return res.status(403).json({ error: "Access denied." });
    }
    const leaves = await Leave.find({ studentId }).sort({ createdAt: -1 });
    res.json(leaves);
  } catch (err) {
    res.status(500).json({ error: "Error fetching leaves." });
  }
});

// ✅ Student Update Face — already has auth check, strengthened
app.post("/student/update-face", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "student") {
      return res.status(403).json({ error: "Only students can update their own face." });
    }
    const studentId = req.user.studentId; // Use token, never body
    const { image, descriptor } = req.body;

    if (!image) {
      return res.status(400).json({ error: "Image required." });
    }
    if (!descriptor || descriptor.length !== 128) {
      return res.status(400).json({ error: "Valid 128-D face descriptor required." });
    }

    // Check for face conflict with other students
    const allStudents = await Student.find({
      studentId: { $ne: studentId },
      descriptor: { $exists: true, $not: { $size: 0 } },
    });
    for (const other of allStudents) {
      const distance = getEuclideanDistance(descriptor, other.descriptor);
      if (distance < 0.55) {
        return res.status(400).json({
          error: `❌ Face already registered to another account. Contact admin.`,
        });
      }
    }

    await Student.findOneAndUpdate({ studentId }, { $set: { image, descriptor } });
    console.log(`✅ Face updated for student: ${studentId}`);
    res.json({ message: "✅ Face successfully updated! You can now mark attendance." });
  } catch (err) {
    console.error("❌ Update Face Error:", err);
    res.status(500).json({ error: "Server error during face update." });
  }
});

// ✅ Student Check Face Status — IDOR Fix
app.get("/student/face-status/:studentId", verifyToken, async (req, res) => {
  try {
    const { studentId } = req.params;
    if (req.user.role === "student" && req.user.studentId !== studentId) {
      return res.status(403).json({ error: "Unauthorized" });
    }
    const student = await Student.findOne({ studentId });
    if (!student) return res.status(404).json({ error: "Not found" });
    const hasFace = student.descriptor && student.descriptor.length === 128;
    res.json({ hasFace });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Calendar Data — IDOR Fix
app.get("/student/calendar/:studentId", verifyToken, async (req, res) => {
  try {
    const { studentId } = req.params;
    if (req.user.role === "student" && req.user.studentId !== studentId) {
      return res.status(403).json({ error: "Access denied." });
    }
    const attendance = await Attendance.find({ studentId });
    const dateMap = {};
    attendance.forEach((a) => {
      if (!dateMap[a.date]) dateMap[a.date] = { present: 0, absent: 0 };
      if (a.status === "present") dateMap[a.date].present++;
      else dateMap[a.date].absent++;
    });
    const calendar = Object.entries(dateMap).map(([date, counts]) => {
      let color = "green";
      if (counts.absent > 0 && counts.present > 0) color = "yellow";
      else if (counts.absent > 0 && counts.present === 0) color = "red";
      return { date, ...counts, color };
    });
    res.json(calendar);
  } catch (err) {
    console.error("❌ Calendar Error:", err);
    res.status(500).json({ error: "Error fetching calendar" });
  }
});

// ===================== ADMIN DATA ROUTES =====================

// ✅ Students with no face (Staff — teachers also need this for alerts tab)
app.get("/admin/students/no-face", verifyStaff, async (req, res) => {
  try {
    const students = await Student.find(
      { $or: [{ descriptor: { $exists: false } }, { descriptor: { $size: 0 } }] },
      { studentId: 1, name: 1, createdAt: 1 }
    );
    res.json(students);
  } catch (err) {
    res.status(500).json({ error: "Error fetching students." });
  }
});

// ✅ List all students (Staff — teachers need this for manual attendance)
// Admin gets full info including parentPhone; teachers get limited fields
app.get("/admin/students", verifyStaff, async (req, res) => {
  try {
    // Limit fields exposed to teacher role
    const fields = req.user.role === "admin"
      ? { studentId: 1, image: 1, name: 1, parentPhone: 1, createdAt: 1 }
      : { studentId: 1, name: 1, createdAt: 1 };
    const students = await Student.find({}, fields).sort({ studentId: 1 });
    res.json(students);
  } catch (err) {
    res.status(500).json({ error: "Error fetching students." });
  }
});

// ✅ Admin: Delete student (Admin only)
app.delete("/admin/students/:id", verifyAdmin, async (req, res) => {
  try {
    const student = await Student.findByIdAndDelete(req.params.id);
    if (!student) return res.status(404).json({ error: "Student not found" });
    await Attendance.deleteMany({ studentId: student.studentId });
    await Leave.deleteMany({ studentId: student.studentId });
    console.log(`🗑️ Deleted student account: ${student.studentId}`);
    res.json({ message: "Student and related records deleted." });
  } catch (err) {
    res.status(500).json({ error: "Server error deleting student." });
  }
});

// ✅ Admin: List all teachers (Admin only)
app.get("/admin/teachers", verifyAdmin, async (req, res) => {
  try {
    const teachers = await Teacher.find({}, { name: 1, username: 1, createdAt: 1 });
    res.json(teachers);
  } catch (err) {
    console.log("❌ FETCH TEACHERS ERROR:", err);
    res.status(500).json({ error: "Error fetching teachers" });
  }
});

// ✅ Defaulters list (Staff — teachers also see this in their Alerts tab)
app.get("/admin/defaulters", verifyStaff, async (req, res) => {
  try {
    const students = await Student.find({}, { studentId: 1, name: 1, parentPhone: 1, parentEmail: 1 });
    const attendance = await Attendance.find();
    const defaulters = [];
    students.forEach((s) => {
      const records = attendance.filter((a) => a.studentId === s.studentId);
      const present = records.filter((a) => a.status === "present").length;
      const total = records.length;
      const perc = total > 0 ? Math.round((present / total) * 100) : 100;
      if (total > 0 && perc < 75) {
        defaulters.push({ studentId: s.studentId, name: s.name || s.studentId, parentPhone: s.parentPhone, parentEmail: s.parentEmail, present, total, percentage: perc });
      }
    });
    defaulters.sort((a, b) => a.percentage - b.percentage);
    res.json(defaulters);
  } catch (err) {
    res.status(500).json({ error: "Error fetching defaulters" });
  }
});

// ✅ Get All Attendance (Admin/Teacher only)
app.get("/attendance", verifyStaff, async (req, res) => {
  try {
    const data = await Attendance.find();
    res.json(data);
  } catch (err) {
    console.log("❌ FETCH ERROR:", err);
    res.status(500).json({ error: "Error fetching data", details: err.message });
  }
});

// ===================== PUBLIC / SHARED ROUTES =====================

// ✅ Get All Subjects (public read — needed for student scan page)
app.get("/subjects", async (req, res) => {
  try {
    const subjects = await Subject.find({}, { name: 1, code: 1, startTime: 1, endTime: 1 }).sort({ name: 1 });
    res.json(subjects);
  } catch (err) {
    console.error("❌ Fetch Subjects Error:", err);
    res.status(500).json({ error: "Error fetching subjects." });
  }
});

// ✅ Check Duplicate for Registration — sanitized, no name leakage
app.get("/api/check-student", async (req, res) => {
  try {
    const { studentId, phone, email } = req.query;
    if (studentId) {
      const normalizedId = studentId.trim().toUpperCase();
      if (!isValidStudentId(normalizedId)) {
        return res.json({ conflict: false }); // Don't hint at format rules
      }
      const exists = await Student.findOne({ studentId: normalizedId });
      // Return conflict without revealing existing student's name
      if (exists) return res.json({ conflict: true, field: "studentId", message: "This Roll No. is already registered." });
    }
    if (phone) {
      if (!isValidPhone(phone)) {
        return res.json({ conflict: false });
      }
      const exists = await Student.findOne({ parentPhone: phone });
      if (exists) return res.json({ conflict: true, field: "phone", message: "This phone number is already registered." });
    }
    if (email) {
      if (!isValidEmail(email)) {
        return res.json({ conflict: false });
      }
      const exists = await Student.findOne({ parentEmail: email });
      if (exists) return res.json({ conflict: true, field: "email", message: "This email is already registered." });
    }
    res.json({ conflict: false });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Register Face (rate limited — no auth required as students register here first)
app.post("/registerFace", registerLimiter, async (req, res) => {
  try {
    const { studentId, name, password, parentPhone, parentEmail, image, descriptor } = req.body;
    console.log("📥 Incoming Register:", studentId ? "ID OK" : "NO ID", image ? "IMG OK" : "NO IMG");

    if (!studentId || !password || !image || !parentPhone || !parentEmail || !name) {
      return res.status(400).json({ error: "All fields (ID, Name, Password, Phone, Email, Image) are required." });
    }

    const normalizedId = studentId.trim().toUpperCase();
    if (!isValidStudentId(normalizedId)) {
      return res.status(400).json({ error: "Invalid Student ID format." });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }
    if (!isValidPhone(parentPhone.trim())) {
      return res.status(400).json({ error: "Invalid phone number format." });
    }
    if (!isValidEmail(parentEmail.trim())) {
      return res.status(400).json({ error: "Invalid email format." });
    }
    const sanitizedName = sanitizeString(name);
    if (!sanitizedName || sanitizedName.length < 2) {
      return res.status(400).json({ error: "Valid name required." });
    }

    const existing = await Student.findOne({ studentId: normalizedId });
    if (existing) return res.status(400).json({ error: "This Roll No. is already registered." });

    const existingPhone = await Student.findOne({ parentPhone: parentPhone.trim() });
    const existingEmail = await Student.findOne({ parentEmail: parentEmail.trim() });
    if (existingEmail) return res.status(400).json({ error: "This email is already registered." });

    if (descriptor && descriptor.length > 0) {
      const allStudents = await Student.find({ descriptor: { $exists: true, $not: { $size: 0 } } });
      for (const student of allStudents) {
        const distance = getEuclideanDistance(descriptor, student.descriptor);
        if (distance < 0.55) {
          return res.status(400).json({ error: "This face is already registered under another account." });
        }
      }
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newStudent = new Student({
      studentId: normalizedId,
      name: sanitizedName,
      parentPhone: parentPhone.trim(),
      parentEmail: parentEmail.trim(),
      password: hashedPassword,
      image,
      descriptor: descriptor || [],
    });
    await newStudent.save();
    console.log("✅ Student Registered:", normalizedId);
    res.json({ message: "✅ Successfully registered." });
  } catch (err) {
    console.log("❌ REGISTER ERROR:", err);
    res.status(500).json({ error: "Server Error during registration." });
  }
});

// ✅ Generate QR (AUTH REQUIRED now — teachers/admins only)
app.get("/generateQR", verifyStaff, async (req, res) => {
  const sessionId = "sess_" + Date.now().toString(36) + Math.random().toString(36).substring(2);
  const data = { class: "BTECH", timestamp: Date.now(), sessionId };
  try {
    const qr = await QRCode.toDataURL(JSON.stringify(data));
    res.send(`<h2>Scan this QR for Attendance</h2><img src="${qr}" /><p>QR valid for 2 minutes</p>`);
  } catch (err) {
    console.log("❌ QR ERROR:", err);
    res.status(500).json({ error: "Error generating QR" });
  }
});

// ✅ Generate QR via API (Staff only)
app.post("/generateQRapi", verifyStaff, async (req, res) => {
  try {
    const { subjectCode, subjectName } = req.body;
    const sessionId = "sess_" + Date.now().toString(36) + Math.random().toString(36).substring(2);
    const data = {
      class: "BTECH",
      subject: sanitizeString(subjectCode || "").toUpperCase(),
      subjectName: sanitizeString(subjectName || ""),
      timestamp: Date.now(),
      sessionId,
    };
    const qr = await QRCode.toDataURL(JSON.stringify(data));
    res.json({ qr });
  } catch (err) {
    console.log("❌ QR API ERROR:", err);
    res.status(500).json({ error: "Error generating QR" });
  }
});

// ✅ Mark Attendance (rate limited — must provide valid studentId/face)
app.post("/markAttendance", attendanceLimiter, async (req, res) => {
  try {
    const { studentId, image, data, descriptor, subject, subjectName } = req.body;
    console.log("📥 Attendance Request for ID:", studentId);

    if (!studentId || !image) {
      return res.status(400).json({ error: "Missing biometrics or ID." });
    }

    const normalizedId = studentId.trim().toUpperCase();
    if (!isValidStudentId(normalizedId)) {
      return res.status(400).json({ error: "Invalid Student ID format." });
    }

    const today = new Date().toISOString().split("T")[0];
    let parsedData = {};
    if (data) {
      try {
        parsedData = typeof data === "string" ? JSON.parse(data) : data;
      } catch (e) {
        console.log("⚠️ QR Data parse failed:", e.message);
      }
    }

    const finalSubject = sanitizeString(subject || parsedData.subject || "").toUpperCase();
    const finalSubjectName = sanitizeString(subjectName || parsedData.subjectName || "");

    // 2-MINUTE QR EXPIRY
    if (parsedData && parsedData.timestamp) {
      const qrAgeMinutes = (Date.now() - parsedData.timestamp) / (1000 * 60);
      if (qrAgeMinutes > 2) {
        return res.status(400).json({ error: "QR Code Expired. Ask teacher to generate a new QR." });
      }
    }

    // SESSION-LOCK CHECK
    if (parsedData && parsedData.sessionId) {
      const sid = parsedData.sessionId;
      if (usedSessions.has(sid)) {
        const owner = usedSessions.get(sid);
        if (owner === normalizedId) {
          return res.status(400).json({ error: "Your attendance for this session is already marked!" });
        } else {
          return res.status(400).json({ error: "QR session already used by another student. Ask teacher for a new QR." });
        }
      }
      addSession(sid, normalizedId); // Bounded add
    }

    // TIMETABLE CHECK
    if (finalSubject) {
      const subjectDoc = await Subject.findOne({ code: finalSubject });
      if (subjectDoc && subjectDoc.startTime && subjectDoc.endTime) {
        const now = new Date();
        const currentTimeInt = now.getHours() * 60 + now.getMinutes();
        const startParts = subjectDoc.startTime.split(":");
        const endParts = subjectDoc.endTime.split(":");
        if (startParts.length === 2 && endParts.length === 2) {
          const startTimeInt = parseInt(startParts[0]) * 60 + parseInt(startParts[1]);
          const endTimeInt = parseInt(endParts[0]) * 60 + parseInt(endParts[1]);
          if (currentTimeInt < startTimeInt) {
            return res.status(400).json({ error: `Class hasn't started yet. Starts at ${subjectDoc.startTime}` });
          }
          if (currentTimeInt > endTimeInt) {
            return res.status(400).json({ error: `Class closed. Ended at ${subjectDoc.endTime}` });
          }
        }
      }
    }

    // DUPLICATE CHECK
    const duplicateQuery = { studentId: normalizedId, date: today };
    if (finalSubject) duplicateQuery.subject = finalSubject;
    const existingEntry = await Attendance.findOne(duplicateQuery);
    if (existingEntry) {
      return res.status(400).json({ error: "Attendance already marked today" + (finalSubject ? ` for ${finalSubject}` : "") });
    }

    const student = await Student.findOne({ studentId: normalizedId });
    if (!student) {
      return res.status(404).json({ error: "Student ID not registered." });
    }

    // FAIL-CLOSED FACE MATCH
    const studentHasDescriptor = student.descriptor && student.descriptor.length === 128;
    const liveDescriptorReceived = descriptor && descriptor.length === 128;

    if (!studentHasDescriptor) {
      console.log(`🚫 BLOCKED [${normalizedId}]: No registered face descriptor in DB.`);
      return res.status(400).json({ error: "Face not registered. Please go to your Student Dashboard and set up your face via 'Update Face'." });
    }
    if (!liveDescriptorReceived) {
      console.log(`🚫 BLOCKED [${normalizedId}]: Live descriptor not received.`);
      return res.status(400).json({ error: "Face scan failed. Keep camera clear and try again." });
    }

    const distance = getEuclideanDistance(descriptor, student.descriptor);
    console.log(`🧠 Face Match Distance [${normalizedId}]: ${distance.toFixed(4)}`);
    if (distance > 0.55) {
      return res.status(400).json({ error: "Face match failed. Proxy attendance detected — access denied." });
    }
    console.log(`✅ Face Match Passed [${normalizedId}] — Distance: ${distance.toFixed(4)}`);

    const newEntry = new Attendance({
      studentId: normalizedId,
      class: parsedData.class || "BTECH",
      subject: finalSubject,
      subjectName: finalSubjectName,
      date: today,
      time: new Date().toLocaleTimeString(),
      status: "present",
      image,
    });
    await newEntry.save();
    console.log("✅ Attendance Saved for", normalizedId);
    
    // Trigger async alert check
    const allAttendance = await Attendance.find({ studentId: normalizedId });
    checkAndSendSubjectAlert(normalizedId, finalSubject, finalSubjectName, today, allAttendance);
    
    res.json({ message: "✅ Attendance Marked Successfully" });
  } catch (err) {
    console.log("❌ ATTENDANCE ERROR:", err);
    res.status(500).json({ error: "Server Error" });
  }
});

// ===================== EMAIL ROUTES (ADMIN ONLY) =====================

// 🔔 INSTANT Subject-Level Alert Helper
// Called after attendance is saved. Sends email if subject attendance < 75%, max 1 alert per subject per day.
async function checkAndSendSubjectAlert(studentId, subjectCode, subjectName, date, allAttendance) {
  try {
    const student = await Student.findOne({ studentId });
    if (!student || !student.parentEmail || student.unsubscribed) return;

    // Spam guard: check if alert was already sent for this subject today
    const alertKey = `${subjectCode}_${date}`;
    if (student.subjectAlertsSentDates && student.subjectAlertsSentDates.get(alertKey)) {
      console.log(`⏭️ [SKIP] Alert already sent today for ${studentId} in ${subjectCode}`);
      return;
    }

    // Calculate this student's attendance for this specific subject
    const subjectRecords = allAttendance.filter(
      a => a.studentId === studentId && a.subject === subjectCode
    );
    const total = subjectRecords.length;
    if (total === 0) return;

    const present = subjectRecords.filter(a => a.status === "present").length;
    const percentage = Math.round((present / total) * 100);

    if (percentage < 75) {
      const serverUrl = process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
      const emailSubject = `⚠️ Low Attendance Alert: ${student.name} in ${subjectName}`;
      const emailBody = [
        `Dear Parent,`,
        ``,
        `This is an automated alert from the Attendance Management System.`,
        ``,
        `Your ward ${student.name} (Roll No: ${studentId}) has low attendance in the following subject:`,
        ``,
        `  Subject            : ${subjectName}`,
        `  Current Attendance : ${percentage}% (${present} present out of ${total} classes)`,
        `  Required           : 75%`,
        ``,
        `Immediate attention is required to avoid eligibility issues for exams.`,
        `Please meet the concerned subject teacher at the earliest.`,
        ``,
        `Regards,`,
        `College Administration`,
        ``,
        `---`,
        `To stop receiving these alerts: ${serverUrl}/unsubscribe/${studentId}`
      ].join("\n");

      console.log(`📧 [INSTANT SUBJECT ALERT] ${studentId} | ${subjectCode} | ${percentage}% -> To: ${student.parentEmail}`);
      await sendEmail(student.parentEmail, emailSubject, emailBody);

      // Mark alert as sent for today so no duplicate emails
      student.subjectAlertsSentDates.set(alertKey, true);
      student.markModified("subjectAlertsSentDates");
      await student.save();
    }
  } catch (err) {
    console.error("❌ checkAndSendSubjectAlert error:", err);
  }
}


async function sendEmail(to, subject, text) {
  try {
    const transporter = await getTransporter();
    const info = await transporter.sendMail({
      from: `"Attendance System" <${emailSenderName}>`,
      to,
      subject,
      text
    });
    
    console.log("📧 Email sent to: " + to);
    if (isEthereal) {
      console.log("🔗 Preview Sent Email: %s", nodemailer.getTestMessageUrl(info));
    }
    
    return { status: 200, message: "Email sent successfully", messageId: info.messageId };
  } catch (error) {
    console.error("❌ Email sending failed:", error);
    return { error: error.message };
  }
}

app.post("/admin/send-absent-email", verifyAdmin, async (req, res) => {
  try {
    const { date, subject } = req.body;
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ error: "Valid date required (YYYY-MM-DD)." });
    }
    let query = { date, status: "absent" };
    if (subject) query.subject = sanitizeString(subject).toUpperCase();

    const absentees = await Attendance.find(query);
    if (absentees.length === 0) {
      return res.json({ message: "No absent students found to send Email." });
    }

    let emailCount = 0;
    for (const record of absentees) {
      const student = await Student.findOne({ studentId: record.studentId });
      if (student && student.parentEmail) {
        const emailSubject = `Attendance Alert: ${student.name} is absent`;
        const emailBody = `Dear Parent,\n\nYour ward ${student.name} is marked absent today (${date}) for the class: ${record.subjectName || record.subject}.\n\nPlease ensure their regular attendance.\n\nRegards,\nCollege Administration`;
        console.log(`📧 [EMAIL] -> To: ${student.parentEmail}`);
        const result = await sendEmail(student.parentEmail, emailSubject, emailBody);
        if (!result.error) emailCount++;
      }
    }
    res.json({ message: `Emails sent to parents of ${emailCount} absent student(s).` });
  } catch (err) {
    console.error("❌ Email Error:", err);
    res.status(500).json({ error: "Error sending Email." });
  }
});

app.post("/admin/send-warning-email", verifyAdmin, async (req, res) => {
  try {
    const { studentId } = req.body;
    if (!studentId) return res.status(400).json({ error: "Student ID required." });
    const student = await Student.findOne({ studentId: studentId.trim().toUpperCase() });
    if (!student || !student.parentEmail) {
      return res.status(404).json({ error: "Student or Parent Email not found." });
    }
    const emailSubject = `URGENT: Low Attendance Warning for ${student.name}`;
    const emailBody = `Dear Parent,\n\nThis is an urgent notice that your ward ${student.name} has an overall attendance below the required 75% threshold.\n\nPlease meet the Head of Department (HOD) at the earliest to discuss this matter, as it may affect their eligibility to appear for exams.\n\nRegards,\nCollege Administration`;
    console.log(`📧 [WARNING EMAIL] -> To: ${student.parentEmail}`);
    const result = await sendEmail(student.parentEmail, emailSubject, emailBody);
    if (result.error) {
      return res.status(500).json({ error: "Failed to send email." });
    }
    res.json({ message: `Warning Email sent to ${student.name}'s parents.` });
  } catch (err) {
    console.error("❌ Email Error:", err);
    res.status(500).json({ error: "Error sending warning Email" });
  }
});

// ===================== AUTOMATED EMAIL SYSTEM (CRON) =====================

app.get("/unsubscribe/:studentId", async (req, res) => {
  try {
    const student = await Student.findOneAndUpdate(
      { studentId: req.params.studentId.toUpperCase() },
      { unsubscribed: true },
      { new: true }
    );
    if (!student) return res.status(404).send("<h1>Student not found.</h1>");
    res.send("<h1>Unsubscribed successfully.</h1><p>You will no longer receive automated attendance emails.</p>");
  } catch (e) {
    res.status(500).send("<h1>Error unsubscribing.</h1>");
  }
});

async function runDailyEmailDigest() {
  console.log("⏰ Running Daily Email Digest...");
  const today = new Date().toISOString().split("T")[0]; // YYYY-MM-DD
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

  try {
    const students = await Student.find({ unsubscribed: false, parentEmail: { $ne: "" } });
    if (students.length === 0) return;

    const allAttendance = await Attendance.find();
    
    // 1. Daily Digest Check (>= 2 absences today)
    const todaysAbsences = allAttendance.filter(a => a.date === today && a.status === "absent");
    const absencesByStudent = {};
    todaysAbsences.forEach(a => {
      if (!absencesByStudent[a.studentId]) absencesByStudent[a.studentId] = [];
      absencesByStudent[a.studentId].push(a.subjectName || a.subject);
    });

    for (const student of students) {
      // Daily Digest
      const absences = absencesByStudent[student.studentId] || [];
      if (absences.length >= 2) {
        const subjectList = absences.join(", ");
        const emailBody = `Dear Parent,\n\nYour ward ${student.name} was absent for ${absences.length} periods today (${today}): ${subjectList}.\n\nPlease ensure their regular attendance.\n\nClick here to unsubscribe: http://localhost:${process.env.PORT || 3000}/unsubscribe/${student.studentId}\n\nRegards,\nCollege Administration`;
        console.log(`📧 [DAILY DIGEST] -> To: ${student.parentEmail}`);
        await sendEmail(student.parentEmail, `Daily Attendance Summary: ${student.name}`, emailBody);
      }

      // Calculate overall stats for thresholds
      const records = allAttendance.filter(a => a.studentId === student.studentId);
      const total = records.length;
      if (total === 0) continue;

      const present = records.filter(a => a.status === "present").length;
      const perc = Math.round((present / total) * 100);

      let updated = false;

      // 2. Threshold < 75%
      if (perc < 75) {
        if (!student.lastWarningEmailSentAt || student.lastWarningEmailSentAt < sevenDaysAgo) {
          const warnBody = `URGENT: Low Attendance Warning for ${student.name}\n\nDear Parent,\nThis is an urgent notice that your ward's overall attendance is ${perc}%, which is below the 75% threshold.\n\nPlease meet the HOD immediately.\n\nClick here to unsubscribe: http://localhost:${process.env.PORT || 3000}/unsubscribe/${student.studentId}\n\nRegards,\nCollege Administration`;
          console.log(`📧 [LOW THRESHOLD WARNING] -> To: ${student.parentEmail}`);
          await sendEmail(student.parentEmail, `URGENT: Low Attendance (${perc}%)`, warnBody);
          student.lastWarningEmailSentAt = new Date();
          updated = true;
        }
      }

      // 3. Consecutive absences check (last 3 distinct dates)
      const uniqueDates = [...new Set(records.map(r => r.date))].sort().reverse();
      if (uniqueDates.length >= 3) {
        const last3Dates = uniqueDates.slice(0, 3);
        const recordsInLast3 = records.filter(r => last3Dates.includes(r.date));
        const presentInLast3 = recordsInLast3.filter(r => r.status === "present").length;
        
        if (presentInLast3 === 0) {
          if (!student.lastConsecutiveWarningSentAt || student.lastConsecutiveWarningSentAt < sevenDaysAgo) {
            const consecBody = `CRITICAL: Continuous Absence Warning\n\nDear Parent,\nYour ward ${student.name} has been absent for the last 3 consecutive college days.\n\nThis is a strict violation of college rules.\n\nClick here to unsubscribe: http://localhost:${process.env.PORT || 3000}/unsubscribe/${student.studentId}`;
            console.log(`📧 [CONSECUTIVE ABSENCE WARNING] -> To: ${student.parentEmail}`);
            await sendEmail(student.parentEmail, `CRITICAL: 3 Days Consecutive Absence`, consecBody);
            student.lastConsecutiveWarningSentAt = new Date();
            updated = true;
          }
        }
      }

      if (updated) await student.save();
    }
  } catch (err) {
    console.error("❌ Cron Error:", err);
  }
}

// Schedule to run every day at 18:00 (6:00 PM)
cron.schedule("0 18 * * *", runDailyEmailDigest);

app.get("/admin/test-cron", verifyAdmin, async (req, res) => {
  runDailyEmailDigest(); // Run async in background
  res.json({ message: "Cron job triggered manually for testing. Check console." });
});

// ===================== SEED DEMO DATA (ADMIN ONLY NOW) =====================
app.post("/seed-demo", verifyAdmin, async (req, res) => {
  try {
    const subjectsToAdd = [
      { name: "Mathematics", code: "MATH101", startTime: "09:00", endTime: "10:00" },
      { name: "Physics", code: "PHY102", startTime: "10:00", endTime: "11:00" },
      { name: "Computer Science", code: "CS103", startTime: "11:00", endTime: "12:00" },
      { name: "English", code: "ENG104", startTime: "14:00", endTime: "15:00" },
    ];
    for (const sub of subjectsToAdd) {
      const exists = await Subject.findOne({ code: sub.code });
      if (!exists) await new Subject(sub).save();
    }

    const demoStudents = [
      { studentId: "CS21001", name: "Amit Sharma", password: "Secure@123" },
      { studentId: "CS21002", name: "Rahul Verma", password: "Secure@456" },
    ];
    for (const ds of demoStudents) {
      const exists = await Student.findOne({ studentId: ds.studentId });
      if (!exists) {
        const hashed = await bcrypt.hash(ds.password, 12);
        await new Student({ studentId: ds.studentId, name: ds.name, password: hashed, parentPhone: "0000000000", image: "", descriptor: [] }).save();
      }
    }

    const subjects = await Subject.find();
    const today = new Date();
    for (const ds of demoStudents) {
      for (let i = 1; i <= 25; i++) {
        const d = new Date(today);
        d.setDate(d.getDate() - i);
        if (d.getDay() === 0) continue;
        const dateStr = d.toISOString().split("T")[0];
        for (const sub of subjects) {
          const exists = await Attendance.findOne({ studentId: ds.studentId, subject: sub.code, date: dateStr });
          if (exists) continue;
          let status = ds.studentId === "CS21001" ? (Math.random() < 0.85 ? "present" : "absent") : (Math.random() < 0.62 ? "present" : "absent");
          await new Attendance({ studentId: ds.studentId, class: "BTECH", subject: sub.code, subjectName: sub.name, date: dateStr, time: sub.startTime || "09:00:00", status, image: "" }).save();
        }
      }
    }

    res.json({ message: "Demo data seeded. CS21001 (Secure@123), CS21002 (Secure@456)" });
  } catch (err) {
    console.error("❌ Seed Error:", err);
    res.status(500).json({ error: "Error seeding data: " + err.message });
  }
});

// ===================== SERVER STARTUP =====================
const PORT = process.env.PORT || 3000;

if (fs.existsSync("./cert.pem") && fs.existsSync("./key.pem")) {
  const options = {
    key: fs.readFileSync("./key.pem"),
    cert: fs.readFileSync("./cert.pem"),
  };
  https.createServer(options, app).listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 HTTPS Server running securely on port ${PORT}`);
  });
} else {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 HTTP Server running on http://localhost:${PORT}`);
    console.log(`ℹ️  To enable HTTPS on mobile, generate certs with mkcert.`);
  });
}