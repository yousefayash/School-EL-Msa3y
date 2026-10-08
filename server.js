const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const SESSION_HOURS = 8;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'MasaiAdmin2026!';
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'database.json');

fs.mkdirSync(DATA_DIR, { recursive: true });

function readDb() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return { registrations: [], sessions: {} };
  }
}
function writeDb(db) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(tmp, DATA_FILE);
}
let db = readDb();
if (!Array.isArray(db.registrations)) db.registrations = [];
if (!db.sessions || typeof db.sessions !== 'object') db.sessions = {};

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'محاولات تسجيل دخول كثيرة. حاول بعد قليل.' }
});
const registrationLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'تم إرسال طلبات كثيرة. حاول بعد قليل.' }
});

function cookieOptions(maxAge) {
  return { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/', maxAge };
}
function parseCookies(req) {
  const header = req.headers.cookie || '';
  return Object.fromEntries(header.split(';').filter(Boolean).map(part => {
    const i = part.indexOf('=');
    return [decodeURIComponent(part.slice(0, i).trim()), decodeURIComponent(part.slice(i + 1).trim())];
  }));
}
function newSession() {
  return crypto.randomBytes(32).toString('hex');
}
function cleanExpiredSessions() {
  const now = Date.now();
  for (const [token, session] of Object.entries(db.sessions)) {
    if (!session || session.expiresAt <= now) delete db.sessions[token];
  }
}
function auth(req, res, next) {
  cleanExpiredSessions();
  const token = parseCookies(req).masai_session;
  const session = token && db.sessions[token];
  if (!session || session.expiresAt <= Date.now()) {
    if (token) res.clearCookie('masai_session', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/' });
    return res.status(401).json({ error: 'غير مصرح' });
  }
  req.admin = { username: session.username };
  next();
}
function sanitize(value, max = 500) {
  return String(value ?? '').trim().slice(0, max);
}
function validRegistration(body) {
  const data = {
    name: sanitize(body.name, 120),
    grade: sanitize(body.grade, 60),
    phone: sanitize(body.phone, 40),
    email: sanitize(body.email, 160),
    notes: sanitize(body.notes, 1000)
  };
  if (!data.name || !data.grade || !data.phone) return { error: 'الاسم والصف ورقم الهاتف مطلوبة.' };
  if (data.email && !/^\S+@\S+\.\S+$/.test(data.email)) return { error: 'البريد الإلكتروني غير صحيح.' };
  return { data };
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'al-masai-school' }));

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const username = sanitize(req.body.username, 80);
  const password = String(req.body.password || '');
  if (username !== ADMIN_USER || !await bcrypt.compare(password, bcrypt.hashSync(ADMIN_PASS, 12))) {
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  }
  cleanExpiredSessions();
  const token = newSession();
  db.sessions[token] = { username, expiresAt: Date.now() + SESSION_HOURS * 60 * 60 * 1000 };
  writeDb(db);
  res.cookie('masai_session', token, cookieOptions(SESSION_HOURS * 60 * 60 * 1000));
  res.json({ ok: true, username });
});

app.post('/api/auth/logout', (req, res) => {
  const token = parseCookies(req).masai_session;
  if (token) delete db.sessions[token];
  writeDb(db);
  res.clearCookie('masai_session', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/' });
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => res.json({ authenticated: true, username: req.admin.username }));

app.post('/api/registrations', registrationLimiter, (req, res) => {
  const result = validRegistration(req.body || {});
  if (result.error) return res.status(400).json({ error: result.error });
  const item = {
    id: crypto.randomUUID(),
    ...result.data,
    date: new Date().toISOString(),
    status: 'جديد'
  };
  db.registrations.unshift(item);
  writeDb(db);
  res.status(201).json({ ok: true, message: 'تم إرسال الطلب بنجاح', registration: { id: item.id } });
});

app.get('/api/admin/registrations', auth, (req, res) => {
  res.json({ registrations: db.registrations });
});

app.delete('/api/admin/registrations', auth, (req, res) => {
  db.registrations = [];
  writeDb(db);
  res.json({ ok: true });
});

app.get('/api/admin/stats', auth, (req, res) => {
  const start = new Date(); start.setHours(0, 0, 0, 0);
  const today = db.registrations.filter(r => new Date(r.date) >= start).length;
  res.json({ total: db.registrations.length, today });
});

// Serve the website's CSS, JavaScript, images, and HTML files.
// This must come before the SPA fallback so /css/style.css and /js/app.js
// are returned as real static files instead of index.html.
app.use(express.static(__dirname, {
  extensions: ['html'],
  index: 'index.html'
}));

app.use((req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'حدث خطأ في الخادم' });
});

app.listen(PORT, HOST, () => console.log(`Al-Masai School server running on http://localhost:${PORT}`));
