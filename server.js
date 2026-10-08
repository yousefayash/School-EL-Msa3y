const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

const SESSION_HOURS = 8;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'MasaiAdmin2026!';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not configured.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

// =========================
// Database
// =========================

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS registrations (
      id UUID PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      grade VARCHAR(60) NOT NULL,
      phone VARCHAR(40) NOT NULL,
      email VARCHAR(160),
      notes TEXT,
      date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      status VARCHAR(40) NOT NULL DEFAULT 'جديد'
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token VARCHAR(128) PRIMARY KEY,
      username VARCHAR(80) NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL
    )
  `);

  console.log('PostgreSQL database initialized.');
}

// =========================
// Middleware
// =========================

app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(compression());

app.use(express.json({ limit: '50kb' }));

app.use(
  express.urlencoded({
    extended: false,
    limit: '50kb'
  })
);

// =========================
// Rate limiting
// =========================

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'محاولات تسجيل دخول كثيرة. حاول بعد قليل.'
  }
});

const registrationLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'تم إرسال طلبات كثيرة. حاول بعد قليل.'
  }
});

// =========================
// Helpers
// =========================

function cookieOptions(maxAge) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge
  };
}

function parseCookies(req) {
  const header = req.headers.cookie || '';

  return Object.fromEntries(
    header
      .split(';')
      .filter(Boolean)
      .map(part => {
        const i = part.indexOf('=');

        return [
          decodeURIComponent(part.slice(0, i).trim()),
          decodeURIComponent(part.slice(i + 1).trim())
        ];
      })
  );
}

function newSession() {
  return crypto.randomBytes(32).toString('hex');
}

function sanitize(value, max = 500) {
  return String(value ?? '')
    .trim()
    .slice(0, max);
}

function validRegistration(body) {
  const data = {
    name: sanitize(body.name, 120),
    grade: sanitize(body.grade, 60),
    phone: sanitize(body.phone, 40),
    email: sanitize(body.email, 160),
    notes: sanitize(body.notes, 1000)
  };

  if (!data.name || !data.grade || !data.phone) {
    return {
      error: 'الاسم والصف ورقم الهاتف مطلوبة.'
    };
  }

  if (
    data.email &&
    !/^\S+@\S+\.\S+$/.test(data.email)
  ) {
    return {
      error: 'البريد الإلكتروني غير صحيح.'
    };
  }

  return { data };
}

// =========================
// Authentication
// =========================

async function cleanExpiredSessions() {
  await pool.query(`
    DELETE FROM sessions
    WHERE expires_at <= NOW()
  `);
}

async function auth(req, res, next) {
  try {
    await cleanExpiredSessions();

    const token = parseCookies(req).masai_session;

    if (!token) {
      return res.status(401).json({
        error: 'غير مصرح'
      });
    }

    const result = await pool.query(
      `
      SELECT username, expires_at
      FROM sessions
      WHERE token = $1
      `,
      [token]
    );

    if (result.rows.length === 0) {
      res.clearCookie(
        'masai_session',
        cookieOptions(0)
      );

      return res.status(401).json({
        error: 'غير مصرح'
      });
    }

    const session = result.rows[0];

    if (new Date(session.expires_at) <= new Date()) {
      await pool.query(
        'DELETE FROM sessions WHERE token = $1',
        [token]
      );

      res.clearCookie(
        'masai_session',
        cookieOptions(0)
      );

      return res.status(401).json({
        error: 'غير مصرح'
      });
    }

    req.admin = {
      username: session.username
    };

    next();
  } catch (error) {
    console.error('Auth error:', error);

    res.status(500).json({
      error: 'حدث خطأ في الخادم'
    });
  }
}

// =========================
// Health
// =========================

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true,
      service: 'al-masai-school',
      database: 'postgresql'
    });
  } catch (error) {
    console.error('Health error:', error);

    res.status(500).json({
      ok: false,
      service: 'al-masai-school',
      database: 'error'
    });
  }
});

// =========================
// Admin Login
// =========================

app.post(
  '/api/auth/login',
  loginLimiter,
  async (req, res) => {
    try {
      const username = sanitize(
        req.body.username,
        80
      );

      const password = String(
        req.body.password || ''
      );

      const passwordHash = await bcrypt.hash(
        ADMIN_PASS,
        12
      );

      const validPassword =
        await bcrypt.compare(
          password,
          passwordHash
        );

      if (
        username !== ADMIN_USER ||
        !validPassword
      ) {
        return res.status(401).json({
          error:
            'اسم المستخدم أو كلمة المرور غير صحيحة'
        });
      }

      await cleanExpiredSessions();

      const token = newSession();

      const expiresAt = new Date(
        Date.now() +
          SESSION_HOURS * 60 * 60 * 1000
      );

      await pool.query(
        `
        INSERT INTO sessions
        (token, username, expires_at)
        VALUES ($1, $2, $3)
        `,
        [
          token,
          username,
          expiresAt
        ]
      );

      res.cookie(
        'masai_session',
        token,
        cookieOptions(
          SESSION_HOURS * 60 * 60 * 1000
        )
      );

      res.json({
        ok: true,
        username
      });
    } catch (error) {
      console.error('Login error:', error);

      res.status(500).json({
        error: 'حدث خطأ في الخادم'
      });
    }
  }
);

// =========================
// Logout
// =========================

app.post(
  '/api/auth/logout',
  async (req, res) => {
    try {
      const token =
        parseCookies(req).masai_session;

      if (token) {
        await pool.query(
          'DELETE FROM sessions WHERE token = $1',
          [token]
        );
      }

      res.clearCookie(
        'masai_session',
        cookieOptions(0)
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error('Logout error:', error);

      res.status(500).json({
        error: 'حدث خطأ في الخادم'
      });
    }
  }
);

// =========================
// Current Admin
// =========================

app.get(
  '/api/auth/me',
  auth,
  (req, res) => {
    res.json({
      authenticated: true,
      username: req.admin.username
    });
  }
);

// =========================
// Registration
// =========================

app.post(
  '/api/registrations',
  registrationLimiter,
  async (req, res) => {
    try {
      const result =
        validRegistration(req.body || {});

      if (result.error) {
        return res.status(400).json({
          error: result.error
        });
      }

      const id = crypto.randomUUID();

      await pool.query(
        `
        INSERT INTO registrations
        (
          id,
          name,
          grade,
          phone,
          email,
          notes,
          date,
          status
        )
        VALUES
        ($1, $2, $3, $4, $5, $6, NOW(), $7)
        `,
        [
          id,
          result.data.name,
          result.data.grade,
          result.data.phone,
          result.data.email || null,
          result.data.notes || null,
          'جديد'
        ]
      );

      res.status(201).json({
        ok: true,
        message: 'تم إرسال الطلب بنجاح',
        registration: {
          id
        }
      });
    } catch (error) {
      console.error(
        'Registration error:',
        error
      );

      res.status(500).json({
        error:
          'تعذر حفظ طلب التسجيل. حاول مرة أخرى.'
      });
    }
  }
);

// =========================
// Admin Registrations
// =========================

app.get(
  '/api/admin/registrations',
  auth,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          name,
          grade,
          phone,
          email,
          notes,
          date,
          status
        FROM registrations
        ORDER BY date DESC
      `);

      res.json({
        registrations: result.rows
      });
    } catch (error) {
      console.error(
        'Get registrations error:',
        error
      );

      res.status(500).json({
        error: 'تعذر تحميل التسجيلات'
      });
    }
  }
);

// =========================
// Delete Registrations
// =========================

app.delete(
  '/api/admin/registrations',
  auth,
  async (req, res) => {
    try {
      await pool.query(
        'DELETE FROM registrations'
      );

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        'Delete registrations error:',
        error
      );

      res.status(500).json({
        error: 'تعذر حذف التسجيلات'
      });
    }
  }
);

// =========================
// Admin Statistics
// =========================

app.get(
  '/api/admin/stats',
  auth,
  async (req, res) => {
    try {
      const totalResult =
        await pool.query(`
          SELECT COUNT(*)::int AS total
          FROM registrations
        `);

      const todayResult =
        await pool.query(`
          SELECT COUNT(*)::int AS today
          FROM registrations
          WHERE date >= CURRENT_DATE
        `);

      res.json({
        total:
          totalResult.rows[0].total,
        today:
          todayResult.rows[0].today
      });
    } catch (error) {
      console.error(
        'Stats error:',
        error
      );

      res.status(500).json({
        error: 'تعذر تحميل الإحصائيات'
      });
    }
  }
);

// =========================
// Static Website
// =========================

app.use(
  express.static(__dirname, {
    extensions: ['html'],
    index: 'index.html'
  })
);

app.use((req, res) => {
  res.sendFile(
    path.join(__dirname, 'index.html')
  );
});

// =========================
// Error Handler
// =========================

app.use(
  (err, req, res, next) => {
    console.error(err);

    res.status(500).json({
      error: 'حدث خطأ في الخادم'
    });
  }
);

// =========================
// Start Server
// =========================

async function startServer() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      HOST,
      () => {
        console.log(
          `Al-Masai School server running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      'Failed to start server:',
      error
    );

    process.exit(1);
  }
}

startServer();