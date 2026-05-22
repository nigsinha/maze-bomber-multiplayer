'use strict';
const express      = require('express');
const helmet       = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit    = require('express-rate-limit');
const bcrypt       = require('bcrypt');
const jwt          = require('jsonwebtoken');
const path         = require('path');
const db           = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = 12;

// ── FIX #8: Hard-fail in production if JWT_SECRET is not set ──────────────────
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start.');
    process.exit(1);
  }
  console.warn('WARNING: JWT_SECRET not set — using insecure default. Set it for production!');
}
const SECRET = JWT_SECRET || 'change-me-in-production-use-long-random-string';

// ── Security middleware ────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'"],   // needed for inline game script
      styleSrc:    ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:     ["'self'", 'https://fonts.gstatic.com'],
      connectSrc:  ["'self'"],
      imgSrc:      ["'self'", 'data:'],
    },
  },
}));
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// ── Rate limiters ──────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 min
  max: 20,
  message: { error: 'Too many requests, slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});
const scoreLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 min
  max: 10,
  message: { error: 'Score submission rate exceeded.' },
});

// ── JWT helpers ────────────────────────────────────────────────────────────────
function signToken(userId, username) {
  return jwt.sign({ sub: userId, username }, SECRET, { expiresIn: '7d' });
}

function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Auth routes ────────────────────────────────────────────────────────────────
// POST /api/register
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || typeof username !== 'string') return res.status(400).json({ error: 'Username required' });
  if (!password || typeof password !== 'string') return res.status(400).json({ error: 'Password required' });

  const u = username.trim();
  if (!/^[a-zA-Z0-9_]{3,16}$/.test(u))
    return res.status(400).json({ error: 'Username must be 3–16 chars: letters, numbers, underscore' });

  const pwErr = validatePassword(password);
  if (pwErr) return res.status(400).json({ error: pwErr });

  const existing = db.prepare('SELECT id FROM users WHERE username_lower = ?').get(u.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const stmt = db.prepare('INSERT INTO users (username, username_lower, password_hash) VALUES (?, ?, ?)');
  const info  = stmt.run(u, u.toLowerCase(), hash);
  const token = signToken(info.lastInsertRowid, u);
  res.json({ token, username: u });
});

// POST /api/login
app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const rec = db.prepare('SELECT * FROM users WHERE username_lower = ?').get(username.trim().toLowerCase());
  if (!rec) {
    // constant-time rejection to prevent user enumeration
    await bcrypt.compare(password, '$2b$12$invalidhashpadding00000000000000000000000000000000000');
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const match = await bcrypt.compare(password, rec.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid username or password' });

  db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(Date.now(), rec.id);
  const token = signToken(rec.id, rec.username);
  res.json({ token, username: rec.username });
});

// GET /api/me  – verify token & return current user
app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ username: user.username });
});

// ── Score routes ───────────────────────────────────────────────────────────────
// POST /api/score  – submit a completed-game score
app.post('/api/score', requireAuth, scoreLimiter, (req, res) => {
  const { score, level, durationMs } = req.body || {};

  // ── FIX #2: Require strict integers (rejects floats, NaN, Infinity) ──────
  if (!Number.isInteger(score) || !Number.isInteger(level) || !Number.isInteger(durationMs))
    return res.status(400).json({ error: 'Invalid payload: score, level, durationMs must be integers' });

  // ── Server-side anti-cheat ────────────────────────────────────────────────
  // 1. Hard cap
  if (score > 50_000) return res.status(400).json({ error: 'Score rejected: implausibly high' });

  // 2. Non-negative
  if (score < 0 || level < 1) return res.status(400).json({ error: 'Score rejected: negative values' });

  // 3. Duration plausibility: need at least 4 s per level cleared
  const minDuration = (level - 1) * 4_000;
  if (durationMs < minDuration) return res.status(400).json({ error: 'Score rejected: too fast for level reached' });

  // 4. Max score per second cap (400 pts/s is superhuman)
  const secs = Math.max(1, durationMs / 1000);
  if (score / secs > 400) return res.status(400).json({ error: 'Score rejected: rate too high' });

  // Use canonical username from users table rather than trusting token payload
  const userRec = db.prepare('SELECT username FROM users WHERE id = ?').get(req.user.sub);
  const username = userRec ? userRec.username : req.user.username;
  db.prepare(
    'INSERT INTO scores (user_id, username, score, level, duration_ms, ts) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(req.user.sub, username, score, level, durationMs, Date.now());

  // Return fresh personal best
  const best = db.prepare(
    'SELECT MAX(score) as best FROM scores WHERE user_id = ?'
  ).get(req.user.sub);

  res.json({ ok: true, personalBest: best.best });
});

// GET /api/leaderboard?period=daily|weekly|monthly|alltime&limit=50
app.get('/api/leaderboard', requireAuth, (req, res) => {
  const period = req.query.period || 'alltime';
  const limit  = Math.min(parseInt(req.query.limit) || 50, 100);

  const ms = { daily: 86_400_000, weekly: 7 * 86_400_000, monthly: 30 * 86_400_000, alltime: Infinity };
  const cutoffMs = ms[period] ?? Infinity;
  const cutoff   = cutoffMs === Infinity ? 0 : Date.now() - cutoffMs;

  // Best score per user in the period.
  // ── FIX #1: CAST level AS INTEGER so response is always a safe integer ────
  // Determine best score per user in the period, then join back to get
  // canonical username from the users table and deterministic ts/level values.
  const rows = db.prepare(`
    WITH best AS (
      SELECT user_id, MAX(score) AS score
      FROM scores
      WHERE ts >= ?
      GROUP BY user_id
    )
    SELECT u.username AS username,
           b.score AS score,
           CAST(MAX(s.level) AS INTEGER) AS level,
           MAX(s.ts) AS ts
    FROM best b
    JOIN scores s ON s.user_id = b.user_id AND s.score = b.score
    JOIN users u ON u.id = b.user_id
    WHERE s.ts >= ?
    GROUP BY b.user_id
    ORDER BY b.score DESC
    LIMIT ?
  `).all(cutoff, cutoff, limit);

  // Personal rank
  const myBest = db.prepare(
    'SELECT MAX(score) as score FROM scores WHERE user_id = ? AND ts >= ?'
  ).get(req.user.sub, cutoff);

  const myScore = myBest?.score ?? 0;
  let myRank = null;
  if (myScore > 0) {
    const rankRow = db.prepare(`
      SELECT COUNT(*) as cnt FROM (
        SELECT MAX(score) as best FROM scores WHERE ts >= ? GROUP BY user_id
      ) WHERE best > ?
    `).get(cutoff, myScore);
    myRank = (rankRow?.cnt ?? 0) + 1;
  }

  res.json({ board: rows, myRank, myScore });
});

// GET /api/personal-best
app.get('/api/personal-best', requireAuth, (req, res) => {
  const row = db.prepare('SELECT MAX(score) as best FROM scores WHERE user_id = ?').get(req.user.sub);
  res.json({ best: row?.best ?? 0 });
});

// ── Helpers ────────────────────────────────────────────────────────────────────
function validatePassword(pwd) {
  if (pwd.length < 6)               return 'Password must be at least 6 characters';
  if (!/[A-Z]/.test(pwd))           return 'Password needs at least one uppercase letter';
  if (!/[0-9]/.test(pwd))           return 'Password needs at least one number';
  if (!/[a-z]/.test(pwd))           return 'Password needs at least one lowercase letter';
  return null;
}

// ── Start ──────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Maze Bomber server running on :${PORT}`));
