require('dotenv').config();  // add this as line 1 of server.js
const express    = require('express');
const session    = require('express-session');
const cors       = require('cors');
const crypto     = require('crypto');
const bcrypt     = require('bcryptjs');
const path       = require('path');
const fs         = require('fs');
const db         = require('./db');
const { server: oauth2server, passport } = require('./auth');

// ── SECURITY LOGGER ──
// Writes to both security.log (for Splunk) AND MySQL security_events table
const LOG_FILE = path.join(__dirname, 'logs', 'security.log');
fs.mkdirSync(path.join(__dirname, 'logs'), { recursive: true });

function securityLog(event) {
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    ...event
  });
  // 1. Write to file — Splunk reads this
  fs.appendFileSync(LOG_FILE, entry + '\n');
  console.log('[SECURITY]', entry);
  // 2. Write to MySQL — lets you query attack history with SQL
  db.logSecurityEvent(event);
}

const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));


// ══════════════════════════════════════════
// ROUTE 1: POST /register
// New in Episode 3 — creates a real user in MySQL
// Hashes password with bcrypt before storing
// This is exactly how real apps work
// ══════════════════════════════════════════
app.post('/register', async (req, res) => {
  const { username, password, email, displayName } = req.body;

  // ── INPUT VALIDATION ──
  if (!username || !password || !email) {
    return res.status(400).json({
      error: 'username, password, and email are required'
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: 'Password must be at least 8 characters'
    });
  }

  try {
    // ── CHECK DUPLICATES ──
    const existingUser  = await db.findUserByUsername(username);
    const existingEmail = await db.findUserByEmail(email);

    if (existingUser) {
      securityLog({
        event_type: 'REGISTER_FAILED',
        endpoint:   '/register',
        src_ip:     req.ip,
        username,
        status:     409,
        reason:     'username_taken'
      });
      return res.status(409).json({ error: 'Username already taken' });
    }

    if (existingEmail) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // ── HASH PASSWORD ──
    // bcrypt work factor 10 = 2^10 = 1024 hashing rounds
    // Plain password NEVER touches the database
    const passwordHash = await bcrypt.hash(password, 10);

    // ── INSERT INTO MYSQL ──
    const newUserId = await db.createUser(
      username,
      passwordHash,
      email,
      displayName || username,
      'user'        // all self-registered users get role: user
    );

    securityLog({
      event_type:  'REGISTER_SUCCESS',
      endpoint:    '/register',
      src_ip:      req.ip,
      username,
      user_id:     newUserId,
      status:      201
    });

    return res.status(201).json({
      success:  true,
      message:  'Account created successfully',
      user_id:  newUserId,
      username,
      role:     'user'
    });

  } catch (err) {
    console.error('[REGISTER ERROR]', err);
    return res.status(500).json({ error: 'Registration failed' });
  }
});


// ══════════════════════════════════════════
// ROUTE 2: POST /login
// Same as before — now reads from MySQL via auth.js
// ══════════════════════════════════════════
app.post('/login', (req, res, next) => {
  passport.authenticate('local', async (err, user, info) => {
    if (err) {
      securityLog({
        event_type: 'LOGIN_ERROR',
        endpoint:   '/login',
        src_ip:     req.ip,
        username:   req.body.username || 'unknown',
        status:     500,
        reason:     'server_error'
      });
      return res.status(500).json({ error: 'Server error' });
    }

    if (!user) {
      securityLog({
        event_type: 'LOGIN_FAILED',
        endpoint:   '/login',
        src_ip:     req.ip,
        username:   req.body.username || 'unknown',
        status:     401,
        reason:     info.message || 'invalid_credentials'
      });
      return res.status(401).json({ error: info.message || 'Invalid credentials' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    await db.saveAccessToken(token, user.id, 'superapp-dashboard', req.ip);

    securityLog({
      event_type: 'LOGIN_SUCCESS',
      endpoint:   '/login',
      src_ip:     req.ip,
      username:   user.username,
      user_id:    user.id,
      role:       user.role,
      status:     200
    });

    return res.json({
      success:      true,
      access_token: token,
      token_type:   'Bearer',
      user: {
        id:          user.id,
        username:    user.username,
        email:       user.email,
        displayName: user.display_name,
        role:        user.role
      }
    });
  })(req, res, next);
});


// ══════════════════════════════════════════
// ROUTE 3: GET /me
// ══════════════════════════════════════════
app.get('/me',
  passport.authenticate('bearer', { session: false }),
  (req, res) => {
    res.json({
      id:          req.user.id,
      username:    req.user.username,
      email:       req.user.email,
      displayName: req.user.display_name,
      role:        req.user.role
    });
  }
);


// ══════════════════════════════════════════
// ROUTE 4: GET /admin
// Admin only — detects token replay via IP mismatch
// ══════════════════════════════════════════
app.get('/admin',
  passport.authenticate('bearer', { session: false }),
  async (req, res) => {
    const tokenRecord = req.user._tokenRecord;
    const requestIp   = req.ip;

    // ── ROLE CHECK ──
    if (req.user.role !== 'admin') {
      securityLog({
        event_type: 'UNAUTHORIZED_ACCESS',
        endpoint:   '/admin',
        src_ip:     requestIp,
        username:   req.user.username,
        role:       req.user.role,
        status:     403,
        reason:     'insufficient_role'
      });
      return res.status(403).json({
        error:  'Access denied',
        reason: 'Admin role required'
      });
    }

    // ── TOKEN REPLAY DETECTION ──
    if (tokenRecord?.issued_ip && tokenRecord.issued_ip !== requestIp) {
      securityLog({
        event_type:    'TOKEN_REPLAY_DETECTED',
        endpoint:      '/admin',
        src_ip:        requestIp,
        issued_ip:     tokenRecord.issued_ip,
        username:      req.user.username,
        role:          req.user.role,
        status:        200,
        reason:        'token_used_from_different_ip'
      });
    }

    securityLog({
      event_type: 'ADMIN_ACCESS',
      endpoint:   '/admin',
      src_ip:     requestIp,
      username:   req.user.username,
      role:       req.user.role,
      status:     200
    });

    return res.json({
      success: true,
      message: 'Welcome to the SecureBank admin panel.',
      data: {
        total_accounts:      1247,
        flagged_transactions: 3,
        active_sessions:     14,
        last_backup:         '2026-03-28T00:00:00Z'
      }
    });
  }
);


// ══════════════════════════════════════════
// ROUTE 5: POST /logout
// Now properly revokes the token in MySQL
// Sets revoked = 1 instead of deleting — keeps audit trail
// ══════════════════════════════════════════
app.post('/logout',
  passport.authenticate('bearer', { session: false }),
  async (req, res) => {
    try {
      const token = req.headers['authorization']?.replace('Bearer ', '').trim();
      if (token) await db.revokeToken(token);

      securityLog({
        event_type: 'LOGOUT',
        endpoint:   '/logout',
        src_ip:     req.ip,
        username:   req.user.username,
        user_id:    req.user.id,
        status:     200
      });

      res.json({ success: true, message: 'Logged out successfully' });
    } catch (err) {
      res.status(500).json({ error: 'Logout failed' });
    }
  }
);


// ══════════════════════════════════════════
// OAUTH2 ROUTES (unchanged)
// ══════════════════════════════════════════
app.get('/oauth/authorize',
  passport.authenticate('bearer', { session: false }),
  oauth2server.authorization((clientId, redirectUri, done) => {
    const client = db.findClientById(clientId);
    if (!client) return done(null, false);
    return done(null, client, redirectUri);
  }),
  (req, res) => {
    res.json({ transactionID: req.oauth2.transactionID, user: req.user });
  }
);

app.use('/oauth/token', (req, res, next) => {
  const originalJson   = res.json.bind(res);
  const originalStatus = res.status.bind(res);
  let statusCode = 200;

  res.status = (code) => { statusCode = code; return originalStatus(code); };
  res.json = (body) => {
    const failed = statusCode === 401 || statusCode === 400 || (body && body.error);
    securityLog({
      event_type: failed ? 'OAUTH_TOKEN_FAILED' : 'OAUTH_TOKEN_SUCCESS',
      endpoint:   '/oauth/token',
      src_ip:     req.ip,
      username:   req.body.username || req.body.client_id || 'unknown',
      grant_type: req.body.grant_type || 'unknown',
      status:     statusCode,
      reason:     failed ? (body.error || 'invalid_credentials') : undefined
    });
    return originalJson(body);
  };
  next();
});

app.post('/oauth/token',
  passport.authenticate(['basic', 'local'], { session: false }),
  oauth2server.token(),
  oauth2server.errorHandler()
);


// ── GRACEFUL SHUTDOWN ──
process.on('SIGINT', async () => {
  console.log('\n  Closing MySQL pool...');
  await db.pool.end();
  process.exit(0);
});


// ── START ──
const PORT = 3000;
app.listen(PORT, () => {
  console.log('');
  console.log('  SecureBank OAuth2 Server');
  console.log(`  http://localhost:${PORT}`);
  console.log('');
  console.log('  Accounts:');
  console.log('  admin   / admin123    → role: admin');
  console.log('  user123 / password123 → role: user');
  console.log('');
  console.log('  Endpoints:');
  console.log('  POST /register  → create new user');
  console.log('  POST /login     → get Bearer token');
  console.log('  GET  /me        → your profile');
  console.log('  GET  /admin     → admin only');
  console.log('  POST /logout    → revoke token');
  console.log('');
});