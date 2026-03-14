const express    = require('express');
const session    = require('express-session');
const cors       = require('cors');
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');
const db         = require('./db');
const { server: oauth2server, passport } = require('./auth');

// ── SECURITY LOGGER ──
// Writes Splunk-friendly JSON logs to security.log
// Format matches what Splunk expects for field extraction
const LOG_FILE = path.join(__dirname, 'logs', 'security.log');
fs.mkdirSync(path.join(__dirname, 'logs'), { recursive: true });

function securityLog(event) {
  const entry = JSON.stringify({
    timestamp: new Date().toISOString(),
    ...event
  });
  fs.appendFileSync(LOG_FILE, entry + '\n');
  console.log('[SECURITY]', entry);
}

const app = express();

// ── MIDDLEWARE ──
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'superapp-session-secret',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Serve your HTML dashboard from /public
app.use(express.static(path.join(__dirname, 'public')));

// ──────────────────────────────────────────
// ROUTE 1: POST /login
// Accepts username + password, returns access token directly
// (Resource Owner Password flow — simplest for a dashboard demo)
// ──────────────────────────────────────────
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      securityLog({
        event_type: 'LOGIN_ERROR',
        endpoint: '/login',
        src_ip: req.ip,
        username: req.body.username || 'unknown',
        status: 500,
        reason: 'server_error'
      });
      return res.status(500).json({ error: 'Server error' });
    }

    if (!user) {
      securityLog({
        event_type: 'LOGIN_FAILED',
        endpoint: '/login',
        src_ip: req.ip,
        username: req.body.username || 'unknown',
        status: 401,
        reason: info.message || 'invalid_credentials'
      });
      return res.status(401).json({ error: info.message || 'Invalid credentials' });
    }

    // Successful login
    const token = crypto.randomBytes(32).toString('hex');
    db.saveAccessToken(token, user.id, 'superapp-dashboard');

    securityLog({
      event_type: 'LOGIN_SUCCESS',
      endpoint: '/login',
      src_ip: req.ip,
      username: user.username,
      user_id: user.id,
      status: 200
    });

    return res.json({
      success: true,
      access_token: token,
      token_type: 'Bearer',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        displayName: user.displayName
      }
    });
  })(req, res, next);
});

// ──────────────────────────────────────────
// ROUTE 2: GET /me
// Protected route — requires Bearer token
// Returns the logged-in user's info
// ──────────────────────────────────────────
app.get('/me', passport.authenticate('bearer', { session: false }), (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    email: req.user.email,
    displayName: req.user.displayName
  });
});

// ──────────────────────────────────────────
// ROUTE 3: POST /logout
// Invalidates the token (in a real app: delete from DB)
// ──────────────────────────────────────────
app.post('/logout', passport.authenticate('bearer', { session: false }), (req, res) => {
  // For demo: just return success (token naturally expires)
  res.json({ success: true, message: 'Logged out successfully' });
});

// ──────────────────────────────────────────
// ROUTE 4: oauth2orize AUTHORIZATION endpoint
// (Full Authorization Code flow — for future use)
// ──────────────────────────────────────────
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

// Logging middleware for /oauth/token — runs before oauth2orize
app.use('/oauth/token', (req, res, next) => {
  const originalJson = res.json.bind(res);
  const originalStatus = res.status.bind(res);
  let statusCode = 200;

  res.status = (code) => {
    statusCode = code;
    return originalStatus(code);
  };

  res.json = (body) => {
    const failed = statusCode === 401 || statusCode === 400 || (body && body.error);
    securityLog({
      event_type: failed ? 'OAUTH_TOKEN_FAILED' : 'OAUTH_TOKEN_SUCCESS',
      endpoint: '/oauth/token',
      src_ip: req.ip,
      username: req.body.username || req.body.client_id || 'unknown',
      grant_type: req.body.grant_type || 'unknown',
      status: statusCode,
      reason: failed ? (body.error || 'invalid_credentials') : undefined
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

// ── START SERVER ──
const PORT = 3000;
app.listen(PORT, () => {
  console.log('');
  console.log('    Random App OAuth2 Server running!');
  console.log(`    http://localhost:${PORT}`);
  console.log('');
  console.log('  Demo credentials:');
  console.log('  Username : admin');
  console.log('  Password : admin123');
  console.log('');
});