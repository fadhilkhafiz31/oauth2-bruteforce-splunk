const express    = require('express');
const session    = require('express-session');
const cors       = require('cors');
const crypto     = require('crypto');
const path       = require('path');
const db         = require('./db');
const { server: oauth2server, passport } = require('./auth');

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
    if (err)    return res.status(500).json({ error: 'Server error' });
    if (!user)  return res.status(401).json({ error: info.message || 'Invalid credentials' });

    // Generate access token
    const token = crypto.randomBytes(32).toString('hex');
    db.saveAccessToken(token, user.id, 'superapp-dashboard');

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
