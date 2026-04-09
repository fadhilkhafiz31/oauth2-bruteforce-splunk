// ══════════════════════════════════════════
// auth.js — Passport strategies
// Episode 3 change: all db calls are now async
// Everything else is identical to Episode 1-2
// ══════════════════════════════════════════


const oauth2orize    = require('oauth2orize');
const passport       = require('passport');
const LocalStrategy  = require('passport-local').Strategy;
const BearerStrategy = require('passport-http-bearer').Strategy;
const bcrypt         = require('bcryptjs');
const crypto         = require('crypto');
const db             = require('./db');

const server = oauth2orize.createServer();

// ── LOCAL STRATEGY ──
// Called on POST /login with username + password
// Now async because db.findUserByUsername hits MySQL
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await db.findUserByUsername(username);
    if (!user) return done(null, false, { message: 'User not found' });

    // bcrypt.compareSync still works — hash is now from MySQL, not hardcoded
    // password_hash is the column name from our users table
    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) return done(null, false, { message: 'Wrong password' });

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// ── SESSION SERIALIZATION ──
passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.findUserById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// ── BEARER STRATEGY ──
// Called on every protected route (GET /me, GET /admin)
// Looks up token in MySQL — returns full user object via JOIN
passport.use(new BearerStrategy(async (token, done) => {
  try {
    // findAccessToken does a JOIN — returns token row + user fields together
    const record = await db.findAccessToken(token);
    if (!record) return done(null, false);
    if (record.revoked) return done(null, false);

    // Build user object from the joined columns
    const user = {
      id:           record.id,
      username:     record.username,
      email:        record.email,
      display_name: record.display_name,
      role:         record.role,
      // Pass token metadata so /admin can check IP mismatch
      _tokenRecord: {
        token_id:   record.token_id,
        issued_ip:  record.issued_ip,
        created_at: record.token_created_at
      }
    };

    return done(null, user, { scope: '*' });
  } catch (err) {
    return done(err);
  }
}));

// ── OAUTH2 AUTHORIZATION CODE GRANT ──
server.grant(oauth2orize.grant.code(async (client, redirectUri, user, ares, done) => {
  try {
    const code = crypto.randomBytes(16).toString('hex');
    await db.saveAuthCode(code, user.id, client.id, redirectUri);
    return done(null, code);
  } catch (err) {
    return done(err);
  }
}));

// ── OAUTH2 TOKEN EXCHANGE ──
server.exchange(oauth2orize.exchange.code(async (client, code, redirectUri, done) => {
  try {
    const authCode = await db.findAuthCode(code);

    if (!authCode)                            return done(null, false);
    if (client.id !== authCode.client_id)     return done(null, false);
    if (redirectUri !== authCode.redirect_uri) return done(null, false);

    await db.deleteAuthCode(code);

    const token = crypto.randomBytes(32).toString('hex');
    await db.saveAccessToken(token, authCode.user_id, client.id);

    return done(null, token);
  } catch (err) {
    return done(err);
  }
}));

module.exports = { server, passport };