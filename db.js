// ══════════════════════════════════════════
// db.js — Real MySQL Database Layer
// Replaces the in-memory array from Episode 1-2
//
// How it works:
//   1. Creates a connection POOL (10 connections ready at all times)
//   2. Every function sends a SQL query to MySQL
//   3. Everything is async/await — DB calls take time
//   4. Uses prepared statements (?) to prevent SQL injection
// ══════════════════════════════════════════

const mysql = require('mysql2/promise');

// ── CONNECTION POOL ──
// Think of this as 10 phone lines to MySQL.
// When server.js calls db.findUserByUsername(),
// it picks up a free line, asks MySQL, hangs up.
// Much faster and safer than opening a new connection each time.
const pool = mysql.createPool({
  host:               process.env.DB_HOST     || 'localhost',
  port:               process.env.DB_PORT     || 3306,
  user:               process.env.DB_USER     || 'root',
  password:           process.env.DB_PASSWORD || '',   // ← change this
  database:           process.env.DB_NAME     || 'securebank_db',
  waitForConnections: true,
  connectionLimit:    10,
  queueLimit:         0,
  typeCast: (field, next) => {
    if (field.type === 'TINY' && field.length === 1) {
      return field.string() === '1';
    }
    return next();
  }
});

// ── TEST CONNECTION ON STARTUP ──
pool.getConnection()
  .then(conn => {
    console.log('  ✓  MySQL connected — securebank_db');
    conn.release();
  })
  .catch(err => {
    console.error('  ✗  MySQL connection failed:', err.message);
    console.error('     Set DB_PASSWORD in your .env file');
    process.exit(1);
  });


// ══════════════════════════════════════════
// USER QUERIES
// ══════════════════════════════════════════

async function findUserByUsername(username) {
  const [rows] = await pool.execute(
    'SELECT * FROM users WHERE username = ? LIMIT 1',
    [username]
  );
  return rows[0] || null;
}

async function findUserById(id) {
  const [rows] = await pool.execute(
    'SELECT * FROM users WHERE id = ? LIMIT 1',
    [id]
  );
  return rows[0] || null;
}

async function findUserByEmail(email) {
  const [rows] = await pool.execute(
    'SELECT * FROM users WHERE email = ? LIMIT 1',
    [email]
  );
  return rows[0] || null;
}

async function createUser(username, passwordHash, email, displayName, role = 'user') {
  const [result] = await pool.execute(
    `INSERT INTO users (username, password_hash, email, display_name, role)
     VALUES (?, ?, ?, ?, ?)`,
    [username, passwordHash, email, displayName, role]
  );
  return result.insertId;
}


// ══════════════════════════════════════════
// ACCESS TOKEN QUERIES
// ══════════════════════════════════════════

async function saveAccessToken(token, userId, clientId, issuedIp = null) {
  await pool.execute(
    `INSERT INTO access_tokens (token, user_id, client_id, issued_ip)
     VALUES (?, ?, ?, ?)`,
    [token, userId, clientId, issuedIp]
  );
}

// JOIN with users table so BearerStrategy gets full user object in one query
async function findAccessToken(token) {
  const [rows] = await pool.execute(
    `SELECT at.id AS token_id, at.token, at.client_id,
            at.issued_ip, at.created_at AS token_created_at,
            at.revoked,
            u.id, u.username, u.email,
            u.display_name, u.role, u.password_hash
     FROM access_tokens at
     JOIN users u ON at.user_id = u.id
     WHERE at.token = ?
       AND at.revoked = 0
     LIMIT 1`,
    [token]
  );
  return rows[0] || null;
}

async function revokeToken(token) {
  await pool.execute(
    'UPDATE access_tokens SET revoked = 1 WHERE token = ?',
    [token]
  );
}


// ══════════════════════════════════════════
// AUTH CODE QUERIES
// ══════════════════════════════════════════

async function saveAuthCode(code, userId, clientId, redirectUri) {
  await pool.execute(
    `INSERT INTO auth_codes (code, user_id, client_id, redirect_uri)
     VALUES (?, ?, ?, ?)`,
    [code, userId, clientId, redirectUri]
  );
}

async function findAuthCode(code) {
  const [rows] = await pool.execute(
    'SELECT * FROM auth_codes WHERE code = ? LIMIT 1',
    [code]
  );
  return rows[0] || null;
}

async function deleteAuthCode(code) {
  await pool.execute(
    'DELETE FROM auth_codes WHERE code = ?',
    [code]
  );
}


// ══════════════════════════════════════════
// CLIENTS — still in-memory, no DB table needed
// OAuth2 clients are static config, not user data
// ══════════════════════════════════════════

const clients = [
  {
    id:          'superapp-dashboard',
    secret:      'superapp-secret',
    name:        'SecureBank Dashboard',
    redirectUri: 'http://localhost:3000/callback'
  }
];

function findClientById(id) {
  return clients.find(c => c.id === id) || null;
}

function findClientByIdAndSecret(id, secret) {
  return clients.find(c => c.id === id && c.secret === secret) || null;
}


// ══════════════════════════════════════════
// SECURITY EVENTS — mirrors security.log into DB
// Bonus: now you can query attack history with SQL
// e.g. SELECT * FROM security_events WHERE event_type = 'LOGIN_FAILED'
// ══════════════════════════════════════════

async function logSecurityEvent(event) {
  try {
    const { event_type, endpoint, src_ip, username,
            user_id, status, reason, ...rest } = event;
    await pool.execute(
      `INSERT INTO security_events
         (event_type, endpoint, src_ip, username, user_id,
          status_code, reason, metadata)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        event_type || null,
        endpoint   || null,
        src_ip     || null,
        username   || null,
        user_id    || null,
        status     || null,
        reason     || null,
        Object.keys(rest).length ? JSON.stringify(rest) : null
      ]
    );
  } catch (err) {
    // Never let a log failure crash the server
    console.error('[DB LOG ERROR]', err.message);
  }
}


module.exports = {
  findUserByUsername,
  findUserById,
  findUserByEmail,
  createUser,
  saveAccessToken,
  findAccessToken,
  revokeToken,
  saveAuthCode,
  findAuthCode,
  deleteAuthCode,
  findClientById,
  findClientByIdAndSecret,
  logSecurityEvent,
  pool
};