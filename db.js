const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host:               process.env.DB_HOST     || 'localhost',
  port:               process.env.DB_PORT     || 3306,
  user:               process.env.DB_USER     || 'root',
  password:           process.env.DB_PASSWORD || 'fadhilhat_619',  
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

// Testing the connection
pool.getConnection()
  .then(connection => {
    console.log(' MySQL Database connected successfully- securebank-db');
    connection.release();
  })
  .catch(err => {
    console.error('Error connecting to MySQL Database:', err.message);
    console.error (' set DBV_password to your MySQL password in .env file');
    process.exit(1);
  });

  // user queries

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

  async function createUser(username, email, passwordHash, displayName, role = 'user'){
  const [result] = await pool.execute(
    'INSERT INTO users (username, email, password_hash, display_name, role) VALUES (?, ?, ?, ?, ?)',
    [username, email, passwordHash, displayName, role]
  );
  return result.insertId;
}

//access token queries
async function saveAccessToken(token, userID, ClientId, IssuedIp = null) {
  await pool.execute(
    'INSERT INTO access_tokens (token, user_id, client_id, issued_ip) VALUES (?, ?, ?, ?)',
    [token, userID, ClientId, IssuedIp]
  );
}

// JOIN with users table so BearerStrategy gets full user object in one query

  async function findAccessToken(token) {
  const [rows] = await pool.execute(
    'SELECT at.id AS token_id, at.token, at.client_id, at.issued_ip, at.created_at, u.id AS user_id, u.username, u.email, u.password_hash, u.display_name, u.role ' +
