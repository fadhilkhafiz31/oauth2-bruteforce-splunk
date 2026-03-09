const oauth2orize   = require('oauth2orize');
const passport      = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const BearerStrategy = require('passport-http-bearer').Strategy;
const bcrypt        = require('bcryptjs');
const crypto        = require('crypto');
const db            = require('./db');


const server = oauth2orize.createServer();


passport.use(new LocalStrategy((username, password, done) => {
  const user = db.findUserByUsername(username);
  if (!user) return done(null, false, { message: 'User not found' });

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) return done(null, false, { message: 'Wrong password' });

  return done(null, user);
}));

passport.serializeUser((user, done)   => done(null, user.id));
passport.deserializeUser((id, done)   => done(null, db.findUserById(id)));


passport.use(new BearerStrategy((token, done) => {
  const record = db.findAccessToken(token);
  if (!record) return done(null, false);

  const user = db.findUserById(record.userId);
  if (!user)  return done(null, false);

  return done(null, user, { scope: '*' });
}));


server.grant(oauth2orize.grant.code((client, redirectUri, user, ares, done) => {
  const code = crypto.randomBytes(16).toString('hex');
  db.saveAuthCode(code, user.id, client.id, redirectUri);
  return done(null, code);
}));

server.exchange(oauth2orize.exchange.code((client, code, redirectUri, done) => {
  const authCode = db.findAuthCode(code);

  if (!authCode)                        return done(null, false);
  if (client.id !== authCode.clientId)  return done(null, false);
  if (redirectUri !== authCode.redirectUri) return done(null, false);

  db.deleteAuthCode(code);

  const token = crypto.randomBytes(32).toString('hex');
  db.saveAccessToken(token, authCode.userId, client.id);

  return done(null, token);
}));

module.exports = { server, passport };
