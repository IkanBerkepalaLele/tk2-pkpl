require('dotenv').config();
require('./auth');

const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const app = express();

app.disable('x-powered-by');
app.use(express.json());
app.use(express.static('public'));

if (!process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET is required.');
}

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    httpOnly: true, 
    secure: false,  //set true when deploy
    sameSite: 'lax',
    maxAge: 60 * 60 * 1000 // 1h
  }
}));

app.use(passport.initialize());
app.use(passport.session());

function isLoggedIn(req, res, next) {
  const authenticated = req.isAuthenticated ? req.isAuthenticated() : !!req.user;
  return authenticated ? next() : res.sendStatus(401);
}

const allowedEmails = new Set(
  (process.env.ALLOWED_EMAILS || '')
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean) // Filter ini akan mengabaikan string kosong
);

function getUserEmail(user) {
  if (!user) {
    return null;
  }

  if (user.email) {
    return String(user.email).toLowerCase();
  }

  if (user.emails && user.emails.length > 0 && user.emails[0].value) {
    return String(user.emails[0].value).toLowerCase();
  }

  return null;
}

function attachAuthContext(req, res, next) {
  const email = getUserEmail(req.user);
  req.authz = {
    email,
    canChangeTheme: !!email && allowedEmails.has(email)
  };
  next();
}

function requireThemeEditor(req, res, next) {
  if (!req.authz || !req.authz.canChangeTheme) {
    return res.status(403).json({ message: 'Forbidden: read-only user.' });
  }
  return next();
}

app.use(attachAuthContext);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/auth/google',
  passport.authenticate('google', { scope: [ 'email', 'profile' ] }
));

app.get('/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/',
    failureRedirect: '/auth/google/failure'
  })
);

app.get('/logout', (req, res, next) => {
  if (req.logout.length > 0) {
    req.logout((err) => {
      if (err) {
        return next(err);
      }
      req.session.destroy(() => {
        res.redirect('/index.html');
      });
    });
    return;
  }

  req.logout();
  req.session.destroy(() => {
    res.redirect('/index.html');
  });
});

app.get('/auth/google/failure', (req, res) => {
  res.status(401).send('Failed to authenticate');
});

// endpoint API untuk mengirim data user ke frontend
app.get('/api/user', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    res.json({
      loggedIn: true,
      name: req.user.displayName,
      email: req.authz.email,
      canChangeTheme: req.authz.canChangeTheme
    });
  } else {
    res.json({ loggedIn: false }); // Jika belum login
  }
});

let themeState = {
  mode: 'light',
  updatedBy: null,
  updatedAt: null
};

app.get('/api/theme', (req, res) => {
  res.json(themeState);
});

app.post('/api/theme', isLoggedIn, requireThemeEditor, (req, res) => {
  const nextMode = req.body ? req.body.mode : null;

  if (!['light', 'dark'].includes(nextMode)) {
    return res.status(400).json({ message: 'Invalid theme mode.' });
  }

  themeState = {
    mode: nextMode,
    updatedBy: req.authz.email,
    updatedAt: new Date().toISOString()
  };

  return res.json({
    message: 'Theme updated.',
    theme: themeState
  });
});

app.listen(5000, () => console.log('listening on port: 5000'));