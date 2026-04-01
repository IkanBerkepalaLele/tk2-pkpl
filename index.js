require('dotenv').config();
require('./auth');

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const app = express();

app.use(express.static('public'));

function isLoggedIn(req, res, next) {
  req.user ? next() : res.sendStatus(401);
}

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { 
    httpOnly: true, 
    secure: false,  //set true when deploy
    sameSite: 'lax',
    maxAge: 60 * 60 * 1000 // 1h
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
  res.send('<a href="/auth/google">Authenticate with Google</a>');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: [ 'email', 'profile' ] }
));

app.get( '/auth/google/callback',
  passport.authenticate( 'google', {
    successRedirect: '/protected',
    failureRedirect: '/auth/google/failure'
  })
);

app.get('/protected', isLoggedIn, (req, res) => {
  res.redirect('/dashboard.html');
});

app.get('/logout', (req, res) => {
  req.logout();
  req.session.destroy();
  res.redirect('/index.html');
});

app.get('/auth/google/failure', (req, res) => {
  res.send('Failed to authenticate');
});

// 1. Definisikan email tim yang diizinkan mengubah tema
const allowedEmails = [
  'mernawatispeed08@gmail.com', 
  'ehgojim@gmail.com',
  'ahaikaln@gmail.com',
  'husainifakhriromza@gmail.com',
  'daffaabhi86gmail.com'
];

// endpoint API untuk mengirim data user ke frontend
app.get('/api/user', isLoggedIn, (req, res) => {
  // Ambil email user dari data profil Google
  const userEmail = req.user.emails && req.user.emails.length > 0 
    ? req.user.emails[0].value 
    : null;

  // Cek apakah email user ada di dalam daftar allowedEmails
  const canChangeTheme = allowedEmails.includes(userEmail);

  // Kirim data dalam format JSON
  res.json({
    name: req.user.displayName,
    email: userEmail,
    canChangeTheme: canChangeTheme
  });
});

app.listen(5000, () => console.log('listening on port: 5000'));