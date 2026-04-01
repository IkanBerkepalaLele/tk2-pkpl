require('dotenv').config();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:5000/auth/google/callback",
  passReqToCallback: true,
  scope: ['email', 'profile']
},
function(request, accessToken, refreshToken, profile, done) {
  const emailObj = profile.emails && profile.emails.length > 0 ? profile.emails[0] : null;
  const email = emailObj ? emailObj.value : null;
  const providerVerified = emailObj ? emailObj.verified !== false : false;
  const tokenVerified = profile._json ? profile._json.email_verified !== false : true;

  if (!email || !providerVerified || !tokenVerified) {
    return done(null, false, { message: 'Google account email is missing or not verified.' });
  }

  return done(null, {
    id: profile.id,
    displayName: profile.displayName,
    email: email.toLowerCase()
  });
}));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

