const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create local Strategy
const localOptions = {
  usernameField: 'email'
};

const localLogin = new LocalStrategy(localOptions, function(
  email,
  password,
  done
) {
  // Verify email and password, call done with user
  // if correct email and password
  // otherwise, call false with done
  User.findOne({ email: email }, function(err, user) {
    if (err) {
      return done(err);
    }

    if (!user) {
      return done(null, false);
    }

    // compare passwords - is password equal to user.password?
    user.comparePassword(password, function(err, isMatch) {
      if (err) {
        return done(err);
      }
      if (!isMatch) {
        return done(null, false);
      }

      return done(null, user);
    });
  });
});

// Set up options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

// Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // See if the user id in the payload exists in db
  User.findById(payload.sub, function(err, user) {
    if (err) {
      return done(err, false);
    }

    if (user) {
      // if it does call done on that User
      done(null, user);
    } else {
      // otherwise call done without a user object
      done(null, false);
    }
  });
});

// Tell Passport to use this Strategy
passport.use(jwtLogin);
passport.use(localLogin);
