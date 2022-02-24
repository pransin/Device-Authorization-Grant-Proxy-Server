const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const session = require('express-session');
const NodeCache = require("node-cache");
const sessionFileStore = require('session-file-store');

// Create a new config file for sensitive data, if one does not exist
const config = require('./config.js');
const crypto = require('crypto');
const { body, validationResult, check } = require('express-validator');
const helpers = require('./helpers.js');
const fetch = require('node-fetch');
const rateLimit = require('express-rate-limit')

require('dotenv').config();
// var indexRouter = require('./routes/index');
// var usersRouter = require('./routes/users');

var app = express();
const fileStore = sessionFileStore(session);
const codeCache = new NodeCache();
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// // Set up OAuth 2.0 authentication through the passport.js brary.           
// const passport = require('passport');
// const auth = require('./auth');
// auth(passport);

// Set up a session middleware to handle user sessions.
// NOTE: A secret is used to sign the cookie. This is just used for this sample
// app and should be changed.
const sessionMiddleware = session({
  resave: true,
  saveUninitialized: true,
  store: new fileStore({}),
  secret: 'no secret for now',
});

// Set up different logger later if required
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Enable user session handling.
app.use(sessionMiddleware);

// Set up passport and session handling.
// app.use(passport.initialize());
// app.use(passport.session());

// Welcome Page. 
app.get('/', (req, res) => {
  res.render('index', { title: 'Google Photos for Kodi' });
});

// User Code verification
app.post('/', [
  body('code')
    .isLength(6)
    .withMessage('Code contains 6-digits')
    .isAlphanumeric()
    .withMessage('Code contains only alphanumeric characters').escape()
],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      res.render('index', {
        title: 'Google Photos for Kodi',
        errors: errors.array(),
        data: req.body,
      })
    }
    else {
      const userCode = req.body.code;
      const cache = codeCache.get(userCode);
      if (cache == undefined) {
        res.render('index', {
          title: 'Google Photos for Kodi',
          errors: ["Invalid Code"],
          data: req.body
        });
      }
      else {
        // state keeps track of the request
        const state = helpers.base64Encode(crypto.randomBytes(16));
        codeCache.set(state, { userCode }, 300);
        const query = {
          'response_type': 'code',
          'client_id': config.oAuthClientID,
          'redirect_uri': process.env.BASE_URL + config.oAuthCallbackUrl,
          'scope': config.scopes.join(' '),
          'access_type': 'offline',
          'state': state
        }
        const authURL = helpers.build_auth_url(config.oAuthEndpoint, query);
        res.redirect(authURL);
      }
    }
  });

// Client GETS to this route to fetch a user code along with certain other parameters
app.get(
  '/device/code', (req, res) => {
    const deviceCode = helpers.base64Encode(crypto.randomBytes(32));
    const cache = {
      'deviceCode': deviceCode,
    };
    const userCode = helpers.generateRandomString(6);
    codeCache.set(userCode, cache, 300);

    // Placeholder entry for deviceCode. Really required?
    codeCache.set(deviceCode, { 'status': 'pending' }, 300);
    const data = {
      'deviceCode': deviceCode,
      'userCode': userCode,
      'verification_uri': process.env.BASE_URL + '/device',
      'expires_in': 300,
      'interval': Math.round(60 / process.env.LIMIT_REQUESTS_PER_MINUTE)
    };
    res.send(data);
  }
)

// Redirect after authentication
app.get(config.oAuthCallbackUrl, async (req, res) => {
  const state = codeCache.get(req.query.state);
  if (!state || !req.query.code)
    res.send('Invalid Request. Try Again');
  else {
    // Exchange authorization code to get access_token and refresh_token
    const params = new URLSearchParams({
      'grant_type': 'authorization_code',
      'code': req.query.code,
      'redirect_uri': process.env.BASE_URL + config.oAuthCallbackUrl,
      'client_id': config.oAuthClientID,
      'client_secret': config.oAuthclientSecret
    });
    const response = await fetch(config.tokenEndpoint, { method: 'POST', body: params });
    const data = await response.json();
    // console.log(response);
    // Kill request in case of failure
    if (!response.ok || !data.access_token) {
      res.send("Failure");
      codeCache.del(state.userCode);
      codeCache.del(state.deviceCode);
      // throw new Error(response);
    }
    else {
      // Request successful. Store tokens in cache for client to fetch later.
      const cache = codeCache.get(state.userCode);
      codeCache.set(cache.deviceCode, {
        'status': 'complete',
        'access_token': data.access_token,
        'refresh_token': data.refresh_token,
        'expires_in': Math.round(0.99 * data.expires_in)
      }, 120)
      codeCache.del(state.userCode);
      // console.log(codeCache.get(cache.deviceCode));
      res.send('Authentication Successful. You will be logged in automatically in KODI');
    }
  }
});

// Rate Limiter
const tokenRequestLimiter = rateLimit({
  max: process.env.LIMIT_REQUESTS_PER_MINUTE,
  message: {
    error: 'slow_down'
  },
  statusCode: 403
});
app.post('/token', tokenRequestLimiter, (req, res) => {
  if (!req.body.deviceCode || !req.body.grant_type)
    res.status(400).send("invalid_request");
  else
    if (req.body.grant_type !== 'urn:ietf:params:oauth:grant-type:device_code')
      res.status(400).send('Only urn:ietf:params:oauth:grant-type:device_code is supported');
    else {
      const data = codeCache.get(req.body.deviceCode);
      // console.log(data)
      if (!data)
        res.status(400).send('invalid_grant');
      else if (data.status === 'pending') {
        res.status(202).send('authorization_pending')
      }
      else {
        // Authorization Complete, Stash the entry for deviceCode
        codeCache.del(req.body.deviceCode);
        res.send(data);
      }
    }
});
// Route for refreshing access_token
app.post('/refresh', async (req, res) => {
  if (req.body.grant_type !== 'refresh_token')
    res.send('invalid_grant')
  else if (!req.body.refresh_token)
    res.send('invalid_request')
  else {
    const params = new URLSearchParams({
      'grant_type': 'refresh_token',
      'refresh_token': req.body.refresh_token,
      'client_id': config.oAuthClientID,
      'client_secret': config.oAuthclientSecret
    });
    const response = await fetch(config.tokenEndpoint, { method: 'POST', body: params });
    if (!response.ok)
      res.status(response.status).send('Failure')
    else {
      const data = await response.json();
      data.expires_in = Math.round(0.999 * data.expires_in)
      res.send(data)
    }
  }
})
// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  if (req.app.get('env') === 'development' && err.status !== 404)
    console.log(err);

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;

// app.get('/auth/google', passport.authenticate('google', {
//   scope: config.scopes,
//   failureFlash: true,  // Display errors to the user.
//   session: true,
// }));

// Callback receiver for the OAuth process after log in.
// app.get(
//   '/auth/google/callback',
//   passport.authenticate(
//     'google', { failureRedirect: '/', failureFlash: true, session: true }),
//   (req, res) => {
//     // User has logged in.
//     console.log('User has logged in.');
//     res.redirect('/');
//   });

// Middleware that adds the user of this session as a local variable,
// so it can be displayed on all pages when logged in.
// app.use((req, res, next) => {
//   res.locals.name = '-';
//   if ( req.user && req.user.profile && req.user.profile.name) {
//     res.locals.name =
//         req.user.profile.name.givenName || req.user.profile.displayName;
//   }

//   res.locals.avatarUrl = '';
//   if (req.user && req.user.profile && req.user.profile.photos) {
//     res.locals.avatarUrl = req.user.profile.photos[0].value;
//   }
//   next();
// });

// app.get(
//   '/logout',
//   (res, req) => {
//     req.logout();
//     res.redirect('/');
// });

// app.use('/', indexRouter);
// app.use('/users', usersRouter);