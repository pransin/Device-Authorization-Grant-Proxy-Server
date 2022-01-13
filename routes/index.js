var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Google Photos for Kodi' });
});

// router.get('/', (req, res) => {
//   if (!req.user || !req.isAuthenticated()) {
//     // Not logged in yet.
//     res.redirect('/auth/google');
//   } else {
//     res.send('Logged in.');
//   }
// });

// router.get('/auth/google', passport.authenticate('google', {
//   scope: config.scopes,
//   failureFlash: true,  // Display errors to the user.
//   session: true,
// }));

// // Callback receiver for the OAuth process after log in.
// router.get(
//   '/auth/google/callback',
//   passport.authenticate(
//     'google', { failureRedirect: '/', failureFlash: true, session: true }),
//   (req, res) => {
//     // User has logged in.
//     logger.info('User has logged in.');
//     res.redirect('/');
//   });

module.exports = router;
