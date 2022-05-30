
const config = {};

// The callback to use for OAuth requests. This is the URL where the app is
// running. For testing and running it locally, use 127.0.0.1.
config.oAuthCallbackUrl = '/auth/google/callback';
// config.oAuthCallbackUrl = 'http://127.0.0.1:8080/auth/google/callback';

// The port where the app should listen for requests.
config.port = 8080;

// The scopes to request. The app requires the photoslibrary.readonly and
// plus.me scopes.
config.scopes = [
  'https://www.googleapis.com/auth/photoslibrary.readonly',
  'openid',
  'email'
];

// The number of photos to load for search requests.
config.photosToLoad = 150;

// The page size to use for search requests. 100 is reccommended.
config.searchPageSize = 100;

// The page size to use for the listing albums request. 50 is reccommended.
config.albumPageSize = 50;

// The API end point to use. Do not change.
config.apiEndpoint = 'https://photoslibrary.googleapis.com';

config.oAuthEndpoint = 'https://accounts.google.com/o/oauth2/v2/auth';

// Endpoint for fetching access and refresh tokens
config.tokenEndpoint = 'https://oauth2.googleapis.com/token'
module.exports = config;
