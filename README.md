# Device Authorization Grant Proxy Server
Add OAuth2 Device Authorization Grant(DAG) support to any API.
This service acts as a OAuth2.0 server, proxying to the real OAuth server.
Useful for the APIs which either do not support DAG natively or allow only a limited set of scopes for this grant.

_Note: In the present form, the server proxies to the Google Photos API but can be easily modified for other APIs._
